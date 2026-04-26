package coverage

import (
	"sort"
	"strings"
	"time"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/connectors"
)

// Compute folds the current configuration and audit observations into a
// per-principal, per-surface coverage matrix. Output is sorted by
// principal id then surface so dashboard rendering is deterministic.
//
// The function is intentionally pure: it does not query the audit store
// directly (callers pass a narrow AuditReader) and does not mutate cfg.
// Tests can drive it with a fake AuditReader and any *config.Config.
//
// Connector inference goes through the package-level connectors.Default
// registry so a future operator-defined connector layer can swap in
// without touching coverage. Callers that want to inject a different
// registry can use ComputeWith.
func Compute(cfg *config.Config, ar AuditReader) []CoverageCell {
	return ComputeWith(cfg, ar, connectors.Default())
}

// ComputeWith is Compute with an explicit Registry. Used by tests that
// want to inject a custom registry; production wiring uses Compute.
func ComputeWith(cfg *config.Config, ar AuditReader, reg connectors.Registry) []CoverageCell {
	if cfg == nil {
		return nil
	}
	if reg == nil {
		reg = connectors.Default()
	}
	now := time.Now()
	observedMethods := observedAuthMethodsFromConfig(cfg)

	var cells []CoverageCell
	for _, p := range cfg.Identity.Principals {
		tokensByType := activeTokenTypes(p, now)
		connector := reg.Infer(tokensByType, observedMethods).ID
		for _, surface := range AllSurfaces {
			cell := computeCell(cfg, p, connector, surface, tokensByType)
			if ar != nil {
				if ts, err := ar.LastSeenByPrincipalSurface(p.ID, string(surface)); err == nil {
					cell.LastSeen = ts
				}
			}
			cells = append(cells, cell)
		}
	}
	sort.Slice(cells, func(i, j int) bool {
		if cells[i].PrincipalID != cells[j].PrincipalID {
			return cells[i].PrincipalID < cells[j].PrincipalID
		}
		return cells[i].Surface < cells[j].Surface
	})
	return cells
}

// observedAuthMethodsFromConfig derives the auth-method evidence map
// the registry needs from current configuration. Today the only piece
// of evidence that comes from config (rather than from the activity
// store) is whether the loopback header is honored on at least one
// surface — that determines the legacy-loopback-header vs unknown
// fork in the registry's inference rule.
//
// PR5 will plumb live activity-derived evidence on top of this so a
// principal that has only ever shown wrapper-signed activity can be
// labeled accordingly. For PR4 the config-derived signal is enough to
// keep local-mode deployments labeled as legacy-loopback-header (the
// existing behavior) and enterprise-mode deployments without working
// tokens labeled as unknown (an honest improvement).
func observedAuthMethodsFromConfig(cfg *config.Config) map[string]bool {
	out := map[string]bool{}
	if cfg == nil {
		return out
	}
	if isLocalLoopbackHeaderActive(cfg, cfg.Gateway.SurfaceAuthConfig) ||
		isLocalLoopbackHeaderActive(cfg, cfg.ForwardProxy.SurfaceAuthConfig) {
		out["trusted_loopback"] = true
	}
	return out
}

// activeTokenTypes returns the set of TokenTypes the principal currently
// holds in active form. Inactive entries (revoked or past expires_at)
// are skipped so a stale revoked gateway token does not look like
// "protected MCP" in the matrix.
func activeTokenTypes(p config.PrincipalConfig, now time.Time) map[string]bool {
	out := make(map[string]bool, len(p.Tokens))
	for _, t := range p.Tokens {
		if t.RevokedAt != "" {
			continue
		}
		if t.ExpiresAt != "" {
			exp, err := time.Parse(time.RFC3339, t.ExpiresAt)
			if err != nil || !now.Before(exp) {
				continue
			}
		}
		out[t.Type] = true
	}
	return out
}

// computeCell decides the (Coverage, AuthMethod, TrustLevel, Limitation)
// for one (principal, surface) pair. The decision uses three inputs:
//   1. Whether the surface is enabled at all.
//   2. Whether the principal holds a token of the matching type.
//   3. The surface's local/enterprise auth posture (loopback header on,
//      require_auth, etc.).
func computeCell(cfg *config.Config, p config.PrincipalConfig, connector string, surface Surface, tokens map[string]bool) CoverageCell {
	cell := CoverageCell{
		PrincipalID: p.ID,
		ConnectorID: connector,
		Surface:     string(surface),
	}

	switch surface {
	case SurfaceMCPHTTP:
		fillMCPHTTP(&cell, cfg, tokens)
	case SurfaceHTTPEgress:
		fillEgress(&cell, cfg, tokens)
	case SurfaceHooks:
		fillHooks(&cell, cfg, tokens)
	}
	return cell
}

func fillMCPHTTP(c *CoverageCell, cfg *config.Config, tokens map[string]bool) {
	if !cfg.Gateway.Enabled {
		c.Coverage = CoverageBlind
		c.Limitation = "gateway not enabled"
		return
	}
	if tokens["gateway_bearer"] {
		c.Coverage = CoverageProtected
		c.AuthMethod = "bearer_token"
		c.TrustLevel = "authenticated"
		return
	}
	// No token but loopback header may still grant trusted_local in
	// local profile when the operator has not flipped to enterprise.
	if isLocalLoopbackHeaderActive(cfg, cfg.Gateway.SurfaceAuthConfig) {
		c.Coverage = CoverageObserved
		c.AuthMethod = "trusted_loopback"
		c.TrustLevel = "trusted_local"
		c.Limitation = "loopback header only — issue a gateway_bearer token for stronger auth"
		return
	}
	c.Coverage = CoverageBlind
	c.Limitation = "no gateway_bearer token configured"
}

func fillEgress(c *CoverageCell, cfg *config.Config, tokens map[string]bool) {
	if !cfg.ForwardProxy.Enabled {
		c.Coverage = CoverageBlind
		c.Limitation = "forward proxy not enabled"
		return
	}
	if tokens["proxy_basic"] {
		c.Coverage = CoverageProtected
		c.AuthMethod = "proxy_token"
		c.TrustLevel = "authenticated"
		// Egress is special: we can block before the action only when the
		// payload is visible (plain HTTP or explicit HTTPS inspection).
		// CONNECT tunnels are domain-only by default. Surface that as a
		// limitation, not as a downgrade.
		c.Limitation = egressProtectionDetail(cfg)
		return
	}
	if isLocalLoopbackHeaderActive(cfg, cfg.ForwardProxy.SurfaceAuthConfig) {
		c.Coverage = CoverageObserved
		c.AuthMethod = "trusted_loopback"
		c.TrustLevel = "trusted_local"
		c.Limitation = "loopback header only — issue a proxy_basic token for stronger auth"
		return
	}
	c.Coverage = CoverageBlind
	c.Limitation = "no proxy_basic token configured"
}

func fillHooks(c *CoverageCell, cfg *config.Config, tokens map[string]bool) {
	// The hooks endpoint is mounted on the gateway's HTTP mux at
	// /hooks/event (see gateway.Start). When the gateway is disabled
	// the surface is not exposed at all — every principal is blind
	// regardless of token configuration.
	if !cfg.Gateway.Enabled {
		c.Coverage = CoverageBlind
		c.Limitation = "hooks endpoint not exposed (gateway disabled)"
		return
	}
	if tokens["hook_bearer"] {
		c.Coverage = CoverageProtected
		c.AuthMethod = "hook_token"
		c.TrustLevel = "authenticated"
		c.Limitation = "pre-action hooks block when client honors the decision; post-action hooks are observed only"
		return
	}
	// Hooks accept unauthenticated POSTs as observed telemetry in local
	// profile. Enterprise / require_auth flips this to blind for the
	// principal because the surface refuses anonymous events.
	if hooksAcceptsUnauth(cfg) {
		c.Coverage = CoverageObserved
		c.AuthMethod = ""
		c.TrustLevel = "anonymous"
		c.Limitation = "no hook_bearer token; events accepted as observed telemetry only"
		return
	}
	c.Coverage = CoverageBlind
	c.Limitation = "no hook_bearer token; surface requires authenticated identity"
}

// isLocalLoopbackHeaderActive mirrors the resolver's local-profile logic:
// loopback header authentication is on either when the surface explicitly
// enabled it or when the operator has not customized auth_methods at all
// in local profile.
func isLocalLoopbackHeaderActive(cfg *config.Config, sa config.SurfaceAuthConfig) bool {
	if !strings.EqualFold(strings.TrimSpace(cfg.Deployment.Profile), "local") &&
		strings.TrimSpace(cfg.Deployment.Profile) != "" {
		return false
	}
	if sa.TrustedLoopbackHeaders {
		return true
	}
	if len(sa.AuthMethods) == 0 {
		return true
	}
	for _, m := range sa.AuthMethods {
		if strings.EqualFold(strings.TrimSpace(m), "trusted_loopback_header") {
			return true
		}
	}
	return false
}

// hooksAcceptsUnauth mirrors what the hook handler does at request
// time: when require_auth is off and the deployment is not enterprise,
// unauthenticated POSTs are recorded as observed telemetry rather than
// rejected.
func hooksAcceptsUnauth(cfg *config.Config) bool {
	if strings.EqualFold(strings.TrimSpace(cfg.Deployment.Profile), "enterprise") {
		return false
	}
	if cfg.Deployment.RequireSurfaceAuth {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Hooks.RequireAuth)) {
	case "true", "yes", "1":
		return false
	}
	return true
}

// egressProtectionDetail picks the right one-sentence caveat for a
// principal that is technically authenticated to the egress proxy but
// whose effective coverage depends on whether HTTPS bodies are being
// inspected. Defaults to the conservative "domain-only" framing because
// HTTPS inspection is opt-in and not configured today.
func egressProtectionDetail(cfg *config.Config) string {
	if cfg.ForwardProxy.ScanResponses && cfg.ForwardProxy.ScanRequests {
		return "plain HTTP bodies inspected; HTTPS CONNECT is domain-only unless inspection is enabled"
	}
	if cfg.ForwardProxy.ScanRequests {
		return "request bodies inspected on plain HTTP; HTTPS CONNECT is domain-only"
	}
	return "domain-only (HTTPS CONNECT and disabled body scanning)"
}
