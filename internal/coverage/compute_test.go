package coverage

import (
	"testing"
	"time"

	"github.com/oktsec/oktsec/internal/config"
)

// fakeAuditReader returns canned timestamps. The narrow AuditReader
// interface is the whole point: Compute can be exercised without a
// real audit store, and tests own exactly what they want LastSeen to
// look like for each (principal, surface).
type fakeAuditReader struct{ stamps map[string]string }

func (f fakeAuditReader) LastSeenByPrincipalSurface(principalID, surface string) (string, error) {
	return f.stamps[principalID+"|"+surface], nil
}

// pickCell returns the cell for a (principal, surface) pair so tests can
// assert per-cell instead of indexing into the slice.
func pickCell(t *testing.T, cells []CoverageCell, principalID string, surface Surface) CoverageCell {
	t.Helper()
	for _, c := range cells {
		if c.PrincipalID == principalID && c.Surface == string(surface) {
			return c
		}
	}
	t.Fatalf("no cell for principal=%q surface=%q (have %d cells)", principalID, surface, len(cells))
	return CoverageCell{}
}

func principalWith(id string, tokenTypes ...string) config.PrincipalConfig {
	p := config.PrincipalConfig{ID: id, DisplayName: id, Kind: "agent"}
	for i, tt := range tokenTypes {
		p.Tokens = append(p.Tokens, config.PrincipalTokenConfig{
			ID:        id + "-tok-" + tt,
			Type:      tt,
			Hash:      "sha256:dummy",
			CreatedAt: time.Now().Add(-time.Duration(i+1) * time.Hour).UTC().Format(time.RFC3339),
		})
	}
	return p
}

// 1. A principal with a gateway_bearer token, on an enabled gateway,
// reports MCP HTTP as protected with bearer-token identity. The other
// surfaces are blind because the principal does not own their tokens.
func TestCompute_BearerGatewayProtected(t *testing.T) {
	cfg := &config.Config{
		Identity: config.IdentityConfig{Principals: []config.PrincipalConfig{
			principalWith("local-codex", "gateway_bearer"),
		}},
		Gateway: config.GatewayConfig{Enabled: true},
	}
	cells := Compute(cfg, nil)

	mcp := pickCell(t, cells, "local-codex", SurfaceMCPHTTP)
	if mcp.Coverage != CoverageProtected || mcp.AuthMethod != "bearer_token" {
		t.Errorf("MCP cell = %+v; want protected/bearer_token", mcp)
	}
	if mcp.TrustLevel != "authenticated" {
		t.Errorf("MCP trust level = %q; want authenticated", mcp.TrustLevel)
	}
	if mcp.ConnectorID != ConnectorGenericMCPHTTP {
		t.Errorf("connector = %q; want %s", mcp.ConnectorID, ConnectorGenericMCPHTTP)
	}
}

// 2. A principal with a proxy_basic token, on an enabled forward proxy,
// is protected at the egress surface. The Limitation field carries the
// HTTPS-CONNECT caveat so dashboards do not over-claim content visibility.
func TestCompute_ProxyTokenProtectedEgress(t *testing.T) {
	cfg := &config.Config{
		Identity: config.IdentityConfig{Principals: []config.PrincipalConfig{
			principalWith("local-codex", "proxy_basic"),
		}},
		ForwardProxy: config.ForwardProxyConfig{Enabled: true, ScanRequests: true},
	}
	cells := Compute(cfg, nil)

	eg := pickCell(t, cells, "local-codex", SurfaceHTTPEgress)
	if eg.Coverage != CoverageProtected {
		t.Errorf("egress coverage = %q; want protected", eg.Coverage)
	}
	if eg.AuthMethod != "proxy_token" {
		t.Errorf("egress auth = %q; want proxy_token", eg.AuthMethod)
	}
	if eg.Limitation == "" {
		t.Error("egress protected cell must carry a Limitation explaining CONNECT visibility")
	}
}

// 3. A principal with a hook_bearer token is protected at the hooks
// surface and the cell explains the pre/post asymmetry instead of
// claiming "fully blocked".
func TestCompute_HookBearerProtected(t *testing.T) {
	cfg := &config.Config{
		Identity: config.IdentityConfig{Principals: []config.PrincipalConfig{
			principalWith("local-codex", "hook_bearer"),
		}},
		// Hooks are mounted on the gateway's HTTP mux, so they are only
		// exposed when the gateway is enabled. Tests that exercise hooks
		// must enable the gateway even when MCP HTTP is not the focus.
		Gateway: config.GatewayConfig{Enabled: true},
	}
	cells := Compute(cfg, nil)

	hk := pickCell(t, cells, "local-codex", SurfaceHooks)
	if hk.Coverage != CoverageProtected || hk.AuthMethod != "hook_token" {
		t.Errorf("hooks cell = %+v; want protected/hook_token", hk)
	}
	if hk.Limitation == "" {
		t.Error("hooks protected cell should explain pre vs post action behavior in Limitation")
	}
}

// 4. A principal with no tokens, in default local profile, falls back to
// the legacy X-Oktsec-Agent loopback path: trusted_local identity but
// only observed coverage. The matrix must not paint this as protected.
func TestCompute_LegacyLoopbackHeaderObservedNotProtected(t *testing.T) {
	cfg := &config.Config{
		Identity: config.IdentityConfig{Principals: []config.PrincipalConfig{
			principalWith("claude-code"),
		}},
		Gateway: config.GatewayConfig{Enabled: true}, // local profile, no AuthMethods override
	}
	cells := Compute(cfg, nil)

	mcp := pickCell(t, cells, "claude-code", SurfaceMCPHTTP)
	if mcp.Coverage == CoverageProtected {
		t.Errorf("MCP cell = %+v; loopback header must not be reported as protected", mcp)
	}
	if mcp.TrustLevel != "trusted_local" {
		t.Errorf("MCP trust level = %q; want trusted_local", mcp.TrustLevel)
	}
	if mcp.ConnectorID != ConnectorLegacyLocalHeader {
		t.Errorf("connector = %q; want %s", mcp.ConnectorID, ConnectorLegacyLocalHeader)
	}
}

// 5. A surface that is not enabled is reported as blind for every
// principal, with a Limitation that names the missing piece. This is
// the structural antidote to the dashboard inflating coverage.
func TestCompute_DisabledSurfaceIsBlind(t *testing.T) {
	cfg := &config.Config{
		Identity: config.IdentityConfig{Principals: []config.PrincipalConfig{
			principalWith("local-codex", "gateway_bearer"),
		}},
		Gateway:      config.GatewayConfig{Enabled: false},      // off
		ForwardProxy: config.ForwardProxyConfig{Enabled: false}, // off
	}
	cells := Compute(cfg, nil)

	mcp := pickCell(t, cells, "local-codex", SurfaceMCPHTTP)
	if mcp.Coverage != CoverageBlind {
		t.Errorf("MCP cell = %+v; disabled gateway must be blind", mcp)
	}
	eg := pickCell(t, cells, "local-codex", SurfaceHTTPEgress)
	if eg.Coverage != CoverageBlind {
		t.Errorf("egress cell = %+v; disabled forward proxy must be blind", eg)
	}
}

// 6. Hooks unauthenticated path: in local profile without require_auth,
// a principal with no hook_bearer token is observed (not blind) because
// the surface accepts anonymous events as telemetry. Enterprise flips
// the same scenario to blind because the surface refuses anonymous.
func TestCompute_HooksUnauthLocalObservedEnterpriseBlind(t *testing.T) {
	base := func(profile string) *config.Config {
		return &config.Config{
			Deployment: config.DeploymentConfig{Profile: profile},
			Identity: config.IdentityConfig{Principals: []config.PrincipalConfig{
				principalWith("local-codex"), // no tokens
			}},
			Gateway: config.GatewayConfig{Enabled: true}, // hooks live on gateway mux
		}
	}

	local := Compute(base("local"), nil)
	hk := pickCell(t, local, "local-codex", SurfaceHooks)
	if hk.Coverage != CoverageObserved {
		t.Errorf("local hooks coverage = %q; want observed", hk.Coverage)
	}

	ent := Compute(base("enterprise"), nil)
	hk = pickCell(t, ent, "local-codex", SurfaceHooks)
	if hk.Coverage != CoverageBlind {
		t.Errorf("enterprise hooks coverage = %q; want blind", hk.Coverage)
	}
}

// 7. Multi-surface principal is reported with the custom-client
// connector. The matrix shows protected for every surface where a
// matching token exists.
func TestCompute_MultiSurfacePrincipalIsCustomClient(t *testing.T) {
	cfg := &config.Config{
		Identity: config.IdentityConfig{Principals: []config.PrincipalConfig{
			principalWith("local-codex", "gateway_bearer", "proxy_basic", "hook_bearer"),
		}},
		Gateway:      config.GatewayConfig{Enabled: true},
		ForwardProxy: config.ForwardProxyConfig{Enabled: true},
	}
	cells := Compute(cfg, nil)

	for _, surface := range AllSurfaces {
		c := pickCell(t, cells, "local-codex", surface)
		if c.Coverage != CoverageProtected {
			t.Errorf("surface %q coverage = %q; want protected", surface, c.Coverage)
		}
		if c.ConnectorID != ConnectorCustomClient {
			t.Errorf("surface %q connector = %q; want %s", surface, c.ConnectorID, ConnectorCustomClient)
		}
	}
}

// 8. Revoked tokens do not contribute to coverage. A principal whose
// only gateway_bearer token has revoked_at set is reported as blind
// for MCP HTTP, even though the token row still exists.
func TestCompute_RevokedTokenDoesNotProtect(t *testing.T) {
	p := principalWith("local-codex", "gateway_bearer")
	p.Tokens[0].RevokedAt = time.Now().UTC().Format(time.RFC3339)
	cfg := &config.Config{
		Identity: config.IdentityConfig{Principals: []config.PrincipalConfig{p}},
		Gateway:  config.GatewayConfig{Enabled: true},
		Deployment: config.DeploymentConfig{Profile: "enterprise"}, // turn off loopback fallback
	}
	cells := Compute(cfg, nil)

	mcp := pickCell(t, cells, "local-codex", SurfaceMCPHTTP)
	if mcp.Coverage == CoverageProtected {
		t.Errorf("MCP cell = %+v; a revoked gateway_bearer must not protect", mcp)
	}
}

// 9b. An expired-only gateway_bearer token must NOT label the principal
// as generic-mcp-http. inferConnectorIDFromActive uses the same active
// set Compute uses for coverage, so an expired token is invisible to
// both. Without this guard, the matrix would advertise a connector the
// principal cannot actually use.
func TestCompute_ExpiredTokenDoesNotInferConnector(t *testing.T) {
	p := principalWith("local-codex", "gateway_bearer")
	p.Tokens[0].ExpiresAt = "2026-01-02T00:00:00Z" // already in the past
	cfg := &config.Config{
		Identity: config.IdentityConfig{Principals: []config.PrincipalConfig{p}},
		Gateway:  config.GatewayConfig{Enabled: true},
		Deployment: config.DeploymentConfig{Profile: "enterprise"},
	}
	cells := Compute(cfg, nil)

	mcp := pickCell(t, cells, "local-codex", SurfaceMCPHTTP)
	if mcp.ConnectorID != ConnectorLegacyLocalHeader {
		t.Errorf("connector = %q; want %s when the only token is expired",
			mcp.ConnectorID, ConnectorLegacyLocalHeader)
	}
	if mcp.Coverage == CoverageProtected {
		t.Errorf("MCP cell = %+v; an expired gateway_bearer must not protect", mcp)
	}
}

// 10. LastSeen flows from the AuditReader into the right surface cell
// for every supported surface. The fake reader keys (principal+surface)
// match what Compute requests, so a regression in either side surfaces
// here as a missing or misplaced timestamp.
func TestCompute_LastSeenPerSurfaceAllThree(t *testing.T) {
	cfg := &config.Config{
		Identity: config.IdentityConfig{Principals: []config.PrincipalConfig{
			principalWith("local-codex", "gateway_bearer", "proxy_basic", "hook_bearer"),
		}},
		Gateway:      config.GatewayConfig{Enabled: true},
		ForwardProxy: config.ForwardProxyConfig{Enabled: true},
	}
	stamps := map[string]string{
		"local-codex|mcp_http":          "2026-04-26T10:00:00Z",
		"local-codex|http_egress_proxy": "2026-04-26T11:00:00Z",
		"local-codex|hooks":             "2026-04-26T12:00:00Z",
	}
	cells := Compute(cfg, fakeAuditReader{stamps: stamps})

	for _, tc := range []struct {
		surface Surface
		want    string
	}{
		{SurfaceMCPHTTP, "2026-04-26T10:00:00Z"},
		{SurfaceHTTPEgress, "2026-04-26T11:00:00Z"},
		{SurfaceHooks, "2026-04-26T12:00:00Z"},
	} {
		if got := pickCell(t, cells, "local-codex", tc.surface).LastSeen; got != tc.want {
			t.Errorf("surface %q last_seen = %q; want %q", tc.surface, got, tc.want)
		}
	}
}

// 9. LastSeen is populated from the AuditReader and threaded onto each
// cell independently. A principal active on MCP HTTP yesterday and on
// hooks 2 minutes ago must show both timestamps in the right cells.
func TestCompute_LastSeenPerSurface(t *testing.T) {
	cfg := &config.Config{
		Identity: config.IdentityConfig{Principals: []config.PrincipalConfig{
			principalWith("local-codex", "gateway_bearer", "hook_bearer"),
		}},
		Gateway: config.GatewayConfig{Enabled: true},
	}
	stamps := map[string]string{
		"local-codex|mcp_http": "2026-04-25T10:00:00Z",
		"local-codex|hooks":    "2026-04-26T13:58:00Z",
	}
	cells := Compute(cfg, fakeAuditReader{stamps: stamps})

	if got := pickCell(t, cells, "local-codex", SurfaceMCPHTTP).LastSeen; got != "2026-04-25T10:00:00Z" {
		t.Errorf("MCP last seen = %q; want 2026-04-25T10:00:00Z", got)
	}
	if got := pickCell(t, cells, "local-codex", SurfaceHooks).LastSeen; got != "2026-04-26T13:58:00Z" {
		t.Errorf("hooks last seen = %q; want 2026-04-26T13:58:00Z", got)
	}
	// A surface with no recorded activity stays empty rather than
	// inheriting another surface's timestamp.
	if got := pickCell(t, cells, "local-codex", SurfaceHTTPEgress).LastSeen; got != "" {
		t.Errorf("egress last seen = %q; want empty", got)
	}
}
