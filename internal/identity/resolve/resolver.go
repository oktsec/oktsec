package resolve

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"time"
)

// Profile selects between local-developer defaults (loose, friction-light)
// and enterprise defaults (fail-closed, strict). The same Resolver code
// honors both; only the policy expressed in Config differs.
type Profile string

const (
	ProfileLocal      Profile = "local"
	ProfileEnterprise Profile = "enterprise"
)

// Config controls Resolver behavior for one Surface. A single Resolver may
// hold one Config per Surface so the same resolver instance can serve the
// gateway and the egress proxy with different rules.
type Config struct {
	Profile Profile

	// AllowedTokenTypes lists which TokenTypes the resolver will try, in
	// priority order. The gateway should pass {GatewayBearer}, the egress
	// proxy {ProxyBasic}, etc.
	AllowedTokenTypes []TokenType

	// TrustedLoopbackHeaders enables the legacy X-Oktsec-Agent header as a
	// principal source — but only when the request originates from the
	// loopback interface. In enterprise mode this should always be false.
	TrustedLoopbackHeaders bool

	// LoopbackHeaderName is the header consulted when TrustedLoopbackHeaders
	// is true. Defaults to "X-Oktsec-Agent" when empty.
	LoopbackHeaderName string

	// ReportedActorPayloadKeys lists payload field names whose values may
	// be surfaced as ReportedActor. The first non-empty value wins. These
	// fields never become Principal regardless of profile.
	ReportedActorPayloadKeys []string

	// ReportedActorHeaderName, when non-empty, lets a surface declare a
	// header that always populates ReportedActor (never Principal). Useful
	// for hook adapters that supply a sub-agent name in headers.
	ReportedActorHeaderName string
}

// DefaultResolver is the shared implementation. It looks up tokens in a
// TokenStore, falls back to the loopback header in local profile when
// allowed, and otherwise returns an anonymous Principal. A Resolver is
// safe for concurrent use; the underlying TokenStore must be too.
type DefaultResolver struct {
	store TokenStore
	now   func() time.Time // injectable for tests
}

// NewDefaultResolver returns a Resolver backed by store. If now is nil the
// resolver uses time.Now.
func NewDefaultResolver(store TokenStore, now func() time.Time) *DefaultResolver {
	if now == nil {
		now = time.Now
	}
	return &DefaultResolver{store: store, now: now}
}

// Resolve honors a per-surface Config. Most callers will wrap this in a
// surface-specific helper that pre-fills the Config for that surface.
func (r *DefaultResolver) Resolve(ctx context.Context, cfg Config, evidence Evidence) (Result, error) {
	// 1. Try every allowed token type, in declared order, against the
	// Authorization header. First match wins.
	if raw, ok := bearerFromAuthorization(evidence.Header); ok {
		for _, t := range cfg.AllowedTokenTypes {
			if t == TokenTypeProxyBasic {
				// Proxy basic comes from a different header; skip here.
				continue
			}
			principal, tok, err := r.store.Lookup(t, raw)
			if err == nil {
				return r.buildResult(principal, tok, evidence, cfg), nil
			}
		}
	}

	// 1b. Proxy-Authorization (basic) for the egress proxy surface. The
	// proxy surface uses Basic <user:> where the username is the raw token.
	if user, ok := userFromProxyAuthorization(evidence.Header); ok {
		for _, t := range cfg.AllowedTokenTypes {
			if t != TokenTypeProxyBasic {
				continue
			}
			principal, tok, err := r.store.Lookup(t, user)
			if err == nil {
				return r.buildResult(principal, tok, evidence, cfg), nil
			}
		}
	}

	// 2. Trusted loopback header is a degraded form of identity used in
	// local profile. The remote address must actually be loopback; the
	// header name is configurable so adapters can opt in to legacy paths
	// (e.g. X-Oktsec-Agent for the MCP gateway).
	if cfg.TrustedLoopbackHeaders && cfg.Profile == ProfileLocal && IsLoopback(evidence.RemoteAddr) {
		headerName := cfg.LoopbackHeaderName
		if headerName == "" {
			headerName = "X-Oktsec-Agent"
		}
		if id := strings.TrimSpace(evidence.Header.Get(headerName)); id != "" {
			result := Result{
				Principal: Principal{
					ID:          id,
					DisplayName: id,
					Kind:        PrincipalKindAgent,
					AuthMethod:  AuthMethodTrustedLoopback,
					TrustLevel:  TrustLocal,
				},
			}
			result.ReportedActor = extractReportedActor(evidence, cfg)
			// Loopback header is weaker than a token; advise the operator
			// once the data path supports it.
			result.Warnings = append(result.Warnings,
				"identity established via loopback header; configure a bearer token for stronger auth")
			return result, nil
		}
	}

	// 3. No identity. ReportedActor may still be populated from payload or
	// a dedicated header so the dashboard can show *something*, but it does
	// not become Principal.
	return Result{
		Principal: Principal{
			ID:          "unknown",
			DisplayName: "unknown",
			Kind:        PrincipalKindUnknown,
			AuthMethod:  AuthMethodNone,
			TrustLevel:  TrustAnonymous,
		},
		ReportedActor: extractReportedActor(evidence, cfg),
	}, nil
}

func (r *DefaultResolver) buildResult(p PrincipalRecord, tok TokenRecord, evidence Evidence, cfg Config) Result {
	res := Result{
		Principal: Principal{
			ID:          p.ID,
			DisplayName: p.DisplayName,
			Kind:        p.Kind,
			AuthMethod:  authMethodForToken(tok.Type),
			TrustLevel:  TrustAuthenticated,
			TokenID:     tok.ID,
			WorkspaceID: p.WorkspaceID,
			Context:     clonePrincipalContext(p.Context),
		},
		ReportedActor: extractReportedActor(evidence, cfg),
	}
	if res.Principal.Kind == "" {
		res.Principal.Kind = PrincipalKindAgent
	}
	if res.Principal.DisplayName == "" {
		res.Principal.DisplayName = res.Principal.ID
	}
	return res
}

func authMethodForToken(t TokenType) AuthMethod {
	switch t {
	case TokenTypeGatewayBearer:
		return AuthMethodBearerToken
	case TokenTypeProxyBasic:
		return AuthMethodProxyToken
	case TokenTypeHookBearer:
		return AuthMethodHookToken
	}
	return AuthMethodNone
}

// bearerFromAuthorization extracts the token portion of an `Authorization:
// Bearer <token>` header. The check is case-insensitive on the scheme name.
func bearerFromAuthorization(h http.Header) (string, bool) {
	v := h.Get("Authorization")
	if v == "" {
		return "", false
	}
	const prefix = "bearer "
	if len(v) <= len(prefix) {
		return "", false
	}
	if !strings.EqualFold(v[:len(prefix)], prefix) {
		return "", false
	}
	tok := strings.TrimSpace(v[len(prefix):])
	if tok == "" {
		return "", false
	}
	return tok, true
}

// userFromProxyAuthorization extracts the username portion of a Proxy
// Basic header. The token is delivered as the username with an empty
// password (matching `http://okt_proxy_xxx:@host:port` env-var URLs).
func userFromProxyAuthorization(h http.Header) (string, bool) {
	v := h.Get("Proxy-Authorization")
	if v == "" {
		return "", false
	}
	const prefix = "basic "
	if len(v) <= len(prefix) || !strings.EqualFold(v[:len(prefix)], prefix) {
		return "", false
	}
	encoded := strings.TrimSpace(v[len(prefix):])
	dec, err := base64Decode(encoded)
	if err != nil {
		return "", false
	}
	user := dec
	if i := strings.IndexByte(dec, ':'); i >= 0 {
		user = dec[:i]
	}
	user = strings.TrimSpace(user)
	if user == "" {
		return "", false
	}
	return user, true
}

func base64Decode(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// extractReportedActor pulls the first non-empty payload key, then falls
// back to the configured header. The Source/Confidence fields tell the
// dashboard how trustworthy the value is.
func extractReportedActor(evidence Evidence, cfg Config) ReportedActor {
	for _, key := range cfg.ReportedActorPayloadKeys {
		if v, ok := stringFromPayload(evidence.Payload, key); ok {
			return ReportedActor{
				ID:          v,
				DisplayName: v,
				Source:      "payload",
				Confidence:  "medium",
			}
		}
	}
	if cfg.ReportedActorHeaderName != "" {
		if v := strings.TrimSpace(evidence.Header.Get(cfg.ReportedActorHeaderName)); v != "" {
			return ReportedActor{
				ID:          v,
				DisplayName: v,
				Source:      "header",
				Confidence:  "medium",
			}
		}
	}
	// Legacy ConfigAgent (set by older surfaces from X-Oktsec-Agent before
	// the resolver existed) becomes a low-confidence reported actor when it
	// is not the established principal.
	if v := strings.TrimSpace(evidence.ConfigAgent); v != "" {
		return ReportedActor{
			ID:          v,
			DisplayName: v,
			Source:      "header",
			Confidence:  "low",
		}
	}
	return ReportedActor{}
}

func stringFromPayload(p map[string]any, key string) (string, bool) {
	if p == nil {
		return "", false
	}
	v, ok := p[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	return s, true
}
