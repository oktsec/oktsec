package gateway

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/identity/resolve"
)

// identityProbe is the downstream handler used by these tests. It captures
// what authMiddleware put into the request context so the assertions can
// verify Principal/ReportedActor/AuthMethod independently of the MCP path.
type identityProbe struct {
	called        bool
	principal     string
	reportedActor string
	authMethod    string
	status        int
}

func (p *identityProbe) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.called = true
		if v, ok := r.Context().Value(agentContextKey).(string); ok {
			p.principal = v
		}
		if v, ok := r.Context().Value(reportedActorContextKey).(string); ok {
			p.reportedActor = v
		}
		if v, ok := r.Context().Value(authMethodContextKey).(string); ok {
			p.authMethod = v
		}
		p.status = http.StatusOK
		w.WriteHeader(http.StatusOK)
	})
}

// gatewayWithPrincipal builds a test gateway with one principal whose
// gateway-bearer token is returned as `raw`. The deployment profile and
// gateway-auth knobs come from the supplied builder so each test can
// declare its own scenario without smuggling globals.
func gatewayWithPrincipal(t *testing.T, principalID string, build func(*config.Config)) (*Gateway, string) {
	t.Helper()
	raw, hash, err := resolve.GenerateRawToken(resolve.TokenTypeGatewayBearer)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	cfg := &config.Config{
		Identity: config.IdentityConfig{
			Principals: []config.PrincipalConfig{{
				ID:          principalID,
				DisplayName: principalID,
				Kind:        "agent",
				Tokens: []config.PrincipalTokenConfig{{
					ID:        principalID + "-tok",
					Type:      "gateway_bearer",
					Hash:      hash,
					CreatedAt: "2026-04-26T00:00:00Z",
				}},
			}},
		},
		Gateway: config.GatewayConfig{Enabled: true},
		Agents:  map[string]config.Agent{},
	}
	if build != nil {
		build(cfg)
	}
	g := newGatewayForTest(cfg, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return g, raw
}

// 1. A valid bearer token wins over a spoofed X-Oktsec-Agent header. The
// header is allowed to surface as a low-confidence reported actor, but
// the Principal must be the token owner.
func TestGatewayAuth_BearerWinsOverSpoofedAgentHeader(t *testing.T) {
	g, raw := gatewayWithPrincipal(t, "local-codex", func(c *config.Config) {
		// Local profile + loopback headers on is the strictest test:
		// even when the legacy header path is enabled, the bearer wins.
		c.Gateway.TrustedLoopbackHeaders = true
	})
	probe := &identityProbe{}
	mw := g.authMiddleware(probe.handler())

	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	req.Header.Set("X-Oktsec-Agent", "admin") // attacker spoof
	req.RemoteAddr = "127.0.0.1:55001"

	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	if !probe.called {
		t.Fatal("middleware short-circuited but should have allowed the request")
	}
	if probe.principal != "local-codex" {
		t.Errorf("principal = %q, want local-codex (bearer must win)", probe.principal)
	}
	if probe.authMethod != string(resolve.AuthMethodBearerToken) {
		t.Errorf("auth method = %q, want bearer_token", probe.authMethod)
	}
	if probe.reportedActor != "admin" {
		t.Errorf("reported actor = %q, want admin (header surfaces as reported only)", probe.reportedActor)
	}
}

// 2. Enterprise profile rejects the loopback header path: even when the
// remote really is loopback and YAML says trusted_loopback_headers=true,
// enterprise treats the header as reported metadata only. With
// require_auth implied by enterprise, the request is 401.
func TestGatewayAuth_EnterpriseRejectsLoopbackHeader(t *testing.T) {
	g, _ := gatewayWithPrincipal(t, "local-codex", func(c *config.Config) {
		c.Deployment.Profile = "enterprise"
		c.Gateway.TrustedLoopbackHeaders = true // honored only in local
	})
	probe := &identityProbe{}
	mw := g.authMiddleware(probe.handler())

	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("X-Oktsec-Agent", "admin")
	req.RemoteAddr = "127.0.0.1:55001"

	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (enterprise must fail closed)", rr.Code)
	}
	if probe.called {
		t.Error("downstream handler should not run on 401")
	}
	if got := rr.Header().Get("WWW-Authenticate"); got == "" {
		t.Error("401 response missing WWW-Authenticate hint")
	}
}

// 3. Local profile with require_auth=true rejects requests that lack an
// authenticated principal. Confirms the explicit override beats the
// permissive local default.
func TestGatewayAuth_RequireAuthRejectsAnonymous(t *testing.T) {
	g, _ := gatewayWithPrincipal(t, "local-codex", func(c *config.Config) {
		c.Gateway.RequireAuth = "true"
	})
	probe := &identityProbe{}
	mw := g.authMiddleware(probe.handler())

	req := httptest.NewRequest("POST", "/mcp", nil)
	req.RemoteAddr = "127.0.0.1:55001"

	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	if probe.called {
		t.Error("downstream handler should not run on 401")
	}
}

// 4. Local profile keeps the legacy loopback header working out of the
// box (no token, no auth_methods override). This is what every existing
// X-Oktsec-Agent caller relies on; backwards-compat must not break.
func TestGatewayAuth_LocalLegacyLoopbackHeaderStillWorks(t *testing.T) {
	g, _ := gatewayWithPrincipal(t, "local-codex", nil) // local default
	probe := &identityProbe{}
	mw := g.authMiddleware(probe.handler())

	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("X-Oktsec-Agent", "claude-code")
	req.RemoteAddr = "127.0.0.1:55001"

	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	if !probe.called {
		t.Fatal("middleware short-circuited; local loopback header should authenticate")
	}
	if probe.principal != "claude-code" {
		t.Errorf("principal = %q, want claude-code", probe.principal)
	}
	if probe.authMethod != string(resolve.AuthMethodTrustedLoopback) {
		t.Errorf("auth method = %q, want trusted_loopback", probe.authMethod)
	}
}

// 5. An expired token is rejected even when its raw secret is valid and
// the hash matches. Lookup-time revalidation contract from the resolver.
func TestGatewayAuth_ExpiredTokenRejected(t *testing.T) {
	cfg := &config.Config{
		Gateway: config.GatewayConfig{Enabled: true, RequireAuth: "true"},
		Agents:  map[string]config.Agent{},
	}
	raw, hash, err := resolve.GenerateRawToken(resolve.TokenTypeGatewayBearer)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	cfg.Identity = config.IdentityConfig{
		Principals: []config.PrincipalConfig{{
			ID: "local-codex",
			Tokens: []config.PrincipalTokenConfig{{
				ID:        "tok-1",
				Type:      "gateway_bearer",
				Hash:      hash,
				CreatedAt: "2026-01-01T00:00:00Z",
				ExpiresAt: "2026-01-02T00:00:00Z", // already in the past
			}},
		}},
	}
	g := newGatewayForTest(cfg, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	probe := &identityProbe{}
	mw := g.authMiddleware(probe.handler())

	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	req.RemoteAddr = "127.0.0.1:55001"

	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for expired token", rr.Code)
	}
}

// 6. The reported-actor surface header (X-Oktsec-Reported-Actor) does NOT
// become Principal. This is the structural invariant that lets dashboards
// safely render a sub-agent name without the resolver upgrading it to
// authority. The Principal stays whatever the bearer token said.
func TestGatewayAuth_ReportedActorHeaderDoesNotAffectPrincipal(t *testing.T) {
	g, raw := gatewayWithPrincipal(t, "local-codex", nil)
	probe := &identityProbe{}
	mw := g.authMiddleware(probe.handler())

	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	req.Header.Set("X-Oktsec-Reported-Actor", "review-subagent")
	req.RemoteAddr = "127.0.0.1:55001"

	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	if probe.principal != "local-codex" {
		t.Errorf("principal = %q, want local-codex", probe.principal)
	}
	if probe.reportedActor != "review-subagent" {
		t.Errorf("reported actor = %q, want review-subagent", probe.reportedActor)
	}
}

// 7. deployment.require_surface_auth=true forces fail-closed even in
// local profile, regardless of gateway.require_auth being unset. Lets a
// developer test the enterprise contract on a laptop without flipping
// the whole profile.
func TestGatewayAuth_DeploymentRequireSurfaceAuthForcesFailClosed(t *testing.T) {
	g, _ := gatewayWithPrincipal(t, "local-codex", func(c *config.Config) {
		c.Deployment.RequireSurfaceAuth = true // local profile, but require auth
	})
	probe := &identityProbe{}
	mw := g.authMiddleware(probe.handler())

	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("X-Oktsec-Agent", "claude-code") // legacy header
	req.RemoteAddr = "127.0.0.1:55001"

	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (deployment.require_surface_auth must force fail-closed)", rr.Code)
	}
	if probe.called {
		t.Error("downstream handler should not run on 401")
	}
}

// 8. Enterprise profile + an explicit auth_methods list that mentions
// trusted_loopback_header still does NOT accept the loopback header as
// Principal. The enterprise floor is non-negotiable: header identity is
// always reported-actor-only when profile is enterprise.
func TestGatewayAuth_EnterpriseOverridesLoopbackHeaderAuthMethod(t *testing.T) {
	g, _ := gatewayWithPrincipal(t, "local-codex", func(c *config.Config) {
		c.Deployment.Profile = "enterprise"
		c.Gateway.AuthMethods = []string{"bearer_token", "trusted_loopback_header"}
	})
	probe := &identityProbe{}
	mw := g.authMiddleware(probe.handler())

	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("X-Oktsec-Agent", "admin")
	req.RemoteAddr = "127.0.0.1:55001"

	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (enterprise must reject loopback header even when auth_methods lists it)", rr.Code)
	}
	if probe.called {
		t.Error("downstream handler should not run on 401")
	}
}
