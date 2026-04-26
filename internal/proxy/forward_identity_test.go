package proxy

import (
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
	"github.com/oktsec/oktsec/internal/identity/resolve"
)

// fpWithPrincipal builds a forward proxy whose identity stack knows
// about one principal owning a proxy_basic token. The build callback
// can adjust deployment / surface auth knobs per test.
func fpWithPrincipal(t *testing.T, principalID string, build func(*config.Config)) (*ForwardProxy, string) {
	t.Helper()
	raw, hash, err := resolve.GenerateRawToken(resolve.TokenTypeProxyBasic)
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
					Type:      "proxy_basic",
					Hash:      hash,
					CreatedAt: "2026-04-26T00:00:00Z",
				}},
			}},
		},
		ForwardProxy: config.ForwardProxyConfig{Enabled: true},
		Agents:       map[string]config.Agent{principalID: {}},
	}
	if build != nil {
		build(cfg)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	scanner := engine.NewScanner("")
	t.Cleanup(func() { scanner.Close() })
	store, err := audit.NewStore(t.TempDir()+"/audit.db", logger)
	if err != nil {
		t.Fatalf("audit store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	rl := NewRateLimiter(0, 60)
	fp := NewForwardProxy(&cfg.ForwardProxy, scanner, store, rl, cfg.Agents, logger, nil, cfg)
	fp.transport = &http.Transport{}
	return fp, raw
}

// proxyBasicHeader builds the Proxy-Authorization Basic value the
// forward proxy expects when a client uses an HTTP_PROXY URL with the
// proxy token as username (and empty password).
func proxyBasicHeader(token string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(token+":"))
}

// 1. proxy_basic token wins over a spoofed X-Oktsec-Agent header. The
// header value still appears as a low-confidence reported actor on the
// audit row, but the policy principal comes from the token.
func TestForwardProxyAuth_TokenWinsOverSpoofedAgentHeader(t *testing.T) {
	fp, raw := fpWithPrincipal(t, "local-codex", nil)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	handler := fp.Wrap(http.NewServeMux())

	req := httptest.NewRequest("GET", target.URL+"/get", nil)
	req.Header.Set("Proxy-Authorization", proxyBasicHeader(raw))
	req.Header.Set("X-Oktsec-Agent", "admin") // spoof attempt
	req.RemoteAddr = "127.0.0.1:1"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (token must authenticate)", rec.Code)
	}
}

// 2. Enterprise profile rejects the loopback header path: an
// unauthenticated request returns 407 Proxy Authentication Required.
func TestForwardProxyAuth_EnterpriseRejectsLoopbackHeader(t *testing.T) {
	fp, _ := fpWithPrincipal(t, "local-codex", func(c *config.Config) {
		c.Deployment.Profile = "enterprise"
		c.ForwardProxy.TrustedLoopbackHeaders = true // honored only in local
	})
	handler := fp.Wrap(http.NewServeMux())

	req := httptest.NewRequest("GET", "http://example.com/get", nil)
	req.Header.Set("X-Oktsec-Agent", "admin")
	req.RemoteAddr = "127.0.0.1:1"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407 (enterprise must fail closed)", rec.Code)
	}
	if got := rec.Header().Get("Proxy-Authenticate"); got == "" {
		t.Error("407 response missing Proxy-Authenticate hint")
	}
}

// 3. require_auth=true on local profile rejects requests with no token
// regardless of the legacy header path.
func TestForwardProxyAuth_RequireAuthRejectsAnonymous(t *testing.T) {
	fp, _ := fpWithPrincipal(t, "local-codex", func(c *config.Config) {
		c.ForwardProxy.RequireAuth = "true"
	})
	handler := fp.Wrap(http.NewServeMux())

	req := httptest.NewRequest("GET", "http://example.com/get", nil)
	req.RemoteAddr = "127.0.0.1:1"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", rec.Code)
	}
}

// 4. Local profile keeps the legacy X-Oktsec-Agent header working when
// the request originates from loopback. Required for back-compat with
// every existing forward-proxy caller.
func TestForwardProxyAuth_LocalLegacyLoopbackHeaderStillWorks(t *testing.T) {
	fp, _ := fpWithPrincipal(t, "local-codex", nil)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	handler := fp.Wrap(http.NewServeMux())

	req := httptest.NewRequest("GET", target.URL+"/get", nil)
	req.Header.Set("X-Oktsec-Agent", "claude-code")
	req.RemoteAddr = "127.0.0.1:1"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (local loopback header should authenticate)", rec.Code)
	}
}

// 5. Expired tokens are rejected at lookup time, not at store-build
// time. Same contract as the gateway.
func TestForwardProxyAuth_ExpiredTokenRejected(t *testing.T) {
	cfg := &config.Config{
		ForwardProxy: config.ForwardProxyConfig{Enabled: true,
			SurfaceAuthConfig: config.SurfaceAuthConfig{RequireAuth: "true"},
		},
		Agents: map[string]config.Agent{},
	}
	raw, hash, err := resolve.GenerateRawToken(resolve.TokenTypeProxyBasic)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	cfg.Identity = config.IdentityConfig{
		Principals: []config.PrincipalConfig{{
			ID: "local-codex",
			Tokens: []config.PrincipalTokenConfig{{
				ID:        "tok-1",
				Type:      "proxy_basic",
				Hash:      hash,
				CreatedAt: "2026-01-01T00:00:00Z",
				ExpiresAt: "2026-01-02T00:00:00Z",
			}},
		}},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	scanner := engine.NewScanner("")
	t.Cleanup(func() { scanner.Close() })
	store, _ := audit.NewStore(t.TempDir()+"/audit.db", logger)
	t.Cleanup(func() { _ = store.Close() })
	fp := NewForwardProxy(&cfg.ForwardProxy, scanner, store, NewRateLimiter(0, 60), cfg.Agents, logger, nil, cfg)
	handler := fp.Wrap(http.NewServeMux())

	req := httptest.NewRequest("GET", "http://example.com/get", nil)
	req.Header.Set("Proxy-Authorization", proxyBasicHeader(raw))
	req.RemoteAddr = "127.0.0.1:1"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407 for expired token", rec.Code)
	}
}

// 6. Proxy-Authorization is stripped from the request before any
// upstream forwarding. Even a hand-rolled forwarder that bypasses
// copyHeaders cannot leak the token to the destination.
func TestForwardProxyAuth_ProxyAuthorizationStrippedBeforeUpstream(t *testing.T) {
	leaked := make(chan string, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked <- r.Header.Get("Proxy-Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	fp, raw := fpWithPrincipal(t, "local-codex", nil)
	handler := fp.Wrap(http.NewServeMux())

	req := httptest.NewRequest("GET", target.URL+"/get", nil)
	req.Header.Set("Proxy-Authorization", proxyBasicHeader(raw))
	req.RemoteAddr = "127.0.0.1:1"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	got := <-leaked
	if got != "" {
		t.Errorf("upstream received Proxy-Authorization header: %q (must be stripped)", got)
	}
}
