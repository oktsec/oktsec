package hooks

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
	"github.com/oktsec/oktsec/internal/identity/resolve"
)

// hooksHandlerWithPrincipal builds a hooks Handler whose identity stack
// knows about one principal owning a hook_bearer token. The build
// callback can adjust deployment / hooks auth knobs per test.
func hooksHandlerWithPrincipal(t *testing.T, principalID string, build func(*config.Config)) (*Handler, string, func()) {
	t.Helper()
	raw, hash, err := resolve.GenerateRawToken(resolve.TokenTypeHookBearer)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	cfg := config.Defaults()
	cfg.Identity.Principals = append(cfg.Identity.Principals, config.PrincipalConfig{
		ID:          principalID,
		DisplayName: principalID,
		Kind:        "agent",
		Tokens: []config.PrincipalTokenConfig{{
			ID:        principalID + "-hook",
			Type:      "hook_bearer",
			Hash:      hash,
			CreatedAt: "2026-04-26T00:00:00Z",
		}},
	})
	if build != nil {
		build(cfg)
	}
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := mustCreateAuditStore(t, dir+"/audit.db", logger)
	scanner := engine.NewScanner("")
	h := NewHandler(scanner, store, cfg, logger)
	return h, raw, func() {
		scanner.Close()
		_ = store.Close()
	}
}

// 1. A valid hook_bearer token wins over a payload-supplied agent name.
// The resolver-established Principal becomes ev.Agent for the audit
// path; the payload value is preserved for display via the resolver's
// reported-actor channel.
func TestHooksAuth_TokenWinsOverPayloadAgent(t *testing.T) {
	h, raw, cleanup := hooksHandlerWithPrincipal(t, "local-codex", nil)
	defer cleanup()

	body, _ := json.Marshal(ToolEvent{
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path":"/tmp/x"}`),
		Agent:     "admin",        // attacker spoof
		AgentType: "review-subagent",
		SessionID: "sess-1",
		Event:     "pre_tool_use",
	})
	req := httptest.NewRequest(http.MethodPost, "/hooks/event", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+raw)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:1"

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	// (Direct audit-row inspection is covered by gateway tests; the
	// invariant exercised here is the request flow: token authenticates,
	// payload spoof does not block or escalate.)
}

// 2. Enterprise profile rejects unauthenticated hooks. No payload is
// even parsed; the handler short-circuits with 401.
func TestHooksAuth_EnterpriseRejectsUnauth(t *testing.T) {
	h, _, cleanup := hooksHandlerWithPrincipal(t, "local-codex", func(c *config.Config) {
		c.Deployment.Profile = "enterprise"
	})
	defer cleanup()

	body, _ := json.Marshal(ToolEvent{ToolName: "Read"})
	req := httptest.NewRequest(http.MethodPost, "/hooks/event", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:1"

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("401 response missing WWW-Authenticate hint")
	}
}

// 3. Local profile keeps unauthenticated hooks working as observed
// telemetry. This is the back-compat path: every existing client that
// posts to /hooks/event with no Authorization header keeps working.
func TestHooksAuth_LocalUnauthenticatedAccepted(t *testing.T) {
	h, _, cleanup := hooksHandlerWithPrincipal(t, "local-codex", nil)
	defer cleanup()

	body, _ := json.Marshal(ToolEvent{
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path":"/tmp/x"}`),
		Agent:     "claude-code",
		SessionID: "sess-2",
		Event:     "pre_tool_use",
	})
	req := httptest.NewRequest(http.MethodPost, "/hooks/event", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

// 4. require_auth=true on local profile flips fail-closed without
// changing the deployment profile. Same contract as the gateway and the
// forward proxy.
func TestHooksAuth_RequireAuthRejectsAnonymous(t *testing.T) {
	h, _, cleanup := hooksHandlerWithPrincipal(t, "local-codex", func(c *config.Config) {
		c.Hooks.RequireAuth = "true"
	})
	defer cleanup()

	body, _ := json.Marshal(ToolEvent{ToolName: "Read"})
	req := httptest.NewRequest(http.MethodPost, "/hooks/event", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:1"

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
