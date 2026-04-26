package audit

import (
	"testing"
	"time"
)

// logRows seeds the store with a slice of entries and waits for them to
// hit the SQLite file. Tests insert via the public Log+Flush path so the
// query under test sees rows the same way it would in production.
func logRows(t *testing.T, store *Store, rows ...Entry) {
	t.Helper()
	for _, r := range rows {
		store.Log(r)
	}
	store.Flush()
}

// 1. A bearer-token gateway row attributes LastSeen to mcp_http for the
// principal that owns it. The egress and hooks surfaces stay empty.
func TestLastSeenByPrincipalSurface_Gateway(t *testing.T) {
	store := newTestStore(t)
	logRows(t, store,
		Entry{
			ID: "gw-1", Timestamp: "2026-04-26T10:00:00Z",
			FromAgent: "local-codex", ToAgent: "local-codex",
			Status: StatusDelivered, PolicyDecision: "ok",
			AuthMethod: "bearer_token",
		},
	)
	got, err := store.LastSeenByPrincipalSurface("local-codex", "mcp_http")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if got != "2026-04-26T10:00:00Z" {
		t.Errorf("mcp_http last seen = %q; want 2026-04-26T10:00:00Z", got)
	}
	if got, _ := store.LastSeenByPrincipalSurface("local-codex", "http_egress_proxy"); got != "" {
		t.Errorf("egress should be empty when only gateway activity exists; got %q", got)
	}
	if got, _ := store.LastSeenByPrincipalSurface("local-codex", "hooks"); got != "" {
		t.Errorf("hooks should be empty when only gateway activity exists; got %q", got)
	}
}

// 2. A proxy_token row attributes LastSeen to http_egress_proxy. Same
// principal can have both gateway and egress rows; each surface returns
// its own MAX(timestamp).
func TestLastSeenByPrincipalSurface_Egress(t *testing.T) {
	store := newTestStore(t)
	logRows(t, store,
		Entry{
			ID: "eg-1", Timestamp: "2026-04-26T11:00:00Z",
			FromAgent: "local-codex", ToAgent: "api.example.com",
			Status: StatusDelivered, PolicyDecision: "proxy_allowed",
			AuthMethod: "proxy_token",
		},
	)
	got, err := store.LastSeenByPrincipalSurface("local-codex", "http_egress_proxy")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if got != "2026-04-26T11:00:00Z" {
		t.Errorf("egress last seen = %q; want 2026-04-26T11:00:00Z", got)
	}
}

// 3. A hook_token row attributes LastSeen to hooks. Important: a row
// with auth_method="" (anonymous hook) must NOT count for a configured
// principal even if from_agent matches — that protects the matrix from
// claiming coverage on the basis of an unauthenticated event.
func TestLastSeenByPrincipalSurface_HooksAuthOnly(t *testing.T) {
	store := newTestStore(t)
	logRows(t, store,
		// Authenticated hook: counts.
		Entry{
			ID: "hk-1", Timestamp: "2026-04-26T12:00:00Z",
			FromAgent: "local-codex", ToAgent: "local-codex",
			ToolName: "Read", Status: StatusDelivered, PolicyDecision: "ok",
			AuthMethod: "hook_token",
		},
		// Anonymous hook with the same from_agent name: must NOT count.
		Entry{
			ID: "hk-2", Timestamp: "2026-04-26T13:00:00Z",
			FromAgent: "local-codex", ToAgent: "local-codex",
			ToolName: "Read", Status: StatusDelivered, PolicyDecision: "ok",
			AuthMethod: "", // anonymous
		},
	)
	got, err := store.LastSeenByPrincipalSurface("local-codex", "hooks")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if got != "2026-04-26T12:00:00Z" {
		t.Errorf("hooks last seen = %q; want 2026-04-26T12:00:00Z (anonymous row must not count)", got)
	}
}

// 4. MAX(timestamp) returns the latest authenticated event for the
// surface even when older events with the same auth_method exist.
func TestLastSeenByPrincipalSurface_ReturnsMostRecent(t *testing.T) {
	store := newTestStore(t)
	logRows(t, store,
		Entry{ID: "1", Timestamp: "2026-04-25T10:00:00Z", FromAgent: "local-codex", Status: StatusDelivered, PolicyDecision: "ok", AuthMethod: "bearer_token"},
		Entry{ID: "2", Timestamp: "2026-04-26T10:00:00Z", FromAgent: "local-codex", Status: StatusDelivered, PolicyDecision: "ok", AuthMethod: "bearer_token"},
		Entry{ID: "3", Timestamp: "2026-04-24T10:00:00Z", FromAgent: "local-codex", Status: StatusDelivered, PolicyDecision: "ok", AuthMethod: "bearer_token"},
	)
	got, _ := store.LastSeenByPrincipalSurface("local-codex", "mcp_http")
	if got != "2026-04-26T10:00:00Z" {
		t.Errorf("most recent timestamp = %q; want 2026-04-26T10:00:00Z", got)
	}
}

// 5. trusted_loopback rows count for both the gateway and the egress
// surfaces — that is how the legacy header gets attributed in local
// profile when no token is configured. Hooks is intentionally stricter:
// it only counts authenticated hook_token rows.
func TestLastSeenByPrincipalSurface_TrustedLoopbackCountsForLegacySurfaces(t *testing.T) {
	store := newTestStore(t)
	logRows(t, store,
		Entry{ID: "1", Timestamp: "2026-04-26T09:00:00Z", FromAgent: "claude-code", Status: StatusDelivered, PolicyDecision: "ok", AuthMethod: "trusted_loopback"},
	)
	if got, _ := store.LastSeenByPrincipalSurface("claude-code", "mcp_http"); got != "2026-04-26T09:00:00Z" {
		t.Errorf("mcp_http should accept trusted_loopback; got %q", got)
	}
	if got, _ := store.LastSeenByPrincipalSurface("claude-code", "http_egress_proxy"); got != "2026-04-26T09:00:00Z" {
		t.Errorf("http_egress_proxy should accept trusted_loopback; got %q", got)
	}
	if got, _ := store.LastSeenByPrincipalSurface("claude-code", "hooks"); got != "" {
		t.Errorf("hooks should not attribute trusted_loopback rows to a principal; got %q", got)
	}
}

// 6. Unknown surface returns empty without error so callers iterating
// over a hardcoded surface list never crash on a typo.
func TestLastSeenByPrincipalSurface_UnknownSurfaceEmpty(t *testing.T) {
	store := newTestStore(t)
	logRows(t, store,
		Entry{ID: "1", Timestamp: time.Now().UTC().Format(time.RFC3339), FromAgent: "local-codex", Status: StatusDelivered, PolicyDecision: "ok", AuthMethod: "bearer_token"},
	)
	got, err := store.LastSeenByPrincipalSurface("local-codex", "not-a-surface")
	if err != nil {
		t.Errorf("unknown surface should not error; got %v", err)
	}
	if got != "" {
		t.Errorf("unknown surface should return empty; got %q", got)
	}
}

// 7. Empty principal returns empty without error.
func TestLastSeenByPrincipalSurface_EmptyPrincipal(t *testing.T) {
	store := newTestStore(t)
	got, err := store.LastSeenByPrincipalSurface("", "mcp_http")
	if err != nil || got != "" {
		t.Errorf("empty principal should be empty/no-error; got %q, %v", got, err)
	}
}
