package dashboard

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/connectors/claudecode"
	"github.com/oktsec/oktsec/internal/identity"
	"github.com/oktsec/oktsec/internal/runtime"
)

// newOverviewTestServer wires a Server backed by a real audit
// store + DB so the runtime auto-build path actually fires. The
// overview handler reads from these stores directly so an
// in-memory mock would not exercise the new tile code.
func newOverviewTestServer(t *testing.T) (*Server, *audit.Store) {
	t.Helper()
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := audit.NewStore(filepath.Join(dir, "test.db"), logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := &config.Config{
		Version: "1",
		Server:  config.ServerConfig{Port: 0},
		DBPath:  filepath.Join(dir, "test.db"),
		Agents:  map[string]config.Agent{"agent-a": {CanMessage: []string{"agent-b"}}},
	}
	srv := NewServer(cfg, filepath.Join(dir, "oktsec.yaml"), store, identity.NewKeyStore(), sharedScanner, logger)
	return srv, store
}

func renderOverview(t *testing.T, srv *Server, cookie *http.Cookie, handler http.Handler) string {
	t.Helper()
	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	return w.Body.String()
}

// TestOverview_NotInstalledShowsSetupPending pins the
// Phase 3C-0 acceptance: with no Claude install at all the tile
// shows "Claude Code not detected" and the posture grade is
// suppressed (no hard score during install). Empty $HOME is
// configured so the connector inspector reports not_installed.
func TestOverview_NotInstalledShowsSetupPending(t *testing.T) {
	emptyHome := t.TempDir()
	t.Setenv("HOME", emptyHome)
	t.Setenv("PATH", "")

	srv, _ := newOverviewTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	body := renderOverview(t, srv, cookie, handler)

	if !strings.Contains(body, "Claude Code not detected") {
		t.Errorf("Overview tile missing not_installed copy; body excerpt: %s", excerpt(body, "Claude Code"))
	}
	if !strings.Contains(body, "Posture grade not yet computed") {
		t.Error("Posture suppression banner not rendered for not_installed")
	}
	if !strings.Contains(body, "Posture (setup pending)") {
		t.Error("Hero score should fall back to 'setup pending' label, not show a number")
	}
}

// TestOverview_HeartbeatFlipsTileToConnectedAndKeepsPosture
// covers the heartbeat-promotes-to-ready path AND the
// suppression rule that "ready" is the threshold for showing
// the hard grade again.
func TestOverview_HeartbeatFlipsTileToConnectedAndKeepsPosture(t *testing.T) {
	// Build an inventory that looks installed so DeriveHealth
	// proceeds past the not_installed / disconnected branches.
	stagedHome := stageClaudeFixture(t, true)
	t.Setenv("HOME", stagedHome)
	t.Setenv("PATH", "")

	srv, auditStore := newOverviewTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	// Seed a runtime heartbeat row directly via the runtime store
	// so the test does not depend on the hook handler being wired.
	rs := srv.runtimeStore()
	if rs == nil {
		t.Fatal("expected runtime store to auto-build off audit DB")
	}
	now := time.Now().UTC()
	hbEnv, _ := runtime.Normalize([]byte(`{"hook_event_name":"SessionStart","session_id":"heartbeat-2026"}`),
		runtime.IdentityResolution{
			PrincipalID: claudecode.PrincipalID,
			ClientID:    claudecode.PrincipalID,
			SessionID:   "heartbeat-2026",
		}, now)
	if err := rs.RecordHook(context.Background(), hbEnv, runtime.OutcomeRefs{}); err != nil {
		t.Fatalf("seed heartbeat: %v", err)
	}
	auditStore.Flush()

	body := renderOverview(t, srv, cookie, handler)
	if !strings.Contains(body, "Connected and observed") {
		t.Errorf("Overview tile missing 'Connected and observed' copy; excerpt: %s", excerpt(body, "Claude Code connection"))
	}
	if strings.Contains(body, "Posture grade not yet computed") {
		t.Error("Posture grade should not be suppressed once status=ready (heartbeat received)")
	}
}

// TestOverview_HeartbeatOnlyDoesNotCountAsRealEvent locks in
// the P2 contract: a heartbeat row writes a SessionStart event
// to runtime_hook_events, but the Overview must keep its
// "Real events: none yet" badge until a non-heartbeat event
// lands. Otherwise `oktsec doctor claude-code --emit-heartbeat`
// would silently inflate the connection-truth view to "real
// activity observed" and mark SessionStart as an observed family.
func TestOverview_HeartbeatOnlyDoesNotCountAsRealEvent(t *testing.T) {
	stagedHome := stageClaudeFixture(t, true)
	t.Setenv("HOME", stagedHome)
	t.Setenv("PATH", "")

	srv, auditStore := newOverviewTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	rs := srv.runtimeStore()
	if rs == nil {
		t.Fatal("expected runtime store")
	}
	now := time.Now().UTC()
	hbEnv, _ := runtime.Normalize([]byte(`{"hook_event_name":"SessionStart","session_id":"heartbeat-only-2026"}`),
		runtime.IdentityResolution{
			PrincipalID: claudecode.PrincipalID,
			ClientID:    claudecode.PrincipalID,
			SessionID:   "heartbeat-only-2026",
		}, now)
	if err := rs.RecordHook(context.Background(), hbEnv, runtime.OutcomeRefs{}); err != nil {
		t.Fatalf("seed heartbeat: %v", err)
	}
	auditStore.Flush()

	body := renderOverview(t, srv, cookie, handler)
	// Heartbeat tile cell must show "received".
	if !strings.Contains(body, ">received<") {
		t.Errorf("Heartbeat cell missing 'received' value; excerpt: %s", excerpt(body, "Heartbeat"))
	}
	// Real events tile cell must still show "none yet".
	idx := strings.Index(body, "Real events")
	if idx < 0 {
		t.Fatal("Real events cell not rendered")
	}
	tail := body[idx:]
	if !strings.Contains(tail[:200], ">none yet<") {
		t.Errorf("Real events cell should show 'none yet' for heartbeat-only state; excerpt: %s", tail[:200])
	}
}

// TestOverview_HooksInstalledNoEventsShowsWaiting locks in the
// "installed, waiting for first observed event" empty state.
// The tile must read as setup pending, not as a security alert.
func TestOverview_HooksInstalledNoEventsShowsWaiting(t *testing.T) {
	stagedHome := stageClaudeFixture(t, true)
	t.Setenv("HOME", stagedHome)
	t.Setenv("PATH", "")

	srv, _ := newOverviewTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	body := renderOverview(t, srv, cookie, handler)
	if !strings.Contains(body, "Installed, waiting for first observed event") {
		t.Errorf("Overview tile missing 'Installed, waiting for first observed event'; excerpt: %s",
			excerpt(body, "Claude Code connection"))
	}
	if strings.Contains(body, "Critical security gaps detected") {
		t.Error("alarmist 'Critical security gaps detected' copy should NOT appear during install")
	}
	if strings.Contains(body, "Deployment needs attention") {
		t.Error("alarmist 'Deployment needs attention' copy should NOT appear during install")
	}
}

// TestOverview_RealEventLiftsToProtectedCoverage exercises the
// final acceptance: a PreToolUse with Protected coverage in the
// runtime row is reflected in the tile's coverage badge.
func TestOverview_RealEventLiftsToProtectedCoverage(t *testing.T) {
	stagedHome := stageClaudeFixture(t, true)
	t.Setenv("HOME", stagedHome)
	t.Setenv("PATH", "")

	srv, auditStore := newOverviewTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	rs := srv.runtimeStore()
	if rs == nil {
		t.Fatal("expected runtime store")
	}
	now := time.Now().UTC()
	env, _ := runtime.Normalize([]byte(`{"hook_event_name":"PreToolUse","session_id":"sess-real","tool_name":"Read"}`),
		runtime.IdentityResolution{
			PrincipalID: claudecode.PrincipalID,
			ClientID:    claudecode.PrincipalID,
			SessionID:   "sess-real",
		}, now)
	if err := rs.RecordHook(context.Background(), env, runtime.OutcomeRefs{
		CoverageMode: "Protected",
		Confidence:   100,
	}); err != nil {
		t.Fatalf("seed event: %v", err)
	}
	auditStore.Flush()

	body := renderOverview(t, srv, cookie, handler)
	if !strings.Contains(body, "Connected and observed") {
		t.Errorf("Overview tile should show Connected and observed; excerpt: %s",
			excerpt(body, "Claude Code connection"))
	}
	if !strings.Contains(body, "Protected") {
		t.Error("Coverage stage 'Protected' should be rendered when runtime row carries it")
	}
}

// stageClaudeFixture writes the minimum settings file to make
// the connector inspector report Detected=true and (when
// withOktsecHook) HookInstalled=true. Returns the temp home dir
// the test should set $HOME to.
func stageClaudeFixture(t *testing.T, withOktsecHook bool) string {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	body := `{}`
	if withOktsecHook {
		body = `{
  "hooks": {
    "PreToolUse": [
      {"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/oktsec hook --port 9090 --event PreToolUse --manifest v2"}]}
    ]
  }
}`
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

// excerpt returns a short window around the first occurrence of
// needle so failure messages stay readable. Empty when not found.
func excerpt(haystack, needle string) string {
	idx := strings.Index(haystack, needle)
	if idx < 0 {
		return "(needle not found)"
	}
	start := idx - 80
	if start < 0 {
		start = 0
	}
	end := idx + len(needle) + 200
	if end > len(haystack) {
		end = len(haystack)
	}
	return haystack[start:end]
}
