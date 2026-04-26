package hooks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/oktsec/oktsec/internal/activity"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
)

// recordingActivityWriter is a test double for activityWriter that
// captures every Insert call. The mu makes it safe to read from the
// test goroutine while the hook handler's emit goroutine writes.
type recordingActivityWriter struct {
	mu     sync.Mutex
	events []activity.Event
	err    error
}

func (r *recordingActivityWriter) Insert(_ context.Context, e activity.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.events = append(r.events, e)
	return nil
}

func (r *recordingActivityWriter) snapshot() []activity.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]activity.Event, len(r.events))
	copy(out, r.events)
	return out
}

func waitForHookActivity(t *testing.T, r *recordingActivityWriter, n int) []activity.Event {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got := r.snapshot()
		if len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("activity recorder: wanted %d events, got %d", n, len(r.snapshot()))
	return nil
}

// 1. A token-authenticated hook event emits a Protected activity event
// with confidence 100. The audit row id is preserved as AuditEntryID
// for correlation.
func TestHooksActivity_TokenAuthIsProtected(t *testing.T) {
	h, raw, cleanup := hooksHandlerWithPrincipal(t, "local-codex", nil)
	defer cleanup()
	rec := &recordingActivityWriter{}
	h.SetActivityStore(rec)

	body, _ := json.Marshal(ToolEvent{
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path":"/tmp/x"}`),
		Agent:     "admin", // payload spoof; resolver wins
		SessionID: "sess-1",
		Event:     "pre_tool_use",
	})
	req := httptest.NewRequest(http.MethodPost, "/hooks/event", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+raw)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:1"

	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec2.Code)
	}

	events := waitForHookActivity(t, rec, 1)
	ev := events[0]
	if ev.PrincipalID != "local-codex" {
		t.Errorf("principal = %q; want local-codex", ev.PrincipalID)
	}
	if ev.AuthMethod != "hook_token" {
		t.Errorf("auth_method = %q; want hook_token", ev.AuthMethod)
	}
	if ev.CoverageMode != activity.CoverageProtected {
		t.Errorf("coverage = %q; want protected", ev.CoverageMode)
	}
	if ev.Confidence != 100 {
		t.Errorf("confidence = %d; want 100", ev.Confidence)
	}
	if ev.Surface != activity.SurfaceHooks || ev.EventType != activity.EventHookEvent {
		t.Errorf("surface/event = %q/%q; want hooks/hook.event", ev.Surface, ev.EventType)
	}
	if ev.AuditEntryID == "" {
		t.Error("audit_entry_id should be populated for correlation")
	}
	if ev.ResourceLabel != "Read" {
		t.Errorf("resource_label = %q; want Read", ev.ResourceLabel)
	}
}

// 2. Reported actor (payload-supplied agent name) is preserved as
// ReportedActor on the activity event but never replaces the
// resolver-established principal.
func TestHooksActivity_ReportedActorDoesNotReplacePrincipal(t *testing.T) {
	h, raw, cleanup := hooksHandlerWithPrincipal(t, "local-codex", nil)
	defer cleanup()
	rec := &recordingActivityWriter{}
	h.SetActivityStore(rec)

	body, _ := json.Marshal(ToolEvent{
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path":"/tmp/x"}`),
		Agent:     "admin", // spoof
		SessionID: "sess-1",
		Event:     "pre_tool_use",
	})
	req := httptest.NewRequest(http.MethodPost, "/hooks/event", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+raw)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:1"

	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)

	events := waitForHookActivity(t, rec, 1)
	ev := events[0]
	if ev.PrincipalID != "local-codex" {
		t.Errorf("principal = %q; want local-codex (spoof must not replace)", ev.PrincipalID)
	}
	if ev.ReportedActor != "admin" {
		t.Errorf("reported_actor = %q; want admin", ev.ReportedActor)
	}
}

// 3. Unauthenticated local hook (no Authorization header, local
// profile) still emits an activity event so the dashboard sees the
// surface as Observed rather than Blind. Empty principal collapses to
// "unknown" so the row validates.
func TestHooksActivity_UnauthenticatedIsObserved(t *testing.T) {
	h, _, cleanup := hooksHandlerWithPrincipal(t, "local-codex", nil)
	defer cleanup()
	rec := &recordingActivityWriter{}
	h.SetActivityStore(rec)

	body, _ := json.Marshal(ToolEvent{
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path":"/tmp/x"}`),
		Agent:     "claude-code",
		SessionID: "sess-2",
		Event:     "pre_tool_use",
	})
	req := httptest.NewRequest(http.MethodPost, "/hooks/event", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec2.Code)
	}

	events := waitForHookActivity(t, rec, 1)
	ev := events[0]
	if ev.PrincipalID != "unknown" {
		t.Errorf("principal = %q; want unknown (anonymous local hook)", ev.PrincipalID)
	}
	if ev.CoverageMode != activity.CoverageObserved {
		t.Errorf("coverage = %q; want observed", ev.CoverageMode)
	}
	if ev.Confidence != 0 {
		t.Errorf("confidence = %d; want 0", ev.Confidence)
	}
	if ev.Surface != activity.SurfaceHooks {
		t.Errorf("surface = %q; want hooks", ev.Surface)
	}
}

// 4. When the hook handler's activity field is nil, the request flow
// is unaffected — audit row still lands and the response is 200.
// Activity emission is best-effort.
func TestHooksActivity_NilStoreDoesNotBreakHandler(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := mustCreateAuditStore(t, dir+"/audit.db", logger)
	defer func() { _ = store.Close() }()
	scanner := engine.NewScanner("")
	defer scanner.Close()
	cfg := config.Defaults()
	h := NewHandler(scanner, store, cfg, logger)
	h.SetActivityStore(nil) // explicitly disable

	body, _ := json.Marshal(ToolEvent{
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path":"/tmp/x"}`),
		Agent:     "claude-code",
		SessionID: "sess-3",
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

// 5. An Insert error from the activity store is logged but does NOT
// affect the request response. Activity is a secondary write;
// failures must not be visible to the client.
func TestHooksActivity_InsertErrorDoesNotAffectRequest(t *testing.T) {
	h, _, cleanup := hooksHandlerWithPrincipal(t, "local-codex", nil)
	defer cleanup()
	rec := &recordingActivityWriter{err: errors.New("simulated db down")}
	h.SetActivityStore(rec)

	body, _ := json.Marshal(ToolEvent{
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path":"/tmp/x"}`),
		Agent:     "claude-code",
		SessionID: "sess-4",
		Event:     "pre_tool_use",
	})
	req := httptest.NewRequest(http.MethodPost, "/hooks/event", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("hooks must succeed even when activity insert fails; status = %d", rec2.Code)
	}
	// Give the goroutine time to attempt and fail; recorder should
	// still hold zero events because Insert returned an error.
	time.Sleep(50 * time.Millisecond)
	if got := rec.snapshot(); len(got) != 0 {
		t.Errorf("recorder should hold zero events on Insert error; got %d", len(got))
	}
}

