package hooks

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oktsec/oktsec/internal/activity"
	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
	"github.com/oktsec/oktsec/internal/runtime"

	_ "modernc.org/sqlite"
)

// newRuntimeWiredHandler builds a Handler against a real audit
// store so the auto-built runtime store has a *sql.DB to attach
// to. Returns the handler, the runtime store handle (for
// queryback), the *sql.DB so tests can inspect runtime tables
// directly, and a no-op flush callback (the real audit close
// runs via t.Cleanup so callers do not have to remember it).
func newRuntimeWiredHandler(t *testing.T) (*Handler, *runtime.Store, *sql.DB, func()) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	auditStore := mustCreateAuditStore(t, dbPath, logger)
	scanner := engine.NewScanner("")
	cfg := config.Defaults()
	h := NewHandler(scanner, auditStore, cfg, logger)
	if h.runtime == nil {
		t.Fatal("expected NewHandler to auto-build runtime store from audit *sql.DB")
	}
	// Stash the audit store on the handler via a closure so post()
	// can drain its batch loop before the test queries any
	// downstream table. Without this the audit writeLoop, the
	// runtime tx, and the activity insert can race for the same
	// SQLite writer and burst posts lose rows under contention.
	t.Cleanup(func() {
		scanner.Close()
		_ = auditStore.Close()
	})
	return h, h.runtime, auditStore.DB(), func() {
		auditStore.Flush()
	}
}

// post helper sends a hook event, drains the audit batch, and
// returns the response body. Drains are necessary because the
// runtime store + audit batch + activity insert all write to one
// SQLite file; without serialising on Flush() between posts a
// burst can lose runtime/audit rows to SQLITE_BUSY contention.
func post(t *testing.T, h *Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/hooks/event", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Oktsec-Client", "claude-code")
	req.Header.Set("X-Oktsec-Agent", "claude-code")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if dbs, ok := h.store.(interface{ Flush() }); ok {
		dbs.Flush()
	}
	return w
}

// TestServeHTTP_WritesRuntimeRowForToolEvent locks in the Phase 3B
// integration: a single PreToolUse landing on /hooks/event must
// produce both the audit row (already covered by the existing
// suite) AND a runtime hook event row joined back through the
// audit_entry_id cross-reference.
func TestServeHTTP_WritesRuntimeRowForToolEvent(t *testing.T) {
	h, store, _, cleanup := newRuntimeWiredHandler(t)
	defer cleanup()

	w := post(t, h, `{"hook_event_name":"PreToolUse","session_id":"sess-3b-tool","tool_name":"Read","tool_input":{"path":"/etc/hosts"}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}

	events, err := store.QueryEvents(context.Background(), runtime.EventQuery{SessionID: "sess-3b-tool"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("runtime event count = %d, want 1", len(events))
	}
	got := events[0]
	if got.HookEventName != "PreToolUse" {
		t.Errorf("hook_event_name = %q, want PreToolUse", got.HookEventName)
	}
	if got.PrincipalID == "" {
		t.Error("principal_id empty — resolver hand-off broke")
	}
	if got.AuditEntryID == "" {
		t.Error("audit_entry_id missing on runtime row — cross-reference broken")
	}
	if got.ActivityEventID == "" {
		t.Error("activity_event_id missing on runtime row — precomputed id was lost")
	}
	if got.ToolInputHash == "" {
		t.Error("tool_input_hash missing on runtime row")
	}
}

// TestServeHTTP_FullSessionRunRoundTrip walks the canonical sequence
// the Phase 3 spec calls out: SessionStart → SubagentStart →
// PreToolUse → PostToolUse → SessionEnd. After all five, the
// runtime tables should carry one session, two actors (root +
// subagent linked by parent), and five hook events.
func TestServeHTTP_FullSessionRunRoundTrip(t *testing.T) {
	h, store, _, cleanup := newRuntimeWiredHandler(t)
	defer cleanup()

	for _, body := range []string{
		`{"hook_event_name":"SessionStart","session_id":"sess-3b-full","cwd":"/Users/dev/proj"}`,
		`{"hook_event_name":"SubagentStart","session_id":"sess-3b-full","agent_id":"sa-1","agent_type":"code-reviewer"}`,
		`{"hook_event_name":"PreToolUse","session_id":"sess-3b-full","agent_id":"sa-1","tool_name":"Read","tool_input":{"path":"/etc/hosts"}}`,
		`{"hook_event_name":"PostToolUse","session_id":"sess-3b-full","agent_id":"sa-1","tool_name":"Read","tool_response":"ok"}`,
		`{"hook_event_name":"SessionEnd","session_id":"sess-3b-full"}`,
	} {
		w := post(t, h, body)
		if w.Code != http.StatusOK {
			t.Fatalf("step body=%s -> status %d, body=%s", body, w.Code, w.Body.String())
		}
	}

	sessions, err := store.QuerySessions(context.Background(), runtime.SessionQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].SessionID != "sess-3b-full" {
		t.Fatalf("sessions = %+v", sessions)
	}
	if sessions[0].EventCount != 5 {
		t.Errorf("event_count = %d, want 5", sessions[0].EventCount)
	}
	if sessions[0].SubagentCount != 1 {
		t.Errorf("subagent_count = %d, want 1", sessions[0].SubagentCount)
	}
	if sessions[0].Status != runtime.SessionStatusEnded {
		t.Errorf("status = %q, want ended", sessions[0].Status)
	}

	actors, err := store.QueryActors(context.Background(), runtime.ActorQuery{SessionID: "sess-3b-full"})
	if err != nil {
		t.Fatal(err)
	}
	if len(actors) != 2 {
		t.Fatalf("actor count = %d, want 2 (root + subagent); got %+v", len(actors), actors)
	}
	var root, sub runtime.Actor
	for _, a := range actors {
		switch a.Kind {
		case runtime.ActorKindRoot:
			root = a
		case runtime.ActorKindSubagent:
			sub = a
		}
	}
	if sub.ParentActorID != root.ID {
		t.Errorf("subagent.parent_actor_id = %q, want root id %q", sub.ParentActorID, root.ID)
	}
	if sub.ClaudeAgentID != "sa-1" || sub.ClaudeAgentType != "code-reviewer" {
		t.Errorf("subagent claude refs = (%q, %q)", sub.ClaudeAgentID, sub.ClaudeAgentType)
	}
}

// TestServeHTTP_HeartbeatLandsAsRuntimeRow confirms the spec's
// promise that `oktsec doctor claude-code --emit-heartbeat` (which
// posts a SessionStart with a heartbeat-* session id) produces a
// runtime session row tagged as heartbeat. The handler does not
// need any heartbeat-specific code path for this to work — the
// normalizer detects the session id pattern.
func TestServeHTTP_HeartbeatLandsAsRuntimeRow(t *testing.T) {
	h, store, _, cleanup := newRuntimeWiredHandler(t)
	defer cleanup()

	w := post(t, h, `{"hook_event_name":"SessionStart","session_id":"heartbeat-20260427T120000Z","source":"oktsec-doctor"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	hb, err := store.LastHeartbeat(context.Background(), "unknown", "claude-code")
	if err != nil {
		t.Fatal(err)
	}
	if hb == nil {
		// principal_id is "unknown" because the test harness has no
		// configured principals; the heartbeat still lands but keyed
		// to the unknown principal. That is the intended local-mode
		// behavior — the dashboard's connector health card scopes to
		// the configured principal in production.
		t.Fatal("LastHeartbeat returned nil for the principal the resolver fell back to")
	}
	if hb.SessionID != "heartbeat-20260427T120000Z" {
		t.Errorf("heartbeat session id = %q", hb.SessionID)
	}
	if hb.ClientID != "claude-code" {
		t.Errorf("heartbeat client_id = %q, want claude-code", hb.ClientID)
	}
}

// TestServeHTTP_RuntimeFailureDoesNotChangeResponse pins the spec
// invariant: a runtime write failure must never turn an allow
// into a deny.
//
// We isolate the failure to the runtime store by swapping in a
// store whose own DB handle is closed. Previously the test closed
// the SHARED audit DB, which left the audit batch goroutine
// reading from a closed handle and polluted later tests in the
// same package. The current setup uses a separate, dedicated DB
// for the failing runtime store so the audit + activity writes
// continue normally and only the runtime path errors out.
func TestServeHTTP_RuntimeFailureDoesNotChangeResponse(t *testing.T) {
	h, _, _, cleanup := newRuntimeWiredHandler(t)
	defer cleanup()

	// Build a runtime store on a separate DB, then close that DB
	// so every RecordHook call returns an error. The audit + activity
	// path keep using the shared DB the helper opened.
	failDir := t.TempDir()
	failDB, err := sql.Open("sqlite", filepath.Join(failDir, "fail.db"))
	if err != nil {
		t.Fatal(err)
	}
	failingStore, err := runtime.Open(context.Background(), failDB, runtime.DialectSQLite)
	if err != nil {
		t.Fatal(err)
	}
	h.SetRuntimeStore(failingStore)
	if err := failDB.Close(); err != nil && !errors.Is(err, sql.ErrConnDone) {
		t.Fatal(err)
	}

	// Even with the runtime store guaranteed to fail, the response
	// must still be 200 OK with decision=allow.
	w := post(t, h, `{"hook_event_name":"PreToolUse","session_id":"sess-fail","tool_name":"Read"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["decision"] != "allow" {
		t.Errorf("decision = %v, want allow (runtime failure must not change security decision)", resp["decision"])
	}
}

// TestServeHTTP_NilRuntimeStoreIsNoOp confirms an injected nil
// runtime store turns the runtime path into a no-op without
// breaking the response. Useful for callers that want to disable
// runtime writes (legacy mocks, future feature flag if ever
// reintroduced).
func TestServeHTTP_NilRuntimeStoreIsNoOp(t *testing.T) {
	h, _, _, cleanup := newRuntimeWiredHandler(t)
	defer cleanup()
	h.SetRuntimeStore(nil)

	w := post(t, h, `{"hook_event_name":"PreToolUse","session_id":"sess-nil","tool_name":"Read"}`)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// TestServeHTTP_ActivityIDMatchesRuntimeRow verifies the
// pre-computed activity_event_id pattern: the same id is on both
// the activity row and the runtime row. Without precomputation
// the runtime row would carry a useless empty string and the
// future joined timeline would lose the cross-reference.
func TestServeHTTP_ActivityIDMatchesRuntimeRow(t *testing.T) {
	h, store, db, cleanup := newRuntimeWiredHandler(t)
	defer cleanup()

	w := post(t, h, `{"hook_event_name":"PostToolUse","session_id":"sess-3b-xref","tool_name":"Read","tool_response":"ok"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	events, err := store.QueryEvents(context.Background(), runtime.EventQuery{SessionID: "sess-3b-xref"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("runtime event count = %d, want 1", len(events))
	}
	runtimeActivityID := events[0].ActivityEventID

	// Wait for the async activity insert to land. The activity
	// insert is bounded by activityInsertTimeout (2s) but the race
	// detector under a full-suite run can push the goroutine past
	// that window; SQLite write lock contention with the runtime
	// tx and the audit batch loop can stretch the wait to ~5-8s
	// under load. 10s gives generous slack before declaring the
	// cross-reference broken.
	deadline := time.Now().Add(10 * time.Second)
	var activityRowID string
	for time.Now().Before(deadline) {
		row := db.QueryRow(`SELECT id FROM activity_events WHERE session_id = ?`, "sess-3b-xref")
		if err := row.Scan(&activityRowID); err == nil && activityRowID != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if activityRowID == "" {
		t.Fatal("activity_events row never landed within 5s")
	}
	if activityRowID != runtimeActivityID {
		t.Errorf("activity_events.id = %q, runtime row's activity_event_id = %q (must match)", activityRowID, runtimeActivityID)
	}
}

// TestServeHTTP_RuntimeRowCarriesCoverage locks in the P1
// invariant: the durable runtime row carries coverage_mode +
// confidence so Phase 3C can render Protected/Observed without
// joining back to the async activity row.
//
// The contract is "runtime row gets the same coverage state the
// activity row got". For a PreToolUse from an unauthenticated
// loopback request that means CoverageMode = "Observed" and
// Confidence = 0 today (the spec deliberately marks anonymous
// telemetry as diagnostic-quality). The test pins
// non-empty CoverageMode and an exact match against
// activity.CoverageFromHookEvent so a future spec tweak there
// flows through without silently breaking the runtime read path.
func TestServeHTTP_RuntimeRowCarriesCoverage(t *testing.T) {
	h, store, _, cleanup := newRuntimeWiredHandler(t)
	defer cleanup()

	w := post(t, h, `{"hook_event_name":"PreToolUse","session_id":"sess-cov","tool_name":"Read","tool_input":{"path":"/etc/hosts"}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	events, err := store.QueryEvents(context.Background(), runtime.EventQuery{SessionID: "sess-cov"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("event count = %d, want 1", len(events))
	}
	if events[0].CoverageMode == "" {
		t.Errorf("runtime row CoverageMode empty — Phase 3C cannot render Protected/Observed without it")
	}
	// Cross-check: the runtime row must agree with the activity
	// helper. Without this assertion, a future drift between the
	// two would silently surface as inconsistent dashboard cells.
	wantCoverage, wantConfidence := activity.CoverageFromHookEvent("", "pre_tool_use")
	if events[0].CoverageMode != string(wantCoverage) {
		t.Errorf("runtime row CoverageMode = %q, want %q (must match activity helper)", events[0].CoverageMode, wantCoverage)
	}
	if events[0].Confidence != wantConfidence {
		t.Errorf("runtime row Confidence = %d, want %d (must match activity helper)", events[0].Confidence, wantConfidence)
	}
}

// TestServeHTTP_BodyWithoutAnyEventFieldStillLandsRuntimeRow
// covers the corner case of generic clients: a payload that
// omits BOTH hook_event_name AND event. The handler's
// ToolEvent.normalize defaults the in-memory event to
// "pre_tool_use" so audit + activity write under that name; the
// runtime path used to lose this entirely because the raw body
// it parsed had nothing to canonicalize. The handler now passes
// its normalized value as a hint via IdentityResolution.HookEventName
// so the runtime row lands too.
func TestServeHTTP_BodyWithoutAnyEventFieldStillLandsRuntimeRow(t *testing.T) {
	h, store, _, cleanup := newRuntimeWiredHandler(t)
	defer cleanup()

	w := post(t, h, `{"tool_name":"Read","session_id":"sess-noevent"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	events, err := store.QueryEvents(context.Background(), runtime.EventQuery{SessionID: "sess-noevent"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("event count = %d, want 1 (handler default must reach runtime)", len(events))
	}
	if events[0].HookEventName != "PreToolUse" {
		t.Errorf("HookEventName = %q, want PreToolUse (handler default)", events[0].HookEventName)
	}
}

// TestServeHTTP_GenericPostToolUseCarriesOutputHash covers the
// other half of the generic-client contract: a post_tool_use
// payload that uses the generic `tool_output` field (a string,
// the shape ToolEvent models) must produce a non-empty
// tool_output_hash on the runtime row. Without the handler hint,
// runtime.Normalize was looking for Claude's `tool_response`
// json.RawMessage and saw nothing.
func TestServeHTTP_GenericPostToolUseCarriesOutputHash(t *testing.T) {
	h, store, _, cleanup := newRuntimeWiredHandler(t)
	defer cleanup()

	w := post(t, h, `{"event":"post_tool_use","session_id":"sess-out","tool_name":"Read","tool_output":"contents of /etc/hosts"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	events, err := store.QueryEvents(context.Background(), runtime.EventQuery{SessionID: "sess-out"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("event count = %d, want 1", len(events))
	}
	if events[0].ToolOutputHash == "" {
		t.Errorf("ToolOutputHash empty for generic post_tool_use; handler hint did not reach runtime")
	}
}

// TestServeHTTP_GenericEventFormatLandsRuntimeRow covers the P2
// contract: a payload using the client-agnostic `event:
// "pre_tool_use"` field (and no hook_event_name) must still
// produce a runtime row. Without the normalizer fallback,
// generic clients would silently skip every runtime write.
func TestServeHTTP_GenericEventFormatLandsRuntimeRow(t *testing.T) {
	h, store, _, cleanup := newRuntimeWiredHandler(t)
	defer cleanup()

	w := post(t, h, `{"event":"pre_tool_use","session_id":"sess-generic","tool_name":"Read"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	events, err := store.QueryEvents(context.Background(), runtime.EventQuery{SessionID: "sess-generic"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("event count = %d, want 1 (generic event must still produce a runtime row)", len(events))
	}
	if events[0].HookEventName != "PreToolUse" {
		t.Errorf("HookEventName = %q, want PreToolUse (canonicalized from pre_tool_use)", events[0].HookEventName)
	}
}

// silence unused complaint when the test set is built without audit
// import side effects.
var _ = audit.Entry{}
