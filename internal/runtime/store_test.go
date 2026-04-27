package runtime

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// newTestStore opens a fresh SQLite store under t.TempDir so each
// test gets a clean database. Returned with Migrate already run.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "runtime.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := Open(context.Background(), db, DialectSQLite)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// TestMigrate_Idempotent locks in the contract that two processes
// (proxy + gateway in `oktsec run`) can call Migrate against the
// same DB without racing. CREATE IF NOT EXISTS should make the
// second call a no-op.
func TestMigrate_Idempotent(t *testing.T) {
	store := newTestStore(t)
	for i := 0; i < 3; i++ {
		if err := store.Migrate(context.Background()); err != nil {
			t.Fatalf("migrate iteration %d: %v", i, err)
		}
	}
	// Sanity: tables must exist after the third migrate.
	for _, table := range []string{"runtime_sessions", "runtime_actors", "runtime_hook_events"} {
		var n int
		row := store.DB().QueryRow(`SELECT COUNT(*) FROM ` + table)
		if err := row.Scan(&n); err != nil {
			t.Errorf("table %s missing: %v", table, err)
		}
	}
}

// TestRecordHook_FullSessionRoundTrip walks the canonical sequence
// the hook handler will use in 3B: SessionStart -> SubagentStart
// -> PreToolUse -> PostToolUse -> SessionEnd. The store must end
// up with one session, two actors (root + subagent), four events,
// and the right counters.
func TestRecordHook_FullSessionRoundTrip(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)

	identity := IdentityResolution{
		PrincipalID: "claude-code",
		ClientID:    "claude-code",
		SessionID:   "sess-fullrt-001",
	}
	steps := []struct {
		event   string
		body    string
		outcome OutcomeRefs
	}{
		{
			event: "SessionStart",
			body:  `{"hook_event_name":"SessionStart","session_id":"sess-fullrt-001","cwd":"/Users/x/proj"}`,
		},
		{
			event: "SubagentStart",
			body:  `{"hook_event_name":"SubagentStart","session_id":"sess-fullrt-001","agent_id":"sa-1","agent_type":"code-reviewer"}`,
		},
		{
			event:   "PreToolUse",
			body:    `{"hook_event_name":"PreToolUse","session_id":"sess-fullrt-001","agent_id":"sa-1","agent_type":"code-reviewer","tool_name":"Read","tool_input":{"path":"/etc/hosts"}}`,
			outcome: OutcomeRefs{Status: "delivered", PolicyDecision: "allow", LatencyMs: 12},
		},
		{
			event:   "PostToolUse",
			body:    `{"hook_event_name":"PostToolUse","session_id":"sess-fullrt-001","agent_id":"sa-1","tool_name":"Read","tool_response":"ok"}`,
			outcome: OutcomeRefs{Status: "delivered", PolicyDecision: "allow", LatencyMs: 8},
		},
		{
			event: "SessionEnd",
			body:  `{"hook_event_name":"SessionEnd","session_id":"sess-fullrt-001"}`,
		},
	}

	for i, step := range steps {
		ts := now.Add(time.Duration(i) * time.Second)
		env, err := Normalize([]byte(step.body), identity, ts)
		if err != nil {
			t.Fatalf("normalize step %d (%s): %v", i, step.event, err)
		}
		if err := store.RecordHook(ctx, env, step.outcome); err != nil {
			t.Fatalf("record step %d (%s): %v", i, step.event, err)
		}
	}

	sessions, err := store.QuerySessions(ctx, SessionQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Fatalf("session count = %d, want 1", len(sessions))
	}
	sess := sessions[0]
	if sess.SessionID != "sess-fullrt-001" {
		t.Errorf("session id = %q", sess.SessionID)
	}
	if sess.EventCount != int64(len(steps)) {
		t.Errorf("event_count = %d, want %d", sess.EventCount, len(steps))
	}
	if sess.ToolEventCount != 2 {
		t.Errorf("tool_event_count = %d, want 2", sess.ToolEventCount)
	}
	if sess.SubagentCount != 1 {
		t.Errorf("subagent_count = %d, want 1", sess.SubagentCount)
	}
	if sess.Status != SessionStatusEnded {
		t.Errorf("status = %q, want ended", sess.Status)
	}

	actors, err := store.QueryActors(ctx, ActorQuery{SessionID: "sess-fullrt-001"})
	if err != nil {
		t.Fatal(err)
	}
	if len(actors) != 2 {
		t.Fatalf("actor count = %d, want 2 (root + subagent); got %+v", len(actors), actors)
	}
	var sub Actor
	var root Actor
	for _, a := range actors {
		switch a.Kind {
		case ActorKindSubagent:
			sub = a
		case ActorKindRoot:
			root = a
		}
	}
	if sub.ID == "" {
		t.Fatal("subagent actor missing")
	}
	if sub.ParentActorID != root.ID {
		t.Errorf("subagent.parent = %q, want root id %q", sub.ParentActorID, root.ID)
	}
	if sub.ClaudeAgentID != "sa-1" || sub.ClaudeAgentType != "code-reviewer" {
		t.Errorf("subagent claude refs = (%q, %q)", sub.ClaudeAgentID, sub.ClaudeAgentType)
	}
	if sub.ToolCount != 2 {
		t.Errorf("subagent tool_count = %d, want 2", sub.ToolCount)
	}
}

// TestRecordHook_LazyActorFromTool exercises the spec's "If an
// event for a subagent arrives before SubagentStart, create the
// subagent actor lazily with source=inferred_from_tool_event"
// rule.
func TestRecordHook_LazyActorFromTool(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	identity := IdentityResolution{
		PrincipalID: "claude-code",
		ClientID:    "claude-code",
		SessionID:   "sess-lazy-001",
	}

	// Tool event arrives FIRST, no SubagentStart yet.
	body := `{"hook_event_name":"PreToolUse","session_id":"sess-lazy-001","agent_id":"sa-late","agent_type":"investigator","tool_name":"Bash"}`
	env, err := Normalize([]byte(body), identity, now)
	if err != nil {
		t.Fatal(err)
	}
	if env.Actor.Source != ActorSourceInferred {
		t.Errorf("expected inferred source, got %q", env.Actor.Source)
	}
	if err := store.RecordHook(ctx, env, OutcomeRefs{Status: "delivered"}); err != nil {
		t.Fatal(err)
	}
	// The lazy child event must produce both the inferred subagent
	// AND the implicit root that the child points at. Without the
	// root row, QueryActorEdges (and Phase 3D's graph query) would
	// left-join to nothing.
	actors, _ := store.QueryActors(ctx, ActorQuery{SessionID: "sess-lazy-001"})
	if len(actors) != 2 {
		t.Fatalf("actor count = %d, want 2 (lazy subagent + implicit root); got %+v", len(actors), actors)
	}
	byKind := map[string]Actor{}
	for _, a := range actors {
		byKind[a.Kind] = a
	}
	root, hasRoot := byKind[ActorKindRoot]
	sub, hasSub := byKind[ActorKindSubagent]
	if !hasRoot || !hasSub {
		t.Fatalf("expected both root and subagent kinds; got %+v", byKind)
	}
	if root.Source != ActorSourceInferred {
		t.Errorf("implicit root.source = %q, want inferred (lazy-from-child)", root.Source)
	}
	if sub.ParentActorID != root.ID {
		t.Errorf("subagent.parent = %q, want implicit root id %q", sub.ParentActorID, root.ID)
	}
	if sub.Source != ActorSourceInferred {
		t.Errorf("lazy subagent.source = %q, want inferred", sub.Source)
	}

	// SubagentStart for the same agent_id arrives AFTER. The spec's
	// upsert rule preserves the inferred source on both rows so the
	// dashboard can show "we saw tool calls before declaration".
	subBody := `{"hook_event_name":"SubagentStart","session_id":"sess-lazy-001","agent_id":"sa-late","agent_type":"investigator"}`
	subEnv, err := Normalize([]byte(subBody), identity, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordHook(ctx, subEnv, OutcomeRefs{}); err != nil {
		t.Fatal(err)
	}
	actors, _ = store.QueryActors(ctx, ActorQuery{SessionID: "sess-lazy-001"})
	if len(actors) != 2 {
		t.Errorf("actor count after late SubagentStart = %d, want 2 (root + subagent rows upserted, no duplicates)", len(actors))
	}
	for _, a := range actors {
		if a.Kind == ActorKindSubagent {
			if a.ClaudeAgentID != "sa-late" || a.ClaudeAgentType != "investigator" {
				t.Errorf("subagent claude refs = (%q, %q)", a.ClaudeAgentID, a.ClaudeAgentType)
			}
		}
	}
}

// TestRecordHook_HeartbeatSession confirms heartbeat session ids
// (heartbeat-<timestamp>) land in runtime_sessions with status =
// heartbeat and last_heartbeat_at populated, and that
// LastHeartbeat returns them.
func TestRecordHook_HeartbeatSession(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	identity := IdentityResolution{
		PrincipalID: "claude-code",
		ClientID:    "claude-code",
		SessionID:   "heartbeat-20260427T120000Z",
	}
	body := `{"hook_event_name":"SessionStart","session_id":"heartbeat-20260427T120000Z","source":"oktsec-doctor"}`
	env, err := Normalize([]byte(body), identity, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordHook(ctx, env, OutcomeRefs{}); err != nil {
		t.Fatal(err)
	}
	sessions, _ := store.QuerySessions(ctx, SessionQuery{Limit: 5})
	if len(sessions) != 1 {
		t.Fatalf("session count = %d", len(sessions))
	}
	if sessions[0].Status != SessionStatusHeartbeat {
		t.Errorf("status = %q, want heartbeat", sessions[0].Status)
	}
	if sessions[0].LastHeartbeatAt.IsZero() {
		t.Error("last_heartbeat_at should be populated")
	}
	hb, err := store.LastHeartbeat(ctx, "claude-code", "claude-code")
	if err != nil {
		t.Fatal(err)
	}
	if hb == nil || hb.SessionID != identity.SessionID {
		t.Errorf("LastHeartbeat = %+v, want session %s", hb, identity.SessionID)
	}
}

// TestRecordHook_BlockedDecisionIncrementsCounters wires the
// outcome's block status into the session/actor block counters.
func TestRecordHook_BlockedDecisionIncrementsCounters(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	identity := IdentityResolution{
		PrincipalID: "claude-code",
		ClientID:    "claude-code",
		SessionID:   "sess-blk-001",
	}

	steps := []struct {
		body    string
		outcome OutcomeRefs
	}{
		{
			body: `{"hook_event_name":"SessionStart","session_id":"sess-blk-001"}`,
		},
		{
			body:    `{"hook_event_name":"PreToolUse","session_id":"sess-blk-001","tool_name":"Bash"}`,
			outcome: OutcomeRefs{Status: "blocked", PolicyDecision: "block"},
		},
	}
	for i, step := range steps {
		env, err := Normalize([]byte(step.body), identity, now.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.RecordHook(ctx, env, step.outcome); err != nil {
			t.Fatal(err)
		}
	}
	sessions, _ := store.QuerySessions(ctx, SessionQuery{Limit: 1})
	if sessions[0].BlockCount != 1 {
		t.Errorf("session block_count = %d, want 1", sessions[0].BlockCount)
	}
	actors, _ := store.QueryActors(ctx, ActorQuery{SessionID: "sess-blk-001"})
	var rootBlocks int64
	for _, a := range actors {
		if a.Kind == ActorKindRoot {
			rootBlocks = a.BlockCount
		}
	}
	if rootBlocks != 1 {
		t.Errorf("root actor block_count = %d, want 1", rootBlocks)
	}
}

// TestQueryEvents_FiltersAndOrdering makes sure the timeline view
// returns events in chronological order and respects per-session
// filtering — the contract the Sessions detail page in 3C will
// rely on.
func TestQueryEvents_FiltersAndOrdering(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	identity := IdentityResolution{
		PrincipalID: "claude-code",
		ClientID:    "claude-code",
		SessionID:   "sess-order",
	}
	for i, body := range []string{
		`{"hook_event_name":"SessionStart","session_id":"sess-order"}`,
		`{"hook_event_name":"PreToolUse","session_id":"sess-order","tool_name":"Read"}`,
		`{"hook_event_name":"PostToolUse","session_id":"sess-order","tool_name":"Read"}`,
	} {
		env, _ := Normalize([]byte(body), identity, now.Add(time.Duration(i)*time.Second))
		if err := store.RecordHook(ctx, env, OutcomeRefs{}); err != nil {
			t.Fatal(err)
		}
	}
	// Different session — must not leak through the SessionID filter.
	other, _ := Normalize([]byte(`{"hook_event_name":"SessionStart","session_id":"sess-other"}`),
		IdentityResolution{PrincipalID: "claude-code", ClientID: "claude-code", SessionID: "sess-other"},
		now.Add(10*time.Second))
	if err := store.RecordHook(ctx, other, OutcomeRefs{}); err != nil {
		t.Fatal(err)
	}

	events, err := store.QueryEvents(ctx, EventQuery{SessionID: "sess-order"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("event count = %d, want 3 (filter must isolate sess-order)", len(events))
	}
	for i := 1; i < len(events); i++ {
		if events[i].Timestamp.Before(events[i-1].Timestamp) {
			t.Errorf("events[%d] earlier than [%d]", i, i-1)
		}
	}
}

// TestRecordHook_PersistsToolHashes asserts that the input/output
// hashes the normalizer computes are written to runtime_hook_events
// AND make it back through QueryEvents — closing the P2 gap where
// the columns existed in the envelope but were dropped on insert.
// Two events with the same tool_input must produce the same hash on
// disk so future correlation queries can group them.
func TestRecordHook_PersistsToolHashes(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	identity := IdentityResolution{
		PrincipalID: "claude-code",
		ClientID:    "claude-code",
		SessionID:   "sess-hashes",
	}

	// First record a SessionStart so the session exists. Then two
	// PreToolUse events with identical tool_input — the persisted
	// rows must carry identical input hashes.
	for _, body := range []string{
		`{"hook_event_name":"SessionStart","session_id":"sess-hashes"}`,
		`{"hook_event_name":"PreToolUse","session_id":"sess-hashes","tool_name":"Bash","tool_input":{"command":"ls /tmp"}}`,
		`{"hook_event_name":"PreToolUse","session_id":"sess-hashes","tool_name":"Bash","tool_input":{"command":"ls /tmp"}}`,
		`{"hook_event_name":"PostToolUse","session_id":"sess-hashes","tool_name":"Bash","tool_response":"file1\nfile2"}`,
	} {
		env, err := Normalize([]byte(body), identity, now)
		if err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Second)
		if err := store.RecordHook(ctx, env, OutcomeRefs{Status: "delivered"}); err != nil {
			t.Fatal(err)
		}
	}

	events, err := store.QueryEvents(ctx, EventQuery{SessionID: "sess-hashes"})
	if err != nil {
		t.Fatal(err)
	}

	var preEvents []HookEvent
	var postEvents []HookEvent
	for _, e := range events {
		switch e.HookEventName {
		case "PreToolUse":
			preEvents = append(preEvents, e)
		case "PostToolUse":
			postEvents = append(postEvents, e)
		}
	}
	if len(preEvents) != 2 {
		t.Fatalf("PreToolUse count = %d, want 2", len(preEvents))
	}
	if preEvents[0].ToolInputHash == "" {
		t.Error("PreToolUse[0].ToolInputHash empty after round-trip")
	}
	if preEvents[0].ToolInputHash != preEvents[1].ToolInputHash {
		t.Errorf("identical tool_input produced different hashes: %q vs %q",
			preEvents[0].ToolInputHash, preEvents[1].ToolInputHash)
	}
	if len(postEvents) != 1 {
		t.Fatalf("PostToolUse count = %d, want 1", len(postEvents))
	}
	if postEvents[0].ToolOutputHash == "" {
		t.Error("PostToolUse.ToolOutputHash empty after round-trip")
	}
}

// TestQueryActorEdges returns root->subagent edges for the graph.
func TestQueryActorEdges(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	identity := IdentityResolution{
		PrincipalID: "claude-code",
		ClientID:    "claude-code",
		SessionID:   "sess-edges",
	}
	for i, body := range []string{
		`{"hook_event_name":"SessionStart","session_id":"sess-edges"}`,
		`{"hook_event_name":"SubagentStart","session_id":"sess-edges","agent_id":"sa-x","agent_type":"explorer"}`,
	} {
		env, _ := Normalize([]byte(body), identity, now.Add(time.Duration(i)*time.Second))
		if err := store.RecordHook(ctx, env, OutcomeRefs{}); err != nil {
			t.Fatal(err)
		}
	}
	edges, err := store.QueryActorEdges(ctx, EdgeQuery{PrincipalID: "claude-code"})
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 1 {
		t.Fatalf("edge count = %d, want 1", len(edges))
	}
	e := edges[0]
	if e.ParentKind != ActorKindRoot || e.ChildKind != ActorKindSubagent {
		t.Errorf("edge kinds = (%s -> %s), want root -> subagent", e.ParentKind, e.ChildKind)
	}
	if e.ChildLabel != "explorer" {
		t.Errorf("child label = %q, want explorer", e.ChildLabel)
	}
}
