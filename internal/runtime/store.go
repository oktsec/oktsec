package runtime

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// runtimeBusyRetries + runtimeBusyBackoff bound the retry loop on
// SQLITE_BUSY. The audit store's batch loop and the runtime tx
// share one *sql.DB; under burst load (or under race-detector
// overhead in CI) the audit batch can hold the writer past the
// SQLite busy_timeout (5s) and the BEGIN here returns
// SQLITE_BUSY. Eight attempts with a small backoff cleared every
// flake observed in the full-suite run; the caller's runtime
// context still bounds the total wall time so a stalled DB cannot
// pin the request goroutine indefinitely.
const (
	runtimeBusyRetries = 8
	runtimeBusyBackoff = 100 * time.Millisecond
)

// isBusyError detects SQLite's SQLITE_BUSY (5) without taking a
// dependency on the driver's typed error. modernc.org/sqlite
// formats the message as "database is locked (5) (SQLITE_BUSY)";
// matching on substring is cheap and survives a driver swap.
func isBusyError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "SQLITE_BUSY") || strings.Contains(msg, "database is locked")
}

// Store is the runtime tables' read+write surface. Phase 3A
// exposes the API only; Phase 3B wires the hook handler to call
// RecordHook on every inbound /hooks/event.
//
// The store wraps an existing *sql.DB borrowed from the audit
// store so all three tables (audit_log, activity_events,
// runtime_*) share one transaction-capable connection. Migrate is
// idempotent and may be called from multiple processes against
// the same DB without racing.
type Store struct {
	db      *sql.DB
	dialect Dialect
}

// Open builds a Store on top of an existing database handle.
// Migrate is invoked here so callers do not have to remember to
// run it; the operation is idempotent under both SQLite and
// Postgres so a second Open against the same DB is a no-op.
func Open(ctx context.Context, db *sql.DB, dialect Dialect) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("runtime: nil db")
	}
	if dialect == "" {
		dialect = DialectSQLite
	}
	if err := Migrate(ctx, db, dialect); err != nil {
		return nil, err
	}
	return &Store{db: db, dialect: dialect}, nil
}

// Migrate re-runs the schema migration. Safe to call repeatedly;
// kept on the Store for callers (tests, healthchecks) that want to
// pin the post-Open invariant without re-importing the package.
func (s *Store) Migrate(ctx context.Context) error {
	return Migrate(ctx, s.db, s.dialect)
}

// DB returns the underlying *sql.DB. Exposed so the dashboard's
// existing direct-query paths (which only run for read-only
// queries today) can build joined queries against runtime tables
// without re-opening the connection. Production write callers
// MUST go through RecordHook so the three tables stay coherent.
func (s *Store) DB() *sql.DB { return s.db }

// RecordHook is the single atomic chokepoint for one hook event.
// It performs:
//
//  1. Upsert runtime_sessions for env.SessionID.
//  2. Upsert runtime_actors for env.Actor (and the implicit root
//     when env.RootActorID points at it).
//  3. Insert one runtime_hook_events row.
//  4. Increment session and actor counters based on lifecycle +
//     stage + outcome.
//
// The whole sequence runs in a single transaction so a partial
// failure leaves the runtime tables coherent. Per spec, runtime
// writes are best-effort relative to security decisions: a failure
// here returns an error but never mutates the audit / activity
// outcome.
func (s *Store) RecordHook(ctx context.Context, env HookEnvelope, outcome OutcomeRefs) error {
	if env.PrincipalID == "" {
		return fmt.Errorf("runtime: RecordHook requires PrincipalID")
	}
	if env.HookEventName == "" {
		return fmt.Errorf("runtime: RecordHook requires HookEventName")
	}
	now := env.ReceivedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}

	// Retry the whole tx (BEGIN, the upserts, the insert, and the
	// COMMIT) on SQLITE_BUSY. The audit store's batch loop and the
	// runtime tx share one *sql.DB, so under burst load any of
	// these statements can collide with the audit batch's open
	// transaction and the driver returns SQLITE_BUSY (5). The
	// audit store already sets busy_timeout=5s; the loop here adds
	// a small backoff between retries so a transient lock does
	// not drop the runtime row entirely. The caller's runtime
	// context bounds the total wall time so a stalled DB cannot
	// pin the request goroutine indefinitely.
	var lastErr error
	for attempt := 0; attempt < runtimeBusyRetries; attempt++ {
		err := s.recordHookOnce(ctx, env, outcome, now)
		if err == nil {
			return nil
		}
		if !isBusyError(err) {
			return err
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return fmt.Errorf("runtime: %w (last busy error: %v)", ctx.Err(), err)
		case <-time.After(runtimeBusyBackoff):
		}
	}
	return fmt.Errorf("runtime: gave up after %d busy retries: %w", runtimeBusyRetries, lastErr)
}

// recordHookOnce is one attempt at the RecordHook transaction.
// Wrapped in a retry loop above so SQLITE_BUSY at any statement —
// not just BEGIN — gives us a fresh shot at the writer lock.
func (s *Store) recordHookOnce(ctx context.Context, env HookEnvelope, outcome OutcomeRefs, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("runtime: begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if env.SessionID != "" {
		if err := s.upsertSessionTx(ctx, tx, env, outcome, now); err != nil {
			return err
		}
	}
	// Implicit root actor. When the first event we see for a session
	// is a child (subagent start, lazy tool call, task created), the
	// child carries env.ParentActorID = "<session>:root" but the root
	// row itself does not yet exist — QueryActorEdges would left-join
	// to nothing and the graph would lose the parent link. Upsert the
	// root row first so the join always finds a parent.
	//
	// We mark the synthetic root as inferred so the dashboard can
	// distinguish "root row created from a real SessionStart" from
	// "root row created lazily because a child event arrived first".
	if env.Actor.ID != "" && env.RootActorID != "" && env.RootActorID != env.Actor.ID {
		rootEnv := env
		rootEnv.Actor = ActorRef{
			ID:     env.RootActorID,
			Kind:   ActorKindRoot,
			Label:  formatRoot(env.ClientID),
			Source: ActorSourceInferred,
		}
		rootEnv.ParentActorID = ""
		rootEnv.RootActorID = ""
		if err := s.upsertActorTx(ctx, tx, rootEnv, now); err != nil {
			return err
		}
	}
	if env.Actor.ID != "" {
		if err := s.upsertActorTx(ctx, tx, env, now); err != nil {
			return err
		}
	}
	if err := s.insertEventTx(ctx, tx, env, outcome, now); err != nil {
		return err
	}
	if env.SessionID != "" {
		if err := s.bumpSessionCountersTx(ctx, tx, env, outcome, now); err != nil {
			return err
		}
	}
	if env.Actor.ID != "" {
		if err := s.bumpActorCountersTx(ctx, tx, env, outcome, now); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("runtime: commit: %w", err)
	}
	committed = true
	return nil
}

// UpsertSession exposes the session upsert path on its own so
// tests and (later) backfill tools can populate runtime_sessions
// without going through a full hook event.
func (s *Store) UpsertSession(ctx context.Context, env HookEnvelope, outcome OutcomeRefs) error {
	if env.SessionID == "" {
		return fmt.Errorf("runtime: UpsertSession requires SessionID")
	}
	now := env.ReceivedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("runtime: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.upsertSessionTx(ctx, tx, env, outcome, now); err != nil {
		return err
	}
	return tx.Commit()
}

// UpsertActor exposes the actor upsert path. Used by tests and by
// the Sessions detail page when it needs to seed actors before any
// event lands (e.g. preview mode).
func (s *Store) UpsertActor(ctx context.Context, env HookEnvelope, outcome OutcomeRefs) error {
	if env.Actor.ID == "" {
		return fmt.Errorf("runtime: UpsertActor requires Actor.ID")
	}
	now := env.ReceivedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("runtime: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.upsertActorTx(ctx, tx, env, now); err != nil {
		return err
	}
	return tx.Commit()
}

// upsertSessionTx is the SQLite-flavoured session upsert. The
// INSERT ... ON CONFLICT pattern here is supported by both modern
// SQLite (>=3.24, which modernc/sqlite ships) and Postgres.
//
// Counters are NOT bumped here — bumpSessionCountersTx owns that
// path so the upsert stays a pure "ensure row exists with current
// metadata" operation.
func (s *Store) upsertSessionTx(ctx context.Context, tx *sql.Tx, env HookEnvelope, outcome OutcomeRefs, now time.Time) error {
	q := `
INSERT INTO runtime_sessions (
    session_id, principal_id, client_id, connector_id, root_actor_id,
    cwd_tail, cwd_hash, transcript_path_tail, transcript_path_hash,
    started_at, last_seen_at, status, start_source, model,
    last_heartbeat_at, last_heartbeat_id, evidence_json, created_at
) VALUES (` + s.placeholders(18) + `)
ON CONFLICT (session_id) DO UPDATE SET
    last_seen_at = excluded.last_seen_at,
    root_actor_id = CASE WHEN runtime_sessions.root_actor_id = '' THEN excluded.root_actor_id ELSE runtime_sessions.root_actor_id END,
    cwd_tail = CASE WHEN runtime_sessions.cwd_tail = '' THEN excluded.cwd_tail ELSE runtime_sessions.cwd_tail END,
    cwd_hash = CASE WHEN runtime_sessions.cwd_hash = '' THEN excluded.cwd_hash ELSE runtime_sessions.cwd_hash END,
    transcript_path_tail = CASE WHEN runtime_sessions.transcript_path_tail = '' THEN excluded.transcript_path_tail ELSE runtime_sessions.transcript_path_tail END,
    transcript_path_hash = CASE WHEN runtime_sessions.transcript_path_hash = '' THEN excluded.transcript_path_hash ELSE runtime_sessions.transcript_path_hash END,
    start_source = CASE WHEN runtime_sessions.start_source = '' THEN excluded.start_source ELSE runtime_sessions.start_source END,
    model = CASE WHEN runtime_sessions.model = '' THEN excluded.model ELSE runtime_sessions.model END,
    last_heartbeat_at = CASE WHEN excluded.last_heartbeat_at <> '' THEN excluded.last_heartbeat_at ELSE runtime_sessions.last_heartbeat_at END,
    last_heartbeat_id = CASE WHEN excluded.last_heartbeat_id <> '' THEN excluded.last_heartbeat_id ELSE runtime_sessions.last_heartbeat_id END
`
	startSource, model, heartbeatAt, heartbeatID := sessionLifecycleHints(env, now)
	status := SessionStatusActive
	if env.HookEventName == "SessionStart" && startSource == "heartbeat" {
		status = SessionStatusHeartbeat
	}
	_, err := tx.ExecContext(ctx, q,
		env.SessionID,
		env.PrincipalID,
		env.ClientID,
		env.ConnectorID,
		env.RootActorID,
		env.CWD,
		env.CWDHash,
		env.TranscriptRef.PathTail,
		env.TranscriptRef.PathHash,
		now.UTC().Format(time.RFC3339Nano),
		now.UTC().Format(time.RFC3339Nano),
		status,
		startSource,
		model,
		heartbeatAt,
		heartbeatID,
		env.RawEvidenceJSON,
		now.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("runtime: upsert session: %w", err)
	}
	if env.HookEventName == "SessionEnd" {
		if _, err := tx.ExecContext(ctx, `UPDATE runtime_sessions SET status = `+s.placeholder(1)+`, ended_at = `+s.placeholder(2)+` WHERE session_id = `+s.placeholder(3),
			SessionStatusEnded, now.UTC().Format(time.RFC3339Nano), env.SessionID); err != nil {
			return fmt.Errorf("runtime: end session: %w", err)
		}
	}
	return nil
}

// upsertActorTx writes the actor row. Conflict resolution mirrors
// the session upsert — the row is created on first sight and
// later events only refresh last_seen_at + non-empty metadata.
//
// Inferred actors (created lazily because a tool event arrived
// before SubagentStart) keep their inferred source even when a
// later SubagentStart updates the same row, so the dashboard can
// show "we saw this subagent's tool calls before its declaration".
func (s *Store) upsertActorTx(ctx context.Context, tx *sql.Tx, env HookEnvelope, now time.Time) error {
	q := `
INSERT INTO runtime_actors (
    id, session_id, principal_id, parent_actor_id, root_actor_id,
    kind, label, source, claude_agent_id, claude_agent_type,
    first_seen_at, last_seen_at, evidence_json
) VALUES (` + s.placeholders(13) + `)
ON CONFLICT (id) DO UPDATE SET
    last_seen_at = excluded.last_seen_at,
    parent_actor_id = CASE WHEN runtime_actors.parent_actor_id = '' THEN excluded.parent_actor_id ELSE runtime_actors.parent_actor_id END,
    root_actor_id = CASE WHEN runtime_actors.root_actor_id = '' THEN excluded.root_actor_id ELSE runtime_actors.root_actor_id END,
    label = CASE WHEN runtime_actors.label = '' THEN excluded.label ELSE runtime_actors.label END,
    claude_agent_id = CASE WHEN runtime_actors.claude_agent_id = '' THEN excluded.claude_agent_id ELSE runtime_actors.claude_agent_id END,
    claude_agent_type = CASE WHEN runtime_actors.claude_agent_type = '' THEN excluded.claude_agent_type ELSE runtime_actors.claude_agent_type END
`
	_, err := tx.ExecContext(ctx, q,
		env.Actor.ID,
		env.SessionID,
		env.PrincipalID,
		env.ParentActorID,
		env.RootActorID,
		env.Actor.Kind,
		env.Actor.Label,
		env.Actor.Source,
		env.Actor.ClaudeAgentID,
		env.Actor.ClaudeAgentType,
		now.UTC().Format(time.RFC3339Nano),
		now.UTC().Format(time.RFC3339Nano),
		env.RawEvidenceJSON,
	)
	if err != nil {
		return fmt.Errorf("runtime: upsert actor: %w", err)
	}
	return nil
}

func (s *Store) insertEventTx(ctx context.Context, tx *sql.Tx, env HookEnvelope, outcome OutcomeRefs, now time.Time) error {
	if env.ID == "" {
		return fmt.Errorf("runtime: insert event: empty ID")
	}
	q := `
INSERT INTO runtime_hook_events (
    id, timestamp, session_id, principal_id,
    actor_id, parent_actor_id, root_actor_id,
    client_id, connector_id,
    hook_event_name, lifecycle, stage, block_capable,
    tool_name, tool_use_id, tool_input_hash, tool_output_hash,
    task_id, task_subject,
    config_source, file_path_tail, file_path_hash,
    status, policy_decision, coverage_mode, confidence,
    audit_entry_id, activity_event_id, latency_ms,
    evidence_json, created_at
) VALUES (` + s.placeholders(31) + `)
`
	_, err := tx.ExecContext(ctx, q,
		env.ID,
		now.UTC().Format(time.RFC3339Nano),
		env.SessionID,
		env.PrincipalID,
		env.Actor.ID,
		env.ParentActorID,
		env.RootActorID,
		env.ClientID,
		env.ConnectorID,
		env.HookEventName,
		env.Lifecycle,
		env.Stage,
		boolToInt(env.BlockCapable),
		env.Tool.Name,
		env.Tool.UseID,
		env.Tool.InputHash,
		env.Tool.OutputHash,
		env.Task.ID,
		truncate(env.Task.Subject, 80),
		env.Config.Source,
		env.File.PathTail,
		env.File.PathHash,
		outcome.Status,
		outcome.PolicyDecision,
		outcome.CoverageMode,
		outcome.Confidence,
		outcome.AuditEntryID,
		outcome.ActivityEventID,
		outcome.LatencyMs,
		env.RawEvidenceJSON,
		now.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("runtime: insert event: %w", err)
	}
	return nil
}

// bumpSessionCountersTx increments the per-session counters for
// the just-recorded event. The conditional updates keep tool/
// subagent/task/block tallies in sync without scanning the events
// table.
func (s *Store) bumpSessionCountersTx(ctx context.Context, tx *sql.Tx, env HookEnvelope, outcome OutcomeRefs, now time.Time) error {
	addTool, addSubagent, addTask, addBlock := counterDeltas(env, outcome)
	q := `UPDATE runtime_sessions SET
    last_seen_at = ` + s.placeholder(1) + `,
    event_count = event_count + 1,
    tool_event_count = tool_event_count + ` + s.placeholder(2) + `,
    subagent_count = subagent_count + ` + s.placeholder(3) + `,
    task_count = task_count + ` + s.placeholder(4) + `,
    block_count = block_count + ` + s.placeholder(5) + `
    WHERE session_id = ` + s.placeholder(6)
	_, err := tx.ExecContext(ctx, q,
		now.UTC().Format(time.RFC3339Nano),
		addTool, addSubagent, addTask, addBlock,
		env.SessionID,
	)
	if err != nil {
		return fmt.Errorf("runtime: bump session counters: %w", err)
	}
	return nil
}

func (s *Store) bumpActorCountersTx(ctx context.Context, tx *sql.Tx, env HookEnvelope, outcome OutcomeRefs, now time.Time) error {
	addTool, _, _, addBlock := counterDeltas(env, outcome)
	q := `UPDATE runtime_actors SET
    last_seen_at = ` + s.placeholder(1) + `,
    event_count = event_count + 1,
    tool_count = tool_count + ` + s.placeholder(2) + `,
    block_count = block_count + ` + s.placeholder(3) + `
    WHERE id = ` + s.placeholder(4)
	_, err := tx.ExecContext(ctx, q,
		now.UTC().Format(time.RFC3339Nano),
		addTool, addBlock, env.Actor.ID,
	)
	if err != nil {
		return fmt.Errorf("runtime: bump actor counters: %w", err)
	}
	return nil
}

// counterDeltas returns (tool, subagent, task, block) increments
// for one event. Centralised so session and actor counters never
// drift in their interpretation of an event family.
func counterDeltas(env HookEnvelope, outcome OutcomeRefs) (tool, subagent, task, block int) {
	switch env.Lifecycle {
	case LifecycleTool:
		tool = 1
	case LifecycleSubagent:
		if env.HookEventName == "SubagentStart" {
			subagent = 1
		}
	case LifecycleTask:
		if env.HookEventName == "TaskCreated" {
			task = 1
		}
	}
	if outcome.Status == "blocked" || outcome.PolicyDecision == "block" {
		block = 1
	}
	return
}

// sessionLifecycleHints derives the session's start source +
// model + heartbeat refs from a SessionStart payload. Defaults to
// empty strings for every other event family so the upsert's
// COALESCE clauses keep existing values.
func sessionLifecycleHints(env HookEnvelope, now time.Time) (startSource, model, heartbeatAt, heartbeatID string) {
	if env.HookEventName != "SessionStart" {
		return "", "", "", ""
	}
	startSource = "session_start"
	if env.Actor.Source == "cli_runtime" {
		startSource = "cli_runtime"
	}
	if isHeartbeatSession(env.SessionID) {
		startSource = "heartbeat"
		heartbeatAt = now.UTC().Format(time.RFC3339Nano)
		heartbeatID = env.SessionID
	}
	return startSource, model, heartbeatAt, heartbeatID
}

// LastHeartbeat returns the most recent heartbeat session for the
// (principal, client) pair. Heartbeats are SessionStart events
// whose session_id starts with "heartbeat-"; the upsert sets
// status=heartbeat and last_heartbeat_at on the session row.
func (s *Store) LastHeartbeat(ctx context.Context, principalID, clientID string) (*Heartbeat, error) {
	q := `SELECT session_id, last_heartbeat_at, client_id
        FROM runtime_sessions
        WHERE principal_id = ` + s.placeholder(1) + `
          AND client_id = ` + s.placeholder(2) + `
          AND last_heartbeat_at <> ''
        ORDER BY last_heartbeat_at DESC LIMIT 1`
	row := s.db.QueryRowContext(ctx, q, principalID, clientID)
	var sessionID, ts, cid string
	if err := row.Scan(&sessionID, &ts, &cid); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("runtime: last heartbeat: %w", err)
	}
	t, _ := time.Parse(time.RFC3339Nano, ts)
	return &Heartbeat{SessionID: sessionID, ReceivedAt: t, ClientID: cid}, nil
}

// QuerySessions returns the recent sessions list, newest first.
// Used by the Sessions page in 3C.
func (s *Store) QuerySessions(ctx context.Context, q SessionQuery) ([]Session, error) {
	limit := q.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	args := []any{}
	where := "1=1"
	idx := 0
	add := func(clause string, vals ...any) {
		idx += len(vals)
		where += " AND " + clause
		args = append(args, vals...)
	}
	if q.PrincipalID != "" {
		add("principal_id = "+s.placeholder(idx+1), q.PrincipalID)
	}
	if q.ClientID != "" {
		add("client_id = "+s.placeholder(idx+1), q.ClientID)
	}
	if q.Status != "" {
		add("status = "+s.placeholder(idx+1), q.Status)
	}
	if !q.Since.IsZero() {
		add("last_seen_at >= "+s.placeholder(idx+1), q.Since.UTC().Format(time.RFC3339Nano))
	}
	if !q.Until.IsZero() {
		add("last_seen_at <= "+s.placeholder(idx+1), q.Until.UTC().Format(time.RFC3339Nano))
	}
	args = append(args, limit)
	limitPh := s.placeholder(idx + 1)

	query := `SELECT session_id, principal_id, client_id, connector_id, root_actor_id,
        cwd_tail, cwd_hash, transcript_path_tail, transcript_path_hash,
        started_at, last_seen_at, ended_at, end_reason, start_source, model, status,
        event_count, tool_event_count, subagent_count, task_count, block_count,
        last_heartbeat_at, last_heartbeat_id
        FROM runtime_sessions WHERE ` + where + `
        ORDER BY last_seen_at DESC LIMIT ` + limitPh
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("runtime: query sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Session
	for rows.Next() {
		var sess Session
		var startedAt, lastSeenAt, endedAt, lastHeartbeatAt string
		if err := rows.Scan(
			&sess.SessionID, &sess.PrincipalID, &sess.ClientID, &sess.ConnectorID, &sess.RootActorID,
			&sess.CWDTail, &sess.CWDHash, &sess.TranscriptPathTail, &sess.TranscriptPathHash,
			&startedAt, &lastSeenAt, &endedAt, &sess.EndReason, &sess.StartSource, &sess.Model, &sess.Status,
			&sess.EventCount, &sess.ToolEventCount, &sess.SubagentCount, &sess.TaskCount, &sess.BlockCount,
			&lastHeartbeatAt, &sess.LastHeartbeatID,
		); err != nil {
			return nil, fmt.Errorf("runtime: scan session: %w", err)
		}
		sess.StartedAt, _ = time.Parse(time.RFC3339Nano, startedAt)
		sess.LastSeenAt, _ = time.Parse(time.RFC3339Nano, lastSeenAt)
		if endedAt != "" {
			sess.EndedAt, _ = time.Parse(time.RFC3339Nano, endedAt)
		}
		if lastHeartbeatAt != "" {
			sess.LastHeartbeatAt, _ = time.Parse(time.RFC3339Nano, lastHeartbeatAt)
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

// QuerySession returns one session plus its actors and events.
// Returns (nil, nil) when the session id is unknown so the caller
// can render a "not found" UI without ErrNoRows leaking through.
func (s *Store) QuerySession(ctx context.Context, sessionID string) (*SessionDetail, error) {
	sessions, err := s.QuerySessions(ctx, SessionQuery{Limit: 1})
	if err != nil {
		return nil, err
	}
	_ = sessions // silence; we look up by id below for clarity
	q := `SELECT session_id, principal_id, client_id, connector_id, root_actor_id,
        cwd_tail, cwd_hash, transcript_path_tail, transcript_path_hash,
        started_at, last_seen_at, ended_at, end_reason, start_source, model, status,
        event_count, tool_event_count, subagent_count, task_count, block_count,
        last_heartbeat_at, last_heartbeat_id
        FROM runtime_sessions WHERE session_id = ` + s.placeholder(1)
	row := s.db.QueryRowContext(ctx, q, sessionID)
	var sess Session
	var startedAt, lastSeenAt, endedAt, lastHeartbeatAt string
	if err := row.Scan(
		&sess.SessionID, &sess.PrincipalID, &sess.ClientID, &sess.ConnectorID, &sess.RootActorID,
		&sess.CWDTail, &sess.CWDHash, &sess.TranscriptPathTail, &sess.TranscriptPathHash,
		&startedAt, &lastSeenAt, &endedAt, &sess.EndReason, &sess.StartSource, &sess.Model, &sess.Status,
		&sess.EventCount, &sess.ToolEventCount, &sess.SubagentCount, &sess.TaskCount, &sess.BlockCount,
		&lastHeartbeatAt, &sess.LastHeartbeatID,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("runtime: scan session detail: %w", err)
	}
	sess.StartedAt, _ = time.Parse(time.RFC3339Nano, startedAt)
	sess.LastSeenAt, _ = time.Parse(time.RFC3339Nano, lastSeenAt)
	if endedAt != "" {
		sess.EndedAt, _ = time.Parse(time.RFC3339Nano, endedAt)
	}
	if lastHeartbeatAt != "" {
		sess.LastHeartbeatAt, _ = time.Parse(time.RFC3339Nano, lastHeartbeatAt)
	}
	actors, err := s.QueryActors(ctx, ActorQuery{SessionID: sessionID, Limit: 200})
	if err != nil {
		return nil, err
	}
	events, err := s.QueryEvents(ctx, EventQuery{SessionID: sessionID, Limit: 500})
	if err != nil {
		return nil, err
	}
	return &SessionDetail{Session: sess, Actors: actors, Events: events}, nil
}

func (s *Store) QueryActors(ctx context.Context, q ActorQuery) ([]Actor, error) {
	limit := q.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	args := []any{}
	where := "1=1"
	idx := 0
	add := func(clause string, vals ...any) {
		idx += len(vals)
		where += " AND " + clause
		args = append(args, vals...)
	}
	if q.SessionID != "" {
		add("session_id = "+s.placeholder(idx+1), q.SessionID)
	}
	if q.PrincipalID != "" {
		add("principal_id = "+s.placeholder(idx+1), q.PrincipalID)
	}
	if q.Kind != "" {
		add("kind = "+s.placeholder(idx+1), q.Kind)
	}
	args = append(args, limit)
	limitPh := s.placeholder(idx + 1)
	query := `SELECT id, session_id, principal_id, parent_actor_id, root_actor_id,
        kind, label, source, claude_agent_id, claude_agent_type,
        first_seen_at, last_seen_at, tool_count, event_count, block_count
        FROM runtime_actors WHERE ` + where + `
        ORDER BY last_seen_at DESC LIMIT ` + limitPh
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("runtime: query actors: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Actor
	for rows.Next() {
		var a Actor
		var first, last string
		if err := rows.Scan(
			&a.ID, &a.SessionID, &a.PrincipalID, &a.ParentActorID, &a.RootActorID,
			&a.Kind, &a.Label, &a.Source, &a.ClaudeAgentID, &a.ClaudeAgentType,
			&first, &last, &a.ToolCount, &a.EventCount, &a.BlockCount,
		); err != nil {
			return nil, fmt.Errorf("runtime: scan actor: %w", err)
		}
		a.FirstSeenAt, _ = time.Parse(time.RFC3339Nano, first)
		a.LastSeenAt, _ = time.Parse(time.RFC3339Nano, last)
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) QueryEvents(ctx context.Context, q EventQuery) ([]HookEvent, error) {
	limit := q.Limit
	if limit <= 0 || limit > 5000 {
		limit = 200
	}
	args := []any{}
	where := "1=1"
	idx := 0
	add := func(clause string, vals ...any) {
		idx += len(vals)
		where += " AND " + clause
		args = append(args, vals...)
	}
	if q.SessionID != "" {
		add("session_id = "+s.placeholder(idx+1), q.SessionID)
	}
	if q.ActorID != "" {
		add("actor_id = "+s.placeholder(idx+1), q.ActorID)
	}
	if q.PrincipalID != "" {
		add("principal_id = "+s.placeholder(idx+1), q.PrincipalID)
	}
	if q.HookEventName != "" {
		add("hook_event_name = "+s.placeholder(idx+1), q.HookEventName)
	}
	if q.AuditEntryID != "" {
		add("audit_entry_id = "+s.placeholder(idx+1), q.AuditEntryID)
	}
	if !q.Since.IsZero() {
		add("timestamp >= "+s.placeholder(idx+1), q.Since.UTC().Format(time.RFC3339Nano))
	}
	if !q.Until.IsZero() {
		add("timestamp <= "+s.placeholder(idx+1), q.Until.UTC().Format(time.RFC3339Nano))
	}
	args = append(args, limit)
	limitPh := s.placeholder(idx + 1)
	query := `SELECT id, timestamp, session_id, principal_id,
        actor_id, parent_actor_id, root_actor_id,
        client_id, connector_id,
        hook_event_name, lifecycle, stage, block_capable,
        tool_name, tool_use_id, tool_input_hash, tool_output_hash,
        task_id, task_subject,
        config_source, file_path_tail, file_path_hash,
        status, policy_decision, coverage_mode, confidence,
        audit_entry_id, activity_event_id, latency_ms
        FROM runtime_hook_events WHERE ` + where + `
        ORDER BY timestamp ASC LIMIT ` + limitPh
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("runtime: query events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []HookEvent
	for rows.Next() {
		var e HookEvent
		var ts string
		var blockCapable int
		if err := rows.Scan(
			&e.ID, &ts, &e.SessionID, &e.PrincipalID,
			&e.ActorID, &e.ParentActorID, &e.RootActorID,
			&e.ClientID, &e.ConnectorID,
			&e.HookEventName, &e.Lifecycle, &e.Stage, &blockCapable,
			&e.ToolName, &e.ToolUseID, &e.ToolInputHash, &e.ToolOutputHash,
			&e.TaskID, &e.TaskSubject,
			&e.ConfigSource, &e.FilePathTail, &e.FilePathHash,
			&e.Status, &e.PolicyDecision, &e.CoverageMode, &e.Confidence,
			&e.AuditEntryID, &e.ActivityEventID, &e.LatencyMs,
		); err != nil {
			return nil, fmt.Errorf("runtime: scan event: %w", err)
		}
		e.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		e.BlockCapable = blockCapable != 0
		out = append(out, e)
	}
	return out, rows.Err()
}

// QueryActorEdges returns the (parent, child) actor edges for the
// graph builder. The query joins runtime_actors against itself so
// the dashboard handler does not have to walk the table twice.
func (s *Store) QueryActorEdges(ctx context.Context, q EdgeQuery) ([]ActorEdge, error) {
	limit := q.Limit
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	args := []any{}
	where := "child.parent_actor_id <> ''"
	idx := 0
	add := func(clause string, vals ...any) {
		idx += len(vals)
		where += " AND " + clause
		args = append(args, vals...)
	}
	if q.PrincipalID != "" {
		add("child.principal_id = "+s.placeholder(idx+1), q.PrincipalID)
	}
	if !q.Since.IsZero() {
		add("child.last_seen_at >= "+s.placeholder(idx+1), q.Since.UTC().Format(time.RFC3339Nano))
	}
	args = append(args, limit)
	limitPh := s.placeholder(idx + 1)

	query := `SELECT parent.id, parent.label, parent.kind,
        child.id, child.label, child.kind,
        child.session_id, child.principal_id,
        child.event_count, child.last_seen_at
        FROM runtime_actors child
        LEFT JOIN runtime_actors parent ON parent.id = child.parent_actor_id
        WHERE ` + where + `
        ORDER BY child.last_seen_at DESC LIMIT ` + limitPh
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("runtime: query edges: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []ActorEdge
	for rows.Next() {
		var e ActorEdge
		var parentID, parentLabel, parentKind sql.NullString
		var lastSeen string
		if err := rows.Scan(
			&parentID, &parentLabel, &parentKind,
			&e.ChildActorID, &e.ChildLabel, &e.ChildKind,
			&e.SessionID, &e.PrincipalID,
			&e.EventCount, &lastSeen,
		); err != nil {
			return nil, fmt.Errorf("runtime: scan edge: %w", err)
		}
		e.ParentActorID = parentID.String
		e.ParentLabel = parentLabel.String
		e.ParentKind = parentKind.String
		e.LastSeenAt, _ = time.Parse(time.RFC3339Nano, lastSeen)
		out = append(out, e)
	}
	return out, rows.Err()
}

// placeholders returns a comma-separated list of n placeholders
// for an INSERT VALUES clause. Centralised so the dialect switch
// never gets out of sync.
func (s *Store) placeholders(n int) string {
	out := ""
	for i := 1; i <= n; i++ {
		if i > 1 {
			out += ", "
		}
		out += s.placeholder(i)
	}
	return out
}

func (s *Store) placeholder(n int) string {
	return placeholder(s.dialect, n)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n]
}
