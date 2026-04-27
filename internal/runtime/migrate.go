package runtime

import (
	"context"
	"database/sql"
	"fmt"
)

// Dialect names the SQL flavor the Store should target. Mirrors
// internal/activity/migrate.go so the proxy and gateway can pass
// the same value they pass to activity.Migrate.
type Dialect string

const (
	DialectSQLite   Dialect = "sqlite"
	DialectPostgres Dialect = "postgres"
)

// schemaSQLite creates the three Phase 3 runtime tables and their
// indexes. CREATE IF NOT EXISTS makes the migration idempotent so
// proxy + gateway in the same process never race; the same
// no-feature-flag posture activity.Migrate uses.
//
// The tables sit beside audit_log and activity_events in the same
// DB. Phase 3A keeps them empty (no writer wired yet). Phase 3B is
// the slice that turns inserts on through the hook handler.
const schemaSQLite = `
CREATE TABLE IF NOT EXISTS runtime_sessions (
    session_id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    client_id TEXT DEFAULT '',
    connector_id TEXT DEFAULT '',
    root_actor_id TEXT DEFAULT '',
    cwd_tail TEXT DEFAULT '',
    cwd_hash TEXT DEFAULT '',
    transcript_path_tail TEXT DEFAULT '',
    transcript_path_hash TEXT DEFAULT '',
    started_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    ended_at TEXT DEFAULT '',
    end_reason TEXT DEFAULT '',
    start_source TEXT DEFAULT '',
    model TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    event_count INTEGER NOT NULL DEFAULT 0,
    tool_event_count INTEGER NOT NULL DEFAULT 0,
    subagent_count INTEGER NOT NULL DEFAULT 0,
    task_count INTEGER NOT NULL DEFAULT 0,
    block_count INTEGER NOT NULL DEFAULT 0,
    last_heartbeat_at TEXT DEFAULT '',
    last_heartbeat_id TEXT DEFAULT '',
    evidence_json TEXT DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_runtime_sessions_principal_time
    ON runtime_sessions(principal_id, last_seen_at);
CREATE INDEX IF NOT EXISTS idx_runtime_sessions_client_time
    ON runtime_sessions(client_id, last_seen_at);
CREATE INDEX IF NOT EXISTS idx_runtime_sessions_status_time
    ON runtime_sessions(status, last_seen_at);

CREATE TABLE IF NOT EXISTS runtime_actors (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    parent_actor_id TEXT DEFAULT '',
    root_actor_id TEXT DEFAULT '',
    kind TEXT NOT NULL,
    label TEXT NOT NULL,
    source TEXT DEFAULT '',
    claude_agent_id TEXT DEFAULT '',
    claude_agent_type TEXT DEFAULT '',
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    tool_count INTEGER NOT NULL DEFAULT 0,
    event_count INTEGER NOT NULL DEFAULT 0,
    block_count INTEGER NOT NULL DEFAULT 0,
    evidence_json TEXT DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_runtime_actors_session
    ON runtime_actors(session_id, kind, last_seen_at);
CREATE INDEX IF NOT EXISTS idx_runtime_actors_parent
    ON runtime_actors(parent_actor_id);
CREATE INDEX IF NOT EXISTS idx_runtime_actors_principal
    ON runtime_actors(principal_id, last_seen_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_runtime_actors_claude_agent
    ON runtime_actors(session_id, claude_agent_id)
    WHERE claude_agent_id <> '';

CREATE TABLE IF NOT EXISTS runtime_hook_events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    session_id TEXT DEFAULT '',
    principal_id TEXT NOT NULL,
    actor_id TEXT DEFAULT '',
    parent_actor_id TEXT DEFAULT '',
    root_actor_id TEXT DEFAULT '',
    client_id TEXT DEFAULT '',
    connector_id TEXT DEFAULT '',
    hook_event_name TEXT NOT NULL,
    lifecycle TEXT NOT NULL,
    stage TEXT NOT NULL,
    block_capable INTEGER NOT NULL DEFAULT 0,
    tool_name TEXT DEFAULT '',
    tool_use_id TEXT DEFAULT '',
    tool_input_hash TEXT DEFAULT '',
    tool_output_hash TEXT DEFAULT '',
    task_id TEXT DEFAULT '',
    task_subject TEXT DEFAULT '',
    config_source TEXT DEFAULT '',
    file_path_tail TEXT DEFAULT '',
    file_path_hash TEXT DEFAULT '',
    status TEXT DEFAULT '',
    policy_decision TEXT DEFAULT '',
    coverage_mode TEXT DEFAULT '',
    confidence INTEGER DEFAULT 0,
    audit_entry_id TEXT DEFAULT '',
    activity_event_id TEXT DEFAULT '',
    latency_ms INTEGER DEFAULT 0,
    evidence_json TEXT DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_runtime_hook_events_session_time
    ON runtime_hook_events(session_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_runtime_hook_events_actor_time
    ON runtime_hook_events(actor_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_runtime_hook_events_principal_time
    ON runtime_hook_events(principal_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_runtime_hook_events_event_time
    ON runtime_hook_events(hook_event_name, timestamp);
CREATE INDEX IF NOT EXISTS idx_runtime_hook_events_audit
    ON runtime_hook_events(audit_entry_id);
CREATE INDEX IF NOT EXISTS idx_runtime_hook_events_tool_input_hash
    ON runtime_hook_events(tool_input_hash, timestamp);
`

// schemaPostgres mirrors schemaSQLite. Postgres rejects partial
// indexes inside the same CREATE INDEX IF NOT EXISTS as SQLite
// without modification — the WHERE clause is portable across both
// engines. TEXT/INTEGER are accepted with the same semantics we
// use here so the column definitions can be shared verbatim.
const schemaPostgres = `
CREATE TABLE IF NOT EXISTS runtime_sessions (
    session_id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    client_id TEXT DEFAULT '',
    connector_id TEXT DEFAULT '',
    root_actor_id TEXT DEFAULT '',
    cwd_tail TEXT DEFAULT '',
    cwd_hash TEXT DEFAULT '',
    transcript_path_tail TEXT DEFAULT '',
    transcript_path_hash TEXT DEFAULT '',
    started_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    ended_at TEXT DEFAULT '',
    end_reason TEXT DEFAULT '',
    start_source TEXT DEFAULT '',
    model TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    event_count INTEGER NOT NULL DEFAULT 0,
    tool_event_count INTEGER NOT NULL DEFAULT 0,
    subagent_count INTEGER NOT NULL DEFAULT 0,
    task_count INTEGER NOT NULL DEFAULT 0,
    block_count INTEGER NOT NULL DEFAULT 0,
    last_heartbeat_at TEXT DEFAULT '',
    last_heartbeat_id TEXT DEFAULT '',
    evidence_json TEXT DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_runtime_sessions_principal_time
    ON runtime_sessions(principal_id, last_seen_at);
CREATE INDEX IF NOT EXISTS idx_runtime_sessions_client_time
    ON runtime_sessions(client_id, last_seen_at);
CREATE INDEX IF NOT EXISTS idx_runtime_sessions_status_time
    ON runtime_sessions(status, last_seen_at);

CREATE TABLE IF NOT EXISTS runtime_actors (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    parent_actor_id TEXT DEFAULT '',
    root_actor_id TEXT DEFAULT '',
    kind TEXT NOT NULL,
    label TEXT NOT NULL,
    source TEXT DEFAULT '',
    claude_agent_id TEXT DEFAULT '',
    claude_agent_type TEXT DEFAULT '',
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    tool_count INTEGER NOT NULL DEFAULT 0,
    event_count INTEGER NOT NULL DEFAULT 0,
    block_count INTEGER NOT NULL DEFAULT 0,
    evidence_json TEXT DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_runtime_actors_session
    ON runtime_actors(session_id, kind, last_seen_at);
CREATE INDEX IF NOT EXISTS idx_runtime_actors_parent
    ON runtime_actors(parent_actor_id);
CREATE INDEX IF NOT EXISTS idx_runtime_actors_principal
    ON runtime_actors(principal_id, last_seen_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_runtime_actors_claude_agent
    ON runtime_actors(session_id, claude_agent_id)
    WHERE claude_agent_id <> '';

CREATE TABLE IF NOT EXISTS runtime_hook_events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    session_id TEXT DEFAULT '',
    principal_id TEXT NOT NULL,
    actor_id TEXT DEFAULT '',
    parent_actor_id TEXT DEFAULT '',
    root_actor_id TEXT DEFAULT '',
    client_id TEXT DEFAULT '',
    connector_id TEXT DEFAULT '',
    hook_event_name TEXT NOT NULL,
    lifecycle TEXT NOT NULL,
    stage TEXT NOT NULL,
    block_capable INTEGER NOT NULL DEFAULT 0,
    tool_name TEXT DEFAULT '',
    tool_use_id TEXT DEFAULT '',
    tool_input_hash TEXT DEFAULT '',
    tool_output_hash TEXT DEFAULT '',
    task_id TEXT DEFAULT '',
    task_subject TEXT DEFAULT '',
    config_source TEXT DEFAULT '',
    file_path_tail TEXT DEFAULT '',
    file_path_hash TEXT DEFAULT '',
    status TEXT DEFAULT '',
    policy_decision TEXT DEFAULT '',
    coverage_mode TEXT DEFAULT '',
    confidence INTEGER DEFAULT 0,
    audit_entry_id TEXT DEFAULT '',
    activity_event_id TEXT DEFAULT '',
    latency_ms INTEGER DEFAULT 0,
    evidence_json TEXT DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_runtime_hook_events_session_time
    ON runtime_hook_events(session_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_runtime_hook_events_actor_time
    ON runtime_hook_events(actor_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_runtime_hook_events_principal_time
    ON runtime_hook_events(principal_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_runtime_hook_events_event_time
    ON runtime_hook_events(hook_event_name, timestamp);
CREATE INDEX IF NOT EXISTS idx_runtime_hook_events_audit
    ON runtime_hook_events(audit_entry_id);
CREATE INDEX IF NOT EXISTS idx_runtime_hook_events_tool_input_hash
    ON runtime_hook_events(tool_input_hash, timestamp);
`

// Migrate creates the three runtime tables and their indexes.
// Idempotent: safe to call repeatedly under both SQLite and
// Postgres, mirroring activity.Migrate's contract so the proxy
// and gateway can call it with the same control flow they already
// use for activity_events.
func Migrate(ctx context.Context, db *sql.DB, d Dialect) error {
	var schema string
	switch d {
	case DialectPostgres:
		schema = schemaPostgres
	case DialectSQLite, "":
		schema = schemaSQLite
	default:
		return fmt.Errorf("runtime: unknown dialect %q", d)
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("runtime: migrate: %w", err)
	}
	return nil
}

// placeholder returns the right SQL placeholder for the dialect at
// position n (1-based). SQLite accepts both "?" and "$N"; we keep
// "?" for SQLite and "$N" for Postgres so the queries match the
// audit + activity stores' style.
func placeholder(d Dialect, n int) string {
	if d == DialectPostgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}
