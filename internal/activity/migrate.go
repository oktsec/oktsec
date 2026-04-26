package activity

import (
	"database/sql"
	"fmt"
)

// schemaSQLite is the CREATE TABLE used when the activity store runs on
// SQLite. The table sits beside audit_log in the same database file so
// migrations and DSN are shared with the audit store; activity is a
// peer table, not a peer database.
//
// Indexes mirror the queries the dashboard runs:
//   - timestamp        for time-window scans
//   - principal+surface+timestamp  for last-seen and drill-down
//   - connector+timestamp          for per-connector views
//   - workspace+timestamp          for workspace activity pages (Phase 2B+)
//   - session+timestamp            for trace timelines
//   - resource_hash+timestamp      for "who else touched this resource"
const schemaSQLite = `
CREATE TABLE IF NOT EXISTS activity_events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    org_id TEXT DEFAULT '',
    host_id TEXT DEFAULT '',
    workspace_id TEXT DEFAULT '',

    principal_id TEXT NOT NULL,
    reported_actor TEXT DEFAULT '',
    auth_method TEXT DEFAULT '',
    principal_trust_level TEXT DEFAULT '',

    connector_id TEXT DEFAULT '',
    client_id TEXT DEFAULT '',
    surface TEXT NOT NULL,
    event_type TEXT NOT NULL,
    evidence_type TEXT NOT NULL,

    session_id TEXT DEFAULT '',
    request_id TEXT DEFAULT '',
    audit_entry_id TEXT DEFAULT '',
    decision_trace_id TEXT DEFAULT '',

    status TEXT DEFAULT '',
    policy_decision TEXT DEFAULT '',
    coverage_mode TEXT NOT NULL,
    confidence INTEGER DEFAULT 0,

    resource_type TEXT DEFAULT '',
    resource_id TEXT DEFAULT '',
    resource_hash TEXT DEFAULT '',
    resource_label TEXT DEFAULT '',

    evidence_json TEXT DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_activity_events_time
    ON activity_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_activity_events_principal_surface_time
    ON activity_events(principal_id, surface, timestamp);
CREATE INDEX IF NOT EXISTS idx_activity_events_connector_time
    ON activity_events(connector_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_activity_events_workspace_time
    ON activity_events(workspace_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_activity_events_session_time
    ON activity_events(session_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_activity_events_resource_time
    ON activity_events(resource_hash, timestamp);
`

// schemaPostgres mirrors schemaSQLite using TEXT/INTEGER (Postgres
// accepts both with the same semantics we use here). DEFAULT is set on
// every nullable column so older code paths can omit fields without
// breaking the insert.
const schemaPostgres = `
CREATE TABLE IF NOT EXISTS activity_events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    org_id TEXT DEFAULT '',
    host_id TEXT DEFAULT '',
    workspace_id TEXT DEFAULT '',

    principal_id TEXT NOT NULL,
    reported_actor TEXT DEFAULT '',
    auth_method TEXT DEFAULT '',
    principal_trust_level TEXT DEFAULT '',

    connector_id TEXT DEFAULT '',
    client_id TEXT DEFAULT '',
    surface TEXT NOT NULL,
    event_type TEXT NOT NULL,
    evidence_type TEXT NOT NULL,

    session_id TEXT DEFAULT '',
    request_id TEXT DEFAULT '',
    audit_entry_id TEXT DEFAULT '',
    decision_trace_id TEXT DEFAULT '',

    status TEXT DEFAULT '',
    policy_decision TEXT DEFAULT '',
    coverage_mode TEXT NOT NULL,
    confidence INTEGER DEFAULT 0,

    resource_type TEXT DEFAULT '',
    resource_id TEXT DEFAULT '',
    resource_hash TEXT DEFAULT '',
    resource_label TEXT DEFAULT '',

    evidence_json TEXT DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_activity_events_time
    ON activity_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_activity_events_principal_surface_time
    ON activity_events(principal_id, surface, timestamp);
CREATE INDEX IF NOT EXISTS idx_activity_events_connector_time
    ON activity_events(connector_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_activity_events_workspace_time
    ON activity_events(workspace_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_activity_events_session_time
    ON activity_events(session_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_activity_events_resource_time
    ON activity_events(resource_hash, timestamp);
`

// Dialect names the SQL flavor the Store should target. Surface adapters
// in PR2+ will pass the same dialect their audit store uses, so audit
// and activity tables live in one DB file with consistent placeholder
// syntax.
type Dialect string

const (
	DialectSQLite   Dialect = "sqlite"
	DialectPostgres Dialect = "postgres"
)

// Migrate creates the activity_events table and its indexes. Safe to
// call repeatedly: every CREATE uses IF NOT EXISTS so a process restart
// or a parallel migration never errors.
func Migrate(db *sql.DB, d Dialect) error {
	var schema string
	switch d {
	case DialectPostgres:
		schema = schemaPostgres
	case DialectSQLite, "":
		schema = schemaSQLite
	default:
		return fmt.Errorf("activity: unknown dialect %q", d)
	}
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("activity: migrate: %w", err)
	}
	return nil
}

// placeholder returns the right SQL placeholder for the dialect at
// position n (1-based). SQLite accepts both "?" and "$N"; we use "?"
// for SQLite and "$N" for Postgres to match the audit store's style.
func placeholder(d Dialect, n int) string {
	if d == DialectPostgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}
