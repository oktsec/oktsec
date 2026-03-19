package audit

import "fmt"

// Dialect abstracts SQL differences between database backends.
// The Store uses a Dialect to generate the few queries that vary
// across databases. ~95% of SQL is identical and uses standard syntax.
type Dialect interface {
	// Name returns the dialect identifier (e.g., "sqlite", "postgres").
	Name() string

	// Placeholder returns the parameter placeholder for the n-th argument (1-indexed).
	// SQLite uses ?, Postgres uses $1, $2, etc.
	Placeholder(n int) string

	// HourExtract returns a SQL expression that extracts the hour (0-23)
	// from a timestamp column stored as RFC3339 text.
	HourExtract(column string) string

	// Upsert returns the INSERT statement for upserting a row.
	// SQLite: INSERT OR REPLACE, Postgres: INSERT ... ON CONFLICT DO UPDATE.
	UpsertRevoked() string

	// InsertIgnore returns the INSERT statement that skips duplicates.
	// SQLite: INSERT OR IGNORE, Postgres: INSERT ... ON CONFLICT DO NOTHING.
	InsertIgnoreAlert() string

	// SchemaSQL returns the CREATE TABLE statements for this dialect.
	SchemaSQL() string

	// MigrateStatements returns ALTER TABLE statements for schema migration.
	// Each statement is executed independently with errors ignored (column may exist).
	MigrateStatements() []string

	// InitPragmas returns dialect-specific initialization statements
	// (e.g., WAL mode for SQLite, connection settings for Postgres).
	InitPragmas() []string
}

// SQLiteDialect implements Dialect for SQLite databases.
type SQLiteDialect struct{}

func (SQLiteDialect) Name() string { return "sqlite" }

func (SQLiteDialect) Placeholder(_ int) string { return "?" }

func (SQLiteDialect) HourExtract(column string) string {
	return fmt.Sprintf("CAST(strftime('%%H', %s) AS INTEGER)", column)
}

func (SQLiteDialect) UpsertRevoked() string {
	return `INSERT OR REPLACE INTO revoked_keys (fingerprint, agent_name, revoked_at, reason) VALUES (?, ?, ?, ?)`
}

func (SQLiteDialect) InsertIgnoreAlert() string {
	return `INSERT OR IGNORE INTO alerts (id, timestamp, event, severity, agent, message_id, detail, channel, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
}

func (SQLiteDialect) SchemaSQL() string { return schema }

func (SQLiteDialect) MigrateStatements() []string {
	return []string{
		"ALTER TABLE audit_log ADD COLUMN intent TEXT DEFAULT ''",
		"ALTER TABLE audit_log ADD COLUMN prev_hash TEXT DEFAULT ''",
		"ALTER TABLE audit_log ADD COLUMN entry_hash TEXT DEFAULT ''",
		"ALTER TABLE audit_log ADD COLUMN proxy_signature TEXT DEFAULT ''",
		"ALTER TABLE audit_log ADD COLUMN session_id TEXT DEFAULT ''",
		"ALTER TABLE audit_log ADD COLUMN tool_name TEXT DEFAULT ''",
		"ALTER TABLE audit_log ADD COLUMN delegation_chain_hash TEXT DEFAULT ''",
		"ALTER TABLE audit_log ADD COLUMN delegation_chain TEXT DEFAULT ''",
		"CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id)",
	}
}

func (SQLiteDialect) InitPragmas() []string {
	return []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA cache_size = -64000",
		"PRAGMA temp_store = MEMORY",
		"PRAGMA busy_timeout=5000",
	}
}

// PostgresDialect implements Dialect for PostgreSQL databases.
type PostgresDialect struct{}

func (PostgresDialect) Name() string { return "postgres" }

func (PostgresDialect) Placeholder(n int) string { return fmt.Sprintf("$%d", n) }

func (PostgresDialect) HourExtract(column string) string {
	return fmt.Sprintf("EXTRACT(HOUR FROM %s::timestamptz)::integer", column)
}

func (PostgresDialect) UpsertRevoked() string {
	return `INSERT INTO revoked_keys (fingerprint, agent_name, revoked_at, reason)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (fingerprint) DO UPDATE SET agent_name=$2, revoked_at=$3, reason=$4`
}

func (PostgresDialect) InsertIgnoreAlert() string {
	return `INSERT INTO alerts (id, timestamp, event, severity, agent, message_id, detail, channel, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (id) DO NOTHING`
}

func (PostgresDialect) SchemaSQL() string { return pgSchema }

func (PostgresDialect) MigrateStatements() []string {
	return []string{
		"ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS intent TEXT DEFAULT ''",
		"ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS prev_hash TEXT DEFAULT ''",
		"ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS entry_hash TEXT DEFAULT ''",
		"ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS proxy_signature TEXT DEFAULT ''",
		"ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS session_id TEXT DEFAULT ''",
		"ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS tool_name TEXT DEFAULT ''",
		"ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS delegation_chain_hash TEXT DEFAULT ''",
		"ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS delegation_chain TEXT DEFAULT ''",
		"CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id)",
	}
}

func (PostgresDialect) InitPragmas() []string { return nil }

// pgSchema is the PostgreSQL-compatible CREATE TABLE schema.
// Uses identical column types to SQLite (TEXT, INTEGER) which Postgres accepts.
const pgSchema = `
CREATE TABLE IF NOT EXISTS audit_log (
	id TEXT PRIMARY KEY,
	timestamp TEXT NOT NULL,
	from_agent TEXT NOT NULL,
	to_agent TEXT NOT NULL,
	content_hash TEXT NOT NULL,
	signature_verified INTEGER,
	pubkey_fingerprint TEXT,
	status TEXT NOT NULL,
	rules_triggered TEXT,
	policy_decision TEXT NOT NULL,
	latency_ms INTEGER,
	intent TEXT DEFAULT '',
	session_id TEXT DEFAULT '',
	tool_name TEXT DEFAULT '',
	prev_hash TEXT DEFAULT '',
	entry_hash TEXT DEFAULT '',
	proxy_signature TEXT DEFAULT '',
	delegation_chain_hash TEXT DEFAULT '',
	delegation_chain TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_status ON audit_log(status);
CREATE INDEX IF NOT EXISTS idx_audit_from ON audit_log(from_agent);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_ts_agent_status ON audit_log(timestamp, from_agent, status);
CREATE INDEX IF NOT EXISTS idx_audit_ts_from_to_status ON audit_log(timestamp, from_agent, to_agent, status);

CREATE TABLE IF NOT EXISTS revoked_keys (
	fingerprint TEXT PRIMARY KEY,
	agent_name TEXT NOT NULL,
	revoked_at TEXT NOT NULL,
	reason TEXT
);

CREATE TABLE IF NOT EXISTS quarantine_queue (
	id TEXT PRIMARY KEY,
	audit_entry_id TEXT NOT NULL,
	content TEXT NOT NULL,
	from_agent TEXT NOT NULL,
	to_agent TEXT NOT NULL,
	status TEXT NOT NULL DEFAULT 'pending',
	reviewed_by TEXT,
	reviewed_at TEXT,
	expires_at TEXT NOT NULL,
	created_at TEXT NOT NULL,
	rules_triggered TEXT,
	signature TEXT,
	timestamp TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine_queue(status);
CREATE INDEX IF NOT EXISTS idx_quarantine_expires ON quarantine_queue(expires_at);
`
