package audit

import (
	"database/sql"
	"fmt"
	"log/slog"

	_ "modernc.org/sqlite"
)

const schema = `
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
	latency_ms INTEGER
);

CREATE INDEX IF NOT EXISTS idx_audit_status ON audit_log(status);
CREATE INDEX IF NOT EXISTS idx_audit_from ON audit_log(from_agent);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
`

// Store manages the SQLite audit log.
type Store struct {
	db     *sql.DB
	writes chan Entry
	done   chan struct{}
	logger *slog.Logger
}

// NewStore opens (or creates) the SQLite audit database.
func NewStore(dbPath string, logger *slog.Logger) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening audit db: %w", err)
	}

	// Enable WAL mode for better concurrent read performance
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		if cerr := db.Close(); cerr != nil {
			return nil, fmt.Errorf("setting WAL mode: %w (also: close: %v)", err, cerr)
		}
		return nil, fmt.Errorf("setting WAL mode: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		if cerr := db.Close(); cerr != nil {
			return nil, fmt.Errorf("creating schema: %w (also: close: %v)", err, cerr)
		}
		return nil, fmt.Errorf("creating schema: %w", err)
	}

	s := &Store{
		db:     db,
		writes: make(chan Entry, 256),
		done:   make(chan struct{}),
		logger: logger,
	}

	go s.writeLoop()
	return s, nil
}

// Log enqueues an audit entry for async writing.
func (s *Store) Log(entry Entry) {
	select {
	case s.writes <- entry:
	default:
		s.logger.Warn("audit write buffer full, dropping entry", "id", entry.ID)
	}
}

// Query returns audit entries matching the given filters.
func (s *Store) Query(opts QueryOpts) ([]Entry, error) {
	query := "SELECT id, timestamp, from_agent, to_agent, content_hash, signature_verified, pubkey_fingerprint, status, rules_triggered, policy_decision, latency_ms FROM audit_log WHERE 1=1"
	var args []any

	if opts.Status != "" {
		query += " AND status = ?"
		args = append(args, opts.Status)
	}
	if opts.Agent != "" {
		query += " AND (from_agent = ? OR to_agent = ?)"
		args = append(args, opts.Agent, opts.Agent)
	}
	if opts.Unverified {
		query += " AND signature_verified != 1"
	}
	if opts.Since != "" {
		query += " AND timestamp >= ?"
		args = append(args, opts.Since)
	}

	query += " ORDER BY timestamp DESC"

	if opts.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", opts.Limit)
	} else {
		query += " LIMIT 50"
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying audit log: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entries []Entry
	for rows.Next() {
		var e Entry
		var fp, rules sql.NullString
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.FromAgent, &e.ToAgent, &e.ContentHash,
			&e.SignatureVerified, &fp, &e.Status, &rules, &e.PolicyDecision, &e.LatencyMs); err != nil {
			return nil, fmt.Errorf("scanning row: %w", err)
		}
		e.PubkeyFingerprint = fp.String
		e.RulesTriggered = rules.String
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// Close flushes pending writes and closes the database.
func (s *Store) Close() error {
	close(s.writes)
	<-s.done
	return s.db.Close()
}

func (s *Store) writeLoop() {
	defer close(s.done)
	for entry := range s.writes {
		_, err := s.db.Exec(
			`INSERT INTO audit_log (id, timestamp, from_agent, to_agent, content_hash, signature_verified, pubkey_fingerprint, status, rules_triggered, policy_decision, latency_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			entry.ID, entry.Timestamp, entry.FromAgent, entry.ToAgent, entry.ContentHash,
			entry.SignatureVerified, entry.PubkeyFingerprint, entry.Status, entry.RulesTriggered,
			entry.PolicyDecision, entry.LatencyMs,
		)
		if err != nil {
			s.logger.Error("audit write failed", "id", entry.ID, "error", err)
		}
	}
}

// QueryOpts holds filters for audit log queries.
type QueryOpts struct {
	Status     string
	Agent      string
	Unverified bool
	Since      string
	Limit      int
}
