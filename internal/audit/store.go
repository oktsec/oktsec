package audit

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

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

CREATE TABLE IF NOT EXISTS revoked_keys (
	fingerprint TEXT PRIMARY KEY,
	agent_name TEXT NOT NULL,
	revoked_at TEXT NOT NULL,
	reason TEXT
);
`

// Hub broadcasts new audit entries to connected SSE clients.
type Hub struct {
	mu   sync.RWMutex
	subs map[chan Entry]struct{}
}

func newHub() *Hub {
	return &Hub{subs: make(map[chan Entry]struct{})}
}

// Subscribe returns a buffered channel that receives new entries.
func (h *Hub) Subscribe() chan Entry {
	ch := make(chan Entry, 16)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

// Unsubscribe removes a subscriber and closes its channel.
func (h *Hub) Unsubscribe(ch chan Entry) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
	close(ch)
}

func (h *Hub) broadcast(entry Entry) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.subs {
		select {
		case ch <- entry:
		default:
			// slow subscriber, drop
		}
	}
}

// Store manages the SQLite audit log.
type Store struct {
	db     *sql.DB
	writes chan Entry
	done   chan struct{}
	logger *slog.Logger
	Hub    *Hub
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
		Hub:    newHub(),
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
	if opts.Search != "" {
		query += " AND (from_agent LIKE ? OR to_agent LIKE ? OR rules_triggered LIKE ? OR status LIKE ?)"
		wild := "%" + opts.Search + "%"
		args = append(args, wild, wild, wild, wild)
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

// RevokeKey persists a key revocation in the database.
func (s *Store) RevokeKey(fingerprint, agentName, reason string) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO revoked_keys (fingerprint, agent_name, revoked_at, reason) VALUES (?, ?, ?, ?)`,
		fingerprint, agentName, time.Now().UTC().Format(time.RFC3339), reason,
	)
	if err != nil {
		return fmt.Errorf("revoking key: %w", err)
	}
	return nil
}

// IsRevoked checks whether a public key fingerprint has been revoked.
func (s *Store) IsRevoked(fingerprint string) (bool, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM revoked_keys WHERE fingerprint = ?`, fingerprint).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("checking revocation: %w", err)
	}
	return count > 0, nil
}

// ListRevokedKeys returns all revoked key records.
func (s *Store) ListRevokedKeys() ([]RevokedKey, error) {
	rows, err := s.db.Query(`SELECT fingerprint, agent_name, revoked_at, COALESCE(reason, '') FROM revoked_keys ORDER BY revoked_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("listing revoked keys: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var keys []RevokedKey
	for rows.Next() {
		var k RevokedKey
		if err := rows.Scan(&k.Fingerprint, &k.AgentName, &k.RevokedAt, &k.Reason); err != nil {
			return nil, fmt.Errorf("scanning revoked key: %w", err)
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// QueryHourlyStats returns message counts grouped by hour for the last 24 hours.
func (s *Store) QueryHourlyStats() (map[int]int, error) {
	rows, err := s.db.Query(`
		SELECT CAST(strftime('%H', timestamp) AS INTEGER) AS hour, COUNT(*)
		FROM audit_log
		WHERE timestamp >= datetime('now', '-24 hours')
		GROUP BY hour
		ORDER BY hour`)
	if err != nil {
		return nil, fmt.Errorf("querying hourly stats: %w", err)
	}
	defer func() { _ = rows.Close() }()

	stats := make(map[int]int)
	for rows.Next() {
		var hour, count int
		if err := rows.Scan(&hour, &count); err != nil {
			return nil, fmt.Errorf("scanning hourly stat: %w", err)
		}
		stats[hour] = count
	}
	return stats, rows.Err()
}

// QueryByID fetches a single audit entry by ID.
func (s *Store) QueryByID(id string) (*Entry, error) {
	row := s.db.QueryRow(
		"SELECT id, timestamp, from_agent, to_agent, content_hash, signature_verified, pubkey_fingerprint, status, rules_triggered, policy_decision, latency_ms FROM audit_log WHERE id = ?", id)

	var e Entry
	var fp, rules sql.NullString
	if err := row.Scan(&e.ID, &e.Timestamp, &e.FromAgent, &e.ToAgent, &e.ContentHash,
		&e.SignatureVerified, &fp, &e.Status, &rules, &e.PolicyDecision, &e.LatencyMs); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("querying by id: %w", err)
	}
	e.PubkeyFingerprint = fp.String
	e.RulesTriggered = rules.String
	return &e, nil
}

// StatusCounts holds the result of a grouped status query.
type StatusCounts struct {
	Total       int `json:"total"`
	Delivered   int `json:"delivered"`
	Blocked     int `json:"blocked"`
	Rejected    int `json:"rejected"`
	Quarantined int `json:"quarantined"`
}

// QueryStats returns message counts grouped by status without loading all rows.
func (s *Store) QueryStats() (*StatusCounts, error) {
	rows, err := s.db.Query(`SELECT status, COUNT(*) FROM audit_log GROUP BY status`)
	if err != nil {
		return nil, fmt.Errorf("querying stats: %w", err)
	}
	defer func() { _ = rows.Close() }()

	sc := &StatusCounts{}
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("scanning stats: %w", err)
		}
		sc.Total += count
		switch status {
		case "delivered":
			sc.Delivered = count
		case "blocked":
			sc.Blocked = count
		case "rejected":
			sc.Rejected = count
		case "quarantined":
			sc.Quarantined = count
		}
	}
	return sc, rows.Err()
}

// EntryJSON returns an Entry serialized as JSON bytes, for SSE broadcast.
func EntryJSON(e Entry) []byte {
	b, _ := json.Marshal(e)
	return b
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
		} else {
			s.Hub.broadcast(entry)
		}
	}
}

// QueryOpts holds filters for audit log queries.
type QueryOpts struct {
	Status     string
	Agent      string
	Unverified bool
	Since      string
	Search     string
	Limit      int
}
