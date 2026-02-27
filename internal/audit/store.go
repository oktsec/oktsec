package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oktsec/oktsec/internal/safefile"
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
CREATE INDEX IF NOT EXISTS idx_audit_ts_agent_status ON audit_log(timestamp, from_agent, status);
CREATE INDEX IF NOT EXISTS idx_audit_ts_from_to_status ON audit_log(timestamp, from_agent, to_agent, status);
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
	db            *sql.DB
	writes        chan Entry
	done          chan struct{}
	logger        *slog.Logger
	Hub           *Hub
	ctx           context.Context
	cancel        context.CancelFunc
	retentionDays int
}

// DB returns the underlying *sql.DB for direct access (benchmarking/migrations).
func (s *Store) DB() *sql.DB { return s.db }

// NewStore opens (or creates) the SQLite audit database.
// retentionDays controls automatic purging of old entries (0 = no purging).
// If the database file or its parent directory is a symlink, it is rejected.
func NewStore(dbPath string, logger *slog.Logger, retentionDays ...int) (*Store, error) {
	if dbPath != ":memory:" {
		// Reject symlinked parent directory
		parentDir := filepath.Dir(dbPath)
		if info, err := os.Lstat(parentDir); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("audit db parent directory is a symlink: %s", parentDir)
			}
		}
		// Reject symlinked database file (only if it already exists)
		if _, err := os.Stat(dbPath); err == nil {
			if err := safefile.RejectSymlink(dbPath); err != nil {
				return nil, fmt.Errorf("audit db: %w", err)
			}
		}
	}

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

	// Set busy timeout so concurrent writers wait instead of returning SQLITE_BUSY
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		if cerr := db.Close(); cerr != nil {
			return nil, fmt.Errorf("setting busy_timeout: %w (also: close: %v)", err, cerr)
		}
		return nil, fmt.Errorf("setting busy_timeout: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		if cerr := db.Close(); cerr != nil {
			return nil, fmt.Errorf("creating schema: %w (also: close: %v)", err, cerr)
		}
		return nil, fmt.Errorf("creating schema: %w", err)
	}

	// Update query planner statistics for optimal index usage
	if _, err := db.Exec("ANALYZE"); err != nil {
		logger.Warn("ANALYZE failed", "error", err)
	}

	retention := 0
	if len(retentionDays) > 0 && retentionDays[0] > 0 {
		retention = retentionDays[0]
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &Store{
		db:            db,
		writes:        make(chan Entry, 256),
		done:          make(chan struct{}),
		logger:        logger,
		Hub:           newHub(),
		ctx:           ctx,
		cancel:        cancel,
		retentionDays: retention,
	}

	go s.writeLoop()
	go s.expiryLoop()
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
	if len(opts.Statuses) > 0 {
		placeholders := make([]string, len(opts.Statuses))
		for i, st := range opts.Statuses {
			placeholders[i] = "?"
			args = append(args, st)
		}
		query += " AND status IN (" + strings.Join(placeholders, ",") + ")"
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
	cutoff := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	rows, err := s.db.Query(`
		SELECT CAST(strftime('%H', timestamp) AS INTEGER) AS hour, COUNT(*)
		FROM audit_log
		WHERE timestamp >= ?
		GROUP BY hour
		ORDER BY hour`, cutoff)
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

// QueryAgentStats returns message counts grouped by status for a specific agent.
func (s *Store) QueryAgentStats(agent string) (*StatusCounts, error) {
	rows, err := s.db.Query(
		`SELECT status, COUNT(*) FROM audit_log WHERE from_agent = ? OR to_agent = ? GROUP BY status`,
		agent, agent,
	)
	if err != nil {
		return nil, fmt.Errorf("querying agent stats: %w", err)
	}
	defer func() { _ = rows.Close() }()

	sc := &StatusCounts{}
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("scanning agent stats: %w", err)
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

// Flush blocks until all pending writes have been processed.
func (s *Store) Flush() {
	for len(s.writes) > 0 {
		time.Sleep(5 * time.Millisecond)
	}
}

// Close flushes pending writes and closes the database.
func (s *Store) Close() error {
	s.cancel()
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
	Statuses   []string // multi-status filter (e.g. blocked + rejected)
	Agent      string
	Unverified bool
	Since      string
	Search     string
	Limit      int
}

// --- Quarantine queue methods ---

// Enqueue inserts a quarantine item synchronously.
func (s *Store) Enqueue(item QuarantineItem) error {
	_, err := s.db.Exec(
		`INSERT INTO quarantine_queue (id, audit_entry_id, content, from_agent, to_agent, status, expires_at, created_at, rules_triggered, signature, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.ID, item.AuditEntryID, item.Content, item.FromAgent, item.ToAgent,
		item.Status, item.ExpiresAt, item.CreatedAt, item.RulesTriggered, item.Signature, item.Timestamp,
	)
	if err != nil {
		return fmt.Errorf("enqueue quarantine: %w", err)
	}
	return nil
}

// QuarantineByID fetches a single quarantine item by ID.
func (s *Store) QuarantineByID(id string) (*QuarantineItem, error) {
	row := s.db.QueryRow(
		`SELECT id, audit_entry_id, content, from_agent, to_agent, status, COALESCE(reviewed_by,''), COALESCE(reviewed_at,''), expires_at, created_at, COALESCE(rules_triggered,''), COALESCE(signature,''), timestamp FROM quarantine_queue WHERE id = ?`, id)

	var item QuarantineItem
	if err := row.Scan(&item.ID, &item.AuditEntryID, &item.Content, &item.FromAgent, &item.ToAgent,
		&item.Status, &item.ReviewedBy, &item.ReviewedAt, &item.ExpiresAt, &item.CreatedAt,
		&item.RulesTriggered, &item.Signature, &item.Timestamp); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("quarantine by id: %w", err)
	}
	return &item, nil
}

// QuarantinePending returns pending quarantine items ordered by creation time.
func (s *Store) QuarantinePending(limit int) ([]QuarantineItem, error) {
	return s.QuarantineQuery("pending", "", limit)
}

// QuarantineQuery returns quarantine items matching the given filters.
func (s *Store) QuarantineQuery(status, agent string, limit int) ([]QuarantineItem, error) {
	query := `SELECT id, audit_entry_id, content, from_agent, to_agent, status, COALESCE(reviewed_by,''), COALESCE(reviewed_at,''), expires_at, created_at, COALESCE(rules_triggered,''), COALESCE(signature,''), timestamp FROM quarantine_queue WHERE 1=1`
	var args []any

	if status != "" {
		query += " AND status = ?"
		args = append(args, status)
	}
	if agent != "" {
		query += " AND (from_agent = ? OR to_agent = ?)"
		args = append(args, agent, agent)
	}

	query += " ORDER BY created_at DESC"

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	} else {
		query += " LIMIT 50"
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("quarantine query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var items []QuarantineItem
	for rows.Next() {
		var item QuarantineItem
		if err := rows.Scan(&item.ID, &item.AuditEntryID, &item.Content, &item.FromAgent, &item.ToAgent,
			&item.Status, &item.ReviewedBy, &item.ReviewedAt, &item.ExpiresAt, &item.CreatedAt,
			&item.RulesTriggered, &item.Signature, &item.Timestamp); err != nil {
			return nil, fmt.Errorf("scanning quarantine row: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// QuarantineApprove marks a quarantine item as approved and updates the audit entry.
func (s *Store) QuarantineApprove(id, reviewedBy string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }() //nolint:errcheck // rollback after commit is a no-op

	res, err := tx.Exec(
		`UPDATE quarantine_queue SET status='approved', reviewed_by=?, reviewed_at=? WHERE id=? AND status='pending'`,
		reviewedBy, now, id,
	)
	if err != nil {
		return fmt.Errorf("approve quarantine: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("quarantine item %q not found or not pending", id)
	}

	// Update the audit entry to reflect approval
	if _, err := tx.Exec(
		`UPDATE audit_log SET status='delivered', policy_decision='quarantine_approved' WHERE id=?`, id,
	); err != nil {
		return fmt.Errorf("update audit entry: %w", err)
	}

	return tx.Commit()
}

// QuarantineReject marks a quarantine item as rejected.
func (s *Store) QuarantineReject(id, reviewedBy string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(
		`UPDATE quarantine_queue SET status='rejected', reviewed_by=?, reviewed_at=? WHERE id=? AND status='pending'`,
		reviewedBy, now, id,
	)
	if err != nil {
		return fmt.Errorf("reject quarantine: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("quarantine item %q not found or not pending", id)
	}
	return nil
}

// QuarantineExpireOld expires quarantine items past their expiry time.
func (s *Store) QuarantineExpireOld() (int, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(
		`UPDATE quarantine_queue SET status='expired' WHERE status='pending' AND expires_at < ?`, now,
	)
	if err != nil {
		return 0, fmt.Errorf("expire quarantine: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// QuarantineStats returns counts grouped by quarantine status.
func (s *Store) QuarantineStats() (*QuarantineStats, error) {
	rows, err := s.db.Query(`SELECT status, COUNT(*) FROM quarantine_queue GROUP BY status`)
	if err != nil {
		return nil, fmt.Errorf("quarantine stats: %w", err)
	}
	defer func() { _ = rows.Close() }()

	qs := &QuarantineStats{}
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("scanning quarantine stats: %w", err)
		}
		qs.Total += count
		switch status {
		case "pending":
			qs.Pending = count
		case "approved":
			qs.Approved = count
		case "rejected":
			qs.Rejected = count
		case "expired":
			qs.Expired = count
		}
	}
	return qs, rows.Err()
}

// QueryUnsignedRate returns the count of unsigned messages and total messages in the last 24h.
func (s *Store) QueryUnsignedRate() (unsigned, total int, err error) {
	cutoff := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	row := s.db.QueryRow(
		`SELECT COUNT(*), COALESCE(SUM(CASE WHEN signature_verified != 1 THEN 1 ELSE 0 END), 0) FROM audit_log WHERE timestamp >= ?`,
		cutoff,
	)
	if err = row.Scan(&total, &unsigned); err != nil {
		return 0, 0, fmt.Errorf("query unsigned rate: %w", err)
	}
	return unsigned, total, nil
}

// QueryTrafficAgents returns distinct agent names seen in traffic in the last 24h.
func (s *Store) QueryTrafficAgents() ([]string, error) {
	cutoff := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	rows, err := s.db.Query(
		`SELECT DISTINCT agent FROM (
			SELECT from_agent AS agent FROM audit_log WHERE timestamp >= ?
			UNION
			SELECT to_agent AS agent FROM audit_log WHERE timestamp >= ?
		)`, cutoff, cutoff,
	)
	if err != nil {
		return nil, fmt.Errorf("query traffic agents: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var agents []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}
		agents = append(agents, name)
	}
	return agents, rows.Err()
}

// QueryTopRules returns the most frequently triggered rules from the last 24 hours.
func (s *Store) QueryTopRules(limit int) ([]RuleStat, error) {
	cutoff := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	rows, err := s.db.Query(`SELECT rules_triggered FROM audit_log WHERE timestamp >= ? AND rules_triggered IS NOT NULL AND rules_triggered != '' AND rules_triggered != '[]'`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("query top rules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	type findingJSON struct {
		RuleID   string `json:"rule_id"`
		Name     string `json:"name"`
		Severity string `json:"severity"`
	}

	counts := make(map[string]*RuleStat)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		var findings []findingJSON
		if err := json.Unmarshal([]byte(raw), &findings); err != nil {
			continue
		}
		for _, f := range findings {
			if rs, ok := counts[f.RuleID]; ok {
				rs.Count++
			} else {
				counts[f.RuleID] = &RuleStat{RuleID: f.RuleID, Name: f.Name, Severity: f.Severity, Count: 1}
			}
		}
	}

	var result []RuleStat
	for _, rs := range counts {
		result = append(result, *rs)
	}

	// Sort by count descending
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j].Count > result[i].Count {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result, rows.Err()
}

// QueryAgentRisk computes risk scores for all agents based on the last 24 hours.
func (s *Store) QueryAgentRisk() ([]AgentRisk, error) {
	cutoff := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	rows, err := s.db.Query(`SELECT from_agent, status, COUNT(*) FROM audit_log WHERE timestamp >= ? GROUP BY from_agent, status`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("query agent risk: %w", err)
	}
	defer func() { _ = rows.Close() }()

	agents := make(map[string]*AgentRisk)
	for rows.Next() {
		var agent, status string
		var count int
		if err := rows.Scan(&agent, &status, &count); err != nil {
			continue
		}
		ar, ok := agents[agent]
		if !ok {
			ar = &AgentRisk{Agent: agent}
			agents[agent] = ar
		}
		ar.Total += count
		switch status {
		case "blocked":
			ar.Blocked += count
		case "quarantined":
			ar.Quarantined += count
		}
	}

	var result []AgentRisk
	for _, ar := range agents {
		if ar.Total > 0 {
			ar.RiskScore = float64(ar.Blocked*3+ar.Quarantined*2) / float64(ar.Total) * 100
		}
		result = append(result, *ar)
	}

	// Sort by risk score descending
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j].RiskScore > result[i].RiskScore {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	return result, rows.Err()
}

// QueryEdgeStats returns aggregated message counts per from→to edge for the last 24 hours.
func (s *Store) QueryEdgeStats() ([]EdgeStat, error) {
	cutoff := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	rows, err := s.db.Query(`SELECT from_agent, to_agent, status, COUNT(*) FROM audit_log WHERE timestamp >= ? GROUP BY from_agent, to_agent, status`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("query edge stats: %w", err)
	}
	defer func() { _ = rows.Close() }()

	type key struct{ from, to string }
	edges := make(map[key]*EdgeStat)
	for rows.Next() {
		var from, to, status string
		var count int
		if err := rows.Scan(&from, &to, &status, &count); err != nil {
			continue
		}
		k := key{from, to}
		es, ok := edges[k]
		if !ok {
			es = &EdgeStat{From: from, To: to}
			edges[k] = es
		}
		es.Total += count
		switch status {
		case "delivered":
			es.Delivered += count
		case "blocked":
			es.Blocked += count
		case "quarantined":
			es.Quarantined += count
		case "rejected":
			es.Rejected += count
		}
	}

	result := make([]EdgeStat, 0, len(edges))
	for _, es := range edges {
		result = append(result, *es)
	}

	// Sort by total descending for deterministic output
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j].Total > result[i].Total {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	return result, rows.Err()
}

// QueryEdgeRules returns the top triggered rules for a specific from→to edge.
func (s *Store) QueryEdgeRules(from, to string, limit int) ([]RuleStat, error) {
	cutoff := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	rows, err := s.db.Query(
		`SELECT rules_triggered FROM audit_log WHERE timestamp >= ? AND from_agent = ? AND to_agent = ? AND rules_triggered IS NOT NULL AND rules_triggered != '' AND rules_triggered != '[]'`,
		cutoff, from, to,
	)
	if err != nil {
		return nil, fmt.Errorf("query edge rules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	type findingJSON struct {
		RuleID   string `json:"rule_id"`
		Name     string `json:"name"`
		Severity string `json:"severity"`
	}

	counts := make(map[string]*RuleStat)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		var findings []findingJSON
		if err := json.Unmarshal([]byte(raw), &findings); err != nil {
			continue
		}
		for _, f := range findings {
			if rs, ok := counts[f.RuleID]; ok {
				rs.Count++
			} else {
				counts[f.RuleID] = &RuleStat{RuleID: f.RuleID, Name: f.Name, Severity: f.Severity, Count: 1}
			}
		}
	}

	result := make([]RuleStat, 0, len(counts))
	for _, rs := range counts {
		result = append(result, *rs)
	}

	// Sort by count descending
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j].Count > result[i].Count {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result, rows.Err()
}

// QueryAgentTopRules returns the most frequently triggered rules for a specific agent (last 24h).
func (s *Store) QueryAgentTopRules(agent string, limit int) ([]RuleStat, error) {
	cutoff := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	rows, err := s.db.Query(
		`SELECT rules_triggered FROM audit_log WHERE timestamp >= ? AND (from_agent = ? OR to_agent = ?) AND rules_triggered IS NOT NULL AND rules_triggered != '' AND rules_triggered != '[]'`,
		cutoff, agent, agent,
	)
	if err != nil {
		return nil, fmt.Errorf("query agent top rules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	type findingJSON struct {
		RuleID   string `json:"rule_id"`
		Name     string `json:"name"`
		Severity string `json:"severity"`
	}

	counts := make(map[string]*RuleStat)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		var findings []findingJSON
		if err := json.Unmarshal([]byte(raw), &findings); err != nil {
			continue
		}
		for _, f := range findings {
			if rs, ok := counts[f.RuleID]; ok {
				rs.Count++
			} else {
				counts[f.RuleID] = &RuleStat{RuleID: f.RuleID, Name: f.Name, Severity: f.Severity, Count: 1}
			}
		}
	}

	var result []RuleStat
	for _, rs := range counts {
		result = append(result, *rs)
	}

	// Sort by count descending
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j].Count > result[i].Count {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result, rows.Err()
}

// QueryAvgLatency returns the average message latency in milliseconds for the last 24 hours.
func (s *Store) QueryAvgLatency() (int, error) {
	cutoff := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	var avgMs int
	err := s.db.QueryRow(
		`SELECT COALESCE(CAST(AVG(latency_ms) AS INTEGER), 0) FROM audit_log WHERE timestamp >= ?`,
		cutoff,
	).Scan(&avgMs)
	if err != nil {
		return 0, fmt.Errorf("query avg latency: %w", err)
	}
	return avgMs, nil
}

// PurgeOldEntries deletes audit log entries older than the given number of days.
// Returns the number of deleted rows.
func (s *Store) PurgeOldEntries(retentionDays int) (int, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	cutoff := time.Now().AddDate(0, 0, -retentionDays).UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`DELETE FROM audit_log WHERE timestamp < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("purging old entries: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// expiryLoop periodically expires old quarantine items and purges old audit entries.
func (s *Store) expiryLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if n, err := s.QuarantineExpireOld(); err != nil {
				s.logger.Error("quarantine expiry failed", "error", err)
			} else if n > 0 {
				s.logger.Info("quarantine items expired", "count", n)
			}
			if s.retentionDays > 0 {
				if n, err := s.PurgeOldEntries(s.retentionDays); err != nil {
					s.logger.Error("audit log purge failed", "error", err)
				} else if n > 0 {
					s.logger.Info("audit log entries purged", "count", n)
				}
			}
		}
	}
}
