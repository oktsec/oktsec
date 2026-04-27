package audit

import (
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ArchivedEntry is the on-disk shape of one archived audit_log row.
// The JSON schema is intentionally stable so external tooling can read
// archives without depending on the internal evolution of audit.Entry.
type ArchivedEntry struct {
	ID                string `json:"id"`
	Timestamp         string `json:"timestamp"`
	FromAgent         string `json:"from_agent"`
	ToAgent           string `json:"to_agent"`
	ToolName          string `json:"tool_name,omitempty"`
	ContentHash       string `json:"content_hash"`
	SignatureVerified int    `json:"signature_verified"`
	PubkeyFingerprint string `json:"pubkey_fingerprint,omitempty"`
	Status            string `json:"status"`
	RulesTriggered    string `json:"rules_triggered,omitempty"`
	PolicyDecision    string `json:"policy_decision"`
	LatencyMs         int64  `json:"latency_ms"`
	Intent            string `json:"intent,omitempty"`
	SessionID         string `json:"session_id,omitempty"`
	PrevHash          string `json:"prev_hash,omitempty"`
	EntryHash         string `json:"entry_hash,omitempty"`
	ProxySignature    string `json:"proxy_signature,omitempty"`
}

// archiveSelectSQL is the column-stable SELECT used by every archive
// writer in this package. Callers append a WHERE clause and ORDER BY.
const archiveSelectSQL = `SELECT id, timestamp, from_agent, to_agent, COALESCE(tool_name,''),
content_hash, signature_verified, pubkey_fingerprint, status,
COALESCE(rules_triggered,''), policy_decision, latency_ms,
COALESCE(intent,''), COALESCE(session_id,''),
COALESCE(prev_hash,''), COALESCE(entry_hash,''), COALESCE(proxy_signature,'')
FROM audit_log`

// writeArchive streams rows that satisfy whereSQL+args to a fresh
// gzipped JSONL file at outPath, returning the row count written. Uses
// O_EXCL so an existing file is never overwritten; the caller picks a
// timestamped name.
func writeArchive(db *sql.DB, outPath, whereSQL string, args ...any) (count int, err error) {
	q := archiveSelectSQL
	if whereSQL != "" {
		q += " WHERE " + whereSQL
	}
	q += " ORDER BY rowid ASC"

	rows, qErr := db.Query(q, args...)
	if qErr != nil {
		return 0, fmt.Errorf("query rows for archive: %w", qErr)
	}
	defer func() { _ = rows.Close() }()

	if err := os.MkdirAll(filepath.Dir(outPath), 0o700); err != nil {
		return 0, fmt.Errorf("creating archive dir: %w", err)
	}
	f, fErr := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if fErr != nil {
		return 0, fmt.Errorf("creating archive file: %w", fErr)
	}
	gz := gzip.NewWriter(f)
	enc := json.NewEncoder(gz)

	for rows.Next() {
		var rec ArchivedEntry
		if scanErr := rows.Scan(&rec.ID, &rec.Timestamp, &rec.FromAgent, &rec.ToAgent, &rec.ToolName,
			&rec.ContentHash, &rec.SignatureVerified, &rec.PubkeyFingerprint, &rec.Status,
			&rec.RulesTriggered, &rec.PolicyDecision, &rec.LatencyMs,
			&rec.Intent, &rec.SessionID,
			&rec.PrevHash, &rec.EntryHash, &rec.ProxySignature); scanErr != nil {
			_ = gz.Close()
			_ = f.Close()
			_ = os.Remove(outPath)
			return 0, fmt.Errorf("scanning row for archive: %w", scanErr)
		}
		if encErr := enc.Encode(&rec); encErr != nil {
			_ = gz.Close()
			_ = f.Close()
			_ = os.Remove(outPath)
			return 0, fmt.Errorf("encoding row to archive: %w", encErr)
		}
		count++
	}
	if rErr := rows.Err(); rErr != nil {
		_ = gz.Close()
		_ = f.Close()
		_ = os.Remove(outPath)
		return 0, fmt.Errorf("iterating rows for archive: %w", rErr)
	}
	if gzErr := gz.Close(); gzErr != nil {
		_ = f.Close()
		_ = os.Remove(outPath)
		return 0, fmt.Errorf("flushing gzip: %w", gzErr)
	}
	if cErr := f.Close(); cErr != nil {
		_ = os.Remove(outPath)
		return 0, fmt.Errorf("closing archive: %w", cErr)
	}
	return count, nil
}

// SetArchiveDir records the directory the store will write archives to
// before any auto-purge. When empty, the auto-purge loop refuses to
// delete even if RetentionDays is positive — the evidence-freeze
// contract is "never delete without an archive".
func (s *Store) SetArchiveDir(dir string) {
	s.archiveDir = dir
}

// ArchiveDir returns the configured archive directory, or "" when none.
func (s *Store) ArchiveDir() string {
	return s.archiveDir
}

// ArchiveAndPurgeOldEntries archives audit_log rows older than
// retentionDays to a gzipped JSONL file inside archiveDir, then deletes
// them. Refuses to run when retentionDays <= 0 or archiveDir is empty,
// so callers can never short-circuit the archive step. Returns the
// rows archived and the absolute archive path (empty when nothing was
// eligible for deletion).
func (s *Store) ArchiveAndPurgeOldEntries(retentionDays int, archiveDir string) (int, string, error) {
	if retentionDays <= 0 {
		return 0, "", nil
	}
	if archiveDir == "" {
		return 0, "", fmt.Errorf("archive_dir is required to purge audit entries; refusing to delete without an archive")
	}
	cutoff := time.Now().AddDate(0, 0, -retentionDays).UTC().Format(time.RFC3339)
	return s.archiveAndDelete(archiveDir, "audit-purge", "timestamp < ?", []any{cutoff})
}

// ArchiveAndClearAll archives every audit_log row to archiveDir, then
// deletes them. This is the only safe path to clear the audit log from
// product surfaces; ClearAll() must not be invoked from dashboard or
// API handlers.
func (s *Store) ArchiveAndClearAll(archiveDir string) (int, string, error) {
	if archiveDir == "" {
		return 0, "", fmt.Errorf("archive_dir is required to clear audit log; refusing to delete without an archive")
	}
	return s.archiveAndDelete(archiveDir, "audit-clear", "", nil)
}

// archiveAndDelete is the single chokepoint for archive-then-delete. It
// writes the gzipped JSONL archive first; only when the archive is
// closed cleanly does it issue the DELETE. If DELETE fails, the archive
// is preserved as evidence the attempt happened.
func (s *Store) archiveAndDelete(archiveDir, kind, whereSQL string, args []any) (int, string, error) {
	if s.readOnly {
		return 0, "", fmt.Errorf("audit store is read-only")
	}
	if err := os.MkdirAll(archiveDir, 0o700); err != nil {
		return 0, "", fmt.Errorf("creating archive dir: %w", err)
	}
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	out := filepath.Join(archiveDir, fmt.Sprintf("%s-%s.jsonl.gz", kind, timestamp))

	count, err := writeArchive(s.db, out, whereSQL, args...)
	if err != nil {
		return 0, "", err
	}
	if count == 0 {
		// Empty archive is meaningless; remove the file to avoid clutter.
		_ = os.Remove(out)
		return 0, "", nil
	}

	deleteSQL := "DELETE FROM audit_log"
	if whereSQL != "" {
		deleteSQL += " WHERE " + whereSQL
	}
	res, err := s.db.Exec(deleteSQL, args...)
	if err != nil {
		return count, out, fmt.Errorf("delete after archive: %w", err)
	}
	deleted, _ := res.RowsAffected()
	if int(deleted) != count {
		// Rows added between archive write and delete is a benign race;
		// surface the mismatch so it shows up in logs but do not fail.
		s.logger.Warn("archive/delete row count mismatch",
			"archived", count, "deleted", deleted, "archive", out)
	}
	return count, out, nil
}

// EvidenceStatus snapshots the audit store's state for visibility
// surfaces (dashboard, doctor command). It does not include the DB
// path because Store does not own that string; the caller wraps the
// snapshot with whatever path it loaded the store from.
type EvidenceStatus struct {
	TotalRows        int    `json:"total_rows"`
	OldestTimestamp  string `json:"oldest_timestamp,omitempty"`
	NewestTimestamp  string `json:"newest_timestamp,omitempty"`
	RetentionDays    int    `json:"retention_days"`
	RetentionPolicy  string `json:"retention_policy"`
	ArchiveDirectory string `json:"archive_directory,omitempty"`
}

// EvidenceStatus returns a snapshot of the audit log size and retention
// policy. Reading the policy string is enough to know whether a future
// auto-purge could delete evidence:
//
//	keep_forever                                  -- safe; no purge
//	configured_without_archive_will_not_purge     -- retention set but no archive_dir; refuses to delete
//	purge_after_<N>_days_with_archive             -- archive-then-delete enabled
func (s *Store) EvidenceStatus() (EvidenceStatus, error) {
	st := EvidenceStatus{
		RetentionDays:    s.retentionDays,
		ArchiveDirectory: s.archiveDir,
	}
	switch {
	case s.retentionDays <= 0:
		st.RetentionPolicy = "keep_forever"
	case s.archiveDir == "":
		st.RetentionPolicy = "configured_without_archive_will_not_purge"
	default:
		st.RetentionPolicy = fmt.Sprintf("purge_after_%d_days_with_archive", s.retentionDays)
	}

	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&total); err != nil {
		return st, fmt.Errorf("counting audit_log rows: %w", err)
	}
	st.TotalRows = total
	if total == 0 {
		return st, nil
	}
	var oldest, newest sql.NullString
	if err := s.db.QueryRow(`SELECT MIN(timestamp), MAX(timestamp) FROM audit_log`).Scan(&oldest, &newest); err != nil {
		return st, fmt.Errorf("range timestamps: %w", err)
	}
	st.OldestTimestamp = oldest.String
	st.NewestTimestamp = newest.String
	return st, nil
}
