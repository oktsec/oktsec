package node

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oktsec/oktsec/internal/safefile"
	_ "modernc.org/sqlite"
)

// dbAvailability reports whether a SQLite DB file is reachable and
// safe to open read-only. Used by the snapshot builder to short-
// circuit inspection without ever running CREATE statements.
type dbAvailability struct {
	Path      string
	Available bool
	// Reason is set when Available is false; one of:
	//   "missing"      — file does not exist
	//   "unreachable"  — symlink, permission denied, etc.
	Reason string
}

// inspectSQLiteAvailability checks whether path can be opened. It
// never creates the file. A non-existent path is reported as
// missing, not as an error.
func inspectSQLiteAvailability(path string) dbAvailability {
	if path == "" {
		return dbAvailability{Available: false, Reason: "missing"}
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return dbAvailability{Path: path, Available: false, Reason: "missing"}
		}
		return dbAvailability{Path: path, Available: false, Reason: "unreachable"}
	}
	if err := safefile.RejectSymlink(path); err != nil {
		return dbAvailability{Path: path, Available: false, Reason: "unreachable"}
	}
	// Refuse a symlinked parent so directory swaps cannot redirect a
	// later inspection at a different DB.
	parent := filepath.Dir(path)
	if info, err := os.Lstat(parent); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return dbAvailability{Path: path, Available: false, Reason: "unreachable"}
		}
	}
	return dbAvailability{Path: path, Available: true}
}

// openSQLiteReadOnly opens an existing SQLite database without
// creating it and without running any migrations. The DSN forces
// SQLite's read-only mode (mode=ro) and PRAGMA query_only=ON guards
// the connection at the engine level. The caller is responsible for
// closing the returned *sql.DB.
//
// The DSN is built through net/url so a filesystem path containing
// '?', '#' or other URI-sensitive characters is properly escaped.
// Without escaping, "/tmp/path?weird.db" would have ?weird.db
// silently parsed as a query string and SQLite would open a
// different (and possibly creatable) file — that violates the
// "snapshot never creates DB files" contract.
func openSQLiteReadOnly(path string) (*sql.DB, error) {
	if path == "" {
		return nil, errors.New("node: empty db path")
	}
	dsn := buildSQLiteReadOnlyDSN(path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("node: opening sqlite ro: %w", err)
	}
	// Make sure the engine refuses any write we might accidentally
	// issue (defence in depth on top of mode=ro).
	if _, err := db.Exec("PRAGMA query_only=ON"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("node: sqlite query_only: %w", err)
	}
	// Cap connections so the inspector never holds more than one
	// file handle on the live DB.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(30 * time.Second)
	return db, nil
}

// buildSQLiteReadOnlyDSN constructs a `file:` URI that opens path
// in mode=ro with a short busy_timeout. The path is encoded so
// reserved URI characters do not collapse into the query string.
//
// Absolute POSIX paths produce "file:/abs/path?mode=ro&..."; relative
// paths produce "file:./relative/path?mode=ro&..." so they cannot be
// confused with a host segment. Windows paths get a leading slash so
// "C:\\Users\\foo.db" -> "file:/C:/Users/foo.db".
func buildSQLiteReadOnlyDSN(path string) string {
	// Convert to a slash-separated path for URI use; backslashes
	// are not legal URI path characters in modernc.org/sqlite's
	// parser on either platform.
	slashed := filepath.ToSlash(path)
	if !strings.HasPrefix(slashed, "/") {
		// Either a Windows drive ("C:/...") or a relative path.
		// Prefix "/" so the result is "file:/C:/..." or
		// "file:/relative/...", which the URI parser treats as
		// a path-rooted reference rather than a host.
		slashed = "/" + slashed
	}
	u := &url.URL{
		Scheme: "file",
		Path:   slashed,
	}
	q := u.Query()
	q.Set("mode", "ro")
	q.Add("_pragma", "busy_timeout(2000)")
	u.RawQuery = q.Encode()
	return u.String()
}

// sqliteTableExists reports whether the named table is present.
// Read-only safe.
func sqliteTableExists(ctx context.Context, db *sql.DB, name string) (bool, error) {
	var found string
	err := db.QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type='table' AND name = ? LIMIT 1`, name,
	).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return found == name, nil
}

// auditDBInspection holds the read-only audit aggregates the snapshot
// needs. Counts are bounded by range; chain verification reads up to
// chainLimit rows.
type auditDBInspection struct {
	Available           bool
	Entries             int
	Allowed             int
	Flagged             int
	Quarantined         int
	Blocked             int
	Rejected            int
	OldestAt            string
	NewestAt            string
	ChainAvailable      bool
	ChainHead           string
	ChainVerified       bool
	ChainScope          string
	ChainEntriesChecked int
}

// inspectAuditSQLite computes the audit aggregates inside [since,until].
// `until` zero means "now". Always read-only; never alters rows.
func inspectAuditSQLite(ctx context.Context, db *sql.DB, since, until time.Time, chainLimit int) (auditDBInspection, error) {
	out := auditDBInspection{}
	exists, err := sqliteTableExists(ctx, db, "audit_log")
	if err != nil {
		return out, fmt.Errorf("audit table check: %w", err)
	}
	if !exists {
		return out, nil
	}
	out.Available = true

	sinceStr := since.UTC().Format(time.RFC3339)
	untilStr := ""
	if !until.IsZero() {
		untilStr = until.UTC().Format(time.RFC3339)
	}

	whereRange, args := buildRangeClause("timestamp", sinceStr, untilStr)

	// Total entries in range.
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM audit_log "+whereRange, args...,
	).Scan(&out.Entries); err != nil {
		return out, fmt.Errorf("audit count: %w", err)
	}

	// Decisions are reported by policy_decision first, because
	// status alone undercounts important signals: a content_flagged
	// row writes status="delivered" and policy_decision="content_flagged",
	// which would otherwise be hidden inside "allowed". Group by
	// the (status, policy_decision) pair so legacy rows that only
	// populated status still classify correctly.
	rows, err := db.QueryContext(ctx,
		`SELECT COALESCE(status,''), COALESCE(policy_decision,''), COUNT(*) FROM audit_log `+whereRange+
			` GROUP BY status, policy_decision`, args...,
	)
	if err != nil {
		return out, fmt.Errorf("audit group: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var status, decision string
		var count int
		if err := rows.Scan(&status, &decision, &count); err != nil {
			return out, fmt.Errorf("audit scan: %w", err)
		}
		switch classifyDecision(status, decision) {
		case "allowed":
			out.Allowed += count
		case "flagged":
			out.Flagged += count
		case "quarantined":
			out.Quarantined += count
		case "blocked":
			out.Blocked += count
		case "rejected":
			out.Rejected += count
		}
	}
	if err := rows.Err(); err != nil {
		return out, fmt.Errorf("audit rows err: %w", err)
	}

	// Oldest/newest in the same range.
	if out.Entries > 0 {
		if err := db.QueryRowContext(ctx,
			"SELECT MIN(timestamp), MAX(timestamp) FROM audit_log "+whereRange, args...,
		).Scan(&out.OldestAt, &out.NewestAt); err != nil {
			return out, fmt.Errorf("audit range: %w", err)
		}
	}
	return out, nil
}

// runtimeDBInspection holds runtime_* table aggregates.
type runtimeDBInspection struct {
	Available          bool
	Sessions           int
	Events             int
	ToolEvents         int
	BlockEvents        int
	LastRealEventAt    string
	LastHeartbeatAt    string
	HasFreshRealEvent  bool
	HasRecentHeartbeat bool
}

// inspectRuntimeSQLite reads the runtime_* tables in read-only mode.
// "Fresh" thresholds match the dashboard surface card semantics:
// real event within 1 hour, heartbeat within 5 minutes.
func inspectRuntimeSQLite(ctx context.Context, db *sql.DB, since, until time.Time) (runtimeDBInspection, error) {
	out := runtimeDBInspection{}
	hasSessions, err := sqliteTableExists(ctx, db, "runtime_sessions")
	if err != nil {
		return out, err
	}
	hasEvents, err := sqliteTableExists(ctx, db, "runtime_hook_events")
	if err != nil {
		return out, err
	}
	if !hasSessions && !hasEvents {
		return out, nil
	}
	out.Available = true

	sinceStr := since.UTC().Format(time.RFC3339)
	untilStr := ""
	if !until.IsZero() {
		untilStr = until.UTC().Format(time.RFC3339)
	}

	if hasSessions {
		whereRange, args := buildRangeClause("last_seen_at", sinceStr, untilStr)
		if err := db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM runtime_sessions "+whereRange, args...,
		).Scan(&out.Sessions); err != nil {
			return out, fmt.Errorf("runtime sessions: %w", err)
		}
	}

	if hasEvents {
		whereRange, args := buildRangeClause("timestamp", sinceStr, untilStr)
		if err := db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM runtime_hook_events "+whereRange, args...,
		).Scan(&out.Events); err != nil {
			return out, fmt.Errorf("runtime events: %w", err)
		}
		// Tool events. Use tool_name != '' as a proxy for tool-call lifecycle.
		toolWhere := whereRange
		toolArgs := append([]any(nil), args...)
		if toolWhere == "" {
			toolWhere = "WHERE tool_name <> ''"
		} else {
			toolWhere += " AND tool_name <> ''"
		}
		if err := db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM runtime_hook_events "+toolWhere, toolArgs...,
		).Scan(&out.ToolEvents); err != nil {
			return out, fmt.Errorf("runtime tool events: %w", err)
		}
		blockWhere := whereRange
		blockArgs := append([]any(nil), args...)
		if blockWhere == "" {
			blockWhere = "WHERE policy_decision IN ('block','quarantine')"
		} else {
			blockWhere += " AND policy_decision IN ('block','quarantine')"
		}
		if err := db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM runtime_hook_events "+blockWhere, blockArgs...,
		).Scan(&out.BlockEvents); err != nil {
			return out, fmt.Errorf("runtime block events: %w", err)
		}

		// Freshness signals — bounded by the snapshot window so the
		// snapshot does not paint a stale install as healthy.
		var lastRealStr sql.NullString
		realWhere := whereRange
		realArgs := append([]any(nil), args...)
		if realWhere == "" {
			realWhere = "WHERE session_id NOT LIKE 'heartbeat-%'"
		} else {
			realWhere += " AND session_id NOT LIKE 'heartbeat-%'"
		}
		if err := db.QueryRowContext(ctx,
			"SELECT MAX(timestamp) FROM runtime_hook_events "+realWhere, realArgs...,
		).Scan(&lastRealStr); err != nil {
			return out, fmt.Errorf("runtime last real: %w", err)
		}
		if lastRealStr.Valid {
			out.LastRealEventAt = lastRealStr.String
		}
		var lastHBStr sql.NullString
		if err := db.QueryRowContext(ctx,
			"SELECT MAX(last_heartbeat_at) FROM runtime_sessions",
		).Scan(&lastHBStr); err == nil && lastHBStr.Valid {
			out.LastHeartbeatAt = lastHBStr.String
		}

		now := time.Now().UTC()
		if t, err := time.Parse(time.RFC3339, out.LastRealEventAt); err == nil {
			out.HasFreshRealEvent = now.Sub(t) <= time.Hour
		}
		if t, err := time.Parse(time.RFC3339, out.LastHeartbeatAt); err == nil {
			out.HasRecentHeartbeat = now.Sub(t) <= 5*time.Minute
		}
	}
	return out, nil
}

// activityDBInspection holds activity_events aggregates.
type activityDBInspection struct {
	Available bool
	Events    int
}

func inspectActivitySQLite(ctx context.Context, db *sql.DB, since, until time.Time) (activityDBInspection, error) {
	out := activityDBInspection{}
	exists, err := sqliteTableExists(ctx, db, "activity_events")
	if err != nil {
		return out, err
	}
	if !exists {
		return out, nil
	}
	out.Available = true
	sinceStr := since.UTC().Format(time.RFC3339)
	untilStr := ""
	if !until.IsZero() {
		untilStr = until.UTC().Format(time.RFC3339)
	}
	whereRange, args := buildRangeClause("timestamp", sinceStr, untilStr)
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM activity_events "+whereRange, args...,
	).Scan(&out.Events); err != nil {
		return out, fmt.Errorf("activity count: %w", err)
	}
	return out, nil
}

// distinctActivePrincipalsSQLite counts active principal_ids observed
// in any of the three tables inside the window. Best-effort: missing
// tables are skipped silently because availability is already reported
// in the snapshot.
func distinctActivePrincipalsSQLite(ctx context.Context, db *sql.DB, since, until time.Time) (int, error) {
	sinceStr := since.UTC().Format(time.RFC3339)
	untilStr := ""
	if !until.IsZero() {
		untilStr = until.UTC().Format(time.RFC3339)
	}
	set := map[string]struct{}{}
	for _, q := range []struct{ table, col string }{
		{"runtime_sessions", "last_seen_at"},
		{"runtime_hook_events", "timestamp"},
		{"activity_events", "timestamp"},
	} {
		exists, err := sqliteTableExists(ctx, db, q.table)
		if err != nil {
			return 0, err
		}
		if !exists {
			continue
		}
		whereRange, args := buildRangeClause(q.col, sinceStr, untilStr)
		query := "SELECT DISTINCT principal_id FROM " + q.table + " " + whereRange
		// Cap the scan so a giant table cannot stall the snapshot.
		query += " LIMIT 10000"
		rows, err := db.QueryContext(ctx, query, args...)
		if err != nil {
			return 0, fmt.Errorf("distinct principals from %s: %w", q.table, err)
		}
		for rows.Next() {
			var p string
			if err := rows.Scan(&p); err != nil {
				_ = rows.Close()
				return 0, err
			}
			if p != "" {
				set[p] = struct{}{}
			}
		}
		if err := rows.Close(); err != nil {
			return 0, err
		}
	}
	return len(set), nil
}

// classifyDecision maps an audit row's (status, policy_decision) pair
// to the bucket the snapshot reports. policy_decision is consulted
// first so a "delivered + content_flagged" row counts as flagged
// instead of being silently rolled into allowed. Status alone is the
// fallback for legacy rows from versions that did not populate
// policy_decision.
func classifyDecision(status, decision string) string {
	d := strings.ToLower(strings.TrimSpace(decision))
	switch d {
	case "content_flagged":
		return "flagged"
	case "content_blocked", "rate_limited", "tool_not_allowed",
		"constraint_violated", "concurrency_exceeded",
		"delegation_invalid", "delegation_scope_violation",
		"delegation_depth_exceeded":
		return "blocked"
	case "content_quarantined":
		return "quarantined"
	case "acl_denied", "agent_suspended", "recipient_suspended",
		"identity_rejected", "signature_required",
		"delegation_required", "scan_error":
		return "rejected"
	case "allow":
		return "allowed"
	}
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "delivered", "allowed", "clean":
		return "allowed"
	case "flagged", "flag":
		return "flagged"
	case "quarantined":
		return "quarantined"
	case "blocked":
		return "blocked"
	case "rejected":
		return "rejected"
	}
	return ""
}

// buildRangeClause builds a "WHERE col >= ? AND col <= ?" fragment.
// Empty until omits the upper bound. Returns "" with empty args when
// both bounds are empty.
func buildRangeClause(col, since, until string) (string, []any) {
	switch {
	case since == "" && until == "":
		return "", nil
	case since != "" && until == "":
		return "WHERE " + col + " >= ?", []any{since}
	case since == "" && until != "":
		return "WHERE " + col + " <= ?", []any{until}
	default:
		return "WHERE " + col + " >= ? AND " + col + " <= ?", []any{since, until}
	}
}
