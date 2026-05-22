package node

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestInspectAvailabilityMissing(t *testing.T) {
	av := inspectSQLiteAvailability(filepath.Join(t.TempDir(), "missing.db"))
	if av.Available {
		t.Fatal("non-existent file must report missing")
	}
	if av.Reason != "missing" {
		t.Fatalf("expected missing, got %q", av.Reason)
	}
}

func TestInspectAvailabilityEmptyPath(t *testing.T) {
	av := inspectSQLiteAvailability("")
	if av.Available || av.Reason != "missing" {
		t.Fatalf("empty path should be missing, got %+v", av)
	}
}

func TestSqliteTableExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oktsec.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec("CREATE TABLE present (a INT)"); err != nil {
		t.Fatalf("create: %v", err)
	}
	_ = db.Close()
	ro, err := openSQLiteReadOnly(path)
	if err != nil {
		t.Fatalf("ro open: %v", err)
	}
	defer func() { _ = ro.Close() }()
	got, err := sqliteTableExists(context.Background(), ro, "present")
	if err != nil || !got {
		t.Fatalf("expected present table, got %v %v", got, err)
	}
	got, err = sqliteTableExists(context.Background(), ro, "absent")
	if err != nil || got {
		t.Fatalf("expected absent missing, got %v %v", got, err)
	}
}

func TestOpenSQLiteReadOnlyRefusesWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oktsec.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec("CREATE TABLE t (a INT)"); err != nil {
		t.Fatalf("create: %v", err)
	}
	_ = db.Close()
	ro, err := openSQLiteReadOnly(path)
	if err != nil {
		t.Fatalf("ro open: %v", err)
	}
	defer func() { _ = ro.Close() }()
	if _, err := ro.Exec("INSERT INTO t VALUES (1)"); err == nil {
		t.Fatal("read-only DB must refuse INSERT")
	}
}

func TestInspectAuditOnMissingTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oktsec.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec("CREATE TABLE marker (x INT)"); err != nil {
		t.Fatalf("create: %v", err)
	}
	_ = db.Close()
	ro, err := openSQLiteReadOnly(path)
	if err != nil {
		t.Fatalf("ro open: %v", err)
	}
	defer func() { _ = ro.Close() }()
	got, err := inspectAuditSQLite(context.Background(), ro, time.Time{}, time.Time{}, 100)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if got.Available {
		t.Fatalf("expected audit table missing")
	}
}

func TestInspectActivityAndRuntimeOnMissingTables(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oktsec.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec("CREATE TABLE marker (x INT)"); err != nil {
		t.Fatalf("create: %v", err)
	}
	_ = db.Close()
	ro, err := openSQLiteReadOnly(path)
	if err != nil {
		t.Fatalf("ro open: %v", err)
	}
	defer func() { _ = ro.Close() }()
	act, err := inspectActivitySQLite(context.Background(), ro, time.Time{}, time.Time{})
	if err != nil || act.Available {
		t.Fatalf("expected activity missing: %v %+v", err, act)
	}
	rt, err := inspectRuntimeSQLite(context.Background(), ro, time.Time{}, time.Time{})
	if err != nil || rt.Available {
		t.Fatalf("expected runtime missing: %v %+v", err, rt)
	}
}

func TestClassifyDecision(t *testing.T) {
	cases := []struct {
		status, decision, want string
	}{
		{"delivered", "allow", "allowed"},
		{"delivered", "content_flagged", "flagged"},
		{"blocked", "content_blocked", "blocked"},
		{"blocked", "rate_limited", "blocked"},
		{"quarantined", "content_quarantined", "quarantined"},
		{"rejected", "identity_rejected", "rejected"},
		{"delivered", "", "allowed"},     // legacy: status only
		{"flagged", "", "flagged"},        // legacy: status only
		{"", "", ""},                       // unknown
	}
	for _, c := range cases {
		if got := classifyDecision(c.status, c.decision); got != c.want {
			t.Errorf("classifyDecision(%q,%q) = %q, want %q", c.status, c.decision, got, c.want)
		}
	}
}

func TestInspectAuditFlaggedNotCountedAsAllowed(t *testing.T) {
	// Regression: a delivered + content_flagged row must surface as
	// flagged in the snapshot. Grouping by status alone would hide
	// it under allowed.
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE audit_log (
		id TEXT PRIMARY KEY,
		timestamp TEXT NOT NULL,
		from_agent TEXT NOT NULL,
		to_agent TEXT NOT NULL,
		content_hash TEXT NOT NULL,
		status TEXT NOT NULL,
		policy_decision TEXT NOT NULL,
		latency_ms INTEGER,
		signature_verified INTEGER,
		prev_hash TEXT DEFAULT '',
		entry_hash TEXT DEFAULT ''
	)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	base := time.Date(2026, 5, 21, 10, 0, 0, 0, time.UTC)
	rows := []struct{ status, decision string }{
		{"delivered", "allow"},
		{"delivered", "content_flagged"},
		{"delivered", "content_flagged"},
		{"blocked", "content_blocked"},
	}
	for i, r := range rows {
		if _, err := db.Exec(`INSERT INTO audit_log (id, timestamp, from_agent, to_agent, content_hash, status, policy_decision, latency_ms, signature_verified)
			VALUES (?, ?, 'a', 'b', 'h', ?, ?, 1, 1)`,
			"row-"+r.status+"-"+r.decision+"-"+time.Duration(i).String(),
			base.Add(time.Duration(i)*time.Minute).Format(time.RFC3339),
			r.status, r.decision,
		); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	_ = db.Close()
	ro, err := openSQLiteReadOnly(path)
	if err != nil {
		t.Fatalf("ro open: %v", err)
	}
	defer func() { _ = ro.Close() }()
	got, err := inspectAuditSQLite(context.Background(), ro, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Time{}, 100)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if got.Flagged != 2 {
		t.Errorf("expected 2 flagged decisions, got %d", got.Flagged)
	}
	if got.Allowed != 1 {
		t.Errorf("expected 1 allowed decision, got %d", got.Allowed)
	}
	if got.Blocked != 1 {
		t.Errorf("expected 1 blocked decision, got %d", got.Blocked)
	}
}

func TestBuildRangeClause(t *testing.T) {
	cases := []struct {
		since, until string
		want         string
		argsLen      int
	}{
		{"", "", "", 0},
		{"2026-01-01T00:00:00Z", "", "WHERE timestamp >= ?", 1},
		{"", "2026-01-01T00:00:00Z", "WHERE timestamp <= ?", 1},
		{"2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z", "WHERE timestamp >= ? AND timestamp <= ?", 2},
	}
	for _, c := range cases {
		gotWhere, gotArgs := buildRangeClause("timestamp", c.since, c.until)
		if gotWhere != c.want {
			t.Errorf("buildRangeClause(%q,%q) where = %q, want %q", c.since, c.until, gotWhere, c.want)
		}
		if len(gotArgs) != c.argsLen {
			t.Errorf("buildRangeClause(%q,%q) args len = %d, want %d", c.since, c.until, len(gotArgs), c.argsLen)
		}
	}
}

func TestBuildSQLiteReadOnlyDSN_EscapesPath(t *testing.T) {
	dsn := buildSQLiteReadOnlyDSN("/tmp/has?weird#chars.db")
	if strings.Count(dsn, "?") != 1 {
		t.Fatalf("DSN should have exactly one '?' (query separator), got %q", dsn)
	}
	if !strings.Contains(dsn, "mode=ro") {
		t.Fatalf("DSN missing mode=ro: %q", dsn)
	}
	if !strings.Contains(dsn, "busy_timeout") {
		t.Fatalf("DSN missing busy_timeout pragma: %q", dsn)
	}
	// Original path with the literal '?' must not survive raw.
	if strings.Contains(dsn, "has?weird") {
		t.Fatalf("DSN must escape literal '?' inside the path, got %q", dsn)
	}
}

func TestOpenSQLiteReadOnly_PathWithQuestionMark(t *testing.T) {
	// Regression: a filesystem path containing '?' (legal on POSIX)
	// must be opened by SQLite as-is. Without URI escaping the part
	// after '?' would be parsed as DSN parameters and SQLite could
	// silently open or create a different file.
	if runtime.GOOS == "windows" {
		t.Skip("'?' is not a legal filename character on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "has?weird.db")
	// Seed via a properly escaped URI so the DB really lands at the
	// path-with-? on disk. Plain sql.Open("sqlite", path) would hit
	// the same DSN-parsing bug this test exists to lock down.
	seedDSN := buildSQLiteReadOnlyDSN(path)
	seedDSN = strings.Replace(seedDSN, "mode=ro", "mode=rwc", 1)
	db, err := sql.Open("sqlite", seedDSN)
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	if _, err := db.Exec("CREATE TABLE marker(x INT)"); err != nil {
		t.Fatalf("create marker: %v", err)
	}
	_ = db.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected file at %s, got %v", path, err)
	}
	ro, err := openSQLiteReadOnly(path)
	if err != nil {
		t.Fatalf("ro open: %v", err)
	}
	defer func() { _ = ro.Close() }()
	exists, err := sqliteTableExists(context.Background(), ro, "marker")
	if err != nil {
		t.Fatalf("table check: %v", err)
	}
	if !exists {
		t.Fatalf("read-only inspector opened the wrong file: marker table not found")
	}
	// And — critically — no decoy "has" file landed beside the
	// real DB. If the inspector had treated "?weird.db" as a query
	// string we would see one.
	if _, err := os.Stat(filepath.Join(dir, "has")); err == nil {
		t.Fatalf("DSN unescaping created a decoy file at %s/has", dir)
	}
}

func TestInspectAvailabilityRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	dir := t.TempDir()
	real := filepath.Join(dir, "real.db")
	link := filepath.Join(dir, "linked.db")
	db, err := sql.Open("sqlite", real)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec("CREATE TABLE t (x INT)"); err != nil {
		t.Fatalf("create: %v", err)
	}
	_ = db.Close()
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	av := inspectSQLiteAvailability(link)
	if av.Available {
		t.Fatal("symlinked DB path must be refused")
	}
}
