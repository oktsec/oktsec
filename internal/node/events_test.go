package node

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CollectRecentEvents reads strictly past the cursor, in order,
// bounded, redacted for export (no intent, no delegation, redacted
// rule findings), and a missing database is a clean no-op.
func TestCollectRecentEvents(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")
	if err := os.WriteFile(cfgPath, []byte("agents: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "audit.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE audit_log (
		id TEXT PRIMARY KEY,
		timestamp TEXT NOT NULL,
		from_agent TEXT NOT NULL,
		to_agent TEXT NOT NULL,
		content_hash TEXT NOT NULL,
		status TEXT NOT NULL,
		rules_triggered TEXT DEFAULT '',
		policy_decision TEXT NOT NULL,
		latency_ms INTEGER,
		signature_verified INTEGER
	)`); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	for i, status := range []string{"delivered", "blocked", "delivered"} {
		if _, err := db.Exec(`INSERT INTO audit_log
			(id, timestamp, from_agent, to_agent, content_hash, status, rules_triggered, policy_decision, latency_ms, signature_verified)
			VALUES (?, ?, 'agent-a', 'agent-b', 'h', ?, '[]', 'allow', 3, 1)`,
			"e"+string(rune('1'+i)), base.Add(time.Duration(i)*time.Minute).Format(time.RFC3339), status); err != nil {
			t.Fatal(err)
		}
	}
	_ = db.Close()

	entries, cursor, err := CollectRecentEvents(cfgPath, dbPath, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || entries[1].Status != "blocked" {
		t.Fatalf("entries: %+v", entries)
	}
	if cursor != base.Add(2*time.Minute).Format(time.RFC3339) {
		t.Fatalf("cursor: %s", cursor)
	}

	// Strictly newer than the cursor: nothing left.
	rest, next, err := CollectRecentEvents(cfgPath, dbPath, cursor, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 || next != cursor {
		t.Fatalf("rest: %d next: %s", len(rest), next)
	}

	// Bounded batch: limit 2 returns the first two and a mid cursor.
	two, mid, err := CollectRecentEvents(cfgPath, dbPath, "", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(two) != 2 || mid != base.Add(time.Minute).Format(time.RFC3339) {
		t.Fatalf("batch: %d mid: %s", len(two), mid)
	}

	// A missing database is a no-op, never an error.
	none, same, err := CollectRecentEvents(cfgPath, filepath.Join(dir, "absent.db"), "x", 10)
	if err != nil || len(none) != 0 || same != "x" {
		t.Fatalf("missing db: %v %d %s", err, len(none), same)
	}
}
