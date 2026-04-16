package commands

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/oktsec/oktsec/internal/audit"
)

// Helpers — write N entries with the given timestamp so tests can draw a
// cutoff cleanly between them.
func seedEntries(t *testing.T, dbPath string, entries []audit.Entry) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := audit.NewStore(dbPath, logger)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		store.Log(e)
	}
	store.Flush()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAuditArchive_ExportsJSONLGz(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")

	old := audit.Entry{ID: "old-1", Timestamp: "2025-06-01T00:00:00Z", FromAgent: "a", ToAgent: "b", ContentHash: "h1", Status: "delivered", PolicyDecision: "clean"}
	newer := audit.Entry{ID: "new-1", Timestamp: "2026-06-01T00:00:00Z", FromAgent: "a", ToAgent: "b", ContentHash: "h2", Status: "delivered", PolicyDecision: "clean"}
	seedEntries(t, dbPath, []audit.Entry{old, newer})

	out := filepath.Join(dir, "archive.jsonl.gz")

	cmd := newAuditCmd()
	cmd.SetArgs([]string{"archive", "--db", dbPath, "--before", "2026-01-01", "--output", out})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("archive failed: %v", err)
	}

	// Verify: archive contains old-1 only, gzipped JSONL.
	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytesReader(data))
	var got []archivedEntry
	for dec.More() {
		var e archivedEntry
		if err := dec.Decode(&e); err != nil {
			t.Fatal(err)
		}
		got = append(got, e)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 archived row, got %d", len(got))
	}
	if got[0].ID != "old-1" {
		t.Fatalf("expected archived id=old-1, got %q", got[0].ID)
	}

	// Verify: archive did NOT touch the live DB (prune is a separate step).
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, _ := audit.NewStoreReadOnly(dbPath, logger)
	defer func() { _ = store.Close() }()
	var n int
	_ = store.DB().QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&n)
	if n != 2 {
		t.Fatalf("archive must be non-destructive, expected 2 rows in DB, got %d", n)
	}
}

func TestAuditPrune_RequiresYesFlag(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")
	seedEntries(t, dbPath, []audit.Entry{
		{ID: "a", Timestamp: "2025-01-01T00:00:00Z", FromAgent: "a", ToAgent: "b", ContentHash: "h", Status: "delivered", PolicyDecision: "clean"},
	})

	cmd := newAuditCmd()
	cmd.SetArgs([]string{"prune", "--db", dbPath, "--before", "2026-01-01"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("prune without --yes must error (destructive)")
	}
}

func TestAuditPrune_DeletesBeforeCutoff(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")
	seedEntries(t, dbPath, []audit.Entry{
		{ID: "old", Timestamp: "2025-06-01T00:00:00Z", FromAgent: "a", ToAgent: "b", ContentHash: "h", Status: "delivered", PolicyDecision: "clean"},
		{ID: "new", Timestamp: "2026-06-01T00:00:00Z", FromAgent: "a", ToAgent: "b", ContentHash: "h", Status: "delivered", PolicyDecision: "clean"},
	})

	cmd := newAuditCmd()
	cmd.SetArgs([]string{"prune", "--db", dbPath, "--before", "2026-01-01", "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("prune failed: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, _ := audit.NewStoreReadOnly(dbPath, logger)
	defer func() { _ = store.Close() }()
	var remaining int
	_ = store.DB().QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&remaining)
	if remaining != 1 {
		t.Fatalf("expected 1 row remaining, got %d", remaining)
	}

	var remainingID string
	_ = store.DB().QueryRow(`SELECT id FROM audit_log`).Scan(&remainingID)
	if remainingID != "new" {
		t.Fatalf("expected only 'new' to remain, got %q", remainingID)
	}
}

// tiny helper to avoid pulling in bytes just for one call
type byteReader struct {
	data []byte
	pos  int
}

func (b *byteReader) Read(p []byte) (int, error) {
	if b.pos >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.pos:])
	b.pos += n
	return n, nil
}
func bytesReader(data []byte) io.Reader { return &byteReader{data: data} }
