package audit

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestStoreWithRetention(t *testing.T, retentionDays int) *Store {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := NewStore(dbPath, logger, retentionDays)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// seedRows inserts a fixed set of audit_log rows whose timestamps span
// from N days ago up to now. Returns the cutoff index used so callers
// can assert how many rows fall on either side.
func seedRows(t *testing.T, s *Store, daysAgoSpread []int) {
	t.Helper()
	now := time.Now().UTC()
	for i, days := range daysAgoSpread {
		ts := now.AddDate(0, 0, -days).Format(time.RFC3339)
		s.Log(Entry{
			ID:             "e" + string(rune('a'+i)),
			Timestamp:      ts,
			FromAgent:      "a",
			ToAgent:        "b",
			ContentHash:    "h",
			Status:         "delivered",
			PolicyDecision: "allow",
		})
	}
	s.Flush()
}

func countRows(t *testing.T, s *Store) int {
	t.Helper()
	var n int
	if err := s.DB().QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestArchiveAndPurge_RefusesWithoutArchiveDir locks in the contract
// that the auto-purge path can never delete without writing an archive
// first. A configured retention with empty archive_dir must error and
// leave every row in place.
func TestArchiveAndPurge_RefusesWithoutArchiveDir(t *testing.T) {
	s := newTestStoreWithRetention(t, 7)
	seedRows(t, s, []int{30, 20, 10, 1})

	count, archive, err := s.ArchiveAndPurgeOldEntries(7, "")
	if err == nil {
		t.Fatal("expected error when archive_dir is empty")
	}
	if count != 0 || archive != "" {
		t.Errorf("expected (0, \"\"), got (%d, %q)", count, archive)
	}
	if got := countRows(t, s); got != 4 {
		t.Errorf("rows after refused purge = %d, want 4 (no rows should be deleted)", got)
	}
}

// TestArchiveAndPurge_WritesArchiveBeforeDeleting verifies that rows
// older than the cutoff land in a .jsonl.gz file before the DELETE
// runs, and that the archive contains exactly the deleted rows.
func TestArchiveAndPurge_WritesArchiveBeforeDeleting(t *testing.T) {
	s := newTestStoreWithRetention(t, 7)
	seedRows(t, s, []int{30, 20, 10, 1})

	dir := t.TempDir()
	count, archive, err := s.ArchiveAndPurgeOldEntries(7, dir)
	if err != nil {
		t.Fatalf("archive-and-purge: %v", err)
	}
	if count != 3 {
		t.Errorf("archived count = %d, want 3", count)
	}
	if archive == "" {
		t.Fatal("archive path should be set when count > 0")
	}
	// Live DB should retain only the row from 1 day ago.
	if got := countRows(t, s); got != 1 {
		t.Errorf("rows after purge = %d, want 1", got)
	}

	// Archive file must exist and round-trip the deleted rows.
	f, err := os.Open(archive)
	if err != nil {
		t.Fatalf("opening archive: %v", err)
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer func() { _ = gz.Close() }()
	dec := json.NewDecoder(gz)
	var archived []ArchivedEntry
	for {
		var rec ArchivedEntry
		if err := dec.Decode(&rec); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("decoding archive line: %v", err)
		}
		archived = append(archived, rec)
	}
	if len(archived) != 3 {
		t.Errorf("archive contained %d rows, want 3", len(archived))
	}
}

// TestArchiveAndPurge_NoEligibleRows leaves the live DB untouched and
// does not write a stub archive file, so an operator's archive
// directory does not fill with empty gz files on every tick.
func TestArchiveAndPurge_NoEligibleRows(t *testing.T) {
	s := newTestStoreWithRetention(t, 30)
	seedRows(t, s, []int{1, 2, 3})

	dir := t.TempDir()
	count, archive, err := s.ArchiveAndPurgeOldEntries(30, dir)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 || archive != "" {
		t.Errorf("expected (0, \"\"), got (%d, %q)", count, archive)
	}
	if got := countRows(t, s); got != 3 {
		t.Errorf("rows = %d, want 3 untouched", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("expected no archive files written, got %d", len(entries))
	}
}

// TestArchiveAndClearAll_RefusesWithoutArchiveDir locks in the contract
// that no product surface can wipe the audit log without an archive
// directory. The earlier behavior (handleAuditClear -> ClearAll with no
// archive) destroyed evidence on first click.
func TestArchiveAndClearAll_RefusesWithoutArchiveDir(t *testing.T) {
	s := newTestStoreWithRetention(t, 0)
	seedRows(t, s, []int{1, 2, 3})

	count, archive, err := s.ArchiveAndClearAll("")
	if err == nil {
		t.Fatal("expected error when archive_dir is empty")
	}
	if count != 0 || archive != "" {
		t.Errorf("expected (0, \"\"), got (%d, %q)", count, archive)
	}
	if got := countRows(t, s); got != 3 {
		t.Errorf("rows after refused clear = %d, want 3", got)
	}
}

// TestArchiveAndClearAll_WritesArchiveThenDeletes verifies the safe
// dashboard path: every row lands in a .jsonl.gz before the DELETE.
func TestArchiveAndClearAll_WritesArchiveThenDeletes(t *testing.T) {
	s := newTestStoreWithRetention(t, 0)
	seedRows(t, s, []int{1, 2, 3})

	dir := t.TempDir()
	count, archive, err := s.ArchiveAndClearAll(dir)
	if err != nil {
		t.Fatalf("archive-and-clear: %v", err)
	}
	if count != 3 {
		t.Errorf("archived = %d, want 3", count)
	}
	if archive == "" {
		t.Fatal("archive path should be set")
	}
	if got := countRows(t, s); got != 0 {
		t.Errorf("rows after clear = %d, want 0", got)
	}
	if _, err := os.Stat(archive); err != nil {
		t.Errorf("archive file missing: %v", err)
	}
}

// TestEvidenceStatus_KeepForeverPolicy spells out the user-visible
// retention policy string for the default install.
func TestEvidenceStatus_KeepForeverPolicy(t *testing.T) {
	s := newTestStoreWithRetention(t, 0)
	seedRows(t, s, []int{0, 0, 0})

	st, err := s.EvidenceStatus()
	if err != nil {
		t.Fatal(err)
	}
	if st.RetentionPolicy != "keep_forever" {
		t.Errorf("policy = %q, want keep_forever", st.RetentionPolicy)
	}
	if st.TotalRows != 3 {
		t.Errorf("rows = %d, want 3", st.TotalRows)
	}
}

// TestEvidenceStatus_ConfiguredWithoutArchive surfaces the trap state:
// an operator set retention but did not configure an archive dir, so
// the auto-purge will refuse. The dashboard reads this string verbatim
// to warn the user.
func TestEvidenceStatus_ConfiguredWithoutArchive(t *testing.T) {
	s := newTestStoreWithRetention(t, 7)
	st, err := s.EvidenceStatus()
	if err != nil {
		t.Fatal(err)
	}
	if st.RetentionPolicy != "configured_without_archive_will_not_purge" {
		t.Errorf("policy = %q, want configured_without_archive_will_not_purge", st.RetentionPolicy)
	}
}

// TestEvidenceStatus_ArchiveAwarePurgePolicy reports the safe
// archive-then-delete state, with the configured retention in days.
func TestEvidenceStatus_ArchiveAwarePurgePolicy(t *testing.T) {
	s := newTestStoreWithRetention(t, 14)
	s.SetArchiveDir(t.TempDir())
	st, err := s.EvidenceStatus()
	if err != nil {
		t.Fatal(err)
	}
	if st.RetentionPolicy != "purge_after_14_days_with_archive" {
		t.Errorf("policy = %q, want purge_after_14_days_with_archive", st.RetentionPolicy)
	}
}
