package commands

import (
	"database/sql"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

// openRawSQLite opens the audit DB directly via the sqlite driver, bypassing
// the audit package so we can stage tampers without any auto-repair running.
func openRawSQLite(path string) (*sql.DB, error) {
	return sql.Open("sqlite", path)
}

// TestVerifyChain_TamperDetectedInReadOnlyMode is the adversarial regression
// test for the verify-chain CLI. Before the read-only fix, opening a DB with
// a tampered policy_decision silently triggered rebuildChainHashes(), which
// re-signed the fraudulent row and reported the chain as valid. That defeats
// the whole point of hash-chain evidence, so this test:
//
//  1. Writes 4 entries to a fresh SQLite audit DB.
//  2. Mutates policy_decision on a middle row via raw SQL.
//  3. Re-opens the DB with NewStoreReadOnly (the CLI's path).
//  4. Expects VerifyChain to flag the tampered row — NOT to silently fix it.
//
// If someone ever removes the readOnly guard from repairChainIfBroken /
// rebuildChainHashes, this test fails.
func TestVerifyChain_TamperDetectedInReadOnlyMode(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "tamper.db")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Step 1: write 4 entries.
	store, err := audit.NewStore(dbPath, logger)
	require.NoError(t, err)
	for i := 0; i < 4; i++ {
		store.Log(audit.Entry{
			ID:             idForIndex(i),
			Timestamp:      "2026-04-16T00:00:00Z",
			FromAgent:      "alice",
			ToAgent:        "bob",
			ContentHash:    "hash-" + idForIndex(i),
			Status:         "delivered",
			PolicyDecision: "clean",
		})
	}
	store.Flush()
	require.NoError(t, store.Close())

	// Step 2: tamper. Raw SQL, no audit code in the path, so the mutation
	// cannot be rewritten by any helper in the package.
	tamperDB, err := openRawSQLite(dbPath)
	require.NoError(t, err)
	_, err = tamperDB.Exec(`UPDATE audit_log SET policy_decision = 'tampered' WHERE id = ?`, idForIndex(2))
	require.NoError(t, err)
	require.NoError(t, tamperDB.Close())

	// Step 3: open read-only through the path the CLI uses.
	ro, err := audit.NewStoreReadOnly(dbPath, logger)
	require.NoError(t, err)
	defer func() { _ = ro.Close() }()

	entries, err := ro.QueryChainEntries(100)
	require.NoError(t, err)
	require.Len(t, entries, 4)

	// Sanity: the tampered row is still visible — proof that rebuild did
	// NOT silently regenerate the hash under us.
	for _, e := range entries {
		if e.ID == idForIndex(2) {
			assert.Equal(t, "tampered", e.PolicyDecision,
				"read-only open must surface the tampered row, not regenerate it")
		}
	}

	// Step 4: VerifyChain must flag the break. Because policy_decision is
	// part of the v2 hash, the tampered row's stored hash no longer matches
	// the recomputed one.
	result := audit.VerifyChain(entries, nil)
	assert.False(t, result.Valid, "tampered chain must NOT verify under read-only open")
	assert.Equal(t, idForIndex(2), result.BrokenID)
}

// Same test, but via the write-enabled NewStore path — this is the path
// used by the live server and SHOULD auto-repair on startup. We assert the
// opposite here: rebuild DOES run, and afterwards VerifyChain returns
// valid (because rebuild re-signed everything). The point is to lock in
// the difference between the two constructors so a future refactor
// doesn't accidentally make them behave the same.
func TestVerifyChain_WritableStoreAutoRepairs(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "rebuild.db")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	store, err := audit.NewStore(dbPath, logger)
	require.NoError(t, err)
	for i := 0; i < 4; i++ {
		store.Log(audit.Entry{
			ID:             idForIndex(i),
			Timestamp:      "2026-04-16T00:00:00Z",
			FromAgent:      "alice",
			ToAgent:        "bob",
			ContentHash:    "hash-" + idForIndex(i),
			Status:         "delivered",
			PolicyDecision: "clean",
		})
	}
	store.Flush()
	require.NoError(t, store.Close())

	tamperDB, err := openRawSQLite(dbPath)
	require.NoError(t, err)
	_, err = tamperDB.Exec(`UPDATE audit_log SET policy_decision = 'tampered' WHERE id = ?`, idForIndex(2))
	require.NoError(t, err)
	require.NoError(t, tamperDB.Close())

	// Writable open: auto-repair should kick in and fix everything.
	rw, err := audit.NewStore(dbPath, logger)
	require.NoError(t, err)
	defer func() { _ = rw.Close() }()

	entries, err := rw.QueryChainEntries(100)
	require.NoError(t, err)

	// The writable path intentionally regenerates — that's its job in
	// production so backfill migrations don't leave a broken chain. We
	// document the behaviour here so anyone touching it has to update
	// both tests.
	result := audit.VerifyChain(entries, nil)
	assert.True(t, result.Valid, "writable store should auto-repair and re-verify clean")
}

func idForIndex(i int) string {
	return "entry-" + string(rune('a'+i))
}
