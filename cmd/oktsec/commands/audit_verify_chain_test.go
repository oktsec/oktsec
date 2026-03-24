package commands

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestDB creates a temp audit store with n chain entries. Returns the db path and cleanup func.
// If proxyKey is non-nil, entries are signed.
func createTestDB(t *testing.T, n int, proxyKey ed25519.PrivateKey) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := audit.NewStore(dbPath, logger)
	require.NoError(t, err)

	if proxyKey != nil {
		store.SetProxyKey(proxyKey)
	}

	for i := 0; i < n; i++ {
		store.Log(audit.Entry{
			ID:             fmt.Sprintf("entry-%04d", i),
			Timestamp:      fmt.Sprintf("2026-03-24T00:00:%02dZ", i%60),
			FromAgent:      "agent-a",
			ToAgent:        "agent-b",
			ContentHash:    fmt.Sprintf("hash-%04d", i),
			Status:         "delivered",
			PolicyDecision: "allow",
		})
	}

	store.Flush()
	err = store.Close()
	require.NoError(t, err)
	return dbPath
}

func TestVerifyChainValid(t *testing.T) {
	dbPath := createTestDB(t, 5, nil)

	// Verify chain without proxy key
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := audit.NewStore(dbPath, logger)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	entries, err := store.QueryChainEntries(100)
	require.NoError(t, err)
	assert.Len(t, entries, 5)

	result := audit.VerifyChain(entries, nil)
	assert.True(t, result.Valid)
	assert.Equal(t, 5, result.Entries)
	assert.Equal(t, -1, result.BrokenAt)
}

func TestVerifyChainValidWithSignatures(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	dbPath := createTestDB(t, 10, priv)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := audit.NewStore(dbPath, logger)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	entries, err := store.QueryChainEntries(100)
	require.NoError(t, err)
	assert.Len(t, entries, 10)

	result := audit.VerifyChain(entries, pub)
	assert.True(t, result.Valid)
	assert.Equal(t, 10, result.Entries)
}

func TestVerifyChainEmpty(t *testing.T) {
	dbPath := createTestDB(t, 0, nil)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := audit.NewStore(dbPath, logger)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	entries, err := store.QueryChainEntries(100)
	require.NoError(t, err)
	assert.Empty(t, entries)

	result := audit.VerifyChain(entries, nil)
	assert.True(t, result.Valid)
	assert.Equal(t, 0, result.Entries)
}

func TestVerifyChainWrongKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Sign with one key
	dbPath := createTestDB(t, 3, priv)

	// Verify with a different key
	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := audit.NewStore(dbPath, logger)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	entries, err := store.QueryChainEntries(100)
	require.NoError(t, err)

	result := audit.VerifyChain(entries, wrongPub)
	assert.False(t, result.Valid)
	assert.Equal(t, "proxy signature invalid", result.Reason)
}

func TestVerifyChainResultJSON(t *testing.T) {
	r := verifyChainResult{
		Valid:          true,
		Entries:        42,
		SignatureCheck: "skipped",
		LastTimestamp:  "2026-03-24T00:00:00Z",
	}

	b, err := json.Marshal(r)
	require.NoError(t, err)

	var decoded map[string]interface{}
	err = json.Unmarshal(b, &decoded)
	require.NoError(t, err)

	assert.Equal(t, true, decoded["valid"])
	assert.Equal(t, float64(42), decoded["entries"])
	assert.Equal(t, "skipped", decoded["signature_check"])
	assert.Equal(t, "2026-03-24T00:00:00Z", decoded["last_timestamp"])
	// broken_at and broken_id should be omitted when valid
	_, hasBrokenAt := decoded["broken_at"]
	assert.False(t, hasBrokenAt)
}

func TestFormatCount(t *testing.T) {
	tests := []struct {
		n    int
		want string
	}{
		{0, "0"},
		{42, "42"},
		{999, "999"},
		{1000, "1,000"},
		{4231, "4,231"},
		{10000, "10,000"},
		{1000000, "1,000,000"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, formatCount(tt.n))
		})
	}
}

func TestTruncateFingerprint(t *testing.T) {
	assert.Equal(t, "abcd...wxyz", truncateFingerprint("abcdefghijklmnopqrstuvwxyz"))
	assert.Equal(t, "short", truncateFingerprint("short"))
}

func TestLoadPubKeyFromFile(t *testing.T) {
	dir := t.TempDir()
	kp, err := identity.GenerateKeypair("proxy")
	require.NoError(t, err)
	require.NoError(t, kp.Save(dir))

	pub, err := loadPubKeyFromFile(filepath.Join(dir, "proxy.pub"))
	require.NoError(t, err)
	assert.Equal(t, kp.PublicKey, pub)
}

func TestResolveKeyPathExplicit(t *testing.T) {
	dir := t.TempDir()
	kp, err := identity.GenerateKeypair("proxy")
	require.NoError(t, err)
	require.NoError(t, kp.Save(dir))

	path := resolveKeyPath(filepath.Join(dir, "proxy.pub"))
	assert.Equal(t, filepath.Join(dir, "proxy.pub"), path)
}
