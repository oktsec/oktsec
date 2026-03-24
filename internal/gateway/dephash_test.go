package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDepHash_FirstRun_RecordsBaseline(t *testing.T) {
	tmp := t.TempDir()
	storePath := filepath.Join(tmp, "store", "dep-hashes.json")
	workDir := filepath.Join(tmp, "server")
	require.NoError(t, os.MkdirAll(workDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(workDir, "requirements.txt"), []byte("flask==3.0\n"), 0o644))

	store := newDepHashStore(storePath)
	changes := store.Check("my-server", workDir)

	require.Len(t, changes, 1)
	assert.Equal(t, "my-server", changes[0].ServerName)
	assert.Equal(t, "requirements.txt", changes[0].File)
	assert.Empty(t, changes[0].OldHash, "first run should have empty OldHash")
	assert.NotEmpty(t, changes[0].NewHash)
}

func TestDepHash_UnchangedManifests_NoChanges(t *testing.T) {
	tmp := t.TempDir()
	storePath := filepath.Join(tmp, "dep-hashes.json")
	workDir := filepath.Join(tmp, "server")
	require.NoError(t, os.MkdirAll(workDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(workDir, "package.json"), []byte(`{"name":"test"}`), 0o644))

	// First run: record baseline.
	store := newDepHashStore(storePath)
	changes := store.Check("srv", workDir)
	require.Len(t, changes, 1)
	require.NoError(t, store.Save())

	// Second run: nothing changed.
	store2 := newDepHashStore(storePath)
	changes2 := store2.Check("srv", workDir)
	assert.Empty(t, changes2)
}

func TestDepHash_ChangedManifest_ReturnsChange(t *testing.T) {
	tmp := t.TempDir()
	storePath := filepath.Join(tmp, "dep-hashes.json")
	workDir := filepath.Join(tmp, "server")
	require.NoError(t, os.MkdirAll(workDir, 0o755))

	original := []byte("flask==3.0\n")
	require.NoError(t, os.WriteFile(filepath.Join(workDir, "requirements.txt"), original, 0o644))

	// First run.
	store := newDepHashStore(storePath)
	_ = store.Check("srv", workDir)
	require.NoError(t, store.Save())

	// Modify the file (rug pull).
	modified := []byte("flask==3.0\nos.system('evil')\n")
	require.NoError(t, os.WriteFile(filepath.Join(workDir, "requirements.txt"), modified, 0o644))

	// Second run.
	store2 := newDepHashStore(storePath)
	changes := store2.Check("srv", workDir)

	require.Len(t, changes, 1)
	assert.Equal(t, "requirements.txt", changes[0].File)
	assert.NotEmpty(t, changes[0].OldHash, "should have stored old hash")
	assert.NotEmpty(t, changes[0].NewHash)
	assert.NotEqual(t, changes[0].OldHash, changes[0].NewHash)

	// Verify hashes are correct SHA-256.
	wantOld := sha256Sum(original)
	wantNew := sha256Sum(modified)
	assert.Equal(t, wantOld, changes[0].OldHash)
	assert.Equal(t, wantNew, changes[0].NewHash)
}

func TestDepHash_MissingWorkingDir_Skipped(t *testing.T) {
	tmp := t.TempDir()
	storePath := filepath.Join(tmp, "dep-hashes.json")

	store := newDepHashStore(storePath)
	changes := store.Check("srv", filepath.Join(tmp, "nonexistent"))
	assert.Empty(t, changes)
}

func TestDepHash_NoManifests_NoChanges(t *testing.T) {
	tmp := t.TempDir()
	storePath := filepath.Join(tmp, "dep-hashes.json")
	workDir := filepath.Join(tmp, "empty-server")
	require.NoError(t, os.MkdirAll(workDir, 0o755))

	store := newDepHashStore(storePath)
	changes := store.Check("srv", workDir)
	assert.Empty(t, changes)
}

func TestDepHash_MultipleManifests_TrackedIndependently(t *testing.T) {
	tmp := t.TempDir()
	storePath := filepath.Join(tmp, "dep-hashes.json")
	workDir := filepath.Join(tmp, "server")
	require.NoError(t, os.MkdirAll(workDir, 0o755))

	require.NoError(t, os.WriteFile(filepath.Join(workDir, "package.json"), []byte(`{"name":"a"}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(workDir, "go.sum"), []byte("h1:abc123\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(workDir, "requirements.txt"), []byte("requests==2.31\n"), 0o644))

	// First run: all three are new.
	store := newDepHashStore(storePath)
	changes := store.Check("srv", workDir)
	require.Len(t, changes, 3)
	require.NoError(t, store.Save())

	// Modify only package.json.
	require.NoError(t, os.WriteFile(filepath.Join(workDir, "package.json"), []byte(`{"name":"b"}`), 0o644))

	// Second run: only package.json should show as changed.
	store2 := newDepHashStore(storePath)
	changes2 := store2.Check("srv", workDir)
	require.Len(t, changes2, 1)
	assert.Equal(t, "package.json", changes2[0].File)
	assert.NotEmpty(t, changes2[0].OldHash)
	assert.NotEmpty(t, changes2[0].NewHash)
	assert.NotEqual(t, changes2[0].OldHash, changes2[0].NewHash)
}

func TestDepHash_SaveCreatesDir(t *testing.T) {
	tmp := t.TempDir()
	storePath := filepath.Join(tmp, "nested", "deep", "dep-hashes.json")

	store := newDepHashStore(storePath)
	err := store.Save()
	require.NoError(t, err)

	_, err = os.Stat(storePath)
	require.NoError(t, err, "store file should exist")
}

func TestDepHash_SavePermissions(t *testing.T) {
	tmp := t.TempDir()
	storePath := filepath.Join(tmp, "dep-hashes.json")

	store := newDepHashStore(storePath)
	require.NoError(t, store.Save())

	info, err := os.Stat(storePath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestDepHash_StoreFileFormat(t *testing.T) {
	tmp := t.TempDir()
	storePath := filepath.Join(tmp, "dep-hashes.json")
	workDir := filepath.Join(tmp, "server")
	require.NoError(t, os.MkdirAll(workDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(workDir, "go.mod"), []byte("module test\n"), 0o644))

	store := newDepHashStore(storePath)
	_ = store.Check("my-srv", workDir)
	require.NoError(t, store.Save())

	data, err := os.ReadFile(storePath)
	require.NoError(t, err)

	var parsed map[string]map[string]string
	require.NoError(t, json.Unmarshal(data, &parsed))
	require.Contains(t, parsed, "my-srv")
	require.Contains(t, parsed["my-srv"], "go.mod")
	assert.Len(t, parsed["my-srv"]["go.mod"], 64, "sha256 hex should be 64 chars")
}

func TestDepHash_CorruptStoreFile_StartsClean(t *testing.T) {
	tmp := t.TempDir()
	storePath := filepath.Join(tmp, "dep-hashes.json")
	require.NoError(t, os.WriteFile(storePath, []byte("not json!!!"), 0o600))

	store := newDepHashStore(storePath)
	assert.NotNil(t, store.hashes)
	assert.Empty(t, store.hashes)
}

func TestDepHash_DefaultPath(t *testing.T) {
	p := defaultDepHashPath()
	assert.Contains(t, p, ".oktsec")
	assert.Contains(t, p, "dep-hashes.json")
}

func sha256Sum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
