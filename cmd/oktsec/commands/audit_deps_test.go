package commands

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/oktsec/oktsec/internal/deps"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAuditDepsCmd(t *testing.T) {
	cmd := newAuditDepsCmd()
	assert.Equal(t, "deps [path]", cmd.Use)
	assert.Equal(t, "Audit MCP server dependencies for supply chain risks", cmd.Short)

	// Verify flags exist
	jsonFlag := cmd.Flags().Lookup("json")
	require.NotNil(t, jsonFlag)
	assert.Equal(t, "false", jsonFlag.DefValue)

	strictFlag := cmd.Flags().Lookup("strict")
	require.NotNil(t, strictFlag)
	assert.Equal(t, "false", strictFlag.DefValue)
}

func TestAuditDepsEmptyDir(t *testing.T) {
	dir := t.TempDir()

	// Running against an empty directory should not error — just report clean
	cmd := newAuditDepsCmd()
	cmd.SetArgs([]string{dir})
	err := cmd.Execute()
	assert.NoError(t, err)
}

func TestAuditDepsWithManifest(t *testing.T) {
	dir := t.TempDir()

	// Create a minimal requirements.txt with a pinned package
	content := "flask==2.3.1\nrequests==2.28.0\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(content), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Pipfile.lock"), []byte("{}"), 0644))

	// This test will make real OSV calls (only 2 packages, fast).
	// In CI, network may be unavailable — that's OK, it produces a warning not an error.
	cmd := newAuditDepsCmd()
	cmd.SetArgs([]string{dir, "--json"})
	err := cmd.Execute()
	assert.NoError(t, err)
}

func TestAuditDepsNonexistentPath(t *testing.T) {
	// Directly test the scanner to verify error handling without triggering os.Exit.
	scanner := deps.NewScanner(nil)
	_, err := scanner.Scan("/nonexistent/path/that/does/not/exist")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "path not found")
}

func TestAuditDepsRegistered(t *testing.T) {
	cmd := newAuditCmd()

	// Verify deps subcommand is registered
	found := false
	for _, sub := range cmd.Commands() {
		if sub.Name() == "deps" {
			found = true
			break
		}
	}
	assert.True(t, found, "deps subcommand should be registered under audit")
}
