package commands

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditNanoClaw_NotInstalled(t *testing.T) {
	findings := auditNanoClawAt("/nonexistent/nanoclaw/mount-allowlist.json")
	assert.Nil(t, findings)
}

func TestAuditNanoClaw_MissingAllowlist(t *testing.T) {
	dir := t.TempDir()
	allowlistPath := filepath.Join(dir, "mount-allowlist.json")
	// Config dir exists (dir), but allowlist file does not

	findings := auditNanoClawAt(allowlistPath)
	assertHasCheck(t, findings, "NC-MNT-001", AuditHigh)
}

func TestAuditNanoClaw_DangerousRoot_Slash(t *testing.T) {
	dir := t.TempDir()
	allowlistPath := filepath.Join(dir, "mount-allowlist.json")
	writeJSON(t, allowlistPath, `{
		"allowedRoots": [{"path": "/", "allowReadWrite": false}],
		"blockedPatterns": ["*.env"],
		"nonMainReadOnly": true
	}`)

	findings := auditNanoClawAt(allowlistPath)
	assertHasCheck(t, findings, "NC-MNT-003", AuditCritical)
}

func TestAuditNanoClaw_DangerousRoot_Tilde(t *testing.T) {
	dir := t.TempDir()
	allowlistPath := filepath.Join(dir, "mount-allowlist.json")
	writeJSON(t, allowlistPath, `{
		"allowedRoots": [{"path": "~", "allowReadWrite": false}],
		"blockedPatterns": ["*.env"],
		"nonMainReadOnly": true
	}`)

	findings := auditNanoClawAt(allowlistPath)
	assertHasCheck(t, findings, "NC-MNT-003", AuditCritical)
}

func TestAuditNanoClaw_NonMainReadOnlyFalse(t *testing.T) {
	dir := t.TempDir()
	allowlistPath := filepath.Join(dir, "mount-allowlist.json")
	writeJSON(t, allowlistPath, `{
		"allowedRoots": [{"path": "/tmp/safe", "allowReadWrite": false}],
		"blockedPatterns": ["*.env"],
		"nonMainReadOnly": false
	}`)

	findings := auditNanoClawAt(allowlistPath)
	assertHasCheck(t, findings, "NC-MNT-002", AuditHigh)
}

func TestAuditNanoClaw_NoBlockedPatterns(t *testing.T) {
	dir := t.TempDir()
	allowlistPath := filepath.Join(dir, "mount-allowlist.json")
	writeJSON(t, allowlistPath, `{
		"allowedRoots": [{"path": "/tmp/safe", "allowReadWrite": false}],
		"blockedPatterns": [],
		"nonMainReadOnly": true
	}`)

	findings := auditNanoClawAt(allowlistPath)
	assertHasCheck(t, findings, "NC-MNT-004", AuditMedium)
}

func TestAuditNanoClaw_ReadWriteSensitivePath(t *testing.T) {
	dir := t.TempDir()
	allowlistPath := filepath.Join(dir, "mount-allowlist.json")
	writeJSON(t, allowlistPath, `{
		"allowedRoots": [{"path": "/etc", "allowReadWrite": true}],
		"blockedPatterns": ["*.env"],
		"nonMainReadOnly": true
	}`)

	findings := auditNanoClawAt(allowlistPath)
	assertHasCheck(t, findings, "NC-MNT-005", AuditHigh)
}

func TestAuditNanoClaw_SecureConfig(t *testing.T) {
	dir := t.TempDir()
	allowlistPath := filepath.Join(dir, "mount-allowlist.json")
	require.NoError(t, os.WriteFile(allowlistPath, []byte(`{
		"allowedRoots": [
			{"path": "/tmp/project", "allowReadWrite": true, "description": "project dir"}
		],
		"blockedPatterns": ["*.env", ".ssh/*", "*.key"],
		"nonMainReadOnly": true
	}`), 0o600))

	findings := auditNanoClawAt(allowlistPath)
	for _, f := range findings {
		assert.LessOrEqual(t, f.Severity, AuditInfo,
			"unexpected finding: [%s] %s — %s", f.CheckID, f.Title, f.Detail)
	}
}

func TestAuditNanoClaw_Stats(t *testing.T) {
	dir := t.TempDir()
	allowlistPath := filepath.Join(dir, "mount-allowlist.json")
	writeJSON(t, allowlistPath, `{
		"allowedRoots": [
			{"path": "/tmp/a", "allowReadWrite": true},
			{"path": "/tmp/b", "allowReadWrite": false}
		],
		"blockedPatterns": ["*.env", ".ssh/*"],
		"nonMainReadOnly": true
	}`)

	findings := auditNanoClawAt(allowlistPath)
	assertHasCheck(t, findings, "NC-MNT-006", AuditInfo)
	// Verify stats content
	for _, f := range findings {
		if f.CheckID == "NC-MNT-006" {
			assert.Contains(t, f.Detail, "2 allowed roots")
			assert.Contains(t, f.Detail, "1 read-write")
			assert.Contains(t, f.Detail, "2 blocked patterns")
			break
		}
	}
}

func TestAuditNanoClaw_ProductField(t *testing.T) {
	dir := t.TempDir()
	allowlistPath := filepath.Join(dir, "mount-allowlist.json")
	writeJSON(t, allowlistPath, `{
		"allowedRoots": [],
		"blockedPatterns": [],
		"nonMainReadOnly": false
	}`)

	findings := auditNanoClawAt(allowlistPath)
	require.NotEmpty(t, findings)
	for _, f := range findings {
		assert.Equal(t, "NanoClaw", f.Product)
	}
}
