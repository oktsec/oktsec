package commands

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditOpenClaw_NotInstalled(t *testing.T) {
	findings := auditOpenClawAt("/nonexistent/path/openclaw.json")
	assert.Nil(t, findings)
}

func TestAuditOpenClaw_ExposedGateway(t *testing.T) {
	for _, bind := range []string{"0.0.0.0", "::", "lan"} {
		t.Run(bind, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "openclaw.json")
			writeJSON(t, configPath, `{"gateway": {"bind": "`+bind+`"}}`)

			findings := auditOpenClawAt(configPath)
			assertHasCheck(t, findings, "OC-001", AuditCritical)
		})
	}
}

func TestAuditOpenClaw_FullProfileNoDeny(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	writeJSON(t, configPath, `{"tools": {"profile": "full"}}`)

	findings := auditOpenClawAt(configPath)
	assertHasCheck(t, findings, "OC-002", AuditCritical)
}

func TestAuditOpenClaw_FullProfileWithDeny(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	writeJSON(t, configPath, `{"tools": {"profile": "full", "deny": ["exec"]}}`)

	findings := auditOpenClawAt(configPath)
	assertNoCheck(t, findings, "OC-002")
}

func TestAuditOpenClaw_ExecWithoutSandbox(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	writeJSON(t, configPath, `{
		"tools": {"allow": ["exec"]},
		"agents": {"worker": {"sandbox": false}}
	}`)

	findings := auditOpenClawAt(configPath)
	assertHasCheck(t, findings, "OC-003", AuditCritical)
}

func TestAuditOpenClaw_ExecWithSandbox(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	writeJSON(t, configPath, `{
		"tools": {"allow": ["exec"]},
		"agents": {"worker": {"sandbox": true}}
	}`)

	findings := auditOpenClawAt(configPath)
	assertNoCheck(t, findings, "OC-003")
}

func TestAuditOpenClaw_OpenDM(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	writeJSON(t, configPath, `{"dmPolicy": "open"}`)

	findings := auditOpenClawAt(configPath)
	assertHasCheck(t, findings, "OC-004", AuditHigh)
}

func TestAuditOpenClaw_PathTraversal(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	writeJSON(t, configPath, `{"$include": ["../../etc/secrets.json"]}`)

	findings := auditOpenClawAt(configPath)
	assertHasCheck(t, findings, "OC-005", AuditCritical)
}

func TestAuditOpenClaw_NoSandboxedAgents(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	writeJSON(t, configPath, `{
		"agents": {
			"a": {"sandbox": false},
			"b": {"sandbox": false}
		}
	}`)

	findings := auditOpenClawAt(configPath)
	assertHasCheck(t, findings, "OC-006", AuditHigh)
}

func TestAuditOpenClaw_SecureConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	require.NoError(t, os.Chmod(dir, 0o700))
	writeJSON(t, configPath, `{
		"gateway": {"bind": "127.0.0.1"},
		"tools": {"profile": "minimal"},
		"dmPolicy": "restricted",
		"agents": {"worker": {"sandbox": true}}
	}`)
	require.NoError(t, os.Chmod(configPath, 0o600))

	findings := auditOpenClawAt(configPath)
	for _, f := range findings {
		assert.LessOrEqual(t, f.Severity, AuditInfo,
			"unexpected finding: [%s] %s", f.CheckID, f.Title)
	}
}

func TestAuditOpenClaw_ProductField(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	writeJSON(t, configPath, `{"dmPolicy": "open"}`)

	findings := auditOpenClawAt(configPath)
	require.NotEmpty(t, findings)
	for _, f := range findings {
		assert.Equal(t, "OpenClaw", f.Product)
	}
}

// --- helpers ---

func writeJSON(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

func assertHasCheck(t *testing.T, findings []AuditFinding, checkID string, severity AuditSeverity) {
	t.Helper()
	for _, f := range findings {
		if f.CheckID == checkID {
			assert.Equal(t, severity, f.Severity, "check %s has wrong severity", checkID)
			return
		}
	}
	t.Errorf("expected finding %s not found in %d findings", checkID, len(findings))
}

func assertNoCheck(t *testing.T, findings []AuditFinding, checkID string) {
	t.Helper()
	for _, f := range findings {
		if f.CheckID == checkID {
			t.Errorf("unexpected finding %s: %s", checkID, f.Title)
			return
		}
	}
}
