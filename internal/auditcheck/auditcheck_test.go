package auditcheck

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func secureBaseline() *config.Config {
	return &config.Config{
		Version: "1",
		Server: config.ServerConfig{
			Port: 8080,
			Bind: "127.0.0.1",
		},
		Identity: config.IdentityConfig{
			KeysDir:          "./keys",
			RequireSignature: true,
		},
		DefaultPolicy: "deny",
		Agents: map[string]config.Agent{
			"agent-a": {
				CanMessage:     []string{"agent-b"},
				BlockedContent: []string{"password"},
			},
			"agent-b": {
				CanMessage:     []string{"agent-a"},
				BlockedContent: []string{"secret"},
			},
		},
		Webhooks: []config.Webhook{
			{URL: "https://hooks.example.com/oktsec", Events: []string{"blocked"}},
		},
		CustomRulesDir: "./rules",
		Quarantine: config.QuarantineConfig{
			Enabled:       true,
			ExpiryHours:   24,
			RetentionDays: 90,
		},
		RateLimit: config.RateLimitConfig{
			PerAgent: 100,
			WindowS:  60,
		},
		Anomaly: config.AnomalyConfig{
			RiskThreshold: 80,
			MinMessages:   10,
		},
	}
}

// --- SIG-001 ---

func TestCheckSignatureDisabled(t *testing.T) {
	cfg := secureBaseline()
	cfg.Identity.RequireSignature = false
	findings := checkSignatureDisabled(cfg, "")
	require.Len(t, findings, 1)
	assert.Equal(t, "SIG-001", findings[0].CheckID)
	assert.Equal(t, Critical, findings[0].Severity)
}

func TestCheckSignatureEnabled(t *testing.T) {
	cfg := secureBaseline()
	findings := checkSignatureDisabled(cfg, "")
	assert.Empty(t, findings)
}

// --- NET-001 ---

func TestCheckNetworkExposure_Exposed(t *testing.T) {
	for _, bind := range []string{"0.0.0.0", "::"} {
		cfg := secureBaseline()
		cfg.Server.Bind = bind
		findings := checkNetworkExposure(cfg, "")
		require.Len(t, findings, 1, "bind=%s", bind)
		assert.Equal(t, "NET-001", findings[0].CheckID)
		assert.Equal(t, Critical, findings[0].Severity)
	}
}

func TestCheckNetworkExposure_Localhost(t *testing.T) {
	cfg := secureBaseline()
	cfg.Server.Bind = "127.0.0.1"
	findings := checkNetworkExposure(cfg, "")
	assert.Empty(t, findings)
}

// --- ACL-001 ---

func TestCheckDefaultPolicyAllow(t *testing.T) {
	cfg := secureBaseline()
	cfg.DefaultPolicy = "allow"
	findings := checkDefaultPolicyAllow(cfg, "")
	require.Len(t, findings, 1)
	assert.Equal(t, "ACL-001", findings[0].CheckID)
	assert.Equal(t, High, findings[0].Severity)
}

func TestCheckDefaultPolicyAllow_EmptyStringIsAllow(t *testing.T) {
	cfg := secureBaseline()
	cfg.DefaultPolicy = ""
	findings := checkDefaultPolicyAllow(cfg, "")
	require.Len(t, findings, 1)
	assert.Equal(t, "ACL-001", findings[0].CheckID)
}

func TestCheckDefaultPolicyDeny(t *testing.T) {
	cfg := secureBaseline()
	findings := checkDefaultPolicyAllow(cfg, "")
	assert.Empty(t, findings)
}

// --- ACL-002 ---

func TestCheckNoAgents(t *testing.T) {
	cfg := secureBaseline()
	cfg.Agents = nil
	findings := checkNoAgents(cfg, "")
	require.Len(t, findings, 1)
	assert.Equal(t, "ACL-002", findings[0].CheckID)
	assert.Equal(t, High, findings[0].Severity)
}

func TestCheckWithAgents(t *testing.T) {
	cfg := secureBaseline()
	findings := checkNoAgents(cfg, "")
	assert.Empty(t, findings)
}

// --- ACL-003 ---

func TestCheckWildcardMessaging(t *testing.T) {
	cfg := secureBaseline()
	cfg.Agents["rogue"] = config.Agent{CanMessage: []string{"*"}}
	findings := checkWildcardMessaging(cfg, "")
	require.Len(t, findings, 1)
	assert.Equal(t, "ACL-003", findings[0].CheckID)
	assert.Equal(t, High, findings[0].Severity)
	assert.Contains(t, findings[0].Title, "rogue")
}

// --- RET-001 ---

func TestCheckQuarantineDisabled(t *testing.T) {
	cfg := secureBaseline()
	cfg.Quarantine.Enabled = false
	findings := checkQuarantineDisabled(cfg, "")
	require.Len(t, findings, 1)
	assert.Equal(t, "RET-001", findings[0].CheckID)
	assert.Equal(t, High, findings[0].Severity)
}

// --- MON-001 ---

func TestCheckRateLimitDisabled(t *testing.T) {
	cfg := secureBaseline()
	cfg.RateLimit.PerAgent = 0
	findings := checkRateLimitDisabled(cfg, "")
	require.Len(t, findings, 1)
	assert.Equal(t, "MON-001", findings[0].CheckID)
	assert.Equal(t, High, findings[0].Severity)
}

// --- SIG-002 ---

func TestCheckKeysDirectory_Missing(t *testing.T) {
	cfg := secureBaseline()
	cfg.Identity.KeysDir = "/nonexistent/keys"
	findings := checkKeysDirectory(cfg, "")
	require.Len(t, findings, 1)
	assert.Equal(t, "SIG-002", findings[0].CheckID)
	assert.Equal(t, High, findings[0].Severity)
}

func TestCheckKeysDirectory_WithKeys(t *testing.T) {
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	require.NoError(t, os.Mkdir(keysDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "agent-a.pub"), []byte("key"), 0o644))

	cfg := secureBaseline()
	cfg.Identity.KeysDir = keysDir
	findings := checkKeysDirectory(cfg, dir)
	assert.Empty(t, findings)
}

func TestCheckKeysDirectory_Empty(t *testing.T) {
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	require.NoError(t, os.Mkdir(keysDir, 0o700))

	cfg := secureBaseline()
	cfg.Identity.KeysDir = keysDir
	findings := checkKeysDirectory(cfg, dir)
	require.Len(t, findings, 1)
	assert.Equal(t, "SIG-002", findings[0].CheckID)
}

func TestCheckKeysDirectory_SkippedWhenNoSignature(t *testing.T) {
	cfg := secureBaseline()
	cfg.Identity.RequireSignature = false
	cfg.Identity.KeysDir = "/nonexistent"
	findings := checkKeysDirectory(cfg, "")
	assert.Empty(t, findings)
}

// --- MON-002 ---

func TestCheckNoWebhooks(t *testing.T) {
	cfg := secureBaseline()
	cfg.Webhooks = nil
	findings := checkNoWebhooks(cfg, "")
	require.Len(t, findings, 1)
	assert.Equal(t, "MON-002", findings[0].CheckID)
	assert.Equal(t, Medium, findings[0].Severity)
}

// --- MON-003 ---

func TestCheckAnomalyThreshold(t *testing.T) {
	cfg := secureBaseline()
	cfg.Anomaly.RiskThreshold = 0
	findings := checkAnomalyThreshold(cfg, "")
	require.Len(t, findings, 1)
	assert.Equal(t, "MON-003", findings[0].CheckID)
	assert.Equal(t, Medium, findings[0].Severity)
}

// --- ACL-004 ---

func TestCheckNoBlockedContent(t *testing.T) {
	cfg := secureBaseline()
	for name, agent := range cfg.Agents {
		agent.BlockedContent = nil
		cfg.Agents[name] = agent
	}
	findings := checkNoBlockedContent(cfg, "")
	require.Len(t, findings, 1)
	assert.Equal(t, "ACL-004", findings[0].CheckID)
	assert.Equal(t, Medium, findings[0].Severity)
}

func TestCheckNoBlockedContent_NoAgents(t *testing.T) {
	cfg := secureBaseline()
	cfg.Agents = nil
	findings := checkNoBlockedContent(cfg, "")
	assert.Empty(t, findings)
}

// --- RET-002 ---

func TestCheckRetentionDays(t *testing.T) {
	cfg := secureBaseline()
	cfg.Quarantine.RetentionDays = 0
	findings := checkRetentionDays(cfg, "")
	require.Len(t, findings, 1)
	assert.Equal(t, "RET-002", findings[0].CheckID)
	assert.Equal(t, Medium, findings[0].Severity)
}

// --- ENG-001 ---

func TestCheckNoCustomRules(t *testing.T) {
	cfg := secureBaseline()
	cfg.CustomRulesDir = ""
	findings := checkNoCustomRules(cfg, "")
	require.Len(t, findings, 1)
	assert.Equal(t, "ENG-001", findings[0].CheckID)
	assert.Equal(t, Medium, findings[0].Severity)
}

// --- NET-002 ---

func TestCheckForwardProxyNoScanResponses(t *testing.T) {
	cfg := secureBaseline()
	cfg.ForwardProxy.Enabled = true
	cfg.ForwardProxy.ScanResponses = false
	findings := checkForwardProxyNoScanResponses(cfg, "")
	require.Len(t, findings, 1)
	assert.Equal(t, "NET-002", findings[0].CheckID)
	assert.Equal(t, Medium, findings[0].Severity)
}

func TestCheckForwardProxyNoScanResponses_Disabled(t *testing.T) {
	cfg := secureBaseline()
	cfg.ForwardProxy.Enabled = false
	findings := checkForwardProxyNoScanResponses(cfg, "")
	assert.Empty(t, findings)
}

// --- SIG-003 ---

func TestCheckPrivateKeyPermissions(t *testing.T) {
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	require.NoError(t, os.Mkdir(keysDir, 0o700))

	// Private key with loose permissions
	keyPath := filepath.Join(keysDir, "agent-a.key")
	require.NoError(t, os.WriteFile(keyPath, []byte("private"), 0o644))

	// Public key should be ignored
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "agent-a.pub"), []byte("public"), 0o644))

	cfg := secureBaseline()
	cfg.Identity.KeysDir = keysDir
	findings := checkPrivateKeyPermissions(cfg, dir)
	require.Len(t, findings, 1)
	assert.Equal(t, "SIG-003", findings[0].CheckID)
	assert.Equal(t, Medium, findings[0].Severity)
	assert.Contains(t, findings[0].Title, "agent-a.key")
}

func TestCheckPrivateKeyPermissions_Secure(t *testing.T) {
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	require.NoError(t, os.Mkdir(keysDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "agent-a.key"), []byte("private"), 0o600))

	cfg := secureBaseline()
	cfg.Identity.KeysDir = keysDir
	findings := checkPrivateKeyPermissions(cfg, dir)
	assert.Empty(t, findings)
}

// --- RET-003 ---

func TestCheckAuditDatabase_NotFound(t *testing.T) {
	dir := t.TempDir()
	cfg := secureBaseline()
	findings := checkAuditDatabase(cfg, dir)
	require.Len(t, findings, 1)
	assert.Equal(t, "RET-003", findings[0].CheckID)
	assert.Equal(t, Info, findings[0].Severity)
	assert.Contains(t, findings[0].Title, "not found")
}

func TestCheckAuditDatabase_Exists(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "oktsec.db"), []byte("data"), 0o644))

	cfg := secureBaseline()
	findings := checkAuditDatabase(cfg, dir)
	require.Len(t, findings, 1)
	assert.Equal(t, "RET-003", findings[0].CheckID)
	assert.Equal(t, Info, findings[0].Severity)
	assert.Contains(t, findings[0].Title, "present")
}

// --- Product auditors ---

func TestProductAuditorsRegistered(t *testing.T) {
	names := make(map[string]bool)
	for _, pa := range productAuditors {
		assert.NotEmpty(t, pa.name)
		assert.NotNil(t, pa.audit)
		assert.False(t, names[pa.name], "duplicate product auditor: %s", pa.name)
		names[pa.name] = true
	}
	assert.True(t, names["OpenClaw"], "OpenClaw auditor not registered")
	assert.True(t, names["NanoClaw"], "NanoClaw auditor not registered")
}

// --- Integration ---

func TestRunChecks_SecureConfig(t *testing.T) {
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	require.NoError(t, os.Mkdir(keysDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "agent-a.pub"), []byte("key"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "agent-a.key"), []byte("priv"), 0o600))

	cfg := secureBaseline()
	cfg.Identity.KeysDir = keysDir

	findings, _, _ := RunChecks(cfg, dir)

	for _, f := range findings {
		assert.LessOrEqual(t, f.Severity, Info,
			"unexpected finding: [%s] %s — %s", f.CheckID, f.Title, f.Detail)
	}
}

// --- ComputeHealthScore ---

func TestComputeHealthScore_Perfect(t *testing.T) {
	findings := []Finding{
		{Severity: Info, CheckID: "RET-003"},
	}
	score, grade := ComputeHealthScore(findings)
	assert.Equal(t, 100, score)
	assert.Equal(t, "A", grade)
}

func TestComputeHealthScore_NoFindings(t *testing.T) {
	score, grade := ComputeHealthScore(nil)
	assert.Equal(t, 100, score)
	assert.Equal(t, "A", grade)
}

func TestComputeHealthScore_OneCritical(t *testing.T) {
	findings := []Finding{
		{Severity: Critical, CheckID: "SIG-001"},
	}
	score, grade := ComputeHealthScore(findings)
	assert.Equal(t, 75, score)
	assert.Equal(t, "B", grade)
}

func TestComputeHealthScore_ManyIssues(t *testing.T) {
	findings := []Finding{
		{Severity: Critical, CheckID: "SIG-001"}, // -25
		{Severity: Critical, CheckID: "NET-001"}, // -25
		{Severity: High, CheckID: "ACL-001"},     // -15
		{Severity: High, CheckID: "ACL-002"},     // -15
		{Severity: Medium, CheckID: "MON-002"},   // -5
	}
	score, grade := ComputeHealthScore(findings)
	assert.Equal(t, 15, score) // 100 - 25 - 25 - 15 - 15 - 5
	assert.Equal(t, "F", grade)
}

func TestComputeHealthScore_FloorAtZero(t *testing.T) {
	findings := []Finding{
		{Severity: Critical},
		{Severity: Critical},
		{Severity: Critical},
		{Severity: Critical},
		{Severity: Critical}, // 5 * -25 = -125
	}
	score, grade := ComputeHealthScore(findings)
	assert.Equal(t, 0, score)
	assert.Equal(t, "F", grade)
}

func TestComputeHealthScore_GradeBoundaries(t *testing.T) {
	tests := []struct {
		name     string
		findings []Finding
		score    int
		grade    string
	}{
		{"perfect", nil, 100, "A"},
		{"one medium", []Finding{{Severity: Medium}}, 95, "A"},
		{"two medium", []Finding{{Severity: Medium}, {Severity: Medium}}, 90, "A"},
		{"one high", []Finding{{Severity: High}}, 85, "B"},
		{"crit+high", []Finding{{Severity: Critical}, {Severity: High}}, 60, "C"},
		{"two crit", []Finding{{Severity: Critical}, {Severity: Critical}}, 50, "D"},
		{"three crit", []Finding{{Severity: Critical}, {Severity: Critical}, {Severity: Critical}}, 25, "F"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, grade := ComputeHealthScore(tt.findings)
			assert.Equal(t, tt.score, score)
			assert.Equal(t, tt.grade, grade)
		})
	}
}

func TestComputeHealthScore_MediumOnly(t *testing.T) {
	findings := []Finding{
		{Severity: Medium}, // -5
		{Severity: Medium}, // -5
		{Severity: Medium}, // -5
	}
	score, grade := ComputeHealthScore(findings)
	assert.Equal(t, 85, score)
	assert.Equal(t, "B", grade)
}

// --- Summarize ---

func TestSummarize(t *testing.T) {
	findings := []Finding{
		{Severity: Critical},
		{Severity: Critical},
		{Severity: High},
		{Severity: Medium},
		{Severity: Medium},
		{Severity: Medium},
		{Severity: Info},
	}
	s := Summarize(findings)
	assert.Equal(t, 2, s.Critical)
	assert.Equal(t, 1, s.High)
	assert.Equal(t, 3, s.Medium)
	assert.Equal(t, 0, s.Low)
	assert.Equal(t, 1, s.Info)
}

// === OpenClaw tests ===

func writeJSON(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

func assertHasCheck(t *testing.T, findings []Finding, checkID string, severity Severity) {
	t.Helper()
	for _, f := range findings {
		if f.CheckID == checkID {
			assert.Equal(t, severity, f.Severity, "check %s has wrong severity", checkID)
			return
		}
	}
	t.Errorf("expected finding %s not found in %d findings", checkID, len(findings))
}

func assertNoCheck(t *testing.T, findings []Finding, checkID string) {
	t.Helper()
	for _, f := range findings {
		if f.CheckID == checkID {
			t.Errorf("unexpected finding %s: %s", checkID, f.Title)
			return
		}
	}
}

func TestAuditOpenClaw_NotInstalled(t *testing.T) {
	findings := auditOpenClawAt("/nonexistent/path/openclaw.json")
	assert.Nil(t, findings)
}

// --- OC-NET-001 ---

func TestAuditOpenClaw_ExposedGateway(t *testing.T) {
	for _, bind := range []string{"lan", "tailnet", "0.0.0.0", "custom"} {
		t.Run(bind, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "openclaw.json")
			writeJSON(t, configPath, `{"gateway": {"bind": "`+bind+`"}}`)

			findings := auditOpenClawAt(configPath)
			assertHasCheck(t, findings, "OC-NET-001", Critical)
		})
	}
}

func TestAuditOpenClaw_LoopbackSafe(t *testing.T) {
	for _, bind := range []string{"loopback", "localhost", "127.0.0.1", "::1"} {
		t.Run(bind, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "openclaw.json")
			require.NoError(t, os.Chmod(dir, 0o700))
			writeJSON(t, configPath, `{"gateway": {"bind": "`+bind+`"}}`)
			require.NoError(t, os.Chmod(configPath, 0o600))

			findings := auditOpenClawAt(configPath)
			assertNoCheck(t, findings, "OC-NET-001")
		})
	}
}

// --- OC-AUTH-001 ---

func TestAuditOpenClaw_NoAuthTokenExposed(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	writeJSON(t, configPath, `{"gateway": {"bind": "lan", "auth": {"token": ""}}}`)

	findings := auditOpenClawAt(configPath)
	assertHasCheck(t, findings, "OC-AUTH-001", Critical)
}

func TestAuditOpenClaw_PlaceholderTokenExposed(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	writeJSON(t, configPath, `{"gateway": {"bind": "lan", "auth": {"token": "replace-with-long-random-token"}}}`)

	findings := auditOpenClawAt(configPath)
	assertHasCheck(t, findings, "OC-AUTH-001", Critical)
}

func TestAuditOpenClaw_TokenModeNoToken(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	require.NoError(t, os.Chmod(dir, 0o700))
	writeJSON(t, configPath, `{"gateway": {"bind": "loopback", "auth": {"mode": "token", "token": ""}}}`)
	require.NoError(t, os.Chmod(configPath, 0o600))

	findings := auditOpenClawAt(configPath)
	assertHasCheck(t, findings, "OC-AUTH-001", Medium)
}

// --- OC-EXEC-001 ---

func TestAuditOpenClaw_ExecAllow(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	writeJSON(t, configPath, `{"tools": {"exec": {"security": "allow"}}}`)

	findings := auditOpenClawAt(configPath)
	assertHasCheck(t, findings, "OC-EXEC-001", Critical)
}

func TestAuditOpenClaw_ExecAskSafe(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	require.NoError(t, os.Chmod(dir, 0o700))
	writeJSON(t, configPath, `{"tools": {"exec": {"security": "ask"}}}`)
	require.NoError(t, os.Chmod(configPath, 0o600))

	findings := auditOpenClawAt(configPath)
	assertNoCheck(t, findings, "OC-EXEC-001")
}

// --- OC-TOOL-001 ---

func TestAuditOpenClaw_FullProfileNoDeny(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	writeJSON(t, configPath, `{"tools": {"profile": "full"}}`)

	findings := auditOpenClawAt(configPath)
	assertHasCheck(t, findings, "OC-TOOL-001", Critical)
}

func TestAuditOpenClaw_FullProfileWithDeny(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	require.NoError(t, os.Chmod(dir, 0o700))
	writeJSON(t, configPath, `{"tools": {"profile": "full", "deny": ["exec"]}}`)
	require.NoError(t, os.Chmod(configPath, 0o600))

	findings := auditOpenClawAt(configPath)
	assertNoCheck(t, findings, "OC-TOOL-001")
}

// --- OC-DM-001 ---

func TestAuditOpenClaw_OpenDMChannel(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	writeJSON(t, configPath, `{"channels": {"slack": {"dmPolicy": "open"}}}`)

	findings := auditOpenClawAt(configPath)
	assertHasCheck(t, findings, "OC-DM-001", High)
}

func TestAuditOpenClaw_PairingDMSafe(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	require.NoError(t, os.Chmod(dir, 0o700))
	writeJSON(t, configPath, `{"channels": {"slack": {"dmPolicy": "pairing"}}}`)
	require.NoError(t, os.Chmod(configPath, 0o600))

	findings := auditOpenClawAt(configPath)
	assertNoCheck(t, findings, "OC-DM-001")
}

// --- OC-SAND-001 ---

func TestAuditOpenClaw_SandboxOffExecAvailable(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	writeJSON(t, configPath, `{
		"agents": {"defaults": {"sandbox": {"mode": "off"}}},
		"tools": {"exec": {"security": "ask"}}
	}`)

	findings := auditOpenClawAt(configPath)
	assertHasCheck(t, findings, "OC-SAND-001", High)
}

func TestAuditOpenClaw_SandboxAllSafe(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	require.NoError(t, os.Chmod(dir, 0o700))
	writeJSON(t, configPath, `{
		"agents": {"defaults": {"sandbox": {"mode": "all"}}},
		"tools": {"exec": {"security": "ask"}}
	}`)
	require.NoError(t, os.Chmod(configPath, 0o600))

	findings := auditOpenClawAt(configPath)
	assertNoCheck(t, findings, "OC-SAND-001")
}

func TestAuditOpenClaw_SandboxOffExecDenied(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	require.NoError(t, os.Chmod(dir, 0o700))
	writeJSON(t, configPath, `{
		"agents": {"defaults": {"sandbox": {"mode": "off"}}},
		"tools": {"deny": ["exec"]}
	}`)
	require.NoError(t, os.Chmod(configPath, 0o600))

	findings := auditOpenClawAt(configPath)
	assertNoCheck(t, findings, "OC-SAND-001")
}

// --- OC-ELEV-001 ---

func TestAuditOpenClaw_ElevatedNoAllowFrom(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	writeJSON(t, configPath, `{"tools": {"elevated": {"enabled": true}}}`)

	findings := auditOpenClawAt(configPath)
	assertHasCheck(t, findings, "OC-ELEV-001", High)
}

func TestAuditOpenClaw_ElevatedWithAllowFrom(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	require.NoError(t, os.Chmod(dir, 0o700))
	writeJSON(t, configPath, `{"tools": {"elevated": {"enabled": true, "allowFrom": ["admin"]}}}`)
	require.NoError(t, os.Chmod(configPath, 0o600))

	findings := auditOpenClawAt(configPath)
	assertNoCheck(t, findings, "OC-ELEV-001")
}

// --- OC-UI-001 / OC-UI-002 ---

func TestAuditOpenClaw_DeviceAuthDisabled(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	writeJSON(t, configPath, `{"gateway": {"controlUi": {"dangerouslyDisableDeviceAuth": true}}}`)

	findings := auditOpenClawAt(configPath)
	assertHasCheck(t, findings, "OC-UI-001", High)
}

func TestAuditOpenClaw_InsecureAuth(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	writeJSON(t, configPath, `{"gateway": {"controlUi": {"allowInsecureAuth": true}}}`)

	findings := auditOpenClawAt(configPath)
	assertHasCheck(t, findings, "OC-UI-002", High)
}

// --- OC-HOOK-001 ---

func TestAuditOpenClaw_ShortWebhookToken(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	writeJSON(t, configPath, `{"hooks": {"token": "short"}}`)

	findings := auditOpenClawAt(configPath)
	assertHasCheck(t, findings, "OC-HOOK-001", High)
}

func TestAuditOpenClaw_LongWebhookToken(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	require.NoError(t, os.Chmod(dir, 0o700))
	writeJSON(t, configPath, `{"hooks": {"token": "abcdefghijklmnopqrstuvwxyz123456"}}`)
	require.NoError(t, os.Chmod(configPath, 0o600))

	findings := auditOpenClawAt(configPath)
	assertNoCheck(t, findings, "OC-HOOK-001")
}

// --- OC-FS-001 ---

func TestAuditOpenClaw_WorkspaceOnlyFalse(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	writeJSON(t, configPath, `{"tools": {"fs": {"workspaceOnly": false}}}`)

	findings := auditOpenClawAt(configPath)
	assertHasCheck(t, findings, "OC-FS-001", Medium)
}

// --- OC-LOG-001 ---

func TestAuditOpenClaw_RedactionOff(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	writeJSON(t, configPath, `{"logging": {"redactSensitive": "off"}}`)

	findings := auditOpenClawAt(configPath)
	assertHasCheck(t, findings, "OC-LOG-001", Medium)
}

// --- OC-DISC-001 ---

func TestAuditOpenClaw_MDNSFull(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	writeJSON(t, configPath, `{"discovery": {"mdns": {"mode": "full"}}}`)

	findings := auditOpenClawAt(configPath)
	assertHasCheck(t, findings, "OC-DISC-001", Medium)
}

// --- OC-HOOK-002 ---

func TestAuditOpenClaw_AllowRequestSessionKey(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	writeJSON(t, configPath, `{"hooks": {"allowRequestSessionKey": true}}`)

	findings := auditOpenClawAt(configPath)
	assertHasCheck(t, findings, "OC-HOOK-002", Medium)
}

// --- OC-SSRF-001 ---

func TestAuditOpenClaw_SSRFPrivateNetwork(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	writeJSON(t, configPath, `{"tools": {"browser": {"ssrfPolicy": {"dangerouslyAllowPrivateNetwork": true}}}}`)

	findings := auditOpenClawAt(configPath)
	assertHasCheck(t, findings, "OC-SSRF-001", Medium)
}

// --- OC-PERM-001 / OC-PERM-002 ---

func TestAuditOpenClaw_LooseDirPermissions(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	require.NoError(t, os.Chmod(dir, 0o755))
	writeJSON(t, configPath, `{}`)

	findings := auditOpenClawAt(configPath)
	assertHasCheck(t, findings, "OC-PERM-001", High)
}

func TestAuditOpenClaw_LooseFilePermissions(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	require.NoError(t, os.Chmod(dir, 0o700))
	writeJSON(t, configPath, `{}`)
	// writeJSON creates with 0644 which is loose

	findings := auditOpenClawAt(configPath)
	assertHasCheck(t, findings, "OC-PERM-002", Medium)
}

// --- OC-INFO-001 ---

func TestAuditOpenClaw_InfoSummary(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	require.NoError(t, os.Chmod(dir, 0o700))
	writeJSON(t, configPath, `{"gateway": {"mode": "local", "bind": "loopback"}}`)
	require.NoError(t, os.Chmod(configPath, 0o600))

	findings := auditOpenClawAt(configPath)
	assertHasCheck(t, findings, "OC-INFO-001", Info)
}

// --- Secure config ---

func TestAuditOpenClaw_SecureConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	require.NoError(t, os.Chmod(dir, 0o700))
	writeJSON(t, configPath, `{
		"gateway": {
			"bind": "loopback",
			"auth": {"mode": "token", "token": "abcdefghijklmnopqrstuvwxyz0123456789abcd"},
			"controlUi": {"allowInsecureAuth": false, "dangerouslyDisableDeviceAuth": false}
		},
		"tools": {
			"profile": "messaging",
			"exec": {"security": "deny"},
			"fs": {"workspaceOnly": true},
			"elevated": {"enabled": false}
		},
		"agents": {"defaults": {"sandbox": {"mode": "all"}}},
		"channels": {"slack": {"dmPolicy": "pairing"}},
		"hooks": {"token": "abcdefghijklmnopqrstuvwxyz0123456789abcd"},
		"logging": {"redactSensitive": "all"},
		"discovery": {"mdns": {"mode": "minimal"}}
	}`)
	require.NoError(t, os.Chmod(configPath, 0o600))

	findings := auditOpenClawAt(configPath)
	for _, f := range findings {
		assert.LessOrEqual(t, f.Severity, Info,
			"unexpected finding: [%s] %s", f.CheckID, f.Title)
	}
}

// --- Product + Remediation fields ---

func TestAuditOpenClaw_ProductField(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	writeJSON(t, configPath, `{"channels": {"slack": {"dmPolicy": "open"}}}`)

	findings := auditOpenClawAt(configPath)
	require.NotEmpty(t, findings)
	for _, f := range findings {
		assert.Equal(t, "OpenClaw", f.Product)
		assert.Equal(t, configPath, f.ConfigPath)
	}
}

func TestAuditOpenClaw_RemediationPresent(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	writeJSON(t, configPath, `{
		"gateway": {"bind": "lan"},
		"tools": {"profile": "full", "exec": {"security": "allow"}},
		"channels": {"slack": {"dmPolicy": "open"}}
	}`)

	findings := auditOpenClawAt(configPath)
	for _, f := range findings {
		if f.Severity > Info {
			assert.NotEmpty(t, f.Remediation,
				"check %s (%s) should have remediation", f.CheckID, f.Title)
		}
	}
}

// === NanoClaw tests ===

func TestAuditNanoClaw_NotInstalled(t *testing.T) {
	findings := auditNanoClawAt("/nonexistent/nanoclaw/mount-allowlist.json")
	assert.Nil(t, findings)
}

func TestAuditNanoClaw_MissingAllowlist(t *testing.T) {
	dir := t.TempDir()
	allowlistPath := filepath.Join(dir, "mount-allowlist.json")

	findings := auditNanoClawAt(allowlistPath)
	assertHasCheck(t, findings, "NC-MNT-001", High)
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
	assertHasCheck(t, findings, "NC-MNT-003", Critical)
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
	assertHasCheck(t, findings, "NC-MNT-003", Critical)
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
	assertHasCheck(t, findings, "NC-MNT-002", High)
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
	assertHasCheck(t, findings, "NC-MNT-004", Medium)
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
	assertHasCheck(t, findings, "NC-MNT-005", High)
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
		assert.LessOrEqual(t, f.Severity, Info,
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
	assertHasCheck(t, findings, "NC-MNT-006", Info)
	for _, f := range findings {
		if f.CheckID == "NC-MNT-006" {
			assert.Contains(t, f.Detail, "2 allowed roots")
			assert.Contains(t, f.Detail, "1 read-write")
			assert.Contains(t, f.Detail, "2 blocked patterns")
			break
		}
	}
}

// --- Remediation ---

func TestFindingRemediation(t *testing.T) {
	dir := t.TempDir()
	cfg := secureBaseline()
	cfg.Identity.RequireSignature = false
	cfg.Server.Bind = "0.0.0.0"
	cfg.DefaultPolicy = "allow"
	cfg.Quarantine.Enabled = false
	cfg.RateLimit.PerAgent = 0
	cfg.Webhooks = nil
	cfg.Anomaly.RiskThreshold = 0
	cfg.CustomRulesDir = ""
	cfg.Quarantine.RetentionDays = 0
	for name, agent := range cfg.Agents {
		agent.BlockedContent = nil
		cfg.Agents[name] = agent
	}

	findings, _, _ := RunChecks(cfg, dir)

	// Every fixable check (non-info) should have a non-empty Remediation
	for _, f := range findings {
		if f.Product != "" {
			continue // only test oktsec checks
		}
		if f.Severity == Info {
			continue
		}
		assert.NotEmpty(t, f.Remediation, "check %s (%s) should have remediation", f.CheckID, f.Title)
	}
}

func TestFindingConfigPath(t *testing.T) {
	dir := t.TempDir()
	cfg := secureBaseline()
	cfg.Identity.RequireSignature = false

	findings, _, _ := RunChecks(cfg, dir)

	for _, f := range findings {
		if f.Product != "" {
			continue
		}
		assert.NotEmpty(t, f.ConfigPath, "check %s should have config_path", f.CheckID)
		assert.Contains(t, f.ConfigPath, "oktsec.yaml", "check %s config_path should reference oktsec.yaml", f.CheckID)
	}
}

// --- ProductInfo ---

func TestProductInfoFor(t *testing.T) {
	info := ProductInfoFor("Oktsec", "/tmp/test")
	assert.Equal(t, "Oktsec", info.Name)
	assert.NotEmpty(t, info.Description)
	assert.Contains(t, info.ConfigPath, "oktsec.yaml")
	assert.NotEmpty(t, info.DocsURL)
	assert.NotEmpty(t, info.Icon)

	info = ProductInfoFor("OpenClaw", "/tmp/test")
	assert.Equal(t, "OpenClaw", info.Name)
	assert.NotEmpty(t, info.Description)
	assert.Contains(t, info.ConfigPath, "openclaw.json")

	info = ProductInfoFor("NanoClaw", "/tmp/test")
	assert.Equal(t, "NanoClaw", info.Name)
	assert.NotEmpty(t, info.Description)
	assert.Contains(t, info.ConfigPath, "mount-allowlist.json")

	info = ProductInfoFor("Unknown", "/tmp/test")
	assert.Equal(t, "Unknown", info.Name)
	assert.Empty(t, info.Description)
}

func TestRunChecks_ReturnsProductInfos(t *testing.T) {
	dir := t.TempDir()
	cfg := secureBaseline()
	cfg.Identity.RequireSignature = false

	_, _, productInfos := RunChecks(cfg, dir)
	assert.Contains(t, productInfos, "Oktsec")
	assert.Equal(t, "Oktsec", productInfos["Oktsec"].Name)
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
