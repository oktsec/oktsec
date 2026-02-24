package commands

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
	assert.Equal(t, AuditCritical, findings[0].Severity)
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
		assert.Equal(t, AuditCritical, findings[0].Severity)
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
	assert.Equal(t, AuditHigh, findings[0].Severity)
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
	assert.Equal(t, AuditHigh, findings[0].Severity)
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
	assert.Equal(t, AuditHigh, findings[0].Severity)
	assert.Contains(t, findings[0].Title, "rogue")
}

// --- RET-001 ---

func TestCheckQuarantineDisabled(t *testing.T) {
	cfg := secureBaseline()
	cfg.Quarantine.Enabled = false
	findings := checkQuarantineDisabled(cfg, "")
	require.Len(t, findings, 1)
	assert.Equal(t, "RET-001", findings[0].CheckID)
	assert.Equal(t, AuditHigh, findings[0].Severity)
}

// --- MON-001 ---

func TestCheckRateLimitDisabled(t *testing.T) {
	cfg := secureBaseline()
	cfg.RateLimit.PerAgent = 0
	findings := checkRateLimitDisabled(cfg, "")
	require.Len(t, findings, 1)
	assert.Equal(t, "MON-001", findings[0].CheckID)
	assert.Equal(t, AuditHigh, findings[0].Severity)
}

// --- SIG-002 ---

func TestCheckKeysDirectory_Missing(t *testing.T) {
	cfg := secureBaseline()
	cfg.Identity.KeysDir = "/nonexistent/keys"
	findings := checkKeysDirectory(cfg, "")
	require.Len(t, findings, 1)
	assert.Equal(t, "SIG-002", findings[0].CheckID)
	assert.Equal(t, AuditHigh, findings[0].Severity)
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
	assert.Equal(t, AuditMedium, findings[0].Severity)
}

// --- MON-003 ---

func TestCheckAnomalyThreshold(t *testing.T) {
	cfg := secureBaseline()
	cfg.Anomaly.RiskThreshold = 0
	findings := checkAnomalyThreshold(cfg, "")
	require.Len(t, findings, 1)
	assert.Equal(t, "MON-003", findings[0].CheckID)
	assert.Equal(t, AuditMedium, findings[0].Severity)
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
	assert.Equal(t, AuditMedium, findings[0].Severity)
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
	assert.Equal(t, AuditMedium, findings[0].Severity)
}

// --- ENG-001 ---

func TestCheckNoCustomRules(t *testing.T) {
	cfg := secureBaseline()
	cfg.CustomRulesDir = ""
	findings := checkNoCustomRules(cfg, "")
	require.Len(t, findings, 1)
	assert.Equal(t, "ENG-001", findings[0].CheckID)
	assert.Equal(t, AuditMedium, findings[0].Severity)
}

// --- NET-002 ---

func TestCheckForwardProxyNoScanResponses(t *testing.T) {
	cfg := secureBaseline()
	cfg.ForwardProxy.Enabled = true
	cfg.ForwardProxy.ScanResponses = false
	findings := checkForwardProxyNoScanResponses(cfg, "")
	require.Len(t, findings, 1)
	assert.Equal(t, "NET-002", findings[0].CheckID)
	assert.Equal(t, AuditMedium, findings[0].Severity)
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
	assert.Equal(t, AuditMedium, findings[0].Severity)
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
	assert.Equal(t, AuditInfo, findings[0].Severity)
	assert.Contains(t, findings[0].Title, "not found")
}

func TestCheckAuditDatabase_Exists(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "oktsec.db"), []byte("data"), 0o644))

	cfg := secureBaseline()
	findings := checkAuditDatabase(cfg, dir)
	require.Len(t, findings, 1)
	assert.Equal(t, "RET-003", findings[0].CheckID)
	assert.Equal(t, AuditInfo, findings[0].Severity)
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

func TestRunAuditChecks_SecureConfig(t *testing.T) {
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	require.NoError(t, os.Mkdir(keysDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "agent-a.pub"), []byte("key"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "agent-a.key"), []byte("priv"), 0o600))

	cfg := secureBaseline()
	cfg.Identity.KeysDir = keysDir

	findings, _ := runAuditChecks(cfg, dir)

	// A fully hardened config should only produce info-level oktsec findings.
	// Product auditors won't detect anything because no products are installed in the test tempdir.
	for _, f := range findings {
		assert.LessOrEqual(t, f.Severity, AuditInfo,
			"unexpected finding: [%s] %s — %s", f.CheckID, f.Title, f.Detail)
	}
}
