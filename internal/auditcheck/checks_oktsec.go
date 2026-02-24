package auditcheck

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oktsec/oktsec/internal/config"
)

func checkSignatureDisabled(cfg *config.Config, _ string) []Finding {
	if !cfg.Identity.RequireSignature {
		return []Finding{{
			Severity:    Critical,
			CheckID:     "SIG-001",
			Title:       "Message signatures not required",
			Detail:      "require_signature is false — any process can spoof agent identity. Set identity.require_signature: true.",
			Remediation: "Set identity.require_signature: true",
		}}
	}
	return nil
}

func checkNetworkExposure(cfg *config.Config, _ string) []Finding {
	bind := cfg.Server.Bind
	if bind == "0.0.0.0" || bind == "::" {
		return []Finding{{
			Severity:    Critical,
			CheckID:     "NET-001",
			Title:       "Proxy exposed to all network interfaces",
			Detail:      fmt.Sprintf("server.bind is %q — the proxy accepts connections from any host. Set server.bind: 127.0.0.1.", bind),
			Remediation: `Set server.bind: "127.0.0.1"`,
		}}
	}
	return nil
}

func checkDefaultPolicyAllow(cfg *config.Config, _ string) []Finding {
	policy := cfg.DefaultPolicy
	if policy == "" {
		policy = "allow"
	}
	if policy == "allow" && len(cfg.Agents) > 0 {
		return []Finding{{
			Severity:    High,
			CheckID:     "ACL-001",
			Title:       "Default policy is 'allow' with agents defined",
			Detail:      "Unconfigured agents bypass ACL entirely. Set default_policy: deny.",
			Remediation: "Set default_policy: deny",
		}}
	}
	return nil
}

func checkNoAgents(cfg *config.Config, _ string) []Finding {
	if len(cfg.Agents) == 0 {
		return []Finding{{
			Severity:    High,
			CheckID:     "ACL-002",
			Title:       "No agents defined",
			Detail:      "Without agent definitions there is no access control. Define agents in the config.",
			Remediation: "Add agents with oktsec agent add <name>",
		}}
	}
	return nil
}

func checkWildcardMessaging(cfg *config.Config, _ string) []Finding {
	var findings []Finding
	for name, agent := range cfg.Agents {
		for _, target := range agent.CanMessage {
			if target == "*" {
				findings = append(findings, Finding{
					Severity:    High,
					CheckID:     "ACL-003",
					Title:       fmt.Sprintf("Agent %q can message everyone", name),
					Detail:      fmt.Sprintf("Agent %q has can_message: [\"*\"]. Restrict to specific targets.", name),
					Remediation: `Replace can_message: ["*"] with specific names`,
				})
				break
			}
		}
	}
	return findings
}

func checkQuarantineDisabled(cfg *config.Config, _ string) []Finding {
	if !cfg.Quarantine.Enabled {
		return []Finding{{
			Severity:    High,
			CheckID:     "RET-001",
			Title:       "Quarantine queue disabled",
			Detail:      "Suspicious messages are not held for human review. Set quarantine.enabled: true.",
			Remediation: "Set quarantine.enabled: true",
		}}
	}
	return nil
}

func checkRateLimitDisabled(cfg *config.Config, _ string) []Finding {
	if cfg.RateLimit.PerAgent == 0 {
		return []Finding{{
			Severity:    High,
			CheckID:     "MON-001",
			Title:       "No per-agent rate limit",
			Detail:      "A compromised agent can flood the proxy. Set rate_limit.per_agent to a reasonable value.",
			Remediation: "Set rate_limit.per_agent: 100",
		}}
	}
	return nil
}

func checkKeysDirectory(cfg *config.Config, configDir string) []Finding {
	if !cfg.Identity.RequireSignature {
		return nil
	}

	keysDir := cfg.Identity.KeysDir
	if keysDir == "" {
		return []Finding{{
			Severity:    High,
			CheckID:     "SIG-002",
			Title:       "Keys directory not configured",
			Detail:      "Signatures are required but no keys_dir is set. Set identity.keys_dir.",
			Remediation: "Run oktsec keygen <agent-name>",
		}}
	}

	if !filepath.IsAbs(keysDir) {
		keysDir = filepath.Join(configDir, keysDir)
	}

	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return []Finding{{
			Severity:    High,
			CheckID:     "SIG-002",
			Title:       "Keys directory missing or unreadable",
			Detail:      fmt.Sprintf("Cannot read keys directory %q: %v", cfg.Identity.KeysDir, err),
			Remediation: "Run oktsec keygen <agent-name>",
		}}
	}

	pubCount := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".pub") {
			pubCount++
		}
	}
	if pubCount == 0 {
		return []Finding{{
			Severity:    High,
			CheckID:     "SIG-002",
			Title:       "Keys directory is empty",
			Detail:      fmt.Sprintf("No .pub files in %q. Generate keys with 'oktsec keygen'.", cfg.Identity.KeysDir),
			Remediation: "Run oktsec keygen <agent-name>",
		}}
	}
	return nil
}

func checkNoWebhooks(cfg *config.Config, _ string) []Finding {
	if len(cfg.Webhooks) == 0 {
		return []Finding{{
			Severity:    Medium,
			CheckID:     "MON-002",
			Title:       "No webhooks configured",
			Detail:      "No external alerting for blocked or quarantined messages. Add webhooks for monitoring.",
			Remediation: "Add webhook URLs under webhooks:",
		}}
	}
	return nil
}

func checkAnomalyThreshold(cfg *config.Config, _ string) []Finding {
	if cfg.Anomaly.RiskThreshold == 0 {
		return []Finding{{
			Severity:    Medium,
			CheckID:     "MON-003",
			Title:       "Anomaly detection threshold is zero",
			Detail:      "No behavioral monitoring. Set anomaly.risk_threshold to enable anomaly detection.",
			Remediation: "Set anomaly.risk_threshold: 80",
		}}
	}
	return nil
}

func checkNoBlockedContent(cfg *config.Config, _ string) []Finding {
	if len(cfg.Agents) == 0 {
		return nil
	}
	for _, agent := range cfg.Agents {
		if len(agent.BlockedContent) > 0 {
			return nil
		}
	}
	return []Finding{{
		Severity:    Medium,
		CheckID:     "ACL-004",
		Title:       "No agents have blocked_content rules",
		Detail:      "Content filtering is not in use. Add blocked_content patterns to agents.",
		Remediation: "Add blocked_content patterns to agents",
	}}
}

func checkRetentionDays(cfg *config.Config, _ string) []Finding {
	if cfg.Quarantine.RetentionDays == 0 {
		return []Finding{{
			Severity:    Medium,
			CheckID:     "RET-002",
			Title:       "Audit log retention is unlimited",
			Detail:      "retention_days is 0 — the audit log will grow indefinitely. Set quarantine.retention_days.",
			Remediation: "Set quarantine.retention_days: 90",
		}}
	}
	return nil
}

func checkNoCustomRules(cfg *config.Config, _ string) []Finding {
	if cfg.CustomRulesDir == "" {
		return []Finding{{
			Severity:    Medium,
			CheckID:     "ENG-001",
			Title:       "No custom rules directory",
			Detail:      "Only default Aguara rules are applied. Set custom_rules_dir for environment-specific detections.",
			Remediation: "Set custom_rules_dir: ./custom-rules",
		}}
	}
	return nil
}

func checkForwardProxyNoScanResponses(cfg *config.Config, _ string) []Finding {
	if cfg.ForwardProxy.Enabled && !cfg.ForwardProxy.ScanResponses {
		return []Finding{{
			Severity:    Medium,
			CheckID:     "NET-002",
			Title:       "Forward proxy does not scan responses",
			Detail:      "Inbound HTTP bodies are not inspected. Set forward_proxy.scan_responses: true.",
			Remediation: "Set forward_proxy.scan_responses: true",
		}}
	}
	return nil
}

func checkPrivateKeyPermissions(cfg *config.Config, configDir string) []Finding {
	keysDir := cfg.Identity.KeysDir
	if keysDir == "" {
		return nil
	}
	if !filepath.IsAbs(keysDir) {
		keysDir = filepath.Join(configDir, keysDir)
	}

	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return nil
	}

	var findings []Finding
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".pub") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		mode := info.Mode().Perm()
		if mode&0o077 != 0 {
			findings = append(findings, Finding{
				Severity:    Medium,
				CheckID:     "SIG-003",
				Title:       fmt.Sprintf("Private key %q has loose permissions", e.Name()),
				Detail:      fmt.Sprintf("File mode is %04o — group/world readable. Run: chmod 600 %s", mode, filepath.Join(keysDir, e.Name())),
				Remediation: fmt.Sprintf("chmod 600 %s", filepath.Join(keysDir, e.Name())),
			})
		}
	}
	return findings
}

func checkAuditDatabase(_ *config.Config, configDir string) []Finding {
	dbPath := filepath.Join(configDir, "oktsec.db")
	info, err := os.Stat(dbPath)
	if err != nil {
		return []Finding{{
			Severity: Info,
			CheckID:  "RET-003",
			Title:    "Audit database not found",
			Detail:   fmt.Sprintf("No oktsec.db at %s — the proxy has not run yet or uses a different path.", configDir),
		}}
	}
	sizeMB := float64(info.Size()) / (1024 * 1024)
	return []Finding{{
		Severity: Info,
		CheckID:  "RET-003",
		Title:    "Audit database present",
		Detail:   fmt.Sprintf("oktsec.db exists (%.1f MB).", sizeMB),
	}}
}
