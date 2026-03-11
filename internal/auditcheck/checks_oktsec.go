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
		sev := Critical
		detail := "Agents can impersonate each other because message signing is off. Any process on this machine can send messages as any agent."
		if isObserveMode(cfg) {
			sev = Info
			detail = "Message signing is off, which is normal for observe mode. Turn it on when you're ready to enforce security."
		}
		return []Finding{{
			Severity:    sev,
			CheckID:     "SIG-001",
			Title:       "Message signing is off",
			Detail:      detail,
			Remediation: "identity.require_signature: true",
			FixURL:      "/dashboard/settings",
		}}
	}
	return nil
}

// isObserveMode returns true when the config is in observe (audit-only) mode.
// Observe mode is the default: no signature enforcement, no blocking.
func isObserveMode(cfg *config.Config) bool {
	return !cfg.Identity.RequireSignature
}

func checkNetworkExposure(cfg *config.Config, _ string) []Finding {
	bind := cfg.Server.Bind
	if bind == "0.0.0.0" || bind == "::" {
		return []Finding{{
			Severity:    Critical,
			CheckID:     "NET-001",
			Title:       "Proxy is accessible from the network",
			Detail:      "Anyone on your network can reach the proxy. It should only listen on localhost unless you need remote access.",
			Remediation: "server.bind: 127.0.0.1",
			FixURL:      "/dashboard/settings",
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
		sev := High
		if isObserveMode(cfg) {
			sev = Medium
		}
		return []Finding{{
			Severity:    sev,
			CheckID:     "ACL-001",
			Title:       "Unknown agents are allowed by default",
			Detail:      "Any agent not in your config can still send messages. Switch to deny-by-default so only registered agents can communicate.",
			Remediation: "default_policy: deny",
			FixURL:      "/dashboard/settings",
		}}
	}
	return nil
}

func checkNoAgents(cfg *config.Config, _ string) []Finding {
	if len(cfg.Agents) == 0 {
		return []Finding{{
			Severity:    High,
			CheckID:     "ACL-002",
			Title:       "No agents registered",
			Detail:      "Without agents, there's no access control. Register your agents so oktsec knows who's allowed to communicate.",
			Remediation: "oktsec agent add <name>",
			FixURL:      "/dashboard/agents",
		}}
	}
	return nil
}

func checkWildcardMessaging(cfg *config.Config, _ string) []Finding {
	sev := High
	if isObserveMode(cfg) {
		sev = Medium
	}
	var findings []Finding
	for name, agent := range cfg.Agents {
		for _, target := range agent.CanMessage {
			if target == "*" {
				findings = append(findings, Finding{
					Severity:    sev,
					CheckID:     "ACL-003",
					Title:       fmt.Sprintf("%s can message any agent", name),
					Detail:      fmt.Sprintf("%s has no restrictions on who it can talk to. Limit it to specific agents to prevent lateral movement.", name),
					Remediation: fmt.Sprintf("agents.%s.can_message: [specific-agents]", name),
					FixURL:      fmt.Sprintf("/dashboard/agents/%s", name),
				})
				break
			}
		}
	}
	return findings
}

func checkQuarantineDisabled(cfg *config.Config, _ string) []Finding {
	if !cfg.Quarantine.Enabled {
		sev := High
		if isObserveMode(cfg) {
			sev = Medium
		}
		return []Finding{{
			Severity:    sev,
			CheckID:     "RET-001",
			Title:       "Suspicious messages aren't quarantined",
			Detail:      "When oktsec detects something suspicious, it can hold the message for human review instead of delivering it. Enable the quarantine queue.",
			Remediation: "quarantine.enabled: true",
			FixURL:      "/dashboard/settings",
		}}
	}
	return nil
}

func checkRateLimitDisabled(cfg *config.Config, _ string) []Finding {
	if cfg.RateLimit.PerAgent == 0 {
		sev := High
		if isObserveMode(cfg) {
			sev = Medium
		}
		return []Finding{{
			Severity:    sev,
			CheckID:     "MON-001",
			Title:       "No rate limiting",
			Detail:      "A compromised or misbehaving agent could flood the system with messages. Set a per-agent limit to prevent abuse.",
			Remediation: "rate_limit.per_agent: 100",
			FixURL:      "/dashboard/settings",
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
			Title:       "No keys directory configured",
			Detail:      "Signatures are required but oktsec doesn't know where to find the agent keys. Set the keys directory.",
			Remediation: "oktsec doctor --repair",
			FixURL:      "/dashboard/settings",
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
			Title:       "Keys directory is missing",
			Detail:      fmt.Sprintf("Can't read %s. Run oktsec doctor --repair to recreate it.", cfg.Identity.KeysDir),
			Remediation: "oktsec doctor --repair",
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
			Title:       "No agent keys found",
			Detail:      "The keys directory is empty. Generate keys for your agents so they can sign messages.",
			Remediation: "oktsec doctor --repair",
		}}
	}
	return nil
}

func checkNoWebhooks(cfg *config.Config, _ string) []Finding {
	if len(cfg.Webhooks) == 0 {
		return []Finding{{
			Severity:    Medium,
			CheckID:     "MON-002",
			Title:       "No alert notifications",
			Detail:      "You won't be notified when oktsec blocks or quarantines a message. Add a webhook (Slack, email, etc.) to stay informed.",
			Remediation: "webhooks: [url]",
			FixURL:      "/dashboard/settings",
		}}
	}
	return nil
}

func checkAnomalyThreshold(cfg *config.Config, _ string) []Finding {
	if cfg.Anomaly.RiskThreshold == 0 {
		return []Finding{{
			Severity:    Medium,
			CheckID:     "MON-003",
			Title:       "Anomaly detection is off",
			Detail:      "oktsec can detect unusual agent behavior patterns (sudden spikes, new communication pairs). Enable it to catch threats early.",
			Remediation: "anomaly.risk_threshold: 80",
			FixURL:      "/dashboard/settings",
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
		Title:       "No content filtering rules",
		Detail:      "Agents can send any content type. Add blocked_content patterns to prevent agents from sending sensitive data like credentials or PII.",
		Remediation: "agents.<name>.blocked_content: [patterns]",
		FixURL:      "/dashboard/agents",
	}}
}

func checkRetentionDays(cfg *config.Config, _ string) []Finding {
	if cfg.Quarantine.RetentionDays == 0 {
		return []Finding{{
			Severity:    Medium,
			CheckID:     "RET-002",
			Title:       "Audit log grows forever",
			Detail:      "The audit database has no retention limit and will grow indefinitely. Set a retention period to manage disk space.",
			Remediation: "quarantine.retention_days: 90",
			FixURL:      "/dashboard/settings",
		}}
	}
	return nil
}

func checkNoCustomRules(cfg *config.Config, _ string) []Finding {
	if cfg.CustomRulesDir == "" {
		return []Finding{{
			Severity:    Medium,
			CheckID:     "ENG-001",
			Title:       "Using default detection rules only",
			Detail:      "oktsec ships with 188 built-in rules. Add custom rules specific to your environment for better coverage.",
			Remediation: "custom_rules_dir: ./rules",
			FixURL:      "/dashboard/rules",
		}}
	}
	return nil
}

func checkForwardProxyNoScanResponses(cfg *config.Config, _ string) []Finding {
	if cfg.ForwardProxy.Enabled && !cfg.ForwardProxy.ScanResponses {
		return []Finding{{
			Severity:    Medium,
			CheckID:     "NET-002",
			Title:       "Egress responses aren't scanned",
			Detail:      "The forward proxy is active but not inspecting HTTP responses. Enable response scanning to catch data exfiltration.",
			Remediation: "forward_proxy.scan_responses: true",
			FixURL:      "/dashboard/settings",
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
				Title:       fmt.Sprintf("Private key %q is readable by others", e.Name()),
				Detail:      fmt.Sprintf("Other users on this machine can read this key. Fix with: chmod 600 %s", filepath.Join(keysDir, e.Name())),
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
			Title:    "Audit database not created yet",
			Detail:   "The database will be created automatically when the proxy processes its first message.",
		}}
	}
	sizeMB := float64(info.Size()) / (1024 * 1024)
	return []Finding{{
		Severity: Info,
		CheckID:  "RET-003",
		Title:    "Audit database active",
		Detail:   fmt.Sprintf("Audit trail is recording (%.1f MB).", sizeMB),
	}}
}
