package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/identity"
	"github.com/spf13/cobra"
)

// AuditSeverity represents the severity of an audit finding.
type AuditSeverity int

const (
	AuditInfo AuditSeverity = iota
	AuditLow
	AuditMedium
	AuditHigh
	AuditCritical
)

func (s AuditSeverity) String() string {
	switch s {
	case AuditInfo:
		return "INFO"
	case AuditLow:
		return "LOW"
	case AuditMedium:
		return "MEDIUM"
	case AuditHigh:
		return "HIGH"
	case AuditCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// AuditFinding is a single issue found during the audit.
type AuditFinding struct {
	Severity AuditSeverity `json:"severity"`
	CheckID  string        `json:"check_id"`
	Title    string        `json:"title"`
	Detail   string        `json:"detail"`
	Product  string        `json:"product,omitempty"`
}

// auditReport is the full audit output.
type auditReport struct {
	ConfigPath string         `json:"config_path"`
	Findings   []AuditFinding `json:"findings"`
	KeysLoaded int            `json:"keys_loaded"`
	AgentCount int            `json:"agent_count"`
	Detected   []string       `json:"detected"`
	Summary    auditSummary   `json:"summary"`
}

type auditSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type checkFunc func(*config.Config, string) []AuditFinding

// productAuditor auto-detects and audits a third-party agent framework.
type productAuditor struct {
	name  string
	audit func() []AuditFinding
}

var productAuditors = []productAuditor{
	{"OpenClaw", auditOpenClaw},
	{"NanoClaw", auditNanoClaw},
}

func newAuditCmd() *cobra.Command {
	var jsonOutput bool
	var sarifOutput bool

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Check deployment security configuration",
		Long:  "Analyzes the oktsec configuration file and filesystem state, producing a security report with actionable findings.",
		Example: `  oktsec audit
  oktsec audit --json
  oktsec audit --sarif
  oktsec audit --config /path/to/oktsec.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			configDir := filepath.Dir(cfgFile)
			if configDir == "." {
				if wd, err := os.Getwd(); err == nil {
					configDir = wd
				}
			}

			findings, detected := runAuditChecks(cfg, configDir)

			// Count keys
			keysLoaded := 0
			if cfg.Identity.KeysDir != "" {
				keysDir := cfg.Identity.KeysDir
				if !filepath.IsAbs(keysDir) {
					keysDir = filepath.Join(configDir, keysDir)
				}
				ks := identity.NewKeyStore()
				if err := ks.LoadFromDir(keysDir); err == nil {
					keysLoaded = ks.Count()
				}
			}

			report := auditReport{
				ConfigPath: cfgFile,
				Findings:   findings,
				KeysLoaded: keysLoaded,
				AgentCount: len(cfg.Agents),
				Detected:   detected,
			}
			for _, f := range findings {
				switch f.Severity {
				case AuditCritical:
					report.Summary.Critical++
				case AuditHigh:
					report.Summary.High++
				case AuditMedium:
					report.Summary.Medium++
				case AuditLow:
					report.Summary.Low++
				case AuditInfo:
					report.Summary.Info++
				}
			}

			if sarifOutput {
				return printAuditSARIF(report)
			}
			if jsonOutput {
				return printAuditJSON(report)
			}
			printAuditTerminal(report)

			if report.Summary.Critical > 0 || report.Summary.High > 0 {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output as JSON")
	cmd.Flags().BoolVar(&sarifOutput, "sarif", false, "output as SARIF v2.1.0")
	return cmd
}

func runAuditChecks(cfg *config.Config, configDir string) ([]AuditFinding, []string) {
	checks := []checkFunc{
		checkSignatureDisabled,
		checkNetworkExposure,
		checkDefaultPolicyAllow,
		checkNoAgents,
		checkWildcardMessaging,
		checkQuarantineDisabled,
		checkRateLimitDisabled,
		checkKeysDirectory,
		checkNoWebhooks,
		checkAnomalyThreshold,
		checkNoBlockedContent,
		checkRetentionDays,
		checkNoCustomRules,
		checkForwardProxyNoScanResponses,
		checkPrivateKeyPermissions,
		checkAuditDatabase,
	}

	var findings []AuditFinding
	for _, check := range checks {
		findings = append(findings, check(cfg, configDir)...)
	}

	var detected []string
	for _, pa := range productAuditors {
		pf := pa.audit()
		if pf != nil {
			detected = append(detected, pa.name)
			findings = append(findings, pf...)
		}
	}

	return findings, detected
}

// --- Checks ---

func checkSignatureDisabled(cfg *config.Config, _ string) []AuditFinding {
	if !cfg.Identity.RequireSignature {
		return []AuditFinding{{
			Severity: AuditCritical,
			CheckID:  "SIG-001",
			Title:    "Message signatures not required",
			Detail:   "require_signature is false — any process can spoof agent identity. Set identity.require_signature: true.",
		}}
	}
	return nil
}

func checkNetworkExposure(cfg *config.Config, _ string) []AuditFinding {
	bind := cfg.Server.Bind
	if bind == "0.0.0.0" || bind == "::" {
		return []AuditFinding{{
			Severity: AuditCritical,
			CheckID:  "NET-001",
			Title:    "Proxy exposed to all network interfaces",
			Detail:   fmt.Sprintf("server.bind is %q — the proxy accepts connections from any host. Set server.bind: 127.0.0.1.", bind),
		}}
	}
	return nil
}

func checkDefaultPolicyAllow(cfg *config.Config, _ string) []AuditFinding {
	policy := cfg.DefaultPolicy
	if policy == "" {
		policy = "allow"
	}
	if policy == "allow" && len(cfg.Agents) > 0 {
		return []AuditFinding{{
			Severity: AuditHigh,
			CheckID:  "ACL-001",
			Title:    "Default policy is 'allow' with agents defined",
			Detail:   "Unconfigured agents bypass ACL entirely. Set default_policy: deny.",
		}}
	}
	return nil
}

func checkNoAgents(cfg *config.Config, _ string) []AuditFinding {
	if len(cfg.Agents) == 0 {
		return []AuditFinding{{
			Severity: AuditHigh,
			CheckID:  "ACL-002",
			Title:    "No agents defined",
			Detail:   "Without agent definitions there is no access control. Define agents in the config.",
		}}
	}
	return nil
}

func checkWildcardMessaging(cfg *config.Config, _ string) []AuditFinding {
	var findings []AuditFinding
	for name, agent := range cfg.Agents {
		for _, target := range agent.CanMessage {
			if target == "*" {
				findings = append(findings, AuditFinding{
					Severity: AuditHigh,
					CheckID:  "ACL-003",
					Title:    fmt.Sprintf("Agent %q can message everyone", name),
					Detail:   fmt.Sprintf("Agent %q has can_message: [\"*\"]. Restrict to specific targets.", name),
				})
				break
			}
		}
	}
	return findings
}

func checkQuarantineDisabled(cfg *config.Config, _ string) []AuditFinding {
	if !cfg.Quarantine.Enabled {
		return []AuditFinding{{
			Severity: AuditHigh,
			CheckID:  "RET-001",
			Title:    "Quarantine queue disabled",
			Detail:   "Suspicious messages are not held for human review. Set quarantine.enabled: true.",
		}}
	}
	return nil
}

func checkRateLimitDisabled(cfg *config.Config, _ string) []AuditFinding {
	if cfg.RateLimit.PerAgent == 0 {
		return []AuditFinding{{
			Severity: AuditHigh,
			CheckID:  "MON-001",
			Title:    "No per-agent rate limit",
			Detail:   "A compromised agent can flood the proxy. Set rate_limit.per_agent to a reasonable value.",
		}}
	}
	return nil
}

func checkKeysDirectory(cfg *config.Config, configDir string) []AuditFinding {
	if !cfg.Identity.RequireSignature {
		return nil
	}

	keysDir := cfg.Identity.KeysDir
	if keysDir == "" {
		return []AuditFinding{{
			Severity: AuditHigh,
			CheckID:  "SIG-002",
			Title:    "Keys directory not configured",
			Detail:   "Signatures are required but no keys_dir is set. Set identity.keys_dir.",
		}}
	}

	if !filepath.IsAbs(keysDir) {
		keysDir = filepath.Join(configDir, keysDir)
	}

	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return []AuditFinding{{
			Severity: AuditHigh,
			CheckID:  "SIG-002",
			Title:    "Keys directory missing or unreadable",
			Detail:   fmt.Sprintf("Cannot read keys directory %q: %v", cfg.Identity.KeysDir, err),
		}}
	}

	pubCount := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".pub") {
			pubCount++
		}
	}
	if pubCount == 0 {
		return []AuditFinding{{
			Severity: AuditHigh,
			CheckID:  "SIG-002",
			Title:    "Keys directory is empty",
			Detail:   fmt.Sprintf("No .pub files in %q. Generate keys with 'oktsec keygen'.", cfg.Identity.KeysDir),
		}}
	}
	return nil
}

func checkNoWebhooks(cfg *config.Config, _ string) []AuditFinding {
	if len(cfg.Webhooks) == 0 {
		return []AuditFinding{{
			Severity: AuditMedium,
			CheckID:  "MON-002",
			Title:    "No webhooks configured",
			Detail:   "No external alerting for blocked or quarantined messages. Add webhooks for monitoring.",
		}}
	}
	return nil
}

func checkAnomalyThreshold(cfg *config.Config, _ string) []AuditFinding {
	if cfg.Anomaly.RiskThreshold == 0 {
		return []AuditFinding{{
			Severity: AuditMedium,
			CheckID:  "MON-003",
			Title:    "Anomaly detection threshold is zero",
			Detail:   "No behavioral monitoring. Set anomaly.risk_threshold to enable anomaly detection.",
		}}
	}
	return nil
}

func checkNoBlockedContent(cfg *config.Config, _ string) []AuditFinding {
	if len(cfg.Agents) == 0 {
		return nil
	}
	for _, agent := range cfg.Agents {
		if len(agent.BlockedContent) > 0 {
			return nil
		}
	}
	return []AuditFinding{{
		Severity: AuditMedium,
		CheckID:  "ACL-004",
		Title:    "No agents have blocked_content rules",
		Detail:   "Content filtering is not in use. Add blocked_content patterns to agents.",
	}}
}

func checkRetentionDays(cfg *config.Config, _ string) []AuditFinding {
	if cfg.Quarantine.RetentionDays == 0 {
		return []AuditFinding{{
			Severity: AuditMedium,
			CheckID:  "RET-002",
			Title:    "Audit log retention is unlimited",
			Detail:   "retention_days is 0 — the audit log will grow indefinitely. Set quarantine.retention_days.",
		}}
	}
	return nil
}

func checkNoCustomRules(cfg *config.Config, _ string) []AuditFinding {
	if cfg.CustomRulesDir == "" {
		return []AuditFinding{{
			Severity: AuditMedium,
			CheckID:  "ENG-001",
			Title:    "No custom rules directory",
			Detail:   "Only default Aguara rules are applied. Set custom_rules_dir for environment-specific detections.",
		}}
	}
	return nil
}

func checkForwardProxyNoScanResponses(cfg *config.Config, _ string) []AuditFinding {
	if cfg.ForwardProxy.Enabled && !cfg.ForwardProxy.ScanResponses {
		return []AuditFinding{{
			Severity: AuditMedium,
			CheckID:  "NET-002",
			Title:    "Forward proxy does not scan responses",
			Detail:   "Inbound HTTP bodies are not inspected. Set forward_proxy.scan_responses: true.",
		}}
	}
	return nil
}

func checkPrivateKeyPermissions(cfg *config.Config, configDir string) []AuditFinding {
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

	var findings []AuditFinding
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
			findings = append(findings, AuditFinding{
				Severity: AuditMedium,
				CheckID:  "SIG-003",
				Title:    fmt.Sprintf("Private key %q has loose permissions", e.Name()),
				Detail:   fmt.Sprintf("File mode is %04o — group/world readable. Run: chmod 600 %s", mode, filepath.Join(keysDir, e.Name())),
			})
		}
	}
	return findings
}

func checkAuditDatabase(_ *config.Config, configDir string) []AuditFinding {
	dbPath := filepath.Join(configDir, "oktsec.db")
	info, err := os.Stat(dbPath)
	if err != nil {
		return []AuditFinding{{
			Severity: AuditInfo,
			CheckID:  "RET-003",
			Title:    "Audit database not found",
			Detail:   fmt.Sprintf("No oktsec.db at %s — the proxy has not run yet or uses a different path.", configDir),
		}}
	}
	sizeMB := float64(info.Size()) / (1024 * 1024)
	return []AuditFinding{{
		Severity: AuditInfo,
		CheckID:  "RET-003",
		Title:    "Audit database present",
		Detail:   fmt.Sprintf("oktsec.db exists (%.1f MB).", sizeMB),
	}}
}

// --- Output ---

func printAuditTerminal(report auditReport) {
	fmt.Println()
	fmt.Println("  oktsec audit")
	fmt.Println("  ────────────────────────────────────────")
	fmt.Printf("  Config:     %s\n", report.ConfigPath)
	fmt.Printf("  Agents:     %d\n", report.AgentCount)
	fmt.Printf("  Keys:       %d loaded\n", report.KeysLoaded)
	if len(report.Detected) > 0 {
		fmt.Printf("  Detected:   %s\n", strings.Join(report.Detected, ", "))
	}

	// Group findings by product, then by severity
	products := []string{""} // oktsec first (empty product)
	products = append(products, report.Detected...)

	byProduct := map[string][]AuditFinding{}
	for _, f := range report.Findings {
		byProduct[f.Product] = append(byProduct[f.Product], f)
	}

	for _, product := range products {
		pFindings := byProduct[product]
		if len(pFindings) == 0 {
			continue
		}

		fmt.Println()
		if product == "" {
			fmt.Println("  OKTSEC")
		} else {
			fmt.Printf("  %s\n", strings.ToUpper(product))
		}

		bySeverity := map[AuditSeverity][]AuditFinding{}
		for _, f := range pFindings {
			bySeverity[f.Severity] = append(bySeverity[f.Severity], f)
		}

		for _, sev := range []AuditSeverity{AuditCritical, AuditHigh, AuditMedium, AuditLow, AuditInfo} {
			group := bySeverity[sev]
			if len(group) == 0 {
				continue
			}
			fmt.Printf("    %s (%d)\n", sev, len(group))
			for _, f := range group {
				fmt.Printf("      [%s] %s\n", f.CheckID, f.Title)
				fmt.Printf("                %s\n", f.Detail)
			}
		}
	}

	fmt.Println()
	fmt.Println("  ────────────────────────────────────────")
	fmt.Printf("  Findings: %d critical, %d high, %d medium, %d info\n",
		report.Summary.Critical, report.Summary.High, report.Summary.Medium, report.Summary.Info)
	fmt.Println()
}

func printAuditJSON(report auditReport) error {
	type jsonFinding struct {
		Severity string `json:"severity"`
		CheckID  string `json:"check_id"`
		Title    string `json:"title"`
		Detail   string `json:"detail"`
		Product  string `json:"product,omitempty"`
	}
	type jsonReport struct {
		ConfigPath string        `json:"config_path"`
		Findings   []jsonFinding `json:"findings"`
		KeysLoaded int           `json:"keys_loaded"`
		AgentCount int           `json:"agent_count"`
		Detected   []string      `json:"detected"`
		Summary    auditSummary  `json:"summary"`
	}

	jr := jsonReport{
		ConfigPath: report.ConfigPath,
		KeysLoaded: report.KeysLoaded,
		AgentCount: report.AgentCount,
		Detected:   report.Detected,
		Summary:    report.Summary,
	}
	if jr.Detected == nil {
		jr.Detected = []string{}
	}
	for _, f := range report.Findings {
		jr.Findings = append(jr.Findings, jsonFinding{
			Severity: f.Severity.String(),
			CheckID:  f.CheckID,
			Title:    f.Title,
			Detail:   f.Detail,
			Product:  f.Product,
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(jr)
}

