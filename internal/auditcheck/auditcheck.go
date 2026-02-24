// Package auditcheck provides security audit checks for oktsec and
// third-party agent frameworks (OpenClaw, NanoClaw). Both the CLI
// commands and the dashboard import this package.
package auditcheck

import (
	"path/filepath"

	"github.com/oktsec/oktsec/internal/config"
)

// Severity represents the severity of an audit finding.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Info:
		return "INFO"
	case Low:
		return "LOW"
	case Medium:
		return "MEDIUM"
	case High:
		return "HIGH"
	case Critical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// Finding is a single issue found during the audit.
type Finding struct {
	Severity    Severity `json:"severity"`
	CheckID     string   `json:"check_id"`
	Title       string   `json:"title"`
	Detail      string   `json:"detail"`
	Product     string   `json:"product,omitempty"`
	ConfigPath  string   `json:"config_path,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

// ProductInfo holds metadata about a detected product for UI display.
type ProductInfo struct {
	Name        string
	Description string
	ConfigPath  string
	DocsURL     string
	Icon        string
}

// ProductInfoFor returns metadata for a known product with dynamic config path.
func ProductInfoFor(name, configDir string) ProductInfo {
	switch name {
	case "Oktsec":
		return ProductInfo{
			Name:        "Oktsec",
			Description: "Security proxy for AI agent-to-agent communication",
			ConfigPath:  filepath.Join(configDir, "oktsec.yaml"),
			DocsURL:     "https://github.com/oktsec/oktsec",
			Icon:        "\U0001f6e1\ufe0f",
		}
	case "OpenClaw":
		return ProductInfo{
			Name:        "OpenClaw",
			Description: "AI agent gateway — multi-channel personal assistant platform",
			ConfigPath:  defaultOpenClawConfigPath(),
			DocsURL:     "https://docs.openclaw.ai/gateway/security",
			Icon:        "\U0001f980",
		}
	case "NanoClaw":
		return ProductInfo{
			Name:        "NanoClaw",
			Description: "Lightweight container mount security for AI agents",
			ConfigPath:  defaultNanoClawAllowlistPath(),
			DocsURL:     "https://github.com/nanoclaw/nanoclaw",
			Icon:        "\U0001f512",
		}
	default:
		return ProductInfo{Name: name}
	}
}

// Summary holds aggregate counts by severity level.
type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type checkFunc func(*config.Config, string) []Finding

// productAuditor auto-detects and audits a third-party agent framework.
type productAuditor struct {
	name  string
	audit func() []Finding
}

var productAuditors = []productAuditor{
	{"OpenClaw", auditOpenClaw},
	{"NanoClaw", auditNanoClaw},
}

// RunChecks executes all audit checks against the given config and returns
// findings, a list of detected third-party products, and product metadata.
func RunChecks(cfg *config.Config, configDir string) ([]Finding, []string, map[string]ProductInfo) {
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

	var findings []Finding
	for _, check := range checks {
		findings = append(findings, check(cfg, configDir)...)
	}

	// Set ConfigPath for all oktsec findings (product == "")
	oktsecConfigPath := filepath.Join(configDir, "oktsec.yaml")
	for i := range findings {
		if findings[i].Product == "" && findings[i].ConfigPath == "" {
			findings[i].ConfigPath = oktsecConfigPath
		}
	}

	productInfos := map[string]ProductInfo{
		"Oktsec": ProductInfoFor("Oktsec", configDir),
	}

	var detected []string
	for _, pa := range productAuditors {
		pf := pa.audit()
		if pf != nil {
			detected = append(detected, pa.name)
			findings = append(findings, pf...)
			productInfos[pa.name] = ProductInfoFor(pa.name, configDir)
		}
	}

	return findings, detected, productInfos
}

// ComputeHealthScore calculates a 0-100 score from audit findings.
// Penalties: critical=-25, high=-15, medium=-5, low=-2, info=0.
func ComputeHealthScore(findings []Finding) (int, string) {
	score := 100
	for _, f := range findings {
		switch f.Severity {
		case Critical:
			score -= 25
		case High:
			score -= 15
		case Medium:
			score -= 5
		case Low:
			score -= 2
		}
	}
	if score < 0 {
		score = 0
	}

	var grade string
	switch {
	case score >= 90:
		grade = "A"
	case score >= 75:
		grade = "B"
	case score >= 60:
		grade = "C"
	case score >= 40:
		grade = "D"
	default:
		grade = "F"
	}
	return score, grade
}

// Summarize returns aggregate severity counts for a slice of findings.
func Summarize(findings []Finding) Summary {
	var s Summary
	for _, f := range findings {
		switch f.Severity {
		case Critical:
			s.Critical++
		case High:
			s.High++
		case Medium:
			s.Medium++
		case Low:
			s.Low++
		case Info:
			s.Info++
		}
	}
	return s
}
