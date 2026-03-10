package verdict

import (
	"encoding/json"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
)

// EncodeFindings marshals findings to JSON or returns "[]".
func EncodeFindings(findings []engine.FindingSummary) string {
	if len(findings) == 0 {
		return "[]"
	}
	data, err := json.Marshal(findings)
	if err != nil {
		return "[]"
	}
	return string(data)
}

// TopSeverity returns the first finding's severity, or "none".
func TopSeverity(findings []engine.FindingSummary) string {
	if len(findings) > 0 {
		return findings[0].Severity
	}
	return audit.SeverityNone
}

// DefaultSeverityVerdict maps a severity string to the default verdict.
// Mirrors the logic in engine.buildOutcome but operates on string severity.
func DefaultSeverityVerdict(severity string) engine.ScanVerdict {
	switch severity {
	case audit.SeverityCritical:
		return engine.VerdictBlock
	case audit.SeverityHigh:
		return engine.VerdictQuarantine
	case audit.SeverityMedium:
		return engine.VerdictFlag
	default:
		return engine.VerdictClean
	}
}

// Severity maps a verdict to a numeric severity for comparison.
// Higher values are more severe.
func Severity(v engine.ScanVerdict) int {
	switch v {
	case engine.VerdictBlock:
		return 3
	case engine.VerdictQuarantine:
		return 2
	case engine.VerdictFlag:
		return 1
	default:
		return 0
	}
}

// ApplyRuleOverrides applies per-rule action overrides from rules config.
// - "ignore" removes findings from the outcome entirely
// - "block"/"quarantine"/"allow-and-flag" overrides that finding's verdict contribution
// Findings without a matching rule keep the default severity-based verdict.
func ApplyRuleOverrides(rules []config.RuleAction, outcome *engine.ScanOutcome) {
	if len(rules) == 0 || len(outcome.Findings) == 0 {
		return
	}

	// Build lookup: ruleID -> action
	overrides := make(map[string]string, len(rules))
	for _, ra := range rules {
		overrides[ra.ID] = ra.Action
	}

	// Filter findings and recalculate verdict
	var kept []engine.FindingSummary
	newVerdict := engine.VerdictClean

	for _, f := range outcome.Findings {
		action, hasOverride := overrides[f.RuleID]
		if hasOverride && action == "ignore" {
			continue // drop finding entirely
		}

		kept = append(kept, f)

		// Determine this finding's verdict
		var v engine.ScanVerdict
		if hasOverride {
			switch action {
			case "block":
				v = engine.VerdictBlock
			case "quarantine":
				v = engine.VerdictQuarantine
			case "allow-and-flag":
				v = engine.VerdictFlag
			}
		} else {
			v = DefaultSeverityVerdict(f.Severity)
		}

		// Keep the most severe verdict
		if Severity(v) > Severity(newVerdict) {
			newVerdict = v
		}
	}

	outcome.Findings = kept
	outcome.Verdict = newVerdict
}

// ApplyBlockedContent escalates verdict to block if any finding's category
// matches the agent's blocked_content list.
func ApplyBlockedContent(agent config.Agent, outcome *engine.ScanOutcome) {
	if len(agent.BlockedContent) == 0 || len(outcome.Findings) == 0 {
		return
	}
	blocked := make(map[string]bool, len(agent.BlockedContent))
	for _, cat := range agent.BlockedContent {
		blocked[cat] = true
	}
	for _, f := range outcome.Findings {
		if blocked[f.Category] {
			outcome.Verdict = engine.VerdictBlock
			return
		}
	}
}
