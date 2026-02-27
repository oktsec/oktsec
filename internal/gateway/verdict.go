package gateway

import (
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
)

// applyRuleOverrides applies per-rule action overrides from cfg.Rules[].
// Duplicated from proxy/handler.go for clean package separation.
func applyRuleOverrides(rules []config.RuleAction, outcome *engine.ScanOutcome) {
	if len(rules) == 0 || len(outcome.Findings) == 0 {
		return
	}

	overrides := make(map[string]string, len(rules))
	for _, ra := range rules {
		overrides[ra.ID] = ra.Action
	}

	var kept []engine.FindingSummary
	newVerdict := engine.VerdictClean

	for _, f := range outcome.Findings {
		action, hasOverride := overrides[f.RuleID]
		if hasOverride && action == "ignore" {
			continue
		}

		kept = append(kept, f)

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
			v = defaultSeverityVerdict(f.Severity)
		}

		if verdictSeverity(v) > verdictSeverity(newVerdict) {
			newVerdict = v
		}
	}

	outcome.Findings = kept
	outcome.Verdict = newVerdict
}

// defaultSeverityVerdict maps a severity string to the default verdict.
func defaultSeverityVerdict(severity string) engine.ScanVerdict {
	switch severity {
	case "critical":
		return engine.VerdictBlock
	case "high":
		return engine.VerdictQuarantine
	case "medium":
		return engine.VerdictFlag
	default:
		return engine.VerdictClean
	}
}

// verdictSeverity maps a verdict to a numeric severity for comparison.
func verdictSeverity(v engine.ScanVerdict) int {
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
