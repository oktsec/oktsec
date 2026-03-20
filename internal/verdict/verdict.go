package verdict

import (
	"encoding/json"
	"strings"

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
// Case-insensitive because Aguara reports "CRITICAL" while audit constants
// use "critical".
func DefaultSeverityVerdict(severity string) engine.ScanVerdict {
	switch strings.ToLower(severity) {
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

// ToAuditStatus maps a scan verdict to the corresponding audit status and decision.
func ToAuditStatus(v engine.ScanVerdict) (status, decision string) {
	switch v {
	case engine.VerdictBlock:
		return audit.StatusBlocked, audit.DecisionContentBlocked
	case engine.VerdictQuarantine:
		return audit.StatusQuarantined, audit.DecisionContentQuarantined
	case engine.VerdictFlag:
		return audit.StatusDelivered, audit.DecisionContentFlagged
	default:
		return audit.StatusDelivered, audit.DecisionAllow
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

// ApplyToolScopedOverrides applies tool-aware rule filtering including
// oktsec's built-in tool exemptions. Use this when Aguara did NOT receive
// tool context (callers that use ScanContent without tool name).
func ApplyToolScopedOverrides(rules []config.RuleAction, outcome *engine.ScanOutcome, toolName string) {
	applyToolScopedOverrides(rules, outcome, toolName, true)
}

// ApplyToolScopedOverridesPostAguara applies tool-aware rule filtering but
// skips built-in tool exemptions because Aguara already applied them during
// scanning (when tool name was passed via WithToolName). Still applies:
// ContentTools filtering, DevWorkflowTools/NLP_ exemption, user overrides.
func ApplyToolScopedOverridesPostAguara(rules []config.RuleAction, outcome *engine.ScanOutcome, toolName string) {
	applyToolScopedOverrides(rules, outcome, toolName, false)
}

func applyToolScopedOverrides(rules []config.RuleAction, outcome *engine.ScanOutcome, toolName string, applyBuiltinExemptions bool) {
	if len(outcome.Findings) == 0 {
		return
	}

	type ruleOvr struct {
		action string
		scoped bool // true if tool is in scope
	}
	overrides := make(map[string]ruleOvr, len(rules))
	for _, ra := range rules {
		scoped := true
		if len(ra.ApplyToTools) > 0 {
			scoped = containsTool(ra.ApplyToTools, toolName)
		} else if len(ra.ExemptTools) > 0 {
			scoped = !containsTool(ra.ExemptTools, toolName)
		}
		overrides[ra.ID] = ruleOvr{action: ra.Action, scoped: scoped}
	}

	kept := make([]engine.FindingSummary, 0, len(outcome.Findings))
	newVerdict := engine.VerdictClean

	// Content tools: only enforce minimal rules (file content matches many patterns).
	// Dev workflow tools: exempt NLP rules (commit messages, prompts contain descriptive text).
	isContentTool := config.ContentTools[toolName]
	isDevTool := config.DevWorkflowTools[toolName]

	for _, f := range outcome.Findings {
		ovr, hasOverride := overrides[f.RuleID]
		// If rule is scoped to specific tools and current tool is NOT in scope,
		// drop the finding entirely (it doesn't apply to this tool).
		if hasOverride && !ovr.scoped {
			continue
		}

		// Content tools: only enforce critical rules (path traversal,
		// system directory write, credential leak). Everything else is
		// expected file content, not an attack.
		if isContentTool && !hasOverride && !config.MinimalEnforceRules[f.RuleID] {
			continue
		}

		// NLP rules exempt on Bash and dev workflow tools — these contain
		// descriptive text (commit messages, prompts, task descriptions)
		// that triggers semantic classifiers but isn't an attack.
		if !hasOverride && (toolName == "Bash" || isDevTool) && strings.HasPrefix(f.RuleID, "NLP_") {
			continue
		}

		// Apply built-in tool exemptions when no user override exists
		// and Aguara hasn't already filtered them.
		if applyBuiltinExemptions && !hasOverride {
			if exemptTools, ok := BuiltinToolExemptions[f.RuleID]; ok {
				if containsTool(exemptTools, toolName) {
					continue
				}
			}
		}

		if hasOverride && ovr.scoped && ovr.action == "ignore" {
			continue
		}

		kept = append(kept, f)

		var v engine.ScanVerdict
		if hasOverride && ovr.scoped {
			switch ovr.action {
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

		if Severity(v) > Severity(newVerdict) {
			newVerdict = v
		}
	}

	outcome.Findings = kept
	outcome.Verdict = newVerdict
}

// ApplyScanProfile adjusts the verdict based on the agent's scan profile
// and the tool being called. Findings are preserved for audit; only the
// verdict is downgraded.
//
// content-aware: shell injection rules (TC-*) downgraded to flag for content tools
// minimal: only MinimalEnforceRules enforced, everything else flagged
func ApplyScanProfile(profile string, outcome *engine.ScanOutcome, toolName string) {
	if profile == "" || profile == config.ScanProfileStrict {
		return
	}
	if len(outcome.Findings) == 0 {
		return
	}

	switch profile {
	case config.ScanProfileContentAware:
		// Only MinimalEnforceRules can block or flag.
		// Everything else is downgraded to clean for trusted agents.
		hasMinimalRule := false
		for _, f := range outcome.Findings {
			if config.MinimalEnforceRules[f.RuleID] {
				hasMinimalRule = true
				break
			}
		}
		if !hasMinimalRule {
			outcome.Verdict = engine.VerdictClean
		} else if outcome.Verdict == engine.VerdictBlock {
			outcome.Verdict = engine.VerdictFlag
		}

	case config.ScanProfileMinimal:
		// Only enforce minimal rules
		hasEnforced := false
		for _, f := range outcome.Findings {
			if config.MinimalEnforceRules[f.RuleID] {
				hasEnforced = true
				break
			}
		}
		if !hasEnforced {
			outcome.Verdict = engine.VerdictFlag
		}
	}
}

// BuiltinToolExemptions maps rule IDs to tools where those rules should
// NOT fire because the detected pattern is the tool's intended behavior.
// For example, shell metacharacters in a Bash tool call are expected,
// not a shell injection. These defaults apply only when the user hasn't
// configured an explicit override for the rule.
var BuiltinToolExemptions = map[string][]string{
	"TC-005":         {"Bash", "Write", "Edit", "MultiEdit", "NotebookEdit", "Agent"}, // Shell patterns in content/agent tools are not injection
	"MCPCFG_002":     {"Bash", "Write", "Edit", "MultiEdit", "NotebookEdit", "Agent"}, // Shell metacharacters in content/agent tools
	"MCPCFG_004":     {"WebFetch", "Fetch", "WebSearch"},                     // Remote URLs — expected in web tools
	"MCPCFG_006":     {"Bash", "Write", "Edit", "MultiEdit", "NotebookEdit"}, // Inline code execution in content tools
	"THIRDPARTY_001": {"WebFetch", "Fetch", "WebSearch"},                     // Runtime URL — expected in web tools
}

func containsTool(tools []string, name string) bool {
	for _, t := range tools {
		if t == name {
			return true
		}
	}
	return false
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
