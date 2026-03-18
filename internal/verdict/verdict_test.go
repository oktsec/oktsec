package verdict

import (
	"testing"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
)

func TestApplyToolScopedOverrides_BuiltinExemptions(t *testing.T) {
	tests := []struct {
		name         string
		ruleID       string
		severity     string
		toolName     string
		wantDropped  bool
		wantVerdict  engine.ScanVerdict
	}{
		{
			name:        "TC-005 dropped on Bash",
			ruleID:      "TC-005",
			severity:    audit.SeverityCritical,
			toolName:    "Bash",
			wantDropped: true,
			wantVerdict: engine.VerdictClean,
		},
		{
			name:        "TC-005 dropped on Edit (content tool)",
			ruleID:      "TC-005",
			severity:    audit.SeverityCritical,
			toolName:    "Edit",
			wantDropped: true,
			wantVerdict: engine.VerdictClean,
		},
		{
			name:        "MCPCFG_002 dropped on Bash",
			ruleID:      "MCPCFG_002",
			severity:    audit.SeverityHigh,
			toolName:    "Bash",
			wantDropped: true,
			wantVerdict: engine.VerdictClean,
		},
		{
			name:        "MCPCFG_004 dropped on WebFetch",
			ruleID:      "MCPCFG_004",
			severity:    audit.SeverityLow,
			toolName:    "WebFetch",
			wantDropped: true,
			wantVerdict: engine.VerdictClean,
		},
		{
			name:        "MCPCFG_004 kept on Bash",
			ruleID:      "MCPCFG_004",
			severity:    audit.SeverityLow,
			toolName:    "Bash",
			wantDropped: false,
			wantVerdict: engine.VerdictClean, // LOW → clean verdict
		},
		{
			name:        "THIRDPARTY_001 dropped on WebSearch",
			ruleID:      "THIRDPARTY_001",
			severity:    audit.SeverityLow,
			toolName:    "WebSearch",
			wantDropped: true,
			wantVerdict: engine.VerdictClean,
		},
		{
			name:        "THIRDPARTY_001 dropped on Read (content tool)",
			ruleID:      "THIRDPARTY_001",
			severity:    audit.SeverityLow,
			toolName:    "Read",
			wantDropped: true,
			wantVerdict: engine.VerdictClean,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outcome := &engine.ScanOutcome{
				Verdict: DefaultSeverityVerdict(tt.severity),
				Findings: []engine.FindingSummary{
					{RuleID: tt.ruleID, Severity: tt.severity},
				},
			}

			// No user-configured rules — only built-in exemptions apply.
			ApplyToolScopedOverrides(nil, outcome, tt.toolName)

			if tt.wantDropped && len(outcome.Findings) != 0 {
				t.Errorf("expected finding %s to be dropped on %s, got %d findings",
					tt.ruleID, tt.toolName, len(outcome.Findings))
			}
			if !tt.wantDropped && len(outcome.Findings) == 0 {
				t.Errorf("expected finding %s to be kept on %s, got 0 findings",
					tt.ruleID, tt.toolName)
			}
			if outcome.Verdict != tt.wantVerdict {
				t.Errorf("verdict = %q, want %q", outcome.Verdict, tt.wantVerdict)
			}
		})
	}
}

func TestApplyToolScopedOverrides_UserOverrideTakesPrecedence(t *testing.T) {
	// User explicitly configures TC-005 to block even on Bash.
	// This should override the built-in exemption.
	rules := []config.RuleAction{
		{ID: "TC-005", Action: "block", ApplyToTools: []string{"Bash", "Edit"}},
	}

	outcome := &engine.ScanOutcome{
		Verdict: engine.VerdictBlock,
		Findings: []engine.FindingSummary{
			{RuleID: "TC-005", Severity: audit.SeverityCritical},
		},
	}

	ApplyToolScopedOverrides(rules, outcome, "Bash")

	if len(outcome.Findings) == 0 {
		t.Error("user override should keep TC-005 on Bash")
	}
	if outcome.Verdict != engine.VerdictBlock {
		t.Errorf("verdict = %q, want block (user override)", outcome.Verdict)
	}
}

func TestApplyToolScopedOverrides_NilRulesStillAppliesBuiltins(t *testing.T) {
	outcome := &engine.ScanOutcome{
		Verdict: engine.VerdictBlock,
		Findings: []engine.FindingSummary{
			{RuleID: "TC-005", Severity: audit.SeverityCritical},
			{RuleID: "MCPCFG_002", Severity: audit.SeverityHigh},
		},
	}

	ApplyToolScopedOverrides(nil, outcome, "Bash")

	if len(outcome.Findings) != 0 {
		t.Errorf("expected all findings dropped on Bash, got %d", len(outcome.Findings))
	}
	if outcome.Verdict != engine.VerdictClean {
		t.Errorf("verdict = %q, want clean", outcome.Verdict)
	}
}
