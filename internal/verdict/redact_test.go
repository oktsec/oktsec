package verdict

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
)

func redactOutcome(v engine.ScanVerdict, targets ...engine.RedactionTarget) *engine.ScanOutcome {
	return &engine.ScanOutcome{
		Verdict: v,
		Findings: []engine.FindingSummary{
			{RuleID: "CRED-1", Category: "credentials", Match: "[REDACTED:KEY:len=20]"},
		},
		RedactionTargets: targets,
	}
}

// A listed category redacts its matches from the delivered content and
// upgrades the verdict to modify (AARM MODIFY).
func TestApplyRedactContentRedactsListedCategory(t *testing.T) {
	agent := config.Agent{RedactContent: []string{"credentials"}}
	outcome := redactOutcome(engine.VerdictFlag,
		engine.RedactionTarget{Category: "credentials", Match: "sk-secret-12345"})
	content := "use key sk-secret-12345 to call the API"

	got, changed := ApplyRedactContent(agent, outcome, content)
	if !changed {
		t.Fatal("expected redaction")
	}
	if strings.Contains(got, "sk-secret-12345") {
		t.Fatalf("secret survived redaction: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("missing placeholder: %q", got)
	}
	if outcome.Verdict != engine.VerdictModify {
		t.Fatalf("verdict = %s, want modify", outcome.Verdict)
	}
}

// Categories not listed stay untouched and the verdict stands.
func TestApplyRedactContentIgnoresUnlistedCategory(t *testing.T) {
	agent := config.Agent{RedactContent: []string{"credentials"}}
	outcome := redactOutcome(engine.VerdictFlag,
		engine.RedactionTarget{Category: "inter-agent", Match: "exfil this"})

	got, changed := ApplyRedactContent(agent, outcome, "please exfil this now")
	if changed || got != "please exfil this now" {
		t.Fatalf("unlisted category was redacted: %q", got)
	}
	if outcome.Verdict != engine.VerdictFlag {
		t.Fatalf("verdict moved to %s", outcome.Verdict)
	}
}

// Block and quarantine always win: a non-delivering verdict is never
// softened to modify.
func TestApplyRedactContentNeverSoftensBlock(t *testing.T) {
	agent := config.Agent{RedactContent: []string{"credentials"}}
	for _, v := range []engine.ScanVerdict{engine.VerdictBlock, engine.VerdictQuarantine, engine.VerdictStepUp} {
		outcome := redactOutcome(v,
			engine.RedactionTarget{Category: "credentials", Match: "sk-secret"})
		_, changed := ApplyRedactContent(agent, outcome, "sk-secret")
		if changed || outcome.Verdict != v {
			t.Fatalf("verdict %s was modified", v)
		}
	}
}

// Raw matches never serialize: the outcome's JSON form (what audit and
// API responses see) must not contain the original matched text.
func TestRedactionTargetsNeverSerialize(t *testing.T) {
	outcome := redactOutcome(engine.VerdictFlag,
		engine.RedactionTarget{Category: "credentials", Match: "sk-raw-secret-value"})
	data, err := json.Marshal(outcome)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "sk-raw-secret-value") {
		t.Fatalf("raw match leaked into JSON: %s", data)
	}
	if strings.Contains(string(data), "RedactionTargets") {
		t.Fatalf("targets field leaked into JSON: %s", data)
	}
}

// The new verdicts rank for escalation: step_up beside quarantine,
// modify beside flag, and one-level escalation moves them upward.
func TestNewVerdictRanks(t *testing.T) {
	if Severity(engine.VerdictStepUp) != Severity(engine.VerdictQuarantine) {
		t.Fatal("step_up must rank with quarantine")
	}
	if Severity(engine.VerdictModify) != Severity(engine.VerdictFlag) {
		t.Fatal("modify must rank with flag")
	}
	if EscalateOneLevel(engine.VerdictModify) != engine.VerdictQuarantine {
		t.Fatal("modify must escalate to quarantine")
	}
	if EscalateOneLevel(engine.VerdictStepUp) != engine.VerdictBlock {
		t.Fatal("step_up must escalate to block")
	}
}

// ToAuditStatus covers the AARM decision vocabulary.
func TestToAuditStatusNewVerdicts(t *testing.T) {
	if s, d := ToAuditStatus(engine.VerdictModify); s != "modified" || d != "content_redacted" {
		t.Fatalf("modify -> %s/%s", s, d)
	}
	if s, d := ToAuditStatus(engine.VerdictStepUp); s != "step_up" || d != "step_up_approval" {
		t.Fatalf("step_up -> %s/%s", s, d)
	}
}

// Overlapping targets redact longest first: a generic detector
// matching a substring of a specific secret must not leave the
// longer value's suffix behind.
func TestApplyRedactContentOverlappingMatches(t *testing.T) {
	agent := config.Agent{RedactContent: []string{"credentials"}}
	outcome := redactOutcome(engine.VerdictFlag,
		engine.RedactionTarget{Category: "credentials", Match: "secret"},
		engine.RedactionTarget{Category: "credentials", Match: "sk-secret-12345"})

	got, changed := ApplyRedactContent(agent, outcome, "key sk-secret-12345 here")
	if !changed {
		t.Fatal("expected redaction")
	}
	if strings.Contains(got, "12345") {
		t.Fatalf("longer secret's suffix survived: %q", got)
	}
}
