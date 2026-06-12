package verdict

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
)

func redactOutcome(v engine.ScanVerdict, targets ...engine.RedactionTarget) *engine.ScanOutcome {
	o := &engine.ScanOutcome{Verdict: v, RedactionTargets: targets}
	// In production every target comes from a finding; pair them by
	// RuleID so the helper mirrors that (deduped) — fail-closed logic
	// keys on a finding having a usable target of the same RuleID.
	seen := map[string]bool{}
	for i, t := range targets {
		id := t.RuleID
		if id == "" {
			id = fmt.Sprintf("RULE-%d", i)
			o.RedactionTargets[i].RuleID = id
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		o.Findings = append(o.Findings, engine.FindingSummary{
			RuleID: id, Category: t.Category, Match: "[REDACTED:KEY:len=20]",
		})
	}
	return o
}

// A listed category redacts its matches from the delivered content and
// upgrades the verdict to modify (AARM MODIFY).
func TestApplyRedactContentRedactsListedCategory(t *testing.T) {
	agent := config.Agent{RedactContent: []string{"credentials"}}
	outcome := redactOutcome(engine.VerdictFlag,
		engine.RedactionTarget{Category: "credentials", Match: "sk-secret-12345"})
	content := "use key sk-secret-12345 to call the API"

	got, changed, needsVerify := ApplyRedactContent(agent, outcome, content)
	if !changed || needsVerify {
		t.Fatalf("changed=%v needsVerify=%v, want exact-match redaction without verify", changed, needsVerify)
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

	got, changed, _ := ApplyRedactContent(agent, outcome, "please exfil this now")
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
		_, changed, _ := ApplyRedactContent(agent, outcome, "sk-secret")
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

	got, changed, _ := ApplyRedactContent(agent, outcome, "key sk-secret-12345 here")
	if !changed {
		t.Fatal("expected redaction")
	}
	if strings.Contains(got, "12345") {
		t.Fatalf("longer secret's suffix survived: %q", got)
	}
}

// Credential findings arrive with their match pre-redacted by the
// engine; the pattern pass still redacts the real secret from the
// delivered content.
func TestApplyRedactContentPatternPassForPreRedactedMatches(t *testing.T) {
	agent := config.Agent{RedactContent: []string{"credential-leak"}}
	outcome := redactOutcome(engine.VerdictFlag,
		engine.RedactionTarget{Category: "credential-leak", Match: "[REDACTED]"})
	content := "use AKIA1234567890ABCDEF for the bucket"

	got, changed, needsVerify := ApplyRedactContent(agent, outcome, content)
	if !changed {
		t.Fatal("expected pattern-pass redaction")
	}
	if !needsVerify {
		t.Fatal("pattern-pass redaction must demand re-scan verification")
	}
	if strings.Contains(got, "AKIA1234567890ABCDEF") {
		t.Fatalf("secret survived: %q", got)
	}
	if outcome.Verdict != engine.VerdictModify {
		t.Fatalf("verdict = %s, want modify", outcome.Verdict)
	}
}

// When the detected content cannot be located (pre-redacted match and
// no pattern hit), delivering the original would silently break the
// redaction promise — the message holds for review instead.
func TestApplyRedactContentFailsClosed(t *testing.T) {
	agent := config.Agent{RedactContent: []string{"credential-leak"}}
	outcome := redactOutcome(engine.VerdictFlag,
		engine.RedactionTarget{Category: "credential-leak", Match: "[REDACTED]"})
	content := "an exotic secret format no pattern knows"

	got, changed, _ := ApplyRedactContent(agent, outcome, content)
	if changed {
		t.Fatal("nothing should have been redacted")
	}
	if got != content {
		t.Fatalf("content mutated: %q", got)
	}
	if outcome.Verdict != engine.VerdictQuarantine {
		t.Fatalf("verdict = %s, want quarantine (fail closed)", outcome.Verdict)
	}
}

// A successful exact-match replacement must never mask a pattern pass
// that located nothing: the message holds for review even though one
// target was redacted.
func TestApplyRedactContentPartialFailureFailsClosed(t *testing.T) {
	agent := config.Agent{RedactContent: []string{"credentials", "credential-leak"}}
	outcome := redactOutcome(engine.VerdictFlag,
		engine.RedactionTarget{Category: "credentials", Match: "plain-token-abc"},
		engine.RedactionTarget{Category: "credential-leak", Match: "[REDACTED]"})
	content := "send plain-token-abc and the exotic secret nothing matches"

	got, changed, _ := ApplyRedactContent(agent, outcome, content)
	if changed {
		t.Fatal("partial redaction must not report success")
	}
	if got != content {
		t.Fatalf("content must return unmodified on fail-closed: %q", got)
	}
	if outcome.Verdict != engine.VerdictQuarantine {
		t.Fatalf("verdict = %s, want quarantine", outcome.Verdict)
	}
}

// Findings in redacted categories never carry their matched value out
// of the proxy — on every exit path.
func TestApplyRedactContentScrubsFindingMatches(t *testing.T) {
	agent := config.Agent{RedactContent: []string{"pii"}}
	outcome := &engine.ScanOutcome{
		Verdict: engine.VerdictFlag,
		Findings: []engine.FindingSummary{
			{RuleID: "PII-1", Category: "pii", Match: "ssn 123-45-6789"},
			{RuleID: "IAP-1", Category: "inter-agent", Match: "unrelated"},
		},
		RedactionTargets: []engine.RedactionTarget{
			{RuleID: "PII-1", Category: "pii", Match: "123-45-6789"},
		},
	}
	_, changed, _ := ApplyRedactContent(agent, outcome, "ssn 123-45-6789")
	if !changed {
		t.Fatal("expected redaction")
	}
	if outcome.Findings[0].Match != "[REDACTED]" {
		t.Fatalf("redacted category's finding still carries the value: %q", outcome.Findings[0].Match)
	}
	if outcome.Findings[1].Match != "unrelated" {
		t.Fatal("unlisted category's finding must stay intact")
	}
}

// Held verdicts scrub too: a blocked message's findings in a redacted
// category never carry the matched value.
func TestApplyRedactContentScrubsOnHeldVerdicts(t *testing.T) {
	agent := config.Agent{RedactContent: []string{"pii"}}
	outcome := &engine.ScanOutcome{
		Verdict: engine.VerdictBlock,
		Findings: []engine.FindingSummary{
			{RuleID: "PII-1", Category: "pii", Match: "ssn 123-45-6789"},
		},
		RedactionTargets: []engine.RedactionTarget{
			{RuleID: "PII-1", Category: "pii", Match: "123-45-6789"},
		},
	}
	_, changed, _ := ApplyRedactContent(agent, outcome, "ssn 123-45-6789")
	if changed || outcome.Verdict != engine.VerdictBlock {
		t.Fatal("held verdict must stand unmodified")
	}
	if outcome.Findings[0].Match != "[REDACTED]" {
		t.Fatalf("held verdict leaked the match: %q", outcome.Findings[0].Match)
	}
}

// A listed finding that arrives with NO redaction target (split-scan
// findings don't carry targets) must fail closed, never deliver as
// ordinary flagged content.
func TestApplyRedactContentFindingWithoutTargetFailsClosed(t *testing.T) {
	agent := config.Agent{RedactContent: []string{"pii"}}
	outcome := &engine.ScanOutcome{
		Verdict: engine.VerdictFlag,
		Findings: []engine.FindingSummary{
			{RuleID: "PII-9", Category: "pii", Match: "[REDACTED]"},
		},
		// No RedactionTargets at all.
	}
	content := "an unlocatable pii detection"
	got, changed, _ := ApplyRedactContent(agent, outcome, content)
	if changed || got != content {
		t.Fatal("nothing should deliver modified")
	}
	if outcome.Verdict != engine.VerdictQuarantine {
		t.Fatalf("verdict = %s, want quarantine (fail closed)", outcome.Verdict)
	}
}

// A target whose reported span does not occur byte-for-byte in the
// original (normalized scan output) must not silently deliver — it
// fails closed when nothing else can locate the detection.
func TestApplyRedactContentNormalizedSpanFailsClosed(t *testing.T) {
	agent := config.Agent{RedactContent: []string{"pii"}}
	outcome := redactOutcome(engine.VerdictFlag,
		engine.RedactionTarget{RuleID: "PII-2", Category: "pii", Match: "normalized-form-not-in-content"})
	content := "the original bytes differ from what the scanner reported"

	got, changed, _ := ApplyRedactContent(agent, outcome, content)
	if changed || got != content {
		t.Fatal("nothing should deliver modified")
	}
	if outcome.Verdict != engine.VerdictQuarantine {
		t.Fatalf("verdict = %s, want quarantine", outcome.Verdict)
	}
}
