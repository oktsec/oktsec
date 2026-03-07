package audit

import (
	"strings"
	"testing"
)

func TestRedact_FullLevel(t *testing.T) {
	e := Entry{
		ID: "1", Timestamp: "2026-01-01T00:00:00Z",
		FromAgent: "a", ToAgent: "b", ContentHash: "abc",
		SignatureVerified: 1, Status: "delivered",
		RulesTriggered: `[{"rule_id":"IAP-001","matched":"secret stuff"}]`,
		PolicyDecision: "allow", LatencyMs: 5,
	}

	r := Redact(e, RedactNone)
	if r.ContentHash != "abc" {
		t.Error("full level should include content hash")
	}
	if r.SignatureVerified == nil {
		t.Error("full level should include signature_verified")
	}
	if !strings.Contains(r.RulesTriggered, "secret stuff") {
		t.Error("full level should not redact rule findings")
	}
}

func TestRedact_AnalystLevel(t *testing.T) {
	e := Entry{
		ID: "1", Timestamp: "2026-01-01T00:00:00Z",
		FromAgent: "a", ToAgent: "b", ContentHash: "abc",
		SignatureVerified: 1, Status: "blocked",
		RulesTriggered: `[{"rule_id":"IAP-001","name":"Prompt Injection","matched":"ignore previous instructions"}]`,
		PolicyDecision: "content_blocked", LatencyMs: 5,
	}

	r := Redact(e, RedactAnalyst)
	if r.ContentHash != "abc" {
		t.Error("analyst level should include content hash")
	}
	if strings.Contains(r.RulesTriggered, "ignore previous instructions") {
		t.Error("analyst level should redact matched content")
	}
	if !strings.Contains(r.RulesTriggered, "[REDACTED]") {
		t.Error("analyst level should contain [REDACTED] placeholder")
	}
	if !strings.Contains(r.RulesTriggered, "IAP-001") {
		t.Error("analyst level should preserve rule IDs")
	}
}

func TestRedact_ExternalLevel(t *testing.T) {
	e := Entry{
		ID: "1", Timestamp: "2026-01-01T00:00:00Z",
		FromAgent: "a", ToAgent: "b", ContentHash: "abc",
		SignatureVerified: 1, Status: "blocked",
		RulesTriggered: `[{"rule_id":"IAP-001"}]`,
		PolicyDecision: "content_blocked", LatencyMs: 5,
	}

	r := Redact(e, RedactExternal)
	if r.ContentHash != "" {
		t.Error("external level should not include content hash")
	}
	if r.SignatureVerified != nil {
		t.Error("external level should not include signature_verified")
	}
	if r.RulesTriggered != "" {
		t.Error("external level should not include rules triggered")
	}
	if r.LatencyMs != nil {
		t.Error("external level should not include latency")
	}
	// Should still have the basics
	if r.Status != "blocked" || r.PolicyDecision != "content_blocked" {
		t.Error("external level should include status and policy decision")
	}
}

func TestRedactEntries(t *testing.T) {
	entries := []Entry{
		{ID: "1", Status: "delivered", PolicyDecision: "allow"},
		{ID: "2", Status: "blocked", PolicyDecision: "content_blocked"},
	}

	result := RedactEntries(entries, RedactExternal)
	if len(result) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(result))
	}
	if result[0].ID != "1" || result[1].ID != "2" {
		t.Error("entry IDs should be preserved")
	}
}

func TestRedactRuleFindings_Empty(t *testing.T) {
	if got := redactRuleFindings(""); got != "" {
		t.Errorf("empty input should return empty, got %q", got)
	}
	if got := redactRuleFindings("[]"); got != "[]" {
		t.Errorf("empty array should pass through, got %q", got)
	}
}

func TestRedactRuleFindings_MultipleMatches(t *testing.T) {
	input := `[{"rule_id":"A","matched":"secret1"},{"rule_id":"B","matched":"secret2"}]`
	got := redactRuleFindings(input)
	if strings.Contains(got, "secret1") || strings.Contains(got, "secret2") {
		t.Errorf("should redact all matched values, got: %s", got)
	}
	if strings.Count(got, "[REDACTED]") != 2 {
		t.Errorf("expected 2 redactions, got: %s", got)
	}
}
