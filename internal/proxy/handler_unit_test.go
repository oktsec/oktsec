package proxy

import (
	"testing"
	"time"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
	"github.com/oktsec/oktsec/internal/verdict"
)

func TestDefaultSeverityVerdict(t *testing.T) {
	tests := map[string]engine.ScanVerdict{
		"critical": engine.VerdictBlock,
		"high":     engine.VerdictQuarantine,
		"medium":   engine.VerdictFlag,
		"low":      engine.VerdictClean,
		"info":     engine.VerdictClean,
		"":         engine.VerdictClean,
	}
	for sev, want := range tests {
		got := verdict.DefaultSeverityVerdict(sev)
		if got != want {
			t.Errorf("DefaultSeverityVerdict(%q) = %s, want %s", sev, got, want)
		}
	}
}

func TestVerdictSeverity(t *testing.T) {
	tests := map[engine.ScanVerdict]int{
		engine.VerdictBlock:      3,
		engine.VerdictQuarantine: 2,
		engine.VerdictFlag:       1,
		engine.VerdictClean:      0,
	}
	for v, want := range tests {
		got := verdict.Severity(v)
		if got != want {
			t.Errorf("Severity(%s) = %d, want %d", v, got, want)
		}
	}
}

func TestVerdictToResponse(t *testing.T) {
	tests := []struct {
		verdict    engine.ScanVerdict
		wantStatus string
		wantHTTP   int
	}{
		{engine.VerdictClean, "delivered", 200},
		{engine.VerdictFlag, "delivered", 200},
		{engine.VerdictQuarantine, "quarantined", 202},
		{engine.VerdictBlock, "blocked", 403},
	}
	for _, tc := range tests {
		status, _, httpStatus := verdictToResponse(tc.verdict)
		if status != tc.wantStatus {
			t.Errorf("verdictToResponse(%s) status = %q, want %q", tc.verdict, status, tc.wantStatus)
		}
		if httpStatus != tc.wantHTTP {
			t.Errorf("verdictToResponse(%s) http = %d, want %d", tc.verdict, httpStatus, tc.wantHTTP)
		}
	}
}

func TestEncodeFindings_Empty(t *testing.T) {
	got := verdict.EncodeFindings(nil)
	if got != "[]" {
		t.Errorf("EncodeFindings(nil) = %q, want %q", got, "[]")
	}
}

func TestEncodeFindings_WithData(t *testing.T) {
	findings := []engine.FindingSummary{
		{RuleID: "IAP-001", Name: "test", Severity: "high"},
	}
	got := verdict.EncodeFindings(findings)
	if got == "[]" {
		t.Error("EncodeFindings should return non-empty JSON for findings")
	}
}

func TestSha256Hash(t *testing.T) {
	h1 := sha256Hash("hello")
	h2 := sha256Hash("hello")
	h3 := sha256Hash("world")

	if h1 != h2 {
		t.Error("same input should produce same hash")
	}
	if h1 == h3 {
		t.Error("different input should produce different hash")
	}
	if len(h1) != 64 {
		t.Errorf("hash length = %d, want 64 (SHA-256 hex)", len(h1))
	}
}

func TestResolveWebhookRef_RawURL(t *testing.T) {
	ts := newTestSetup(t, false)
	got := ts.handler.resolveWebhookRef("https://example.com/webhook")
	if got != "https://example.com/webhook" {
		t.Errorf("resolveWebhookRef(URL) = %q, want URL", got)
	}
}

func TestResolveWebhookRef_Named_NotFound(t *testing.T) {
	ts := newTestSetup(t, false)
	got := ts.handler.resolveWebhookRef("my-channel")
	if got != "" {
		t.Errorf("resolveWebhookRef(unknown) = %q, want empty", got)
	}
}

func TestHandler_ApplyBlockedContent_NoAgent(t *testing.T) {
	ts := newTestSetup(t, false)
	outcome := &engine.ScanOutcome{
		Verdict:  engine.VerdictFlag,
		Findings: []engine.FindingSummary{{Category: "injection"}},
	}
	ts.handler.applyBlockedContent("nonexistent-agent", outcome)
	if outcome.Verdict != engine.VerdictFlag {
		t.Errorf("verdict changed for nonexistent agent: %s", outcome.Verdict)
	}
}

func TestHandler_ApplyBlockedContent_Matching(t *testing.T) {
	ts := newTestSetup(t, false)
	ts.handler.cfg.Agents["test-agent"] = config.Agent{
		BlockedContent: []string{"injection"},
		CanMessage:     []string{"target-agent"},
	}

	outcome := &engine.ScanOutcome{
		Verdict:  engine.VerdictFlag,
		Findings: []engine.FindingSummary{{Category: "injection"}},
	}
	ts.handler.applyBlockedContent("test-agent", outcome)
	if outcome.Verdict != engine.VerdictBlock {
		t.Errorf("verdict = %s, want block", outcome.Verdict)
	}
}

func TestHandler_ApplyBlockedContent_NoMatch(t *testing.T) {
	ts := newTestSetup(t, false)
	ts.handler.cfg.Agents["test-agent"] = config.Agent{
		BlockedContent: []string{"malware"},
		CanMessage:     []string{"target-agent"},
	}

	outcome := &engine.ScanOutcome{
		Verdict:  engine.VerdictFlag,
		Findings: []engine.FindingSummary{{Category: "injection"}},
	}
	ts.handler.applyBlockedContent("test-agent", outcome)
	if outcome.Verdict != engine.VerdictFlag {
		t.Errorf("verdict = %s, want flag (no change)", outcome.Verdict)
	}
}

func TestHandler_EscalateByHistory_NoBlocks(t *testing.T) {
	ts := newTestSetup(t, false)
	outcome := &engine.ScanOutcome{Verdict: engine.VerdictFlag}
	ts.handler.escalateByHistory("test-agent", outcome)
	if outcome.Verdict != engine.VerdictFlag {
		t.Errorf("verdict = %s, want flag (no history)", outcome.Verdict)
	}
}

func TestHandler_EscalateByHistory_SkipsBlock(t *testing.T) {
	ts := newTestSetup(t, false)
	outcome := &engine.ScanOutcome{Verdict: engine.VerdictBlock}
	ts.handler.escalateByHistory("test-agent", outcome)
	if outcome.Verdict != engine.VerdictBlock {
		t.Errorf("verdict = %s, want block (unchanged)", outcome.Verdict)
	}
}

func TestHandler_EscalateByHistory_SkipsClean(t *testing.T) {
	ts := newTestSetup(t, false)
	outcome := &engine.ScanOutcome{Verdict: engine.VerdictClean}
	ts.handler.escalateByHistory("test-agent", outcome)
	if outcome.Verdict != engine.VerdictClean {
		t.Errorf("verdict = %s, want clean (unchanged)", outcome.Verdict)
	}
}

func TestHandler_NotifyByRuleOverrides_NoRules(t *testing.T) {
	ts := newTestSetup(t, false)
	// Should not panic when no rules configured
	ts.handler.notifyByRuleOverrides("msg-1", &MessageRequest{
		From: "test-agent", To: "target-agent",
	}, []engine.FindingSummary{{RuleID: "R1", Severity: "high"}})
}

func TestHandler_ApplyRuleOverrides_NoRules(t *testing.T) {
	ts := newTestSetup(t, false)
	outcome := &engine.ScanOutcome{
		Verdict:  engine.VerdictFlag,
		Findings: []engine.FindingSummary{{RuleID: "R1", Severity: "medium"}},
	}
	verdict.ApplyRuleOverrides(ts.handler.cfg.Rules, outcome)
	if outcome.Verdict != engine.VerdictFlag {
		t.Errorf("verdict = %s, want flag (no rules to override)", outcome.Verdict)
	}
}

func TestHandler_ApplyRuleOverrides_IgnoreDropsFinding(t *testing.T) {
	ts := newTestSetup(t, false)
	ts.handler.cfg.Rules = []config.RuleAction{
		{ID: "IAP-001", Action: "ignore"},
	}
	outcome := &engine.ScanOutcome{
		Verdict:  engine.VerdictQuarantine,
		Findings: []engine.FindingSummary{{RuleID: "IAP-001", Severity: "high"}},
	}
	verdict.ApplyRuleOverrides(ts.handler.cfg.Rules, outcome)
	if len(outcome.Findings) != 0 {
		t.Errorf("findings = %d, want 0 (ignored)", len(outcome.Findings))
	}
	if outcome.Verdict != engine.VerdictClean {
		t.Errorf("verdict = %s, want clean (all findings ignored)", outcome.Verdict)
	}
}

func TestHandler_ApplyRuleOverrides_Block(t *testing.T) {
	ts := newTestSetup(t, false)
	ts.handler.cfg.Rules = []config.RuleAction{
		{ID: "IAP-001", Action: "block"},
	}
	outcome := &engine.ScanOutcome{
		Verdict:  engine.VerdictFlag,
		Findings: []engine.FindingSummary{{RuleID: "IAP-001", Severity: "medium"}},
	}
	verdict.ApplyRuleOverrides(ts.handler.cfg.Rules, outcome)
	if outcome.Verdict != engine.VerdictBlock {
		t.Errorf("verdict = %s, want block", outcome.Verdict)
	}
}

func TestHandler_NotifyByRuleOverrides_WithRuleNotify(t *testing.T) {
	ts := newTestSetup(t, false)
	ts.handler.cfg.Rules = []config.RuleAction{
		{ID: "IAP-001", Action: "block", Notify: []string{"https://example.com/webhook"}},
	}
	// Should not panic even if webhook delivery fails
	ts.handler.notifyByRuleOverrides("msg-1", &MessageRequest{
		From: "test-agent", To: "target-agent", Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, []engine.FindingSummary{{RuleID: "IAP-001", Severity: "high", Name: "test", Category: "injection"}})
}

func TestHandler_NotifyByRuleOverrides_CategoryFallback(t *testing.T) {
	ts := newTestSetup(t, false)
	ts.handler.cfg.CategoryWebhooks = []config.CategoryWebhook{
		{Category: "injection", Notify: []string{"https://example.com/webhook"}},
	}
	// Should use category-level webhook when no rule-level notify
	ts.handler.notifyByRuleOverrides("msg-1", &MessageRequest{
		From: "test-agent", To: "target-agent", Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, []engine.FindingSummary{{RuleID: "IAP-001", Severity: "high", Category: "injection"}})
}

func TestHandler_NotifyByRuleOverrides_NamedChannel(t *testing.T) {
	ts := newTestSetup(t, false)
	ts.handler.cfg.Webhooks = []config.Webhook{
		{Name: "alerts", URL: "https://example.com/alerts"},
	}
	ts.handler.cfg.Rules = []config.RuleAction{
		{ID: "IAP-001", Action: "block", Notify: []string{"alerts"}},
	}
	ts.handler.notifyByRuleOverrides("msg-1", &MessageRequest{
		From: "test-agent", To: "target-agent", Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, []engine.FindingSummary{{RuleID: "IAP-001", Severity: "high"}})
}

func TestHandler_ResolveWebhookRef_Named(t *testing.T) {
	ts := newTestSetup(t, false)
	ts.handler.cfg.Webhooks = []config.Webhook{
		{Name: "alerts", URL: "https://example.com/alerts"},
	}
	got := ts.handler.resolveWebhookRef("alerts")
	if got != "https://example.com/alerts" {
		t.Errorf("resolveWebhookRef(alerts) = %q, want URL", got)
	}
}

func TestHandler_ApplyRuleOverrides_AllowAndFlag(t *testing.T) {
	ts := newTestSetup(t, false)
	ts.handler.cfg.Rules = []config.RuleAction{
		{ID: "IAP-001", Action: "allow-and-flag"},
	}
	outcome := &engine.ScanOutcome{
		Verdict:  engine.VerdictBlock,
		Findings: []engine.FindingSummary{{RuleID: "IAP-001", Severity: "critical"}},
	}
	verdict.ApplyRuleOverrides(ts.handler.cfg.Rules, outcome)
	if outcome.Verdict != engine.VerdictFlag {
		t.Errorf("verdict = %s, want flag (allow-and-flag override)", outcome.Verdict)
	}
}

func TestHandler_ScanConcatenated_NoEscalation(t *testing.T) {
	ts := newTestSetup(t, false)
	outcome := &engine.ScanOutcome{Verdict: engine.VerdictClean}
	ctx := t
	_ = ctx
	// scanConcatenated should not escalate clean messages
	ts.handler.scanConcatenated(
		t.Context(), "test-agent", "Hello, this is a normal message", outcome,
	)
	if outcome.Verdict != engine.VerdictClean {
		t.Errorf("verdict = %s, want clean", outcome.Verdict)
	}
}

func TestHandler_ScanConcatenated_SkipsSevere(t *testing.T) {
	ts := newTestSetup(t, false)
	outcome := &engine.ScanOutcome{Verdict: engine.VerdictBlock}
	ts.handler.scanConcatenated(
		t.Context(), "test-agent", "blocked content", outcome,
	)
	if outcome.Verdict != engine.VerdictBlock {
		t.Errorf("verdict = %s, want block (unchanged)", outcome.Verdict)
	}
}

func TestHandler_ApplyRuleOverrides_QuarantineOverride(t *testing.T) {
	ts := newTestSetup(t, false)
	ts.handler.cfg.Rules = []config.RuleAction{
		{ID: "IAP-001", Action: "quarantine"},
	}
	outcome := &engine.ScanOutcome{
		Verdict:  engine.VerdictFlag,
		Findings: []engine.FindingSummary{{RuleID: "IAP-001", Severity: "medium"}},
	}
	verdict.ApplyRuleOverrides(ts.handler.cfg.Rules, outcome)
	if outcome.Verdict != engine.VerdictQuarantine {
		t.Errorf("verdict = %s, want quarantine", outcome.Verdict)
	}
}

// --- Remediation guidance tests ---

func TestTopRemediation_Empty(t *testing.T) {
	got := topRemediation(nil)
	if got != "" {
		t.Errorf("topRemediation(nil) = %q, want empty", got)
	}
}

func TestTopRemediation_SingleFinding(t *testing.T) {
	findings := []engine.FindingSummary{
		{RuleID: "IAP-001", Severity: "high", Remediation: "Do not override system prompts."},
	}
	got := topRemediation(findings)
	if got != "Do not override system prompts." {
		t.Errorf("topRemediation = %q, want remediation text", got)
	}
}

func TestTopRemediation_HighestSeverityWins(t *testing.T) {
	findings := []engine.FindingSummary{
		{RuleID: "IAP-002", Severity: "medium", Remediation: "Medium fix."},
		{RuleID: "IAP-001", Severity: "critical", Remediation: "Critical fix."},
		{RuleID: "IAP-003", Severity: "high", Remediation: "High fix."},
	}
	got := topRemediation(findings)
	if got != "Critical fix." {
		t.Errorf("topRemediation = %q, want 'Critical fix.'", got)
	}
}

func TestTopRemediation_NoRemediationText(t *testing.T) {
	findings := []engine.FindingSummary{
		{RuleID: "IAP-001", Severity: "high"},
	}
	got := topRemediation(findings)
	if got != "" {
		t.Errorf("topRemediation = %q, want empty (no remediation text)", got)
	}
}

func TestSeverityRank(t *testing.T) {
	tests := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
		"info":     0,
		"":         0,
	}
	for sev, want := range tests {
		got := severityRank(sev)
		if got != want {
			t.Errorf("severityRank(%q) = %d, want %d", sev, got, want)
		}
	}
}

func TestSuggestionForDecision(t *testing.T) {
	tests := []struct {
		decision string
		wantNon  bool // true if we expect non-empty suggestion
	}{
		{"content_blocked", true},
		{"content_quarantined", true},
		{"identity_rejected", true},
		{"signature_required", true},
		{"delegation_invalid", true},
		{"delegation_required", true},
		{"acl_denied", true},
		{"agent_suspended", true},
		{"recipient_suspended", true},
		{"allow", false},
		{"content_flagged", false},
		{"", false},
	}
	for _, tc := range tests {
		got := suggestionForDecision(tc.decision)
		if tc.wantNon && got == "" {
			t.Errorf("suggestionForDecision(%q) = empty, want non-empty", tc.decision)
		}
		if !tc.wantNon && got != "" {
			t.Errorf("suggestionForDecision(%q) = %q, want empty", tc.decision, got)
		}
	}
}

func TestConsecutiveDenials_IncrementAndReset(t *testing.T) {
	ts := newTestSetup(t, false)
	h := ts.handler

	// Initially zero
	if c := h.consecutiveDenialCount("agent-a", "sess-1"); c != 0 {
		t.Errorf("initial count = %d, want 0", c)
	}

	// Increment
	h.recordDenial("agent-a", "sess-1")
	h.recordDenial("agent-a", "sess-1")
	if c := h.consecutiveDenialCount("agent-a", "sess-1"); c != 2 {
		t.Errorf("after 2 denials = %d, want 2", c)
	}

	// Different agent/session is independent
	h.recordDenial("agent-b", "sess-1")
	if c := h.consecutiveDenialCount("agent-b", "sess-1"); c != 1 {
		t.Errorf("agent-b count = %d, want 1", c)
	}

	// Reset on success
	h.resetDenials("agent-a", "sess-1")
	if c := h.consecutiveDenialCount("agent-a", "sess-1"); c != 0 {
		t.Errorf("after reset = %d, want 0", c)
	}

	// agent-b unaffected by agent-a reset
	if c := h.consecutiveDenialCount("agent-b", "sess-1"); c != 1 {
		t.Errorf("agent-b after agent-a reset = %d, want 1", c)
	}
}

func TestConsecutiveDenials_WarningAt3(t *testing.T) {
	ts := newTestSetup(t, false)
	h := ts.handler

	// Should not panic; warning is logged at count >= 3
	for i := 0; i < 5; i++ {
		h.recordDenial("agent-a", "sess-1")
	}
	if c := h.consecutiveDenialCount("agent-a", "sess-1"); c != 5 {
		t.Errorf("count = %d, want 5", c)
	}
}
