package audit

import (
	"testing"
	"time"
)

func sampleLLMAnalysis(id, msgID string) LLMAnalysis {
	return LLMAnalysis{
		ID:                id,
		MessageID:         msgID,
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
		FromAgent:         "agent-a",
		ToAgent:           "agent-b",
		Provider:          "openai",
		Model:             "gpt-4",
		RiskScore:         0.75,
		RecommendedAction: "flag",
		Confidence:        0.9,
		ThreatsJSON:       `["prompt_injection"]`,
		IntentJSON:        `{"goal":"data_exfil"}`,
		LatencyMs:         120,
		TokensUsed:        500,
		RuleGenerated:     "",
	}
}

func TestLogLLMAnalysis(t *testing.T) {
	store := newTestStore(t)

	a := sampleLLMAnalysis("llm-1", "msg-1")
	if err := store.LogLLMAnalysis(a); err != nil {
		t.Fatalf("LogLLMAnalysis failed: %v", err)
	}

	// Verify it was inserted by querying back
	got, err := store.QueryLLMAnalysisByMessage("msg-1")
	if err != nil {
		t.Fatalf("QueryLLMAnalysisByMessage failed: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil result after insert")
	}
	if got.ID != "llm-1" {
		t.Errorf("ID = %q, want %q", got.ID, "llm-1")
	}
	if got.RiskScore != 0.75 {
		t.Errorf("RiskScore = %f, want 0.75", got.RiskScore)
	}
	if got.TokensUsed != 500 {
		t.Errorf("TokensUsed = %d, want 500", got.TokensUsed)
	}
	if got.Provider != "openai" {
		t.Errorf("Provider = %q, want %q", got.Provider, "openai")
	}
}

func TestLogLLMAnalysisDuplicateID(t *testing.T) {
	store := newTestStore(t)

	a := sampleLLMAnalysis("llm-dup", "msg-dup")
	if err := store.LogLLMAnalysis(a); err != nil {
		t.Fatalf("first insert failed: %v", err)
	}
	// Duplicate primary key should error
	if err := store.LogLLMAnalysis(a); err == nil {
		t.Error("expected error on duplicate ID insert, got nil")
	}
}

func TestQueryLLMAnalyses(t *testing.T) {
	store := newTestStore(t)

	// Insert 5 records
	for i := 0; i < 5; i++ {
		a := sampleLLMAnalysis(
			"llm-q-"+string(rune('a'+i)),
			"msg-q-"+string(rune('a'+i)),
		)
		// Stagger timestamps so ordering is deterministic
		a.Timestamp = time.Now().UTC().Add(time.Duration(i) * time.Second).Format(time.RFC3339)
		if err := store.LogLLMAnalysis(a); err != nil {
			t.Fatalf("insert %d failed: %v", i, err)
		}
	}

	// Query with limit 3
	results, err := store.QueryLLMAnalyses(3)
	if err != nil {
		t.Fatalf("QueryLLMAnalyses failed: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}

	// Should be ordered by timestamp DESC (most recent first)
	if results[0].ID != "llm-q-e" {
		t.Errorf("first result ID = %q, want %q", results[0].ID, "llm-q-e")
	}

	// Query with limit 0 should default to 50 (return all 5)
	all, err := store.QueryLLMAnalyses(0)
	if err != nil {
		t.Fatalf("QueryLLMAnalyses(0) failed: %v", err)
	}
	if len(all) != 5 {
		t.Fatalf("got %d results with limit=0, want 5", len(all))
	}
}

func TestQueryLLMAnalysisByMessage(t *testing.T) {
	store := newTestStore(t)

	a := sampleLLMAnalysis("llm-bm-1", "msg-bm-1")
	a.RuleGenerated = "RULE-001"
	if err := store.LogLLMAnalysis(a); err != nil {
		t.Fatalf("insert failed: %v", err)
	}

	// Query existing message
	got, err := store.QueryLLMAnalysisByMessage("msg-bm-1")
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if got.MessageID != "msg-bm-1" {
		t.Errorf("MessageID = %q, want %q", got.MessageID, "msg-bm-1")
	}
	if got.RuleGenerated != "RULE-001" {
		t.Errorf("RuleGenerated = %q, want %q", got.RuleGenerated, "RULE-001")
	}

	// Query non-existent message should return nil, nil
	missing, err := store.QueryLLMAnalysisByMessage("no-such-msg")
	if err != nil {
		t.Fatalf("expected nil error for missing message, got: %v", err)
	}
	if missing != nil {
		t.Errorf("expected nil for non-existent message, got %+v", missing)
	}
}

func TestQueryAgentLLMRisk(t *testing.T) {
	store := newTestStore(t)

	// Empty table returns empty map
	empty, err := store.QueryAgentLLMRisk()
	if err != nil {
		t.Fatalf("empty table: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("expected 0 agents, got %d", len(empty))
	}

	// Insert analyses for two agents
	records := []LLMAnalysis{
		{
			ID: "ar1", MessageID: "arm1", Timestamp: "2025-01-01T00:00:00Z",
			FromAgent: "risky-bot", ToAgent: "target-a", Provider: "openai", Model: "gpt-4",
			RiskScore: 80, RecommendedAction: "block", Confidence: 0.9,
			ThreatsJSON: `["injection"]`, IntentJSON: `{}`, LatencyMs: 100, TokensUsed: 200,
			RuleGenerated: "RULE-1",
		},
		{
			ID: "ar2", MessageID: "arm2", Timestamp: "2025-01-01T00:01:00Z",
			FromAgent: "risky-bot", ToAgent: "target-b", Provider: "openai", Model: "gpt-4",
			RiskScore: 60, RecommendedAction: "investigate", Confidence: 0.8,
			ThreatsJSON: `["exfil"]`, IntentJSON: `{}`, LatencyMs: 150, TokensUsed: 300,
		},
		{
			ID: "ar3", MessageID: "arm3", Timestamp: "2025-01-01T00:02:00Z",
			FromAgent: "safe-bot", ToAgent: "target-a", Provider: "openai", Model: "gpt-4",
			RiskScore: 5, RecommendedAction: "none", Confidence: 0.95,
			ThreatsJSON: `[]`, IntentJSON: `{}`, LatencyMs: 80, TokensUsed: 100,
		},
	}
	for _, r := range records {
		if err := store.LogLLMAnalysis(r); err != nil {
			t.Fatalf("insert %s: %v", r.ID, err)
		}
	}

	// Mark one as confirmed
	if err := store.UpdateLLMReviewStatus("ar1", "confirmed"); err != nil {
		t.Fatalf("update review status: %v", err)
	}

	risks, err := store.QueryAgentLLMRisk()
	if err != nil {
		t.Fatalf("QueryAgentLLMRisk: %v", err)
	}

	// risky-bot: 2 analyses, avg 70, max 80, 2 threats, 1 confirmed, 1 rule
	rb, ok := risks["risky-bot"]
	if !ok {
		t.Fatal("expected risky-bot in results")
	}
	if rb.AnalysisCount != 2 {
		t.Errorf("risky-bot AnalysisCount = %d, want 2", rb.AnalysisCount)
	}
	if rb.AvgRiskScore != 70 {
		t.Errorf("risky-bot AvgRiskScore = %f, want 70", rb.AvgRiskScore)
	}
	if rb.MaxRiskScore != 80 {
		t.Errorf("risky-bot MaxRiskScore = %f, want 80", rb.MaxRiskScore)
	}
	if rb.ThreatCount != 2 {
		t.Errorf("risky-bot ThreatCount = %d, want 2", rb.ThreatCount)
	}
	if rb.ConfirmedCount != 1 {
		t.Errorf("risky-bot ConfirmedCount = %d, want 1", rb.ConfirmedCount)
	}

	// safe-bot: 1 analysis, avg 5, max 5, 0 threats
	sb, ok := risks["safe-bot"]
	if !ok {
		t.Fatal("expected safe-bot in results")
	}
	if sb.AnalysisCount != 1 {
		t.Errorf("safe-bot AnalysisCount = %d, want 1", sb.AnalysisCount)
	}
	if sb.ThreatCount != 0 {
		t.Errorf("safe-bot ThreatCount = %d, want 0", sb.ThreatCount)
	}
}

func TestQueryAgentRiskBlendedScoring(t *testing.T) {
	store := newTestStore(t)

	// Create audit log entries — risky-bot has some blocks
	ts := "2025-01-01T00:00:00Z"
	for i := 0; i < 10; i++ {
		status := "delivered"
		if i < 3 {
			status = "blocked"
		}
		store.Log(Entry{
			ID: "blend-" + string(rune('a'+i)), Timestamp: ts,
			FromAgent: "risky-bot", ToAgent: "target",
			Status: status, PolicyDecision: "pipeline",
		})
	}
	store.Flush()

	// Insert LLM analysis for risky-bot
	_ = store.LogLLMAnalysis(LLMAnalysis{
		ID: "bl1", MessageID: "blm1", Timestamp: ts,
		FromAgent: "risky-bot", ToAgent: "target", Provider: "openai", Model: "gpt-4",
		RiskScore: 80, RecommendedAction: "block", Confidence: 0.9,
		ThreatsJSON: `["injection"]`, IntentJSON: `{}`, LatencyMs: 100, TokensUsed: 200,
	})

	// Query agent risk — should blend audit + LLM
	risks, err := store.QueryAgentRisk(ts)
	if err != nil {
		t.Fatalf("QueryAgentRisk: %v", err)
	}
	if len(risks) == 0 {
		t.Fatal("expected at least one agent risk result")
	}

	var rb *AgentRisk
	for i := range risks {
		if risks[i].Agent == "risky-bot" {
			rb = &risks[i]
			break
		}
	}
	if rb == nil {
		t.Fatal("risky-bot not found in results")
	}

	// Audit-only score: (3*3 + 0*2) / 10 * 100 = 90 (clamped to 90, under 100)
	// LLM avg risk: 80
	// Blended: 90*0.6 + 80*0.4 = 54 + 32 = 86
	if rb.RiskScore < 85 || rb.RiskScore > 87 {
		t.Errorf("blended RiskScore = %f, want ~86", rb.RiskScore)
	}
	if rb.LLMAvgRisk != 80 {
		t.Errorf("LLMAvgRisk = %f, want 80", rb.LLMAvgRisk)
	}
	if rb.LLMThreatCount != 1 {
		t.Errorf("LLMThreatCount = %d, want 1", rb.LLMThreatCount)
	}
}

func TestQueryLLMStats(t *testing.T) {
	store := newTestStore(t)

	// Stats on empty table
	empty, err := store.QueryLLMStats()
	if err != nil {
		t.Fatalf("QueryLLMStats on empty table failed: %v", err)
	}
	if empty.TotalAnalyses != 0 {
		t.Errorf("empty TotalAnalyses = %d, want 0", empty.TotalAnalyses)
	}

	// Insert 3 records with varying stats
	records := []LLMAnalysis{
		{
			ID: "s1", MessageID: "ms1", Timestamp: time.Now().UTC().Format(time.RFC3339),
			FromAgent: "a", ToAgent: "b", Provider: "openai", Model: "gpt-4",
			RiskScore: 0.8, RecommendedAction: "block", Confidence: 0.95,
			ThreatsJSON: `["injection"]`, IntentJSON: `{}`,
			LatencyMs: 100, TokensUsed: 200, RuleGenerated: "RULE-X",
		},
		{
			ID: "s2", MessageID: "ms2", Timestamp: time.Now().UTC().Format(time.RFC3339),
			FromAgent: "a", ToAgent: "c", Provider: "openai", Model: "gpt-4",
			RiskScore: 0.3, RecommendedAction: "clean", Confidence: 0.7,
			ThreatsJSON: `[]`, IntentJSON: `{}`,
			LatencyMs: 200, TokensUsed: 300, RuleGenerated: "",
		},
		{
			ID: "s3", MessageID: "ms3", Timestamp: time.Now().UTC().Format(time.RFC3339),
			FromAgent: "b", ToAgent: "a", Provider: "anthropic", Model: "claude",
			RiskScore: 0.9, RecommendedAction: "quarantine", Confidence: 0.85,
			ThreatsJSON: `["exfil","prompt_injection"]`, IntentJSON: `{}`,
			LatencyMs: 300, TokensUsed: 500, RuleGenerated: "RULE-Y",
		},
	}
	for _, r := range records {
		if err := store.LogLLMAnalysis(r); err != nil {
			t.Fatalf("insert %s failed: %v", r.ID, err)
		}
	}

	stats, err := store.QueryLLMStats()
	if err != nil {
		t.Fatalf("QueryLLMStats failed: %v", err)
	}

	if stats.TotalAnalyses != 3 {
		t.Errorf("TotalAnalyses = %d, want 3", stats.TotalAnalyses)
	}
	// Total tokens: 200 + 300 + 500 = 1000
	if stats.TotalTokens != 1000 {
		t.Errorf("TotalTokens = %d, want 1000", stats.TotalTokens)
	}
	// Avg latency: (100 + 200 + 300) / 3 = 200
	if stats.AvgLatencyMs != 200 {
		t.Errorf("AvgLatencyMs = %f, want 200", stats.AvgLatencyMs)
	}
	// Threats found: s1 and s3 have non-empty/non-"[]" threats = 2
	if stats.TotalThreats != 2 {
		t.Errorf("ThreatsFound = %d, want 2", stats.TotalThreats)
	}
	// Rules generated: s1 and s3 have non-empty rule_generated = 2
	if stats.RulesGenerated != 2 {
		t.Errorf("RulesGenerated = %d, want 2", stats.RulesGenerated)
	}
}
