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
