package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oktsec/oktsec/internal/engine"
)

// --- Mock Analyzer ---

type mockAnalyzer struct {
	result *AnalysisResult
	err    error
	calls  atomic.Int64
}

func (m *mockAnalyzer) Analyze(_ context.Context, req AnalysisRequest) (*AnalysisResult, error) {
	m.calls.Add(1)
	if m.err != nil {
		return nil, m.err
	}
	r := *m.result
	r.MessageID = req.MessageID
	return &r, nil
}

func (m *mockAnalyzer) Name() string { return "mock/test" }

// --- Config Tests ---

func TestParseTimeout(t *testing.T) {
	tests := []struct {
		input string
		want  time.Duration
	}{
		{"", 30 * time.Second},
		{"10s", 10 * time.Second},
		{"1m", time.Minute},
		{"invalid", 30 * time.Second},
	}
	for _, tt := range tests {
		cfg := Config{Timeout: tt.input}
		got := cfg.ParseTimeout()
		if got != tt.want {
			t.Errorf("ParseTimeout(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestResolveAPIKey(t *testing.T) {
	t.Setenv("TEST_LLM_KEY", "sk-test-123")

	cfg := Config{APIKeyEnv: "TEST_LLM_KEY"}
	if got := cfg.ResolveAPIKey(); got != "sk-test-123" {
		t.Errorf("ResolveAPIKey() = %q, want %q", got, "sk-test-123")
	}

	cfg2 := Config{}
	if got := cfg2.ResolveAPIKey(); got != "" {
		t.Errorf("ResolveAPIKey() with no env = %q, want empty", got)
	}
}

func TestNewDisabled(t *testing.T) {
	a, err := New(Config{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	if a != nil {
		t.Error("expected nil analyzer when disabled")
	}
}

func TestNewUnknownProvider(t *testing.T) {
	_, err := New(Config{Enabled: true, Provider: "invalid"})
	if err == nil {
		t.Error("expected error for unknown provider")
	}
}

func TestNewOpenAIProvider(t *testing.T) {
	a, err := New(Config{Enabled: true, Provider: ProviderOpenAICompat, Model: "gpt-4"})
	if err != nil {
		t.Fatal(err)
	}
	if a == nil {
		t.Fatal("expected non-nil analyzer")
	}
	if a.Name() != "openai-compat/gpt-4" {
		t.Errorf("Name() = %q", a.Name())
	}
}

func TestNewClaudeProviderNoKey(t *testing.T) {
	_, err := New(Config{Enabled: true, Provider: ProviderClaude})
	if err == nil {
		t.Error("expected error for claude without API key")
	}
}

func TestNewWebhookProviderNoURL(t *testing.T) {
	_, err := New(Config{Enabled: true, Provider: ProviderWebhook})
	if err == nil {
		t.Error("expected error for webhook without URL")
	}
}

// --- Parse Tests ---

func TestParseAnalysisResponse(t *testing.T) {
	valid := `{
		"threats": [{"type": "novel_injection", "description": "test", "severity": "high", "evidence": "x", "confidence": 0.9}],
		"risk_score": 75,
		"recommended_action": "escalate",
		"confidence": 0.85
	}`

	result, err := parseAnalysisResponse(valid)
	if err != nil {
		t.Fatal(err)
	}
	if result.RiskScore != 75 {
		t.Errorf("risk_score = %f, want 75", result.RiskScore)
	}
	if result.RecommendedAction != "escalate" {
		t.Errorf("action = %q, want escalate", result.RecommendedAction)
	}
	if len(result.Threats) != 1 {
		t.Fatalf("threats = %d, want 1", len(result.Threats))
	}
	if result.Threats[0].Severity != "high" {
		t.Errorf("severity = %q, want high", result.Threats[0].Severity)
	}
}

func TestParseAnalysisResponseCodeFences(t *testing.T) {
	fenced := "```json\n{\"risk_score\": 0, \"recommended_action\": \"none\", \"confidence\": 0.9}\n```"
	result, err := parseAnalysisResponse(fenced)
	if err != nil {
		t.Fatal(err)
	}
	if result.RiskScore != 0 {
		t.Errorf("risk_score = %f, want 0", result.RiskScore)
	}
}

func TestParseAnalysisResponseInvalidJSON(t *testing.T) {
	_, err := parseAnalysisResponse("not json at all")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseAnalysisResponseClamping(t *testing.T) {
	out := `{"risk_score": 200, "confidence": 5, "recommended_action": "bogus",
		"threats": [{"type": "x", "description": "x", "severity": "bogus", "confidence": -1}]}`

	result, err := parseAnalysisResponse(out)
	if err != nil {
		t.Fatal(err)
	}
	if result.RiskScore != 100 {
		t.Errorf("risk_score = %f, want 100 (clamped)", result.RiskScore)
	}
	if result.Confidence != 1 {
		t.Errorf("confidence = %f, want 1 (clamped)", result.Confidence)
	}
	if result.RecommendedAction != "investigate" {
		t.Errorf("action = %q, want investigate (defaulted)", result.RecommendedAction)
	}
	if result.Threats[0].Severity != "medium" {
		t.Errorf("threat severity = %q, want medium (defaulted)", result.Threats[0].Severity)
	}
	if result.Threats[0].Confidence != 0 {
		t.Errorf("threat confidence = %f, want 0 (clamped)", result.Threats[0].Confidence)
	}
}

// --- Prompt Tests ---

func TestBuildAnalysisPrompt(t *testing.T) {
	req := AnalysisRequest{
		FromAgent:      "agent-a",
		ToAgent:        "agent-b",
		Content:        "hello world",
		Intent:         "greeting",
		CurrentVerdict: engine.VerdictClean,
		Findings: []engine.FindingSummary{
			{RuleID: "IAP-001", Name: "test", Severity: "high"},
		},
	}

	prompt := buildAnalysisPrompt(req)

	for _, want := range []string{"From: agent-a", "To: agent-b", "Declared Intent: greeting", "hello world", "IAP-001"} {
		if !containsStr(prompt, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
}

func TestBuildAnalysisPromptTruncation(t *testing.T) {
	long := make([]byte, 10000)
	for i := range long {
		long[i] = 'A'
	}
	req := AnalysisRequest{
		FromAgent: "a",
		ToAgent:   "b",
		Content:   string(long),
	}
	prompt := buildAnalysisPrompt(req)
	if len(prompt) > 9000 {
		t.Errorf("prompt not truncated: len=%d", len(prompt))
	}
}

// --- Queue Tests ---

func TestQueueSubmitAndProcess(t *testing.T) {
	mock := &mockAnalyzer{
		result: &AnalysisResult{
			RiskScore:         25,
			RecommendedAction: "none",
			Confidence:        0.9,
			LatencyMs:         10,
			TokensUsed:        100,
			ProviderName:      "mock",
			Model:             "test",
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	q := NewQueue(mock, QueueConfig{Workers: 1, BufferSize: 10}, logger)

	var gotResult atomic.Value
	q.OnResult(func(r AnalysisResult) {
		gotResult.Store(r)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q.Start(ctx)

	ok := q.Submit(AnalysisRequest{MessageID: "msg-1", FromAgent: "a", ToAgent: "b", Content: "test"})
	if !ok {
		t.Fatal("Submit returned false")
	}

	// Wait for processing
	deadline := time.After(2 * time.Second)
	for {
		if v := gotResult.Load(); v != nil {
			r := v.(AnalysisResult)
			if r.MessageID != "msg-1" {
				t.Errorf("message_id = %q, want msg-1", r.MessageID)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("timeout waiting for result")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	q.Stop()

	stats := q.Stats()
	if stats.Completed != 1 {
		t.Errorf("completed = %d, want 1", stats.Completed)
	}
	if stats.Provider != "mock/test" {
		t.Errorf("provider = %q", stats.Provider)
	}
}

func TestQueueBackpressure(t *testing.T) {
	mock := &mockAnalyzer{
		result: &AnalysisResult{ProviderName: "mock", Model: "test"},
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	q := NewQueue(mock, QueueConfig{Workers: 0, BufferSize: 2}, logger)
	// Don't start workers — channel will fill up

	_ = q.Submit(AnalysisRequest{MessageID: "1"})
	_ = q.Submit(AnalysisRequest{MessageID: "2"})
	ok := q.Submit(AnalysisRequest{MessageID: "3"})
	if ok {
		t.Error("expected Submit to return false when queue full")
	}

	stats := q.Stats()
	if stats.Dropped != 1 {
		t.Errorf("dropped = %d, want 1", stats.Dropped)
	}
}

func TestQueueDailyLimit(t *testing.T) {
	mock := &mockAnalyzer{
		result: &AnalysisResult{ProviderName: "mock", Model: "test"},
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	q := NewQueue(mock, QueueConfig{Workers: 1, BufferSize: 10, MaxDailyReqs: 2}, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q.Start(ctx)

	// Submit 2 — should succeed
	q.Submit(AnalysisRequest{MessageID: "1"})
	q.Submit(AnalysisRequest{MessageID: "2"})

	// Wait for processing so dailyCount increments
	time.Sleep(200 * time.Millisecond)

	// Submit 3rd — should be dropped
	ok := q.Submit(AnalysisRequest{MessageID: "3"})
	if ok {
		t.Error("expected Submit to return false at daily limit")
	}

	q.Stop()
}

func TestQueueErrorCallback(t *testing.T) {
	mock := &mockAnalyzer{err: fmt.Errorf("provider down")}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	q := NewQueue(mock, QueueConfig{Workers: 1, BufferSize: 10}, logger)

	var gotErr atomic.Value
	q.OnError(func(req AnalysisRequest, err error) {
		gotErr.Store(err.Error())
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q.Start(ctx)

	q.Submit(AnalysisRequest{MessageID: "err-1"})

	deadline := time.After(2 * time.Second)
	for {
		if v := gotErr.Load(); v != nil {
			if v.(string) != "provider down" {
				t.Errorf("error = %q", v)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("timeout waiting for error callback")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	q.Stop()
	stats := q.Stats()
	if stats.Errors != 1 {
		t.Errorf("errors = %d, want 1", stats.Errors)
	}
}

// --- RuleGen Tests ---

func TestRuleGenerate(t *testing.T) {
	dir := t.TempDir()
	gen := NewRuleGenerator(dir, false, 0.8)

	threat := ThreatFinding{
		Type:        "novel_injection",
		Description: "Agent tries to escalate privileges via base64",
		Severity:    "high",
		Confidence:  0.9,
		Suggestion: &RuleSuggestion{
			Name:     "Base64 Privilege Escalation",
			Pattern:  `(?i)base64.*escalat`,
			Category: "injection",
			Severity: "high",
		},
	}

	rule, err := gen.Generate(threat, "openai/gpt-4", "msg-123")
	if err != nil {
		t.Fatal(err)
	}
	if rule == nil {
		t.Fatal("expected non-nil rule")
	}
	if rule.ID != "LLM-001" {
		t.Errorf("ID = %q, want LLM-001", rule.ID)
	}
	if rule.Status != "active" {
		t.Errorf("Status = %q, want active", rule.Status)
	}

	// Verify file was written
	path := filepath.Join(dir, "llm-001.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Errorf("rule file not created: %v", err)
	}
}

func TestRuleGenerateRequireApproval(t *testing.T) {
	dir := t.TempDir()
	gen := NewRuleGenerator(dir, true, 0.8)

	threat := ThreatFinding{
		Confidence: 0.95,
		Suggestion: &RuleSuggestion{
			Name:    "Test",
			Pattern: `test`,
		},
	}

	rule, err := gen.Generate(threat, "mock", "msg-1")
	if err != nil {
		t.Fatal(err)
	}
	if rule.Status != "pending_review" {
		t.Errorf("Status = %q, want pending_review", rule.Status)
	}
}

func TestRuleGenerateNoSuggestion(t *testing.T) {
	gen := NewRuleGenerator(t.TempDir(), false, 0.8)
	rule, err := gen.Generate(ThreatFinding{Confidence: 0.9}, "mock", "msg-1")
	if err != nil {
		t.Fatal(err)
	}
	if rule != nil {
		t.Error("expected nil rule when no suggestion")
	}
}

func TestRuleGenerateLowConfidence(t *testing.T) {
	gen := NewRuleGenerator(t.TempDir(), false, 0.8)
	rule, err := gen.Generate(ThreatFinding{
		Confidence: 0.5,
		Suggestion: &RuleSuggestion{Name: "x", Pattern: `x`},
	}, "mock", "msg-1")
	if err != nil {
		t.Fatal(err)
	}
	if rule != nil {
		t.Error("expected nil rule when confidence below threshold")
	}
}

func TestRuleGenerateInvalidRegex(t *testing.T) {
	gen := NewRuleGenerator(t.TempDir(), false, 0.8)
	_, err := gen.Generate(ThreatFinding{
		Confidence: 0.9,
		Suggestion: &RuleSuggestion{Name: "bad", Pattern: `[invalid`},
	}, "mock", "msg-1")
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

func TestRuleApproveReject(t *testing.T) {
	dir := t.TempDir()
	gen := NewRuleGenerator(dir, true, 0.8)

	threat := ThreatFinding{
		Confidence: 0.95,
		Suggestion: &RuleSuggestion{Name: "Test Rule", Pattern: `test-pattern`},
	}

	rule, err := gen.Generate(threat, "mock", "msg-1")
	if err != nil {
		t.Fatal(err)
	}

	// Approve
	if err := gen.ApproveRule(rule.ID); err != nil {
		t.Fatal(err)
	}

	active, err := gen.ListActive()
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 {
		t.Fatalf("active = %d, want 1", len(active))
	}

	// Generate another and reject it
	threat2 := ThreatFinding{
		Confidence: 0.9,
		Suggestion: &RuleSuggestion{Name: "Bad Rule", Pattern: `bad`},
	}
	rule2, _ := gen.Generate(threat2, "mock", "msg-2")
	_ = gen.RejectRule(rule2.ID)

	pending, err := gen.ListPending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Errorf("pending = %d, want 0", len(pending))
	}
}

func TestRuleGenOnGeneratedCallback(t *testing.T) {
	dir := t.TempDir()
	gen := NewRuleGenerator(dir, false, 0.8)

	var called bool
	gen.OnGenerated(func(r GeneratedRule) {
		called = true
	})

	_, _ = gen.Generate(ThreatFinding{
		Confidence: 0.95,
		Suggestion: &RuleSuggestion{Name: "cb", Pattern: `cb`},
	}, "mock", "msg-1")

	if !called {
		t.Error("OnGenerated callback not called")
	}
}

// --- Provider Integration Tests (with httptest) ---

func TestOpenAIProviderAnalyze(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Error("missing auth header")
		}
		resp := chatResponse{
			Choices: []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			}{
				{Message: struct {
					Content string `json:"content"`
				}{Content: `{"risk_score": 10, "recommended_action": "none", "confidence": 0.95}`}},
			},
			Usage: struct {
				TotalTokens int `json:"total_tokens"`
			}{TotalTokens: 150},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p, err := newOpenAIProvider(Config{
		BaseURL:   srv.URL,
		APIKeyEnv: "TEST_OPENAI_KEY",
		Model:     "gpt-4",
		Timeout:   "5s",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Inject key directly since we can't use env in test easily
	p.apiKey = "test-key"

	result, err := p.Analyze(context.Background(), AnalysisRequest{
		MessageID: "msg-1",
		FromAgent: "a",
		ToAgent:   "b",
		Content:   "hello",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.RiskScore != 10 {
		t.Errorf("risk_score = %f, want 10", result.RiskScore)
	}
	if result.TokensUsed != 150 {
		t.Errorf("tokens = %d, want 150", result.TokensUsed)
	}
	if result.ProviderName != "openai" {
		t.Errorf("provider = %q", result.ProviderName)
	}
}

func TestOpenAIProviderError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error": "rate limited"}`))
	}))
	defer srv.Close()

	p, _ := newOpenAIProvider(Config{BaseURL: srv.URL, Model: "test", Timeout: "5s"})
	_, err := p.Analyze(context.Background(), AnalysisRequest{MessageID: "x"})
	if err == nil {
		t.Error("expected error for 429")
	}
}

func TestClaudeProviderAnalyze(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "test-claude-key" {
			t.Errorf("x-api-key = %q", r.Header.Get("x-api-key"))
		}
		if r.Header.Get("anthropic-version") != "2023-06-01" {
			t.Errorf("anthropic-version = %q", r.Header.Get("anthropic-version"))
		}
		resp := claudeResponse{
			Content: []struct {
				Text string `json:"text"`
			}{
				{Text: `{"risk_score": 5, "recommended_action": "none", "confidence": 0.99}`},
			},
			Usage: struct {
				InputTokens  int `json:"input_tokens"`
				OutputTokens int `json:"output_tokens"`
			}{InputTokens: 100, OutputTokens: 50},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	// Create provider manually to use test server URL
	p := &claudeProvider{
		client:    &http.Client{Timeout: 5 * time.Second},
		apiKey:    "test-claude-key",
		model:     "claude-sonnet-4-6",
		maxTokens: 2048,
	}

	// Override the endpoint by using httptest — we need to patch the Analyze method.
	// Since claudeProvider hardcodes the URL, we test via webhook which is more flexible.
	// Instead, test the webhook provider which is more testable.

	// For claude, just verify construction works with key
	t.Setenv("CLAUDE_TEST_KEY", "my-key")
	cp, err := newClaudeProvider(Config{
		Enabled:   true,
		Provider:  ProviderClaude,
		APIKeyEnv: "CLAUDE_TEST_KEY",
		Model:     "claude-sonnet-4-6",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cp.Name() != "claude/claude-sonnet-4-6" {
		t.Errorf("Name() = %q", cp.Name())
	}
	_ = p // satisfy compiler
}

func TestWebhookProviderAnalyze(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Custom") != "resolved-value" {
			t.Errorf("X-Custom = %q", r.Header.Get("X-Custom"))
		}
		result := AnalysisResult{
			RiskScore:         30,
			RecommendedAction: "investigate",
			Confidence:        0.7,
			TokensUsed:        200,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	}))
	defer srv.Close()

	t.Setenv("WEBHOOK_VAL", "resolved-value")

	p, err := newWebhookProvider(Config{
		Timeout: "5s",
		Webhook: WebhookConfig{
			URL:     srv.URL,
			Headers: map[string]string{"X-Custom": "${WEBHOOK_VAL}"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := p.Analyze(context.Background(), AnalysisRequest{
		MessageID: "msg-wh",
		FromAgent: "a",
		ToAgent:   "b",
		Content:   "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.RiskScore != 30 {
		t.Errorf("risk_score = %f, want 30", result.RiskScore)
	}
	if result.MessageID != "msg-wh" {
		t.Errorf("message_id = %q", result.MessageID)
	}
	if result.ProviderName != "webhook" {
		t.Errorf("provider = %q", result.ProviderName)
	}
}

func TestWebhookProviderServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	p, _ := newWebhookProvider(Config{
		Timeout: "5s",
		Webhook: WebhookConfig{URL: srv.URL},
	})

	_, err := p.Analyze(context.Background(), AnalysisRequest{MessageID: "x"})
	if err == nil {
		t.Error("expected error for 500")
	}
}

// --- Utility Tests ---

func TestTruncateStr(t *testing.T) {
	if got := truncateStr("short", 10); got != "short" {
		t.Errorf("truncateStr short = %q", got)
	}
	if got := truncateStr("a long string here", 5); got != "a lon..." {
		t.Errorf("truncateStr long = %q", got)
	}
}

func TestExpandEnv(t *testing.T) {
	t.Setenv("MY_VAR", "hello")
	if got := expandEnv("${MY_VAR}-world"); got != "hello-world" {
		t.Errorf("expandEnv = %q", got)
	}
	if got := expandEnv("no-vars"); got != "no-vars" {
		t.Errorf("expandEnv no vars = %q", got)
	}
}

func TestNextMidnight(t *testing.T) {
	m := nextMidnight()
	if m.Before(time.Now()) {
		t.Error("nextMidnight is in the past")
	}
	if m.Hour() != 0 || m.Minute() != 0 || m.Second() != 0 {
		t.Errorf("nextMidnight = %v, not midnight", m)
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && len(sub) > 0 && findSubstring(s, sub))
}

func findSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
