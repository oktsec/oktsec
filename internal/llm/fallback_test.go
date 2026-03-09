package llm

import (
	"context"
	"errors"
	"log/slog"
	"testing"
)

func TestFallbackAnalyzer_PrimarySuccess(t *testing.T) {
	primary := &mockAnalyzer{result: &AnalysisResult{RiskScore: 42, ProviderName: "primary"}}
	secondary := &mockAnalyzer{result: &AnalysisResult{RiskScore: 10, ProviderName: "secondary"}}
	fb := NewFallbackAnalyzer(primary, secondary, slog.Default())

	result, err := fb.Analyze(context.Background(), AnalysisRequest{MessageID: "msg-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ProviderName != "primary" {
		t.Errorf("expected primary provider, got %q", result.ProviderName)
	}
	if primary.calls.Load() != 1 {
		t.Errorf("primary calls = %d, want 1", primary.calls.Load())
	}
	if secondary.calls.Load() != 0 {
		t.Errorf("secondary calls = %d, want 0", secondary.calls.Load())
	}
	stats := fb.Stats()
	if stats.PrimaryOK != 1 {
		t.Errorf("PrimaryOK = %d, want 1", stats.PrimaryOK)
	}
}

func TestFallbackAnalyzer_PrimaryFailsFallbackSucceeds(t *testing.T) {
	primary := &mockAnalyzer{err: errors.New("connection refused")}
	secondary := &mockAnalyzer{result: &AnalysisResult{RiskScore: 55, ProviderName: "secondary"}}
	fb := NewFallbackAnalyzer(primary, secondary, slog.Default())

	result, err := fb.Analyze(context.Background(), AnalysisRequest{MessageID: "msg-2"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ProviderName != "secondary" {
		t.Errorf("expected secondary provider, got %q", result.ProviderName)
	}
	if primary.calls.Load() != 1 {
		t.Errorf("primary calls = %d, want 1", primary.calls.Load())
	}
	if secondary.calls.Load() != 1 {
		t.Errorf("secondary calls = %d, want 1", secondary.calls.Load())
	}
	stats := fb.Stats()
	if stats.SecondaryOK != 1 {
		t.Errorf("SecondaryOK = %d, want 1", stats.SecondaryOK)
	}
}

func TestFallbackAnalyzer_BothFail(t *testing.T) {
	primary := &mockAnalyzer{err: errors.New("primary down")}
	secondary := &mockAnalyzer{err: errors.New("secondary down")}
	fb := NewFallbackAnalyzer(primary, secondary, slog.Default())

	_, err := fb.Analyze(context.Background(), AnalysisRequest{MessageID: "msg-3"})
	if err == nil {
		t.Fatal("expected error when both fail")
	}
	if primary.calls.Load() != 1 || secondary.calls.Load() != 1 {
		t.Errorf("expected both providers called once")
	}
	stats := fb.Stats()
	if stats.SecondaryFail != 1 {
		t.Errorf("SecondaryFail = %d, want 1", stats.SecondaryFail)
	}
}

func TestFallbackAnalyzer_Name(t *testing.T) {
	primary := &mockAnalyzer{result: &AnalysisResult{}}
	secondary := &mockAnalyzer{result: &AnalysisResult{}}
	fb := NewFallbackAnalyzer(primary, secondary, slog.Default())

	if fb.Name() != "mock/test" {
		t.Errorf("Name() = %q, want %q", fb.Name(), "mock/test")
	}
}

func TestNewWithFallback_NoFallback(t *testing.T) {
	// With nil fallback config, should return plain analyzer
	cfg := Config{
		Enabled:  true,
		Provider: ProviderWebhook,
		Webhook:  WebhookConfig{URL: "http://localhost:9999"},
	}
	analyzer, err := NewWithFallback(cfg, nil, slog.Default())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if analyzer == nil {
		t.Fatal("expected non-nil analyzer")
	}
	// Should NOT be a FallbackAnalyzer
	if _, ok := analyzer.(*FallbackAnalyzer); ok {
		t.Error("expected plain analyzer, got FallbackAnalyzer")
	}
}

func TestNewWithFallback_WithFallback(t *testing.T) {
	cfg := Config{
		Enabled:  true,
		Provider: ProviderWebhook,
		Webhook:  WebhookConfig{URL: "http://localhost:9999"},
	}
	fb := &FallbackConfig{
		Provider: ProviderWebhook,
	}
	analyzer, err := NewWithFallback(cfg, fb, slog.Default())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if analyzer == nil {
		t.Fatal("expected non-nil analyzer")
	}
	if _, ok := analyzer.(*FallbackAnalyzer); !ok {
		t.Error("expected FallbackAnalyzer")
	}
}

func TestNewWithFallback_Disabled(t *testing.T) {
	cfg := Config{Enabled: false}
	analyzer, err := NewWithFallback(cfg, nil, slog.Default())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if analyzer != nil {
		t.Error("expected nil analyzer when disabled")
	}
}
