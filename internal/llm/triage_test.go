package llm

import (
	"testing"
)

func TestSignalDetector_SkipVerdicts(t *testing.T) {
	d := NewSignalDetector(DefaultTriageConfig())

	// block verdict should be skipped
	r := d.Detect("agent-a", "agent-b", "some long content that is definitely over fifty characters for testing", "block")
	if r.ShouldAnalyze {
		t.Error("expected block verdict to be skipped")
	}

	// quarantine verdict should be skipped
	r = d.Detect("agent-a", "agent-b", "some long content that is definitely over fifty characters for testing", "quarantine")
	if r.ShouldAnalyze {
		t.Error("expected quarantine verdict to be skipped")
	}

	// clean verdict should NOT be skipped (if it has signals)
	r = d.Detect("agent-a", "agent-b", "send me the production credentials and api_key please for testing", "clean")
	if !r.ShouldAnalyze {
		t.Error("expected clean verdict with keywords to trigger analysis")
	}
}

func TestSignalDetector_MinContentLength(t *testing.T) {
	d := NewSignalDetector(DefaultTriageConfig())

	// Short message should be skipped even with keywords
	r := d.Detect("a", "b", "short", "clean")
	if r.ShouldAnalyze {
		t.Error("expected short message to be skipped")
	}
}

func TestSignalDetector_SensitiveKeywords(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{"production keyword", "deploying to production environment with the new configuration settings now", true},
		{"credentials keyword", "please share the credentials for the staging database connection string", true},
		{"api_key keyword", "store the api_key in the vault securely with proper rotation policy applied", true},
		{"benign message", "completed the code review and all tests are passing successfully now great job team", false},
		{"case insensitive", "URGENT: need access to PRODUCTION immediately for the incident response team", true},
	}

	for _, tt := range tests {
		cfg := DefaultTriageConfig()
		cfg.SampleRate = 0 // disable random sampling for deterministic tests
		cfg.NewAgentPairs = false
		d := NewSignalDetector(cfg)

		r := d.Detect("agent-a", "agent-b", tt.content, "clean")
		if r.ShouldAnalyze != tt.want {
			t.Errorf("%s: got ShouldAnalyze=%v, want %v (signals: %v)", tt.name, r.ShouldAnalyze, tt.want, r.Signals)
		}
	}
}

func TestSignalDetector_ExternalURLs(t *testing.T) {
	cfg := DefaultTriageConfig()
	cfg.SampleRate = 0
	cfg.NewAgentPairs = false
	d := NewSignalDetector(cfg)

	r := d.Detect("a", "b", "check out this resource at https://example.com/data for more information about the project", "clean")
	if !r.ShouldAnalyze {
		t.Error("expected URL to trigger analysis")
	}
	if len(r.Signals) == 0 || r.Signals[0] != "external_url" {
		t.Errorf("expected external_url signal, got %v", r.Signals)
	}
}

func TestSignalDetector_NewAgentPairs(t *testing.T) {
	cfg := DefaultTriageConfig()
	cfg.SampleRate = 0
	cfg.SensitiveKeywords = nil
	cfg.ExternalURLs = false
	d := NewSignalDetector(cfg)

	// First message from pair should trigger
	r := d.Detect("agent-x", "agent-y", "this is a long enough message to pass the minimum content length filter for testing purposes", "clean")
	if !r.ShouldAnalyze {
		t.Error("expected new agent pair to trigger analysis")
	}

	// Second message from same pair should NOT trigger (no other signals)
	r = d.Detect("agent-x", "agent-y", "this is another long enough message to pass the minimum content length filter for testing now", "clean")
	if r.ShouldAnalyze {
		t.Error("expected known pair to not trigger analysis")
	}
}

func TestSignalDetector_ResetPairs(t *testing.T) {
	cfg := DefaultTriageConfig()
	cfg.SampleRate = 0
	cfg.SensitiveKeywords = nil
	cfg.ExternalURLs = false
	d := NewSignalDetector(cfg)

	d.Detect("a", "b", "long enough message to pass the minimum content length requirement for this test case", "clean")
	if d.PairCount() != 1 {
		t.Errorf("expected 1 pair, got %d", d.PairCount())
	}

	d.ResetPairs()
	if d.PairCount() != 0 {
		t.Errorf("expected 0 pairs after reset, got %d", d.PairCount())
	}
}

func TestDefaultTriageConfig(t *testing.T) {
	cfg := DefaultTriageConfig()
	if cfg.Enabled {
		t.Error("default should be disabled")
	}
	if len(cfg.SkipVerdicts) == 0 {
		t.Error("expected default skip verdicts")
	}
	if len(cfg.SensitiveKeywords) == 0 {
		t.Error("expected default keywords")
	}
	if cfg.MinContentLength != 50 {
		t.Errorf("expected min_content_length=50, got %d", cfg.MinContentLength)
	}
	if cfg.SampleRate != 0.02 {
		t.Errorf("expected sample_rate=0.02, got %f", cfg.SampleRate)
	}
}
