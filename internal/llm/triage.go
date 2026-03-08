package llm

import (
	"math/rand/v2"
	"strings"
	"sync"
)

// TriageConfig controls the pre-LLM signal detector.
type TriageConfig struct {
	Enabled           bool     `yaml:"enabled"`
	SkipVerdicts      []string `yaml:"skip_verdicts"`       // verdicts to skip LLM analysis for (e.g. block, quarantine)
	SensitiveKeywords []string `yaml:"sensitive_keywords"`  // words that trigger LLM analysis
	MinContentLength  int      `yaml:"min_content_length"`  // skip messages shorter than this
	NewAgentPairs     bool     `yaml:"new_agent_pairs"`     // flag unseen from->to pairs
	SampleRate        float64  `yaml:"sample_rate"`         // random sampling rate for clean messages (0.0-1.0)
	ExternalURLs      bool     `yaml:"external_urls"`       // flag messages with URLs
}

// DefaultTriageConfig returns sensible defaults for the signal detector.
func DefaultTriageConfig() TriageConfig {
	return TriageConfig{
		Enabled:      false,
		SkipVerdicts: []string{"block", "quarantine"},
		SensitiveKeywords: []string{
			"production", "credentials", "api_key", "admin", "root",
			"bypass", "external", "urgent", "secret", "password",
			"token", "private_key", "exfiltrate", "inject",
		},
		MinContentLength: 50,
		NewAgentPairs:    true,
		SampleRate:       0.02,
		ExternalURLs:     true,
	}
}

// SignalResult describes why a message was flagged for LLM analysis.
type SignalResult struct {
	ShouldAnalyze bool     `json:"should_analyze"`
	Signals       []string `json:"signals,omitempty"`
}

// SignalDetector is a fast pre-filter that determines if a message
// needs LLM analysis. It runs in ~1ms (pure string matching, no regex).
// Safe for concurrent use from multiple queue workers.
type SignalDetector struct {
	cfg       TriageConfig
	mu        sync.RWMutex
	seenPairs map[string]bool // tracks from->to pairs
}

// NewSignalDetector creates a signal detector from config.
func NewSignalDetector(cfg TriageConfig) *SignalDetector {
	return &SignalDetector{
		cfg:       cfg,
		seenPairs: make(map[string]bool),
	}
}

// Detect checks a message for signals that warrant LLM analysis.
// This is designed to be fast (<1ms) — pure string operations, no regex.
func (d *SignalDetector) Detect(from, to, content, verdict string) SignalResult {
	var signals []string

	// Skip verdicts that already have a deterministic outcome
	for _, sv := range d.cfg.SkipVerdicts {
		if verdict == sv {
			return SignalResult{ShouldAnalyze: false}
		}
	}

	// Skip messages that are too short to be meaningful threats
	if len(content) < d.cfg.MinContentLength {
		return SignalResult{ShouldAnalyze: false}
	}

	lower := strings.ToLower(content)

	// Check for sensitive keywords
	for _, kw := range d.cfg.SensitiveKeywords {
		if strings.Contains(lower, kw) {
			signals = append(signals, "keyword:"+kw)
			break // one keyword match is enough
		}
	}

	// Check for external URLs
	if d.cfg.ExternalURLs {
		if strings.Contains(lower, "http://") || strings.Contains(lower, "https://") {
			signals = append(signals, "external_url")
		}
	}

	// Check for new agent pairs
	if d.cfg.NewAgentPairs && from != "" && to != "" {
		pair := from + "->" + to
		d.mu.RLock()
		seen := d.seenPairs[pair]
		d.mu.RUnlock()
		if !seen {
			d.mu.Lock()
			if !d.seenPairs[pair] { // double-check under write lock
				d.seenPairs[pair] = true
				signals = append(signals, "new_agent_pair:"+pair)
			}
			d.mu.Unlock()
		}
	}

	// Random sampling of clean traffic
	if len(signals) == 0 && d.cfg.SampleRate > 0 {
		if rand.Float64() < d.cfg.SampleRate {
			signals = append(signals, "random_sample")
		}
	}

	return SignalResult{
		ShouldAnalyze: len(signals) > 0,
		Signals:       signals,
	}
}

// ResetPairs clears the seen agent pairs cache.
// Call periodically (e.g., daily) to re-detect pairs.
func (d *SignalDetector) ResetPairs() {
	d.mu.Lock()
	d.seenPairs = make(map[string]bool)
	d.mu.Unlock()
}

// PairCount returns the number of tracked agent pairs.
func (d *SignalDetector) PairCount() int {
	d.mu.RLock()
	n := len(d.seenPairs)
	d.mu.RUnlock()
	return n
}
