// Package llm provides async LLM-powered security analysis for oktsec.
//
// The LLM layer runs asynchronously after the deterministic rule pipeline.
// It never blocks the proxy response. Users choose their own LLM provider:
// OpenAI-compatible APIs (covers Ollama, vLLM, llama.cpp, Groq, Together,
// Azure, Mistral, LM Studio), Anthropic Claude, or a custom webhook.
package llm

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
)

// Provider identifies the LLM backend type.
type Provider string

const (
	// ProviderOpenAICompat covers OpenAI, Ollama, vLLM, llama.cpp,
	// Mistral, Azure, Groq, Together, LM Studio, and any Chat
	// Completions-compatible API.
	ProviderOpenAICompat Provider = "openai"

	// ProviderClaude uses the Anthropic Messages API.
	ProviderClaude Provider = "claude"

	// ProviderWebhook sends analysis requests to a custom HTTP endpoint.
	ProviderWebhook Provider = "webhook"
)

// Analyzer is the interface all LLM providers implement.
type Analyzer interface {
	// Analyze runs security analysis on a message and returns structured findings.
	Analyze(ctx context.Context, req AnalysisRequest) (*AnalysisResult, error)

	// Name returns the provider/model identifier for metrics and logging.
	Name() string
}

// AnalysisRequest is sent to the LLM for async analysis.
type AnalysisRequest struct {
	MessageID      string                  `json:"message_id"`
	FromAgent      string                  `json:"from_agent"`
	ToAgent        string                  `json:"to_agent"`
	Content        string                  `json:"content"`
	Intent         string                  `json:"intent,omitempty"`
	CurrentVerdict engine.ScanVerdict      `json:"current_verdict"`
	Findings       []engine.FindingSummary `json:"existing_findings,omitempty"`
	Timestamp      time.Time               `json:"timestamp"`
}

// AnalysisResult is the structured LLM response.
type AnalysisResult struct {
	MessageID         string          `json:"message_id"`
	FromAgent         string          `json:"from_agent,omitempty"`
	ToAgent           string          `json:"to_agent,omitempty"`
	Threats           []ThreatFinding `json:"threats,omitempty"`
	IntentAnalysis    *IntentResult   `json:"intent_analysis,omitempty"`
	RiskScore         float64         `json:"risk_score"`
	RecommendedAction string          `json:"recommended_action"` // escalate, confirm, investigate, none
	Confidence        float64         `json:"confidence"`
	LatencyMs         int64           `json:"latency_ms"`
	TokensUsed        int             `json:"tokens_used"`
	ProviderName      string          `json:"provider"`
	Model             string          `json:"model"`
}

// ThreatFinding is a single threat detected by the LLM.
type ThreatFinding struct {
	Type        string          `json:"type"` // novel_injection, semantic_exfil, intent_drift, etc.
	Description string          `json:"description"`
	Severity    string          `json:"severity"` // critical, high, medium, low
	Evidence    string          `json:"evidence"`
	Confidence  float64         `json:"confidence"`
	Suggestion  *RuleSuggestion `json:"suggestion,omitempty"`
}

// RuleSuggestion is an LLM-proposed deterministic rule.
type RuleSuggestion struct {
	Name     string `json:"name"`
	Pattern  string `json:"pattern"`  // regex
	Category string `json:"category"`
	Severity string `json:"severity"`
}

// IntentResult is the LLM's analysis of intent alignment.
type IntentResult struct {
	DeclaredIntent string  `json:"declared_intent"`
	ActualIntent   string  `json:"actual_intent"`
	Alignment      float64 `json:"alignment"` // 0-1
	Drift          bool    `json:"drift"`
	Reason         string  `json:"reason"`
}

// Config holds LLM layer configuration.
type Config struct {
	Enabled     bool     `yaml:"enabled"`
	Provider    Provider `yaml:"provider"`
	Model       string   `yaml:"model"`
	BaseURL     string   `yaml:"base_url,omitempty"`
	APIKeyEnv   string   `yaml:"api_key_env,omitempty"`
	APIVersion  string   `yaml:"api_version,omitempty"` // for Azure OpenAI

	MaxTokens     int     `yaml:"max_tokens,omitempty"`
	Temperature   float64 `yaml:"temperature,omitempty"`
	MaxConcurrent int     `yaml:"max_concurrent,omitempty"`
	QueueSize     int     `yaml:"queue_size,omitempty"`
	MaxDailyReqs  int64   `yaml:"max_daily_requests,omitempty"`
	Timeout       string  `yaml:"timeout,omitempty"` // duration string: "30s", "1m"

	Analyze          AnalyzeConfig  `yaml:"analyze,omitempty"`
	MinContentLength int            `yaml:"min_content_length,omitempty"`

	RuleGen RuleGenConfig  `yaml:"rulegen,omitempty"`
	Intent  IntentConfig   `yaml:"intent,omitempty"`
	Webhook WebhookConfig  `yaml:"webhook,omitempty"`
}

// Type aliases for LLM sub-configs. The canonical definitions live in
// internal/config to keep YAML tags in one place. Using aliases (not
// type definitions) makes the types fully interchangeable.
type (
	AnalyzeConfig  = config.LLMAnalyzeConfig
	RuleGenConfig  = config.LLMRuleGenConfig
	IntentConfig   = config.LLMIntentConfig
	WebhookConfig  = config.LLMWebhookConfig
	FallbackConfig = config.LLMFallbackConfig
	TriageConfig   = config.LLMTriageConfig
	BudgetConfig   = config.LLMBudgetConfig
)

// ParseTimeout returns the configured timeout as a time.Duration.
func (c *Config) ParseTimeout() time.Duration {
	if c.Timeout == "" {
		return 30 * time.Second
	}
	d, err := time.ParseDuration(c.Timeout)
	if err != nil {
		return 30 * time.Second
	}
	return d
}

// ResolveAPIKey reads the API key from the environment variable.
// Returns empty string if env var is not set (valid for local providers).
func (c *Config) ResolveAPIKey() string {
	if c.APIKeyEnv == "" {
		return ""
	}
	return os.Getenv(c.APIKeyEnv)
}

// New creates an Analyzer from config.
// Returns nil, nil if LLM is disabled.
func New(cfg Config) (Analyzer, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	switch cfg.Provider {
	case ProviderOpenAICompat:
		return newOpenAIProvider(cfg)
	case ProviderClaude:
		return newClaudeProvider(cfg)
	case ProviderWebhook:
		return newWebhookProvider(cfg)
	default:
		return nil, fmt.Errorf("unknown llm provider: %q (valid: openai, claude, webhook)", cfg.Provider)
	}
}

// NewWithFallback creates a primary Analyzer and optionally wraps it with
// a FallbackAnalyzer if fallback config is provided. Returns nil, nil if disabled.
func NewWithFallback(cfg Config, fb *FallbackConfig, logger *slog.Logger) (Analyzer, error) {
	primary, err := New(cfg)
	if err != nil || primary == nil {
		return primary, err
	}
	if fb == nil || fb.Provider == "" {
		return primary, nil
	}

	// Build secondary config from fallback + inherit defaults from primary
	secCfg := Config{
		Enabled:     true,
		Provider:    Provider(fb.Provider),
		Model:       fb.Model,
		BaseURL:     fb.BaseURL,
		APIKeyEnv:   fb.APIKeyEnv,
		APIVersion:  fb.APIVersion,
		MaxTokens:   fb.MaxTokens,
		Temperature: cfg.Temperature,
		Timeout:     fb.Timeout,
		Webhook:     cfg.Webhook,
	}
	if secCfg.MaxTokens == 0 {
		secCfg.MaxTokens = cfg.MaxTokens
	}
	if secCfg.Timeout == "" {
		secCfg.Timeout = cfg.Timeout
	}

	secondary, err := New(secCfg)
	if err != nil {
		return nil, fmt.Errorf("fallback provider: %w", err)
	}

	logger.Info("llm fallback configured",
		"primary", primary.Name(),
		"secondary", secondary.Name(),
	)
	return NewFallbackAnalyzer(primary, secondary, logger), nil
}
