package llm

import (
	"log/slog"

	"github.com/oktsec/oktsec/internal/config"
)

// SetupQueue creates a fully wired LLM analysis queue from application config.
// Returns the queue (caller must Start/Stop it) and an optional signal detector.
// Returns nil, nil if the analyzer cannot be created.
func SetupQueue(cfg config.LLMConfig, logger *slog.Logger) (*Queue, *SignalDetector) {
	llmCfg := Config{
		Enabled:          true,
		Provider:         Provider(cfg.Provider),
		Model:            cfg.Model,
		BaseURL:          cfg.BaseURL,
		APIKey:           cfg.APIKey,
		APIKeyEnv:        cfg.APIKeyEnv,
		APIVersion:       cfg.APIVersion,
		MaxTokens:        cfg.MaxTokens,
		Temperature:      cfg.Temperature,
		MaxConcurrent:    cfg.MaxConcurrent,
		QueueSize:        cfg.QueueSize,
		MaxDailyReqs:     cfg.MaxDailyReqs,
		Timeout:          cfg.Timeout,
		Analyze:          cfg.Analyze,
		MinContentLength: cfg.MinContentLength,
		RuleGen:          cfg.RuleGen,
		Webhook:          cfg.Webhook,
	}

	var fbCfg *FallbackConfig
	if cfg.Fallback.Provider != "" {
		fbCfg = &cfg.Fallback
	}

	analyzer, err := NewWithFallback(llmCfg, fbCfg, logger)
	if err != nil {
		logger.Error("failed to create LLM analyzer", "error", err)
		return nil, nil
	}

	queueCfg := QueueConfig{
		Workers:      cfg.MaxConcurrent,
		BufferSize:   cfg.QueueSize,
		MaxDailyReqs: cfg.MaxDailyReqs,
	}
	queue := NewQueue(analyzer, queueCfg, logger)

	// Wire budget tracker if limits are set
	if cfg.Budget.DailyLimitUSD > 0 || cfg.Budget.MonthlyLimitUSD > 0 {
		queue.SetBudget(NewBudgetTracker(cfg.Budget, logger))
		logger.Info("llm budget control enabled",
			"daily_limit", cfg.Budget.DailyLimitUSD,
			"monthly_limit", cfg.Budget.MonthlyLimitUSD,
		)
	}

	// Signal detector (triage pre-filter)
	var sd *SignalDetector
	if cfg.Triage.Enabled {
		sd = NewSignalDetector(cfg.Triage)
		logger.Info("llm triage enabled", "sample_rate", cfg.Triage.SampleRate)
	}

	logger.Info("llm analysis enabled",
		"provider", cfg.Provider,
		"model", cfg.Model,
	)
	return queue, sd
}
