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
		APIKeyEnv:        cfg.APIKeyEnv,
		APIVersion:       cfg.APIVersion,
		MaxTokens:        cfg.MaxTokens,
		Temperature:      cfg.Temperature,
		MaxConcurrent:    cfg.MaxConcurrent,
		QueueSize:        cfg.QueueSize,
		MaxDailyReqs:     cfg.MaxDailyReqs,
		Timeout:          cfg.Timeout,
		Analyze:          AnalyzeConfig(cfg.Analyze),
		MinContentLength: cfg.MinContentLength,
		RuleGen:          RuleGenConfig(cfg.RuleGen),
		Webhook:          WebhookConfig(cfg.Webhook),
	}

	var fbCfg *FallbackConfig
	if cfg.Fallback.Provider != "" {
		fbCfg = &FallbackConfig{
			Provider:   Provider(cfg.Fallback.Provider),
			Model:      cfg.Fallback.Model,
			BaseURL:    cfg.Fallback.BaseURL,
			APIKeyEnv:  cfg.Fallback.APIKeyEnv,
			APIVersion: cfg.Fallback.APIVersion,
			MaxTokens:  cfg.Fallback.MaxTokens,
			Timeout:    cfg.Fallback.Timeout,
		}
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
		budgetCfg := BudgetConfig{
			DailyLimitUSD:   cfg.Budget.DailyLimitUSD,
			MonthlyLimitUSD: cfg.Budget.MonthlyLimitUSD,
			WarnThreshold:   cfg.Budget.WarnThreshold,
			OnLimit:         cfg.Budget.OnLimit,
		}
		queue.SetBudget(NewBudgetTracker(budgetCfg, logger))
		logger.Info("llm budget control enabled",
			"daily_limit", budgetCfg.DailyLimitUSD,
			"monthly_limit", budgetCfg.MonthlyLimitUSD,
		)
	}

	// Signal detector (triage pre-filter)
	var sd *SignalDetector
	if cfg.Triage.Enabled {
		sd = NewSignalDetector(TriageConfig(cfg.Triage))
		logger.Info("llm triage enabled", "sample_rate", cfg.Triage.SampleRate)
	}

	logger.Info("llm analysis enabled",
		"provider", cfg.Provider,
		"model", cfg.Model,
	)
	return queue, sd
}
