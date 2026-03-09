package llm

import (
	"log/slog"
	"sync"
	"time"
)

// BudgetConfig controls LLM spending limits.
type BudgetConfig struct {
	DailyLimitUSD   float64 // 0 = unlimited
	MonthlyLimitUSD float64 // 0 = unlimited
	WarnThreshold   float64 // fraction (0.0-1.0), default 0.8
	OnLimit         string  // "skip" | "fallback" | "block"
}

// BudgetStatus describes the current budget state.
type BudgetStatus struct {
	DailySpent      float64 `json:"daily_spent_usd"`
	DailyLimit      float64 `json:"daily_limit_usd"`
	DailyRemaining  float64 `json:"daily_remaining_usd"`
	DailyPercent    float64 `json:"daily_percent"`
	MonthlySpent    float64 `json:"monthly_spent_usd"`
	MonthlyLimit    float64 `json:"monthly_limit_usd"`
	MonthlyRemain   float64 `json:"monthly_remaining_usd"`
	MonthlyPercent  float64 `json:"monthly_percent"`
	DailyWarning    bool    `json:"daily_warning"`
	MonthlyWarning  bool    `json:"monthly_warning"`
	DailyExhausted  bool    `json:"daily_exhausted"`
	MonthlyExhaust  bool    `json:"monthly_exhausted"`
	TotalCalls      int64   `json:"total_calls"`
	DroppedBudget   int64   `json:"dropped_budget"`
}

// BudgetTracker tracks LLM spending against daily and monthly limits.
// Safe for concurrent use.
type BudgetTracker struct {
	mu sync.Mutex

	cfg BudgetConfig

	dailySpent   float64
	monthlySpent float64
	dailyCalls   int64
	droppedCount int64

	dailyResetAt   time.Time
	monthlyResetAt time.Time

	logger *slog.Logger
}

// NewBudgetTracker creates a budget tracker with the given limits.
func NewBudgetTracker(cfg BudgetConfig, logger *slog.Logger) *BudgetTracker {
	if cfg.WarnThreshold <= 0 || cfg.WarnThreshold > 1 {
		cfg.WarnThreshold = 0.8
	}
	if cfg.OnLimit == "" {
		cfg.OnLimit = "skip"
	}
	now := time.Now()
	return &BudgetTracker{
		cfg:            cfg,
		dailyResetAt:   nextMidnight(),
		monthlyResetAt: nextMonthStart(now),
		logger:         logger,
	}
}

// CanSpend checks if the budget allows another API call.
// Returns (allowed, reason). Reason is empty if allowed.
func (b *BudgetTracker) CanSpend() (bool, string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.maybeReset()

	if b.cfg.DailyLimitUSD > 0 && b.dailySpent >= b.cfg.DailyLimitUSD {
		b.droppedCount++
		llmBudgetExhausted.Inc()
		return false, "daily_limit"
	}
	if b.cfg.MonthlyLimitUSD > 0 && b.monthlySpent >= b.cfg.MonthlyLimitUSD {
		b.droppedCount++
		llmBudgetExhausted.Inc()
		return false, "monthly_limit"
	}
	return true, ""
}

// RecordCost adds the actual cost of an API call to the running totals.
func (b *BudgetTracker) RecordCost(tokensIn, tokensOut int, priceInPerM, priceOutPerM float64) {
	cost := float64(tokensIn)/1e6*priceInPerM + float64(tokensOut)/1e6*priceOutPerM

	b.mu.Lock()
	defer b.mu.Unlock()
	b.maybeReset()

	b.dailySpent += cost
	b.monthlySpent += cost
	b.dailyCalls++

	llmBudgetSpent.WithLabelValues("daily").Set(b.dailySpent)
	llmBudgetSpent.WithLabelValues("monthly").Set(b.monthlySpent)

	// Warn if crossing threshold
	if b.cfg.DailyLimitUSD > 0 {
		pct := b.dailySpent / b.cfg.DailyLimitUSD
		if pct >= b.cfg.WarnThreshold && (b.dailySpent-cost)/b.cfg.DailyLimitUSD < b.cfg.WarnThreshold {
			b.logger.Warn("llm daily budget warning",
				"spent", b.dailySpent,
				"limit", b.cfg.DailyLimitUSD,
				"percent", pct*100,
			)
		}
	}
	if b.cfg.MonthlyLimitUSD > 0 {
		pct := b.monthlySpent / b.cfg.MonthlyLimitUSD
		if pct >= b.cfg.WarnThreshold && (b.monthlySpent-cost)/b.cfg.MonthlyLimitUSD < b.cfg.WarnThreshold {
			b.logger.Warn("llm monthly budget warning",
				"spent", b.monthlySpent,
				"limit", b.cfg.MonthlyLimitUSD,
				"percent", pct*100,
			)
		}
	}
}

// Status returns the current budget status for dashboard display.
func (b *BudgetTracker) Status() BudgetStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.maybeReset()

	s := BudgetStatus{
		DailySpent:   b.dailySpent,
		DailyLimit:   b.cfg.DailyLimitUSD,
		MonthlySpent: b.monthlySpent,
		MonthlyLimit: b.cfg.MonthlyLimitUSD,
		TotalCalls:   b.dailyCalls,
		DroppedBudget: b.droppedCount,
	}

	if s.DailyLimit > 0 {
		s.DailyRemaining = s.DailyLimit - s.DailySpent
		if s.DailyRemaining < 0 {
			s.DailyRemaining = 0
		}
		s.DailyPercent = s.DailySpent / s.DailyLimit * 100
		s.DailyWarning = s.DailyPercent >= b.cfg.WarnThreshold*100
		s.DailyExhausted = s.DailySpent >= s.DailyLimit
	}

	if s.MonthlyLimit > 0 {
		s.MonthlyRemain = s.MonthlyLimit - s.MonthlySpent
		if s.MonthlyRemain < 0 {
			s.MonthlyRemain = 0
		}
		s.MonthlyPercent = s.MonthlySpent / s.MonthlyLimit * 100
		s.MonthlyWarning = s.MonthlyPercent >= b.cfg.WarnThreshold*100
		s.MonthlyExhaust = s.MonthlySpent >= s.MonthlyLimit
	}

	return s
}

// UpdateConfig hot-reloads budget limits without losing spend tracking.
func (b *BudgetTracker) UpdateConfig(cfg BudgetConfig) {
	if cfg.WarnThreshold <= 0 || cfg.WarnThreshold > 1 {
		cfg.WarnThreshold = 0.8
	}
	if cfg.OnLimit == "" {
		cfg.OnLimit = "skip"
	}
	b.mu.Lock()
	b.cfg = cfg
	b.mu.Unlock()
}

// maybeReset resets counters at day/month boundaries. Must be called with mu held.
func (b *BudgetTracker) maybeReset() {
	now := time.Now()
	if now.After(b.dailyResetAt) {
		b.dailySpent = 0
		b.dailyCalls = 0
		b.droppedCount = 0
		b.dailyResetAt = nextMidnight()
		llmBudgetSpent.WithLabelValues("daily").Set(0)
	}
	if now.After(b.monthlyResetAt) {
		b.monthlySpent = 0
		b.monthlyResetAt = nextMonthStart(now)
		llmBudgetSpent.WithLabelValues("monthly").Set(0)
	}
}

func nextMonthStart(now time.Time) time.Time {
	y, m, _ := now.Date()
	if m == time.December {
		return time.Date(y+1, time.January, 1, 0, 0, 0, 0, now.Location())
	}
	return time.Date(y, m+1, 1, 0, 0, 0, 0, now.Location())
}
