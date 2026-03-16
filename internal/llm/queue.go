package llm

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Queue manages async LLM analysis with backpressure and cost control.
type Queue struct {
	analyzer Analyzer
	ch       chan AnalysisRequest
	logger   *slog.Logger

	// Callbacks
	onResult func(AnalysisResult)
	onError  func(AnalysisRequest, error)

	// Cost control
	maxDaily   int64
	dailyCount atomic.Int64
	dailyReset time.Time
	mu         sync.Mutex
	budget     *BudgetTracker

	// Stats
	completed atomic.Int64
	dropped   atomic.Int64
	totalMs   atomic.Int64
	errCount  atomic.Int64

	// Lifecycle
	workers int
	wg      sync.WaitGroup
	cancel  context.CancelFunc
}

// QueueConfig configures the analysis queue.
type QueueConfig struct {
	Workers      int   // concurrent analysis workers (default: 3)
	BufferSize   int   // channel buffer (default: 100)
	MaxDailyReqs int64 // 0 = unlimited
}

// NewQueue creates an analysis queue.
func NewQueue(analyzer Analyzer, cfg QueueConfig, logger *slog.Logger) *Queue {
	if cfg.Workers <= 0 {
		cfg.Workers = 3
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 100
	}

	return &Queue{
		analyzer:   analyzer,
		ch:         make(chan AnalysisRequest, cfg.BufferSize),
		logger:     logger,
		workers:    cfg.Workers,
		maxDaily:   cfg.MaxDailyReqs,
		dailyReset: nextMidnight(),
	}
}

// OnResult sets the callback for completed analyses.
func (q *Queue) OnResult(fn func(AnalysisResult)) {
	q.onResult = fn
}

// OnError sets the callback for failed analyses.
func (q *Queue) OnError(fn func(AnalysisRequest, error)) {
	q.onError = fn
}

// SetBudget attaches a budget tracker to the queue.
func (q *Queue) SetBudget(b *BudgetTracker) {
	q.budget = b
}

// Budget returns the attached budget tracker (may be nil).
func (q *Queue) Budget() *BudgetTracker {
	return q.budget
}

// Submit enqueues an analysis request.
// Returns false if queue is full, daily limit reached, or budget exhausted.
func (q *Queue) Submit(req AnalysisRequest) bool {
	if q.maxDaily > 0 {
		q.mu.Lock()
		if time.Now().After(q.dailyReset) {
			q.dailyCount.Store(0)
			q.dailyReset = nextMidnight()
		}
		q.mu.Unlock()

		if q.dailyCount.Load() >= q.maxDaily {
			q.dropped.Add(1)
			llmAnalysisTotal.WithLabelValues("dropped_daily_limit", q.analyzer.Name()).Inc()
			return false
		}
	}

	// Budget check
	if q.budget != nil {
		if ok, reason := q.budget.CanSpend(); !ok {
			q.dropped.Add(1)
			llmAnalysisTotal.WithLabelValues("dropped_"+reason, q.analyzer.Name()).Inc()
			q.logger.Warn("llm analysis dropped: budget exhausted",
				"reason", reason,
				"message_id", req.MessageID,
			)
			return false
		}
	}

	select {
	case q.ch <- req:
		llmQueueDepth.Set(float64(len(q.ch)))
		return true
	default:
		q.dropped.Add(1)
		llmAnalysisTotal.WithLabelValues("dropped_queue_full", q.analyzer.Name()).Inc()
		return false
	}
}

// Start launches worker goroutines.
func (q *Queue) Start(ctx context.Context) {
	ctx, q.cancel = context.WithCancel(ctx)
	for i := 0; i < q.workers; i++ {
		q.wg.Add(1)
		go q.worker(ctx)
	}
	q.logger.Info("llm analysis queue started",
		"workers", q.workers,
		"buffer", cap(q.ch),
		"provider", q.analyzer.Name(),
	)
}

func (q *Queue) worker(ctx context.Context) {
	defer q.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case req, ok := <-q.ch:
			if !ok {
				return
			}
			llmQueueDepth.Set(float64(len(q.ch)))
			q.process(ctx, req)
		}
	}
}

func (q *Queue) process(ctx context.Context, req AnalysisRequest) {
	q.dailyCount.Add(1)

	result, err := q.analyzer.Analyze(ctx, req)
	if err != nil {
		q.errCount.Add(1)
		llmAnalysisTotal.WithLabelValues("failed", q.analyzer.Name()).Inc()
		q.logger.Warn("llm analysis failed",
			"message_id", req.MessageID,
			"error", err,
		)
		if q.onError != nil {
			q.onError(req, err)
		}
		return
	}

	// Carry request metadata into result for audit storage
	result.FromAgent = req.FromAgent
	result.ToAgent = req.ToAgent

	q.completed.Add(1)
	q.totalMs.Add(result.LatencyMs)

	llmAnalysisTotal.WithLabelValues("completed", q.analyzer.Name()).Inc()
	llmAnalysisLatency.WithLabelValues(q.analyzer.Name()).Observe(float64(result.LatencyMs) / 1000)
	llmTokensUsed.WithLabelValues(result.ProviderName, result.Model).Add(float64(result.TokensUsed))

	for _, t := range result.Threats {
		llmThreatsDetected.WithLabelValues(t.Type, t.Severity).Inc()
	}

	q.logger.Info("llm analysis complete",
		"message_id", req.MessageID,
		"threats", len(result.Threats),
		"risk_score", result.RiskScore,
		"action", result.RecommendedAction,
		"latency_ms", result.LatencyMs,
		"tokens", result.TokensUsed,
	)

	if q.onResult != nil {
		q.onResult(*result)
	}
}

// Stop gracefully shuts down the queue.
func (q *Queue) Stop() {
	if q.cancel != nil {
		q.cancel()
	}
	q.wg.Wait()
}

// QueueStats holds queue statistics.
type QueueStats struct {
	Pending    int    `json:"pending"`
	Completed  int64  `json:"completed"`
	Errors     int64  `json:"errors"`
	Dropped    int64  `json:"dropped"`
	DailyCount int64  `json:"daily_count"`
	DailyLimit int64  `json:"daily_limit"`
	AvgLatency int64  `json:"avg_latency_ms"`
	Provider   string `json:"provider"`
}

// Stats returns queue statistics.
func (q *Queue) Stats() QueueStats {
	completed := q.completed.Load()
	avgMs := int64(0)
	if completed > 0 {
		avgMs = q.totalMs.Load() / completed
	}
	return QueueStats{
		Pending:    len(q.ch),
		Completed:  completed,
		Errors:     q.errCount.Load(),
		Dropped:    q.dropped.Load(),
		DailyCount: q.dailyCount.Load(),
		DailyLimit: q.maxDaily,
		AvgLatency: avgMs,
		Provider:   q.analyzer.Name(),
	}
}

// TestConnection sends a minimal analysis request to verify the LLM provider is reachable.
func (q *Queue) TestConnection(ctx context.Context) (*AnalysisResult, error) {
	return q.analyzer.Analyze(ctx, AnalysisRequest{
		MessageID: "test-connection",
		FromAgent: "test-agent",
		ToAgent:   "test-target",
		Content:   "Hello, this is a connectivity test.",
	})
}

func nextMidnight() time.Time {
	now := time.Now()
	return time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
}
