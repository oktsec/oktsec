package llm

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
)

// FallbackAnalyzer wraps a primary and secondary Analyzer. If the primary
// returns an error, the request is retried on the secondary. This provides
// resilience against provider outages and model-specific failures.
type FallbackAnalyzer struct {
	primary   Analyzer
	secondary Analyzer
	logger    *slog.Logger

	// Stats
	primaryOK     atomic.Int64
	secondaryOK   atomic.Int64
	secondaryFail atomic.Int64
}

// NewFallbackAnalyzer creates an analyzer that falls back to secondary on primary failure.
func NewFallbackAnalyzer(primary, secondary Analyzer, logger *slog.Logger) *FallbackAnalyzer {
	return &FallbackAnalyzer{
		primary:   primary,
		secondary: secondary,
		logger:    logger,
	}
}

// Analyze tries the primary analyzer first. On failure, falls back to secondary.
func (f *FallbackAnalyzer) Analyze(ctx context.Context, req AnalysisRequest) (*AnalysisResult, error) {
	result, err := f.primary.Analyze(ctx, req)
	if err == nil {
		f.primaryOK.Add(1)
		return result, nil
	}

	// Primary failed — try secondary
	f.logger.Warn("primary LLM failed, falling back",
		"primary", f.primary.Name(),
		"secondary", f.secondary.Name(),
		"message_id", req.MessageID,
		"error", err,
	)
	llmFallbackTotal.Inc()

	result, err2 := f.secondary.Analyze(ctx, req)
	if err2 != nil {
		f.secondaryFail.Add(1)
		return nil, fmt.Errorf("primary (%s): %w; fallback (%s): %v", f.primary.Name(), err, f.secondary.Name(), err2)
	}

	f.secondaryOK.Add(1)
	return result, nil
}

// Name returns a combined name for metrics.
func (f *FallbackAnalyzer) Name() string {
	return f.primary.Name()
}

// FallbackStats holds fallback usage statistics.
type FallbackStats struct {
	PrimaryOK     int64 `json:"primary_ok"`
	SecondaryOK   int64 `json:"secondary_ok"`
	SecondaryFail int64 `json:"secondary_fail"`
}

// Stats returns fallback usage counters.
func (f *FallbackAnalyzer) Stats() FallbackStats {
	return FallbackStats{
		PrimaryOK:     f.primaryOK.Load(),
		SecondaryOK:   f.secondaryOK.Load(),
		SecondaryFail: f.secondaryFail.Load(),
	}
}
