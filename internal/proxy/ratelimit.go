package proxy

import (
	"sync"
	"time"
)

// RateLimiter implements a sliding-window rate limit per agent.
type RateLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	counters map[string][]time.Time
}

// NewRateLimiter creates a rate limiter. If limit <= 0, Allow always returns true.
func NewRateLimiter(limit int, windowSeconds int) *RateLimiter {
	if windowSeconds <= 0 {
		windowSeconds = 60
	}
	return &RateLimiter{
		limit:    limit,
		window:   time.Duration(windowSeconds) * time.Second,
		counters: make(map[string][]time.Time),
	}
}

// Allow checks whether the agent is within rate limit. Returns false if exceeded.
func (rl *RateLimiter) Allow(agent string) bool {
	if rl.limit <= 0 {
		return true
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Prune old timestamps
	timestamps := rl.counters[agent]
	pruned := timestamps[:0]
	for _, ts := range timestamps {
		if ts.After(cutoff) {
			pruned = append(pruned, ts)
		}
	}

	if len(pruned) >= rl.limit {
		rl.counters[agent] = pruned
		return false
	}

	rl.counters[agent] = append(pruned, now)
	return true
}
