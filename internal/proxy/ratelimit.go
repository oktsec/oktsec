// Package proxy implements the HTTP message proxy, stdio proxy, forward proxy,
// and the security pipeline (rate limiting, identity, ACL, scanning, verdicts).
package proxy

import (
	"hash/fnv"
	"sync"
	"time"
)

const rlShardCount = 64

// rlShard is one partition of the rate limiter's state.
type rlShard struct {
	mu       sync.Mutex
	counters map[string][]time.Time
}

// RateLimiter implements a sliding-window rate limit per agent.
// Internally it uses sharded locks to reduce contention at high request rates.
type RateLimiter struct {
	limit  int
	window time.Duration
	shards [rlShardCount]rlShard
	done   chan struct{}
}

// NewRateLimiter creates a rate limiter. If limit <= 0, Allow always returns true.
func NewRateLimiter(limit int, windowSeconds int) *RateLimiter {
	if windowSeconds <= 0 {
		windowSeconds = 60
	}
	rl := &RateLimiter{
		limit:  limit,
		window: time.Duration(windowSeconds) * time.Second,
		done:   make(chan struct{}),
	}
	for i := range rl.shards {
		rl.shards[i].counters = make(map[string][]time.Time)
	}
	// Evict stale entries periodically. The interval is 2x the window
	// duration (minimum 30s) so we don't spin for very small windows.
	evictInterval := rl.window * 2
	if evictInterval < 30*time.Second {
		evictInterval = 30 * time.Second
	}
	go rl.evictLoop(evictInterval)
	return rl
}

// Allow checks whether the agent is within rate limit. Returns false if exceeded.
func (rl *RateLimiter) Allow(agent string) bool {
	if rl.limit <= 0 {
		return true
	}

	s := &rl.shards[rl.shardIndex(agent)]
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Prune old timestamps
	timestamps := s.counters[agent]
	pruned := timestamps[:0]
	for _, ts := range timestamps {
		if ts.After(cutoff) {
			pruned = append(pruned, ts)
		}
	}

	if len(pruned) >= rl.limit {
		s.counters[agent] = pruned
		return false
	}

	s.counters[agent] = append(pruned, now)
	return true
}

// Stop terminates the background eviction goroutine. Safe to call multiple times.
func (rl *RateLimiter) Stop() {
	select {
	case <-rl.done:
	default:
		close(rl.done)
	}
}

// shardIndex returns the shard index for the given key.
func (rl *RateLimiter) shardIndex(key string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return h.Sum32() % rlShardCount
}

// evictLoop periodically removes map entries whose newest timestamp
// is older than 2x the window duration.
func (rl *RateLimiter) evictLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-rl.done:
			return
		case <-ticker.C:
			rl.evict()
		}
	}
}

// evict removes stale entries from all shards. An entry is stale when all
// of its timestamps are older than 2x the window duration.
func (rl *RateLimiter) evict() {
	cutoff := time.Now().Add(-2 * rl.window)
	for i := range rl.shards {
		s := &rl.shards[i]
		s.mu.Lock()
		for agent, timestamps := range s.counters {
			if len(timestamps) == 0 || timestamps[len(timestamps)-1].Before(cutoff) {
				delete(s.counters, agent)
			}
		}
		s.mu.Unlock()
	}
}
