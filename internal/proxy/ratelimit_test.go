package proxy

import (
	"fmt"
	"sync"
	"testing"
)

func TestRateLimiter_AllowsUnderLimit(t *testing.T) {
	rl := NewRateLimiter(5, 60)
	defer rl.Stop()
	for i := 0; i < 5; i++ {
		if !rl.Allow("agent-a") {
			t.Errorf("request %d should be allowed", i)
		}
	}
}

func TestRateLimiter_BlocksOverLimit(t *testing.T) {
	rl := NewRateLimiter(3, 60)
	defer rl.Stop()
	for i := 0; i < 3; i++ {
		rl.Allow("agent-a")
	}
	if rl.Allow("agent-a") {
		t.Error("request over limit should be blocked")
	}
}

func TestRateLimiter_DisabledWhenZero(t *testing.T) {
	rl := NewRateLimiter(0, 60)
	defer rl.Stop()
	for i := 0; i < 100; i++ {
		if !rl.Allow("agent-a") {
			t.Error("disabled limiter should always allow")
		}
	}
}

func TestRateLimiter_DisabledWhenNegative(t *testing.T) {
	rl := NewRateLimiter(-1, 60)
	defer rl.Stop()
	if !rl.Allow("agent-a") {
		t.Error("negative limit should always allow")
	}
}

func TestRateLimiter_IsolatesAgents(t *testing.T) {
	rl := NewRateLimiter(2, 60)
	defer rl.Stop()
	rl.Allow("agent-a")
	rl.Allow("agent-a")

	// agent-a exhausted, but agent-b should still be allowed
	if !rl.Allow("agent-b") {
		t.Error("agent-b should be allowed independently")
	}
	if rl.Allow("agent-a") {
		t.Error("agent-a should be blocked")
	}
}

func TestRateLimiter_DefaultWindow(t *testing.T) {
	rl := NewRateLimiter(5, 0)
	defer rl.Stop()
	if rl.window.Seconds() != 60 {
		t.Errorf("default window = %v, want 60s", rl.window)
	}
}

func TestRateLimiter_NegativeWindow(t *testing.T) {
	rl := NewRateLimiter(5, -10)
	defer rl.Stop()
	if rl.window.Seconds() != 60 {
		t.Errorf("negative window should default to 60s, got %v", rl.window)
	}
}

func TestRateLimiter_ConcurrentAccess(t *testing.T) {
	rl := NewRateLimiter(1000, 60)
	defer rl.Stop()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			agent := fmt.Sprintf("agent-%d", id%5)
			for j := 0; j < 100; j++ {
				rl.Allow(agent)
			}
		}(i)
	}
	wg.Wait()
}

func TestRateLimiter_Evict(t *testing.T) {
	rl := NewRateLimiter(10, 1)
	defer rl.Stop()

	rl.Allow("agent-stale")
	// Verify the entry exists in a shard
	idx := rl.shardIndex("agent-stale")
	s := &rl.shards[idx]
	s.mu.Lock()
	if _, ok := s.counters["agent-stale"]; !ok {
		t.Fatal("expected agent-stale entry before eviction")
	}
	// Manually clear timestamps to simulate staleness
	s.counters["agent-stale"] = nil
	s.mu.Unlock()

	// Run eviction directly
	rl.evict()

	s.mu.Lock()
	_, ok := s.counters["agent-stale"]
	s.mu.Unlock()
	if ok {
		t.Error("expected agent-stale to be evicted")
	}
}
