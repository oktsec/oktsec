package proxy

import (
	"testing"
)

func TestRateLimiter_AllowsUnderLimit(t *testing.T) {
	rl := NewRateLimiter(5, 60)
	for i := 0; i < 5; i++ {
		if !rl.Allow("agent-a") {
			t.Errorf("request %d should be allowed", i)
		}
	}
}

func TestRateLimiter_BlocksOverLimit(t *testing.T) {
	rl := NewRateLimiter(3, 60)
	for i := 0; i < 3; i++ {
		rl.Allow("agent-a")
	}
	if rl.Allow("agent-a") {
		t.Error("request over limit should be blocked")
	}
}

func TestRateLimiter_DisabledWhenZero(t *testing.T) {
	rl := NewRateLimiter(0, 60)
	for i := 0; i < 100; i++ {
		if !rl.Allow("agent-a") {
			t.Error("disabled limiter should always allow")
		}
	}
}

func TestRateLimiter_DisabledWhenNegative(t *testing.T) {
	rl := NewRateLimiter(-1, 60)
	if !rl.Allow("agent-a") {
		t.Error("negative limit should always allow")
	}
}

func TestRateLimiter_IsolatesAgents(t *testing.T) {
	rl := NewRateLimiter(2, 60)
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
	if rl.window.Seconds() != 60 {
		t.Errorf("default window = %v, want 60s", rl.window)
	}
}

func TestRateLimiter_NegativeWindow(t *testing.T) {
	rl := NewRateLimiter(5, -10)
	if rl.window.Seconds() != 60 {
		t.Errorf("negative window should default to 60s, got %v", rl.window)
	}
}
