package gateway

import (
	"testing"
	"time"

	"github.com/oktsec/oktsec/internal/config"
)

func TestToolPolicyEnforcer_MaxAmount(t *testing.T) {
	e := NewToolPolicyEnforcer()
	policy := config.ToolPolicy{MaxAmount: 100}

	r := e.Check("agent-a", "create_card", 50, policy)
	if !r.Allowed {
		t.Fatalf("expected allowed, got: %s", r.Reason)
	}

	r = e.Check("agent-a", "create_card", 150, policy)
	if r.Allowed {
		t.Fatal("expected blocked for amount exceeding max")
	}
	if r.Decision != "amount_exceeded" {
		t.Fatalf("expected amount_exceeded, got %s", r.Decision)
	}
}

func TestToolPolicyEnforcer_MaxAmountBoundary(t *testing.T) {
	e := NewToolPolicyEnforcer()
	policy := config.ToolPolicy{MaxAmount: 100}

	// Exact amount should pass
	r := e.Check("agent-a", "create_card", 100, policy)
	if !r.Allowed {
		t.Fatalf("exact max amount should be allowed, got: %s", r.Reason)
	}
}

func TestToolPolicyEnforcer_RequireApproval(t *testing.T) {
	e := NewToolPolicyEnforcer()
	policy := config.ToolPolicy{RequireApprovalAbove: 50}

	r := e.Check("agent-a", "create_card", 30, policy)
	if !r.Allowed {
		t.Fatalf("expected allowed below threshold, got: %s", r.Reason)
	}

	r = e.Check("agent-a", "create_card", 75, policy)
	if r.Allowed {
		t.Fatal("expected quarantine for amount above approval threshold")
	}
	if r.Decision != "quarantine_approval" {
		t.Fatalf("expected quarantine_approval, got %s", r.Decision)
	}
}

func TestToolPolicyEnforcer_RateLimit(t *testing.T) {
	e := NewToolPolicyEnforcer()
	policy := config.ToolPolicy{RateLimit: 3}

	for i := 0; i < 3; i++ {
		r := e.Check("agent-a", "read_file", 0, policy)
		if !r.Allowed {
			t.Fatalf("call %d should be allowed", i+1)
		}
		e.Record("agent-a", "read_file", 0)
	}

	r := e.Check("agent-a", "read_file", 0, policy)
	if r.Allowed {
		t.Fatal("expected rate limited after 3 calls")
	}
	if r.Decision != "rate_limited" {
		t.Fatalf("expected rate_limited, got %s", r.Decision)
	}
}

func TestToolPolicyEnforcer_RateLimitIsolation(t *testing.T) {
	e := NewToolPolicyEnforcer()
	policy := config.ToolPolicy{RateLimit: 2}

	// Exhaust agent-a
	e.Record("agent-a", "tool1", 0)
	e.Record("agent-a", "tool1", 0)

	r := e.Check("agent-a", "tool1", 0, policy)
	if r.Allowed {
		t.Fatal("agent-a should be rate limited")
	}

	// agent-b should be fine
	r = e.Check("agent-b", "tool1", 0, policy)
	if !r.Allowed {
		t.Fatalf("agent-b should not be rate limited, got: %s", r.Reason)
	}
}

func TestToolPolicyEnforcer_DailyLimit(t *testing.T) {
	e := NewToolPolicyEnforcer()
	policy := config.ToolPolicy{DailyLimit: 500}

	// Spend 200 + 200 = 400 → under limit
	e.Record("agent-a", "create_card", 200)
	e.Record("agent-a", "create_card", 200)

	r := e.Check("agent-a", "create_card", 50, policy)
	if !r.Allowed {
		t.Fatalf("450 total should be under 500 limit, got: %s", r.Reason)
	}

	// Another 150 → 400 + 150 = 550 → over limit
	r = e.Check("agent-a", "create_card", 150, policy)
	if r.Allowed {
		t.Fatal("expected daily limit exceeded")
	}
	if r.Decision != "daily_limit_exceeded" {
		t.Fatalf("expected daily_limit_exceeded, got %s", r.Decision)
	}
}

func TestToolPolicyEnforcer_DailyLimitZeroAmount(t *testing.T) {
	e := NewToolPolicyEnforcer()
	policy := config.ToolPolicy{DailyLimit: 100}

	// Zero-amount calls should always pass the daily limit check
	r := e.Check("agent-a", "tool1", 0, policy)
	if !r.Allowed {
		t.Fatalf("zero amount should pass daily limit, got: %s", r.Reason)
	}
}

func TestToolPolicyEnforcer_CombinedPolicies(t *testing.T) {
	e := NewToolPolicyEnforcer()
	policy := config.ToolPolicy{
		MaxAmount:            100,
		DailyLimit:           500,
		RequireApprovalAbove: 50,
		RateLimit:            10,
	}

	// Amount 75: passes MaxAmount (<=100) but fails RequireApprovalAbove (>50)
	r := e.Check("agent-a", "create_card", 75, policy)
	if r.Allowed {
		t.Fatal("expected quarantine for amount above approval threshold")
	}
	if r.Decision != "quarantine_approval" {
		t.Fatalf("expected quarantine_approval, got %s", r.Decision)
	}

	// Amount 30: passes all checks
	r = e.Check("agent-a", "create_card", 30, policy)
	if !r.Allowed {
		t.Fatalf("amount 30 should pass all checks, got: %s", r.Reason)
	}

	// Amount 200: fails MaxAmount first
	r = e.Check("agent-a", "create_card", 200, policy)
	if r.Decision != "amount_exceeded" {
		t.Fatalf("expected amount_exceeded, got %s", r.Decision)
	}
}

func TestToolPolicyEnforcer_NoPolicyAllows(t *testing.T) {
	e := NewToolPolicyEnforcer()
	policy := config.ToolPolicy{} // all zeros

	r := e.Check("agent-a", "any_tool", 999, policy)
	if !r.Allowed {
		t.Fatalf("empty policy should allow everything, got: %s", r.Reason)
	}
}

func TestToolPolicyEnforcer_ExpiredCallsPruned(t *testing.T) {
	e := NewToolPolicyEnforcer()
	policy := config.ToolPolicy{RateLimit: 2}

	// Manually inject old timestamps
	e.mu.Lock()
	key := "agent-a:tool1"
	old := time.Now().Add(-2 * time.Hour)
	e.calls[key] = []time.Time{old, old}
	e.mu.Unlock()

	// Old calls should be pruned, so this should be allowed
	r := e.Check("agent-a", "tool1", 0, policy)
	if !r.Allowed {
		t.Fatalf("expired calls should be pruned, got: %s", r.Reason)
	}
}

func TestExtractAmount(t *testing.T) {
	tests := []struct {
		name string
		args map[string]any
		want float64
	}{
		{"float amount", map[string]any{"amount": 42.5}, 42.5},
		{"int value", map[string]any{"value": 100}, 100},
		{"string price", map[string]any{"price": "99.99"}, 99.99},
		{"cost field", map[string]any{"cost": 50.0}, 50.0},
		{"total field", map[string]any{"total": 75.0}, 75.0},
		{"no amount fields", map[string]any{"name": "test"}, 0},
		{"nil args", nil, 0},
		{"empty args", map[string]any{}, 0},
		{"invalid string", map[string]any{"amount": "not-a-number"}, 0},
		{"priority order", map[string]any{"amount": 10.0, "value": 20.0}, 10.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractAmount(tt.args)
			if got != tt.want {
				t.Errorf("ExtractAmount(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}
