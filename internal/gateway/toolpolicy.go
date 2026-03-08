package gateway

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/oktsec/oktsec/internal/config"
)

// ToolPolicyEnforcer checks per-agent tool policies (spending limits, rate
// limits, approval thresholds) at gateway call time.  All state is in-memory;
// counters reset naturally as windows expire.
type ToolPolicyEnforcer struct {
	mu     sync.Mutex
	calls  map[string][]time.Time // "agent:tool" → call timestamps (for rate limit)
	spends map[string][]spend     // "agent:tool" → daily spend records
}

type spend struct {
	amount float64
	at     time.Time
}

// PolicyResult holds the outcome of a tool policy check.
type PolicyResult struct {
	Allowed  bool
	Decision string // "allow", "rate_limited", "amount_exceeded", "daily_limit_exceeded", "quarantine_approval"
	Reason   string
}

// NewToolPolicyEnforcer creates an enforcer.
func NewToolPolicyEnforcer() *ToolPolicyEnforcer {
	return &ToolPolicyEnforcer{
		calls:  make(map[string][]time.Time),
		spends: make(map[string][]spend),
	}
}

// Check validates a tool call against the agent's ToolPolicy.
// amount is extracted from the tool call arguments (0 if not applicable).
func (e *ToolPolicyEnforcer) Check(agent, tool string, amount float64, policy config.ToolPolicy) PolicyResult {
	now := time.Now()

	// 1. Per-call max amount
	if policy.MaxAmount > 0 && amount > policy.MaxAmount {
		return PolicyResult{
			Allowed:  false,
			Decision: "amount_exceeded",
			Reason:   fmt.Sprintf("amount %.2f exceeds max %.2f for tool %q", amount, policy.MaxAmount, tool),
		}
	}

	// 2. Approval threshold → quarantine
	if policy.RequireApprovalAbove > 0 && amount > policy.RequireApprovalAbove {
		return PolicyResult{
			Allowed:  false,
			Decision: "quarantine_approval",
			Reason:   fmt.Sprintf("amount %.2f exceeds approval threshold %.2f for tool %q", amount, policy.RequireApprovalAbove, tool),
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	key := agent + ":" + tool

	// 3. Rate limit (calls per hour)
	if policy.RateLimit > 0 {
		cutoff := now.Add(-1 * time.Hour)
		calls := e.calls[key]
		recent := pruneTimestamps(calls, cutoff)
		e.calls[key] = recent
		if len(recent) >= policy.RateLimit {
			return PolicyResult{
				Allowed:  false,
				Decision: "rate_limited",
				Reason:   fmt.Sprintf("tool %q rate limit %d/hr exceeded for agent %q", tool, policy.RateLimit, agent),
			}
		}
	}

	// 4. Daily spending limit
	if policy.DailyLimit > 0 && amount > 0 {
		cutoff := now.Add(-24 * time.Hour)
		spends := e.spends[key]
		spends = pruneSpends(spends, cutoff)
		e.spends[key] = spends
		var total float64
		for _, s := range spends {
			total += s.amount
		}
		if total+amount > policy.DailyLimit {
			return PolicyResult{
				Allowed:  false,
				Decision: "daily_limit_exceeded",
				Reason:   fmt.Sprintf("daily spend %.2f + %.2f exceeds limit %.2f for tool %q", total, amount, policy.DailyLimit, tool),
			}
		}
	}

	return PolicyResult{Allowed: true, Decision: "allow"}
}

// Record records a successful tool call for rate and spend tracking.
func (e *ToolPolicyEnforcer) Record(agent, tool string, amount float64) {
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	key := agent + ":" + tool
	e.calls[key] = append(e.calls[key], now)
	if amount > 0 {
		e.spends[key] = append(e.spends[key], spend{amount: amount, at: now})
	}
}

// ExtractAmount looks for a monetary value in tool call arguments.
// Checks common field names: amount, value, price, cost, total.
func ExtractAmount(args map[string]any) float64 {
	for _, key := range []string{"amount", "value", "price", "cost", "total"} {
		v, ok := args[key]
		if !ok {
			continue
		}
		switch n := v.(type) {
		case float64:
			return n
		case int:
			return float64(n)
		case string:
			if f, err := strconv.ParseFloat(n, 64); err == nil {
				return f
			}
		}
	}
	return 0
}

func pruneTimestamps(ts []time.Time, cutoff time.Time) []time.Time {
	n := 0
	for _, t := range ts {
		if t.After(cutoff) {
			ts[n] = t
			n++
		}
	}
	return ts[:n]
}

func pruneSpends(ss []spend, cutoff time.Time) []spend {
	n := 0
	for _, s := range ss {
		if s.at.After(cutoff) {
			ss[n] = s
			n++
		}
	}
	return ss[:n]
}
