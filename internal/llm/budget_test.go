package llm

import (
	"log/slog"
	"testing"
)

func TestBudgetTracker_CanSpend_Unlimited(t *testing.T) {
	b := NewBudgetTracker(BudgetConfig{}, slog.Default())
	ok, reason := b.CanSpend()
	if !ok {
		t.Errorf("unlimited budget should allow spending, got reason=%q", reason)
	}
}

func TestBudgetTracker_DailyLimit(t *testing.T) {
	b := NewBudgetTracker(BudgetConfig{
		DailyLimitUSD: 1.00,
		WarnThreshold: 0.8,
		OnLimit:       "skip",
	}, slog.Default())

	// Should allow initially
	ok, _ := b.CanSpend()
	if !ok {
		t.Fatal("should allow spending under limit")
	}

	// Record cost up to limit
	b.RecordCost(1000000, 500000, 1.0, 2.0) // $1.00 + $1.00 = $2.00
	ok, reason := b.CanSpend()
	if ok {
		t.Fatal("should deny spending over daily limit")
	}
	if reason != "daily_limit" {
		t.Errorf("expected reason=daily_limit, got %q", reason)
	}
}

func TestBudgetTracker_MonthlyLimit(t *testing.T) {
	b := NewBudgetTracker(BudgetConfig{
		MonthlyLimitUSD: 0.50,
		WarnThreshold:   0.8,
	}, slog.Default())

	b.RecordCost(500000, 250000, 1.0, 2.0) // $0.50 + $0.50 = $1.00
	ok, reason := b.CanSpend()
	if ok {
		t.Fatal("should deny spending over monthly limit")
	}
	if reason != "monthly_limit" {
		t.Errorf("expected reason=monthly_limit, got %q", reason)
	}
}

func TestBudgetTracker_Status(t *testing.T) {
	b := NewBudgetTracker(BudgetConfig{
		DailyLimitUSD:   10.0,
		MonthlyLimitUSD: 100.0,
		WarnThreshold:   0.8,
	}, slog.Default())

	b.RecordCost(100000, 50000, 1.0, 2.0) // $0.10 + $0.10 = $0.20

	s := b.Status()
	if s.DailyLimit != 10.0 {
		t.Errorf("expected daily limit 10.0, got %f", s.DailyLimit)
	}
	if s.MonthlyLimit != 100.0 {
		t.Errorf("expected monthly limit 100.0, got %f", s.MonthlyLimit)
	}
	if s.DailySpent < 0.19 || s.DailySpent > 0.21 {
		t.Errorf("expected daily spent ~0.20, got %f", s.DailySpent)
	}
	if s.DailyExhausted {
		t.Error("should not be exhausted")
	}
	if s.DailyWarning {
		t.Error("should not be warning at 2%")
	}
	if s.TotalCalls != 1 {
		t.Errorf("expected 1 call, got %d", s.TotalCalls)
	}
}

func TestBudgetTracker_UpdateConfig(t *testing.T) {
	b := NewBudgetTracker(BudgetConfig{
		DailyLimitUSD: 100.0,
	}, slog.Default())

	// Record some spend
	b.RecordCost(1000000, 500000, 1.0, 2.0) // $2.00

	// Update to a lower limit
	b.UpdateConfig(BudgetConfig{DailyLimitUSD: 1.0})

	// Should now be over limit
	ok, _ := b.CanSpend()
	if ok {
		t.Fatal("should deny after lowering limit below current spend")
	}

	// Spend tracking should be preserved
	s := b.Status()
	if s.DailySpent < 1.9 {
		t.Errorf("spend should be preserved after config update, got %f", s.DailySpent)
	}
}

func TestBudgetTracker_DefaultWarnThreshold(t *testing.T) {
	b := NewBudgetTracker(BudgetConfig{
		DailyLimitUSD: 10.0,
		WarnThreshold: 0, // should default to 0.8
	}, slog.Default())

	// Spend 85% of budget
	b.RecordCost(850000, 0, 10.0, 0) // $8.50

	s := b.Status()
	if !s.DailyWarning {
		t.Error("should warn at 85% when threshold defaults to 80%")
	}
}
