package policy

import (
	"testing"
	"time"
)

func TestEvaluateConstraints_RateAllow(t *testing.T) {
	tracker := newConstraintTracker()
	constraints := []Constraint{
		{Type: "rate", MaxMessages: 5, WindowSecs: 60},
	}

	for i := 0; i < 5; i++ {
		d := EvaluateConstraints("a", "b", constraints, tracker)
		if !d.Allowed {
			t.Fatalf("message %d should be allowed: %s", i+1, d.Reason)
		}
	}

	// 6th should be denied
	d := EvaluateConstraints("a", "b", constraints, tracker)
	if d.Allowed {
		t.Fatal("6th message should be rate limited")
	}
}

func TestEvaluateConstraints_RateDifferentEdges(t *testing.T) {
	tracker := newConstraintTracker()
	constraints := []Constraint{
		{Type: "rate", MaxMessages: 1, WindowSecs: 60},
	}

	d := EvaluateConstraints("a", "b", constraints, tracker)
	if !d.Allowed {
		t.Fatalf("a->b should be allowed: %s", d.Reason)
	}

	// Different edge should have its own counter
	d = EvaluateConstraints("a", "c", constraints, tracker)
	if !d.Allowed {
		t.Fatalf("a->c should be allowed (different edge): %s", d.Reason)
	}
}

func TestEvaluateConstraints_TTLValid(t *testing.T) {
	tracker := newConstraintTracker()
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	constraints := []Constraint{
		{Type: "ttl", ExpiresAt: future},
	}

	d := EvaluateConstraints("a", "b", constraints, tracker)
	if !d.Allowed {
		t.Fatalf("future TTL should be allowed: %s", d.Reason)
	}
}

func TestEvaluateConstraints_TTLExpired(t *testing.T) {
	tracker := newConstraintTracker()
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	constraints := []Constraint{
		{Type: "ttl", ExpiresAt: past},
	}

	d := EvaluateConstraints("a", "b", constraints, tracker)
	if d.Allowed {
		t.Fatal("expired TTL should be denied")
	}
}

func TestEvaluateConstraints_TTLInvalid(t *testing.T) {
	tracker := newConstraintTracker()
	constraints := []Constraint{
		{Type: "ttl", ExpiresAt: "not-a-date"},
	}

	d := EvaluateConstraints("a", "b", constraints, tracker)
	if d.Allowed {
		t.Fatal("invalid TTL should be denied")
	}
}

func TestEvaluateConstraints_MultipleConstraints(t *testing.T) {
	tracker := newConstraintTracker()
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	constraints := []Constraint{
		{Type: "rate", MaxMessages: 10, WindowSecs: 60},
		{Type: "ttl", ExpiresAt: future},
	}

	d := EvaluateConstraints("a", "b", constraints, tracker)
	if !d.Allowed {
		t.Fatalf("both constraints should pass: %s", d.Reason)
	}
}

func TestEvaluateConstraints_Empty(t *testing.T) {
	tracker := newConstraintTracker()
	d := EvaluateConstraints("a", "b", nil, tracker)
	if !d.Allowed {
		t.Fatal("empty constraints should allow")
	}
}

func TestEvaluateConstraints_UnknownType(t *testing.T) {
	tracker := newConstraintTracker()
	constraints := []Constraint{
		{Type: "unknown_future_type"},
	}

	d := EvaluateConstraints("a", "b", constraints, tracker)
	if !d.Allowed {
		t.Fatal("unknown constraint types should be skipped (forward compat)")
	}
}
