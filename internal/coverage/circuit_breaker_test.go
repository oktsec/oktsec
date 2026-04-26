package coverage

import (
	"errors"
	"testing"
)

// countingReader wraps a stub-style AuditReader and records call
// count so the breaker tests can prove the inner reader stops being
// called once the threshold is hit.
type countingReader struct {
	stamp string
	err   error
	calls int
}

func (c *countingReader) LastSeenByPrincipalSurface(_, _ string) (string, error) {
	c.calls++
	return c.stamp, c.err
}

// 1. The breaker is transparent in the happy path: every call hits
// the inner reader and the consecutive-fail counter never advances.
func TestCircuitBreaker_HappyPath(t *testing.T) {
	inner := &countingReader{stamp: "2026-04-26T10:00:00Z"}
	br := NewCircuitBreakerReader(inner, 3)

	for i := 0; i < 10; i++ {
		got, err := br.LastSeenByPrincipalSurface("p", "s")
		if err != nil {
			t.Fatalf("call %d: err = %v", i, err)
		}
		if got != "2026-04-26T10:00:00Z" {
			t.Errorf("call %d: got %q; want stamp", i, got)
		}
	}
	if inner.calls != 10 {
		t.Errorf("inner calls = %d; want 10 (breaker should be transparent)", inner.calls)
	}
	if br.Tripped() {
		t.Error("breaker tripped on a clean run")
	}
}

// 2. Threshold consecutive errors trip the breaker. The next call
// short-circuits — empty result, nil error, inner reader untouched.
// Bounds the worst-case render-time contribution at timeout × threshold
// regardless of how many cells follow.
func TestCircuitBreaker_TripsAfterThresholdFailures(t *testing.T) {
	inner := &countingReader{err: errors.New("simulated activity stall")}
	br := NewCircuitBreakerReader(inner, 3)

	// 3 errors trip the breaker.
	for i := 0; i < 3; i++ {
		_, err := br.LastSeenByPrincipalSurface("p", "s")
		if err == nil {
			t.Errorf("call %d: err = nil; want error", i)
		}
	}
	if !br.Tripped() {
		t.Fatal("breaker should be tripped after threshold consecutive failures")
	}
	beforeShort := inner.calls

	// Subsequent calls do not touch the inner reader.
	for i := 0; i < 100; i++ {
		got, err := br.LastSeenByPrincipalSurface("p", "s")
		if err != nil {
			t.Errorf("post-trip call %d: err = %v; want nil (short-circuit)", i, err)
		}
		if got != "" {
			t.Errorf("post-trip call %d: got %q; want empty (short-circuit)", i, got)
		}
	}
	if inner.calls != beforeShort {
		t.Errorf("inner calls = %d; want %d (no calls should reach a tripped breaker)", inner.calls, beforeShort)
	}
}

// 3. A successful call resets the consecutive-fail counter. Two
// failures followed by a success followed by two more failures must
// not trip a threshold=3 breaker — the counter never reaches 3 in a
// row.
func TestCircuitBreaker_SuccessResetsCounter(t *testing.T) {
	inner := &countingReader{}
	br := NewCircuitBreakerReader(inner, 3)

	inner.err = errors.New("fail-1")
	_, _ = br.LastSeenByPrincipalSurface("p", "s")
	inner.err = errors.New("fail-2")
	_, _ = br.LastSeenByPrincipalSurface("p", "s")

	inner.err = nil
	inner.stamp = "2026-04-26T10:00:00Z"
	if got, err := br.LastSeenByPrincipalSurface("p", "s"); err != nil || got == "" {
		t.Fatalf("success after failures: got=%q err=%v; want stamp/nil", got, err)
	}

	inner.err = errors.New("fail-3")
	_, _ = br.LastSeenByPrincipalSurface("p", "s")
	inner.err = errors.New("fail-4")
	_, _ = br.LastSeenByPrincipalSurface("p", "s")

	if br.Tripped() {
		t.Error("breaker tripped despite a success resetting the consecutive-fail counter")
	}
}

// 4. Threshold values < 1 are clamped to 1 so callers cannot disable
// the breaker by accident. A zero or negative threshold trips on the
// first failure, which is the safest behavior.
func TestCircuitBreaker_ThresholdClampedToOne(t *testing.T) {
	inner := &countingReader{err: errors.New("boom")}
	br := NewCircuitBreakerReader(inner, 0)

	_, _ = br.LastSeenByPrincipalSurface("p", "s")
	if !br.Tripped() {
		t.Error("threshold=0 must clamp to 1 and trip on the first failure")
	}
}

// 5. A nil inner reader is a valid no-op state. The breaker returns
// ("", nil) so callers can wire the wrapper unconditionally without
// nil-checking the underlying store.
func TestCircuitBreaker_NilInnerIsNoop(t *testing.T) {
	br := NewCircuitBreakerReader(nil, 3)
	got, err := br.LastSeenByPrincipalSurface("p", "s")
	if err != nil || got != "" {
		t.Errorf("nil inner: got=%q err=%v; want empty/nil", got, err)
	}
}
