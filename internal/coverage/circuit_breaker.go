package coverage

// CircuitBreakerReader wraps an AuditReader and stops calling the
// underlying reader once consecutive failures exceed a threshold.
// Once tripped it returns ("", nil) for the remainder of its
// lifetime, which the hybrid reader treats as "no row" and falls
// back to its other reader.
//
// The breaker is per-instance state and is NOT goroutine-safe:
// callers must build a fresh wrapper per render so that
//   - a transient stall does not permanently disable the underlying
//     reader across requests, and
//   - the breaker state from one render does not leak into another.
//
// This design exists because LastSeen is called once per
// (principal, surface) pair: 50 principals × 3 surfaces = 150
// per-cell calls per render. Without a breaker, a stalled activity
// store would burn the per-cell timeout 150 times before the audit
// fallback ever ran. With threshold=3 the worst case is bounded at
// timeout × 3, regardless of principal count.
type CircuitBreakerReader struct {
	inner            AuditReader
	threshold        int
	consecutiveFails int
	tripped          bool
}

// NewCircuitBreakerReader returns an AuditReader that calls inner at
// most threshold consecutive times after the first failure before
// short-circuiting for the rest of its lifetime. threshold must be
// >= 1; values < 1 are treated as 1 (trip on the first failure).
func NewCircuitBreakerReader(inner AuditReader, threshold int) *CircuitBreakerReader {
	if threshold < 1 {
		threshold = 1
	}
	return &CircuitBreakerReader{inner: inner, threshold: threshold}
}

// LastSeenByPrincipalSurface delegates to the inner reader unless the
// breaker has tripped. Each error increments the consecutive-failure
// counter; a successful call resets it. Once the counter reaches the
// threshold the breaker stays tripped for the rest of the wrapper's
// lifetime — building a fresh wrapper per render is the recovery
// mechanism.
//
// A nil inner reader behaves as a no-op (empty result, no error) so
// callers can wire the breaker unconditionally without nil-checking.
func (c *CircuitBreakerReader) LastSeenByPrincipalSurface(principalID, surface string) (string, error) {
	if c == nil || c.inner == nil {
		return "", nil
	}
	if c.tripped {
		return "", nil
	}
	ts, err := c.inner.LastSeenByPrincipalSurface(principalID, surface)
	if err != nil {
		c.consecutiveFails++
		if c.consecutiveFails >= c.threshold {
			c.tripped = true
		}
		return "", err
	}
	c.consecutiveFails = 0
	return ts, nil
}

// Tripped reports whether the breaker has stopped calling the inner
// reader. Exported so the dashboard can surface a one-time warning
// without poking at private state.
func (c *CircuitBreakerReader) Tripped() bool {
	if c == nil {
		return false
	}
	return c.tripped
}
