package policy

import (
	"fmt"
	"sync"
	"time"

	"github.com/oktsec/oktsec/internal/config"
)

// ConstraintTracker tracks per-edge message counts for rate constraints.
type ConstraintTracker struct {
	mu      sync.Mutex
	windows map[string]*slidingCount
}

type slidingCount struct {
	timestamps []time.Time
}

// NewConstraintTracker creates a tracker for ACL rate constraints.
func NewConstraintTracker() *ConstraintTracker {
	return &ConstraintTracker{
		windows: make(map[string]*slidingCount),
	}
}

func (ct *ConstraintTracker) checkRate(from, to string, maxMessages, windowSecs int) bool {
	if maxMessages <= 0 {
		return true
	}
	window := time.Duration(windowSecs) * time.Second
	if window <= 0 {
		window = 60 * time.Second
	}

	key := from + "->" + to
	ct.mu.Lock()
	defer ct.mu.Unlock()

	sc, ok := ct.windows[key]
	if !ok {
		sc = &slidingCount{}
		ct.windows[key] = sc
	}

	now := time.Now()
	cutoff := now.Add(-window)

	valid := sc.timestamps[:0]
	for _, ts := range sc.timestamps {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}
	sc.timestamps = valid

	if len(sc.timestamps) >= maxMessages {
		return false
	}

	sc.timestamps = append(sc.timestamps, now)
	return true
}

// EvaluateConstraints checks all constraints on an ACL entry.
// Returns a Decision -- allowed if all constraints pass.
func EvaluateConstraints(from, to string, constraints []config.ACLConstraint, tracker *ConstraintTracker) Decision {
	for _, c := range constraints {
		switch c.Type {
		case "rate":
			if !tracker.checkRate(from, to, c.MaxMessages, c.WindowSecs) {
				return Decision{
					Allowed: false,
					Reason:  fmt.Sprintf("rate constraint exceeded: max %d messages per %ds for %s->%s", c.MaxMessages, c.WindowSecs, from, to),
				}
			}
		case "ttl":
			if c.ExpiresAt != "" {
				exp, err := time.Parse(time.RFC3339, c.ExpiresAt)
				if err != nil {
					return Decision{Allowed: false, Reason: fmt.Sprintf("invalid ttl expires_at: %v", err)}
				}
				if time.Now().UTC().After(exp) {
					return Decision{
						Allowed: false,
						Reason:  fmt.Sprintf("ttl constraint expired at %s for %s->%s", c.ExpiresAt, from, to),
					}
				}
			}
		}
	}
	return Decision{Allowed: true, Reason: "constraints satisfied"}
}
