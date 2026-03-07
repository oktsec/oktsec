package policy

import (
	"fmt"
	"sync"
	"time"
)

// Constraint defines a condition on an ACL entry beyond simple allow/deny.
type Constraint struct {
	Type        string   `yaml:"type" json:"type"`                             // "rate", "ttl"
	MaxMessages int      `yaml:"max_messages,omitempty" json:"max_messages,omitempty"` // for type=rate
	WindowSecs  int      `yaml:"window_secs,omitempty" json:"window_secs,omitempty"`   // for type=rate
	ExpiresAt   string   `yaml:"expires_at,omitempty" json:"expires_at,omitempty"`     // for type=ttl (RFC3339)
	Categories  []string `yaml:"categories,omitempty" json:"categories,omitempty"`     // reserved for future use
}

// ACLEntry defines a permission from one agent to a target with optional constraints.
type ACLEntry struct {
	Target      string       `yaml:"target" json:"target"`
	Constraints []Constraint `yaml:"constraints,omitempty" json:"constraints,omitempty"`
}

// constraintTracker tracks per-edge message counts for rate constraints.
type constraintTracker struct {
	mu      sync.Mutex
	windows map[string]*slidingCount // key: "from->to"
}

type slidingCount struct {
	timestamps []time.Time
}

func newConstraintTracker() *constraintTracker {
	return &constraintTracker{
		windows: make(map[string]*slidingCount),
	}
}

// checkRate checks if a rate constraint is satisfied and records the message.
// Returns true if the message is allowed.
func (ct *constraintTracker) checkRate(from, to string, maxMessages, windowSecs int) bool {
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

	// Prune old entries
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
// Returns a Decision — allowed if all constraints pass.
func EvaluateConstraints(from, to string, constraints []Constraint, tracker *constraintTracker) Decision {
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
