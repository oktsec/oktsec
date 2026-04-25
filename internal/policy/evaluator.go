// Package policy evaluates per-agent ACL rules to determine whether a
// message between two agents should be allowed or denied.
package policy

import (
	"fmt"

	"github.com/oktsec/oktsec/internal/config"
)

// Decision represents the outcome of a policy evaluation.
type Decision struct {
	Allowed bool
	Reason  string
}

// Evaluator checks access control policies.
type Evaluator struct {
	agents        map[string]config.Agent
	defaultPolicy string // "allow" or "deny"
	tracker       *ConstraintTracker
}

// NewEvaluator creates a policy evaluator from the config.
func NewEvaluator(cfg *config.Config) *Evaluator {
	dp := cfg.DefaultPolicy
	if dp == "" {
		dp = "allow"
	}
	return &Evaluator{
		agents:        cfg.Agents,
		defaultPolicy: dp,
		tracker:       NewConstraintTracker(),
	}
}

// CheckACL verifies that the sender is allowed to message the recipient.
func (e *Evaluator) CheckACL(from, to string) Decision {
	if len(e.agents) == 0 {
		return Decision{Allowed: true, Reason: "no ACL configured"}
	}

	agent, exists := e.agents[from]
	if !exists {
		if e.defaultPolicy == "deny" {
			return Decision{Allowed: false, Reason: fmt.Sprintf("unknown sender %q denied by default policy", from)}
		}
		return Decision{Allowed: true, Reason: "sender not in policy"}
	}

	// Check structured ACL entries first (with constraints).
	if len(agent.ACLEntries) > 0 {
		for _, entry := range agent.ACLEntries {
			if entry.Target == to || entry.Target == "*" {
				if len(entry.Constraints) > 0 {
					return EvaluateConstraints(from, to, entry.Constraints, e.tracker)
				}
				return Decision{Allowed: true, Reason: "allowed by ACL entry"}
			}
		}
		// If ACL entries exist but none matched, also check can_message
		// for backwards compatibility before denying.
	}

	// Legacy can_message list (no constraints).
	if len(agent.CanMessage) == 0 && len(agent.ACLEntries) == 0 {
		return Decision{Allowed: true, Reason: "no restrictions on sender"}
	}

	for _, allowed := range agent.CanMessage {
		if allowed == to || allowed == "*" {
			return Decision{Allowed: true, Reason: "allowed by ACL"}
		}
	}

	// Neither ACL entries nor can_message matched.
	if len(agent.CanMessage) > 0 || len(agent.ACLEntries) > 0 {
		return Decision{
			Allowed: false,
			Reason:  fmt.Sprintf("agent %q is not allowed to message %q", from, to),
		}
	}

	return Decision{Allowed: true, Reason: "no restrictions on sender"}
}
