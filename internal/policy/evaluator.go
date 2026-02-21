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
	agents map[string]config.Agent
}

// NewEvaluator creates a policy evaluator from the config.
func NewEvaluator(cfg *config.Config) *Evaluator {
	return &Evaluator{
		agents: cfg.Agents,
	}
}

// CheckACL verifies that the sender is allowed to message the recipient.
func (e *Evaluator) CheckACL(from, to string) Decision {
	// If no agents are configured, allow all
	if len(e.agents) == 0 {
		return Decision{Allowed: true, Reason: "no ACL configured"}
	}

	agent, exists := e.agents[from]
	if !exists {
		// Unknown sender — allow by default (they're not restricted)
		return Decision{Allowed: true, Reason: "sender not in policy"}
	}

	// If can_message is empty, agent can message anyone
	if len(agent.CanMessage) == 0 {
		return Decision{Allowed: true, Reason: "no restrictions on sender"}
	}

	for _, allowed := range agent.CanMessage {
		if allowed == to || allowed == "*" {
			return Decision{Allowed: true, Reason: "allowed by ACL"}
		}
	}

	return Decision{
		Allowed: false,
		Reason:  fmt.Sprintf("agent %q is not allowed to message %q", from, to),
	}
}
