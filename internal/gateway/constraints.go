package gateway

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ToolConstraint defines per-tool parameter and usage limits for an agent.
type ToolConstraint struct {
	Tool             string                     `yaml:"tool" json:"tool"`
	Parameters       map[string]ParamConstraint `yaml:"parameters,omitempty" json:"parameters,omitempty"`
	MaxResponseBytes int                        `yaml:"max_response_bytes,omitempty" json:"max_response_bytes,omitempty"`
	CooldownSecs     int                        `yaml:"cooldown_secs,omitempty" json:"cooldown_secs,omitempty"`
}

// ParamConstraint defines validation rules for a single tool parameter.
type ParamConstraint struct {
	AllowedPatterns []string `yaml:"allowed_patterns,omitempty" json:"allowed_patterns,omitempty"` // glob patterns
	BlockedPatterns []string `yaml:"blocked_patterns,omitempty" json:"blocked_patterns,omitempty"` // glob patterns
	MaxLength       int      `yaml:"max_length,omitempty" json:"max_length,omitempty"`
}

// ToolChainRule blocks certain tools after a triggering tool is called.
type ToolChainRule struct {
	If           string   `yaml:"if" json:"if"`                       // tool that triggers
	Then         []string `yaml:"then" json:"then"`                   // tools that become blocked
	CooldownSecs int      `yaml:"cooldown_secs" json:"cooldown_secs"` // how long the block lasts
}

// ConstraintChecker validates tool calls against per-agent constraints.
type ConstraintChecker struct {
	constraints map[string][]ToolConstraint // agent → constraints
	chainRules  map[string][]ToolChainRule  // agent → chain rules
	cooldowns   *cooldownTracker
}

// NewConstraintChecker creates a constraint checker from agent configs.
func NewConstraintChecker(agentConstraints map[string][]ToolConstraint, agentChainRules map[string][]ToolChainRule) *ConstraintChecker {
	return &ConstraintChecker{
		constraints: agentConstraints,
		chainRules:  agentChainRules,
		cooldowns:   newCooldownTracker(),
	}
}

// ConstraintResult holds the outcome of a constraint check.
type ConstraintResult struct {
	Allowed bool
	Reason  string
}

// CheckToolCall validates a tool call against the agent's constraints.
func (cc *ConstraintChecker) CheckToolCall(agent, tool string, params map[string]string) ConstraintResult {
	// Check chain rules first (tool blocked due to prior tool call)
	if cc.cooldowns.isBlocked(agent, tool) {
		return ConstraintResult{
			Allowed: false,
			Reason:  fmt.Sprintf("tool %q is blocked by chain rule for agent %q", tool, agent),
		}
	}

	constraints, ok := cc.constraints[agent]
	if !ok {
		return ConstraintResult{Allowed: true, Reason: "no constraints configured"}
	}

	for _, tc := range constraints {
		if tc.Tool != tool {
			continue
		}

		// Check per-tool cooldown
		if tc.CooldownSecs > 0 && cc.cooldowns.isOnCooldown(agent, tool, tc.CooldownSecs) {
			return ConstraintResult{
				Allowed: false,
				Reason:  fmt.Sprintf("tool %q is on cooldown (%ds) for agent %q", tool, tc.CooldownSecs, agent),
			}
		}

		// Check parameter constraints
		for paramName, pc := range tc.Parameters {
			val, exists := params[paramName]
			if !exists {
				continue
			}

			if r := checkParamConstraint(paramName, val, pc); !r.Allowed {
				return r
			}
		}
	}

	return ConstraintResult{Allowed: true, Reason: "constraints satisfied"}
}

// RecordToolCall records a tool call for cooldown and chain rule tracking.
func (cc *ConstraintChecker) RecordToolCall(agent, tool string) {
	cc.cooldowns.record(agent, tool)

	// Apply chain rules
	rules, ok := cc.chainRules[agent]
	if !ok {
		return
	}
	for _, rule := range rules {
		if rule.If == tool {
			for _, blocked := range rule.Then {
				cc.cooldowns.block(agent, blocked, rule.CooldownSecs)
			}
		}
	}
}

func checkParamConstraint(name, value string, pc ParamConstraint) ConstraintResult {
	// Max length
	if pc.MaxLength > 0 && len(value) > pc.MaxLength {
		return ConstraintResult{
			Allowed: false,
			Reason:  fmt.Sprintf("parameter %q exceeds max length %d", name, pc.MaxLength),
		}
	}

	// Blocked patterns (checked first — deny takes precedence)
	for _, pattern := range pc.BlockedPatterns {
		if matched, _ := filepath.Match(pattern, value); matched {
			return ConstraintResult{
				Allowed: false,
				Reason:  fmt.Sprintf("parameter %q matches blocked pattern %q", name, pattern),
			}
		}
		// Also check if the value contains the pattern as a path segment
		if strings.Contains(value, strings.TrimPrefix(strings.TrimSuffix(pattern, "**"), "**")) {
			if matched, _ := filepath.Match(pattern, value); matched {
				return ConstraintResult{
					Allowed: false,
					Reason:  fmt.Sprintf("parameter %q matches blocked pattern %q", name, pattern),
				}
			}
		}
	}

	// Allowed patterns (if specified, value must match at least one)
	if len(pc.AllowedPatterns) > 0 {
		matched := false
		for _, pattern := range pc.AllowedPatterns {
			if m, _ := filepath.Match(pattern, value); m {
				matched = true
				break
			}
		}
		if !matched {
			return ConstraintResult{
				Allowed: false,
				Reason:  fmt.Sprintf("parameter %q does not match any allowed pattern", name),
			}
		}
	}

	return ConstraintResult{Allowed: true}
}

// cooldownTracker manages per-agent tool call timing and chain blocks.
type cooldownTracker struct {
	mu        sync.Mutex
	lastCalls map[string]time.Time // "agent:tool" → last call time
	blocks    map[string]time.Time // "agent:tool" → blocked until
}

func newCooldownTracker() *cooldownTracker {
	return &cooldownTracker{
		lastCalls: make(map[string]time.Time),
		blocks:    make(map[string]time.Time),
	}
}

func (ct *cooldownTracker) record(agent, tool string) {
	ct.mu.Lock()
	ct.lastCalls[agent+":"+tool] = time.Now()
	ct.mu.Unlock()
}

func (ct *cooldownTracker) isOnCooldown(agent, tool string, cooldownSecs int) bool {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	last, ok := ct.lastCalls[agent+":"+tool]
	if !ok {
		return false
	}
	return time.Since(last) < time.Duration(cooldownSecs)*time.Second
}

func (ct *cooldownTracker) block(agent, tool string, secs int) {
	ct.mu.Lock()
	ct.blocks[agent+":"+tool] = time.Now().Add(time.Duration(secs) * time.Second)
	ct.mu.Unlock()
}

func (ct *cooldownTracker) isBlocked(agent, tool string) bool {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	until, ok := ct.blocks[agent+":"+tool]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(ct.blocks, agent+":"+tool)
		return false
	}
	return true
}
