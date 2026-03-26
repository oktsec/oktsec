package proxy

import (
	"log/slog"
	"net"
	"strings"

	"github.com/oktsec/oktsec/internal/config"
)

// ResolvedEgressPolicy is the merged result of global + per-agent egress settings.
type ResolvedEgressPolicy struct {
	AllowedDomains    []string
	BlockedDomains    []string
	ToolRestrictions  map[string][]string // tool -> allowed domains
	ScanRequests      bool
	ScanResponses     bool
	BlockedCategories []string
	RateLimit         int
	RateWindow        int
}

// EgressEvaluator merges global forward proxy config with per-agent egress policies.
type EgressEvaluator struct {
	global          *config.ForwardProxyConfig
	agents          map[string]config.Agent
	trustBoundaries *config.TrustBoundaries
}

// NewEgressEvaluator creates an evaluator from the global config, agents map,
// and optional trust boundaries (nil is safe).
func NewEgressEvaluator(global *config.ForwardProxyConfig, agents map[string]config.Agent, tb *config.TrustBoundaries) *EgressEvaluator {
	return &EgressEvaluator{global: global, agents: agents, trustBoundaries: tb}
}

// Resolve merges the global forward proxy config with the agent's egress policy.
// If the agent has no egress config, global settings are returned.
func (e *EgressEvaluator) Resolve(agentName string) *ResolvedEgressPolicy {
	p := &ResolvedEgressPolicy{
		AllowedDomains: e.global.AllowedDomains,
		BlockedDomains: e.global.BlockedDomains,
		ScanRequests:   e.global.ScanRequests,
		ScanResponses:  e.global.ScanResponses,
	}

	agent, ok := e.agents[agentName]
	if !ok || agent.Egress == nil {
		return p
	}

	eg := agent.Egress

	// Resolve integration presets into allowed domains
	if len(eg.Integrations) > 0 {
		presetDomains := config.ResolveIntegrationDomains(eg.Integrations)
		p.AllowedDomains = mergeUnique(p.AllowedDomains, presetDomains)
	}

	// Resolve scope-based trust boundaries (only when allowed_domains is empty).
	// Explicit allowed_domains takes precedence over scope.
	if len(eg.AllowedDomains) == 0 && eg.Scope != "" {
		scopeDomains := e.resolveScope(eg.Scope)
		p.AllowedDomains = mergeUnique(p.AllowedDomains, scopeDomains)
	}

	// Per-agent domains are additive to global + presets
	if len(eg.AllowedDomains) > 0 {
		p.AllowedDomains = mergeUnique(p.AllowedDomains, eg.AllowedDomains)
	}
	if len(eg.BlockedDomains) > 0 {
		p.BlockedDomains = mergeUnique(p.BlockedDomains, eg.BlockedDomains)
	}

	// Tool-level restrictions
	if len(eg.ToolRestrictions) > 0 {
		p.ToolRestrictions = eg.ToolRestrictions
	}

	// Explicit booleans override global; nil inherits
	if eg.ScanRequests != nil {
		p.ScanRequests = *eg.ScanRequests
	}
	if eg.ScanResponses != nil {
		p.ScanResponses = *eg.ScanResponses
	}

	p.BlockedCategories = eg.BlockedCategories

	if eg.RateLimit > 0 {
		p.RateLimit = eg.RateLimit
		p.RateWindow = eg.RateWindow
		if p.RateWindow <= 0 {
			p.RateWindow = 60
		}
	}

	return p
}

// resolveScope expands an egress scope string into a list of allowed domains.
// Supported formats:
//   - "internal"                  → trust_boundaries.internal domains
//   - "internal+extra.com,other"  → internal domains + the extra domains
func (e *EgressEvaluator) resolveScope(scope string) []string {
	var domains []string

	base := scope
	var extras string
	if idx := strings.Index(scope, "+"); idx >= 0 {
		base = scope[:idx]
		extras = scope[idx+1:]
	}

	if base == "internal" {
		if e.trustBoundaries != nil && len(e.trustBoundaries.Internal) > 0 {
			domains = append(domains, e.trustBoundaries.Internal...)
		} else {
			slog.Warn("egress scope references 'internal' but trust_boundaries.internal is empty")
		}
	}

	if extras != "" {
		for _, d := range strings.Split(extras, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				domains = append(domains, d)
			}
		}
	}

	return domains
}

// DomainAllowed checks a host against the resolved policy.
// Global blocked_domains always win (cannot be overridden per-agent).
func (p *ResolvedEgressPolicy) DomainAllowed(host string) bool {
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}

	for _, d := range p.BlockedDomains {
		if strings.EqualFold(hostname, d) {
			return false
		}
	}

	if len(p.AllowedDomains) > 0 {
		for _, d := range p.AllowedDomains {
			if strings.EqualFold(hostname, d) {
				return true
			}
		}
		return false
	}

	return true
}

// ToolDomainAllowed checks if a specific tool is allowed to access a domain.
// If tool_restrictions is set for the tool, only those domains are allowed.
// If the tool is not in tool_restrictions, falls back to DomainAllowed.
func (p *ResolvedEgressPolicy) ToolDomainAllowed(toolName, host string) bool {
	if len(p.ToolRestrictions) == 0 {
		return p.DomainAllowed(host)
	}

	domains, hasRestriction := p.ToolRestrictions[toolName]
	if !hasRestriction {
		return p.DomainAllowed(host)
	}

	// Tool has explicit restrictions
	if len(domains) == 0 {
		return false // empty list = no egress for this tool
	}

	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}

	// Check blocked first (global blocked always wins)
	for _, d := range p.BlockedDomains {
		if strings.EqualFold(hostname, d) {
			return false
		}
	}

	for _, d := range domains {
		if strings.EqualFold(hostname, d) {
			return true
		}
	}
	return false
}

// CategoryBlocked checks if a finding category is in the blocked list.
func (p *ResolvedEgressPolicy) CategoryBlocked(category string) bool {
	for _, c := range p.BlockedCategories {
		if strings.EqualFold(c, category) {
			return true
		}
	}
	return false
}

// mergeUnique combines two string slices, deduplicating case-insensitively.
func mergeUnique(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	var result []string
	for _, s := range a {
		lower := strings.ToLower(s)
		if !seen[lower] {
			seen[lower] = true
			result = append(result, s)
		}
	}
	for _, s := range b {
		lower := strings.ToLower(s)
		if !seen[lower] {
			seen[lower] = true
			result = append(result, s)
		}
	}
	return result
}
