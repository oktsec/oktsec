package proxy

import (
	"testing"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/stretchr/testify/assert"
)

func TestEgressEvaluator_NoAgentConfig(t *testing.T) {
	eval := NewEgressEvaluator(&config.ForwardProxyConfig{
		AllowedDomains: []string{"api.example.com"},
		BlockedDomains: []string{"evil.com"},
		ScanRequests:   true,
	}, nil)

	p := eval.Resolve("unknown-agent")
	assert.Equal(t, []string{"api.example.com"}, p.AllowedDomains)
	assert.Equal(t, []string{"evil.com"}, p.BlockedDomains)
	assert.True(t, p.ScanRequests)
	assert.False(t, p.ScanResponses)
}

func TestEgressEvaluator_AgentNoEgress(t *testing.T) {
	eval := NewEgressEvaluator(&config.ForwardProxyConfig{
		AllowedDomains: []string{"global.com"},
		ScanRequests:   true,
	}, map[string]config.Agent{
		"agent-a": {CanMessage: []string{"agent-b"}},
	})

	p := eval.Resolve("agent-a")
	assert.Equal(t, []string{"global.com"}, p.AllowedDomains)
	assert.True(t, p.ScanRequests)
}

func TestEgressEvaluator_AdditiveDomains(t *testing.T) {
	eval := NewEgressEvaluator(&config.ForwardProxyConfig{
		AllowedDomains: []string{"global.com"},
		BlockedDomains: []string{"evil.com"},
	}, map[string]config.Agent{
		"researcher": {
			Egress: &config.EgressPolicy{
				AllowedDomains: []string{"arxiv.org", "global.com"}, // dupe should be deduped
				BlockedDomains: []string{"pastebin.com"},
			},
		},
	})

	p := eval.Resolve("researcher")
	assert.Contains(t, p.AllowedDomains, "global.com")
	assert.Contains(t, p.AllowedDomains, "arxiv.org")
	assert.Len(t, p.AllowedDomains, 2) // deduped

	assert.Contains(t, p.BlockedDomains, "evil.com")
	assert.Contains(t, p.BlockedDomains, "pastebin.com")
}

func TestEgressEvaluator_GlobalBlocklistWins(t *testing.T) {
	eval := NewEgressEvaluator(&config.ForwardProxyConfig{
		BlockedDomains: []string{"evil.com"},
	}, map[string]config.Agent{
		"agent": {
			Egress: &config.EgressPolicy{
				AllowedDomains: []string{"evil.com"}, // agent allows it, but global blocks
			},
		},
	})

	p := eval.Resolve("agent")
	// evil.com is in both allowed (from agent) and blocked (from global)
	// DomainAllowed should return false because blocked takes precedence
	assert.False(t, p.DomainAllowed("evil.com"))
}

func TestEgressEvaluator_BoolOverride(t *testing.T) {
	scanTrue := true
	scanFalse := false

	eval := NewEgressEvaluator(&config.ForwardProxyConfig{
		ScanRequests:  true,
		ScanResponses: false,
	}, map[string]config.Agent{
		"override-both": {
			Egress: &config.EgressPolicy{
				ScanRequests:  &scanFalse,
				ScanResponses: &scanTrue,
			},
		},
		"inherit": {
			Egress: &config.EgressPolicy{
				// nil bools — should inherit global
			},
		},
	})

	p := eval.Resolve("override-both")
	assert.False(t, p.ScanRequests)
	assert.True(t, p.ScanResponses)

	p = eval.Resolve("inherit")
	assert.True(t, p.ScanRequests)
	assert.False(t, p.ScanResponses)
}

func TestEgressEvaluator_RateLimit(t *testing.T) {
	eval := NewEgressEvaluator(&config.ForwardProxyConfig{}, map[string]config.Agent{
		"limited": {
			Egress: &config.EgressPolicy{
				RateLimit:  50,
				RateWindow: 120,
			},
		},
		"default-window": {
			Egress: &config.EgressPolicy{
				RateLimit: 100,
				// no window — should default to 60
			},
		},
	})

	p := eval.Resolve("limited")
	assert.Equal(t, 50, p.RateLimit)
	assert.Equal(t, 120, p.RateWindow)

	p = eval.Resolve("default-window")
	assert.Equal(t, 100, p.RateLimit)
	assert.Equal(t, 60, p.RateWindow)
}

func TestEgressEvaluator_BlockedCategories(t *testing.T) {
	eval := NewEgressEvaluator(&config.ForwardProxyConfig{}, map[string]config.Agent{
		"restricted": {
			Egress: &config.EgressPolicy{
				BlockedCategories: []string{"credentials", "pii"},
			},
		},
	})

	p := eval.Resolve("restricted")
	assert.True(t, p.CategoryBlocked("credentials"))
	assert.True(t, p.CategoryBlocked("PII")) // case insensitive
	assert.False(t, p.CategoryBlocked("injection"))
}

func TestResolvedPolicy_DomainAllowed(t *testing.T) {
	tests := []struct {
		name    string
		policy  ResolvedEgressPolicy
		host    string
		allowed bool
	}{
		{
			name:    "no restrictions",
			policy:  ResolvedEgressPolicy{},
			host:    "anything.com",
			allowed: true,
		},
		{
			name:    "blocked domain",
			policy:  ResolvedEgressPolicy{BlockedDomains: []string{"evil.com"}},
			host:    "evil.com",
			allowed: false,
		},
		{
			name:    "blocked domain with port",
			policy:  ResolvedEgressPolicy{BlockedDomains: []string{"evil.com"}},
			host:    "evil.com:443",
			allowed: false,
		},
		{
			name:    "allowed domain",
			policy:  ResolvedEgressPolicy{AllowedDomains: []string{"good.com"}},
			host:    "good.com",
			allowed: true,
		},
		{
			name:    "not in allowlist",
			policy:  ResolvedEgressPolicy{AllowedDomains: []string{"good.com"}},
			host:    "other.com",
			allowed: false,
		},
		{
			name:    "case insensitive",
			policy:  ResolvedEgressPolicy{AllowedDomains: []string{"Good.COM"}},
			host:    "good.com",
			allowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.allowed, tt.policy.DomainAllowed(tt.host))
		})
	}
}

func TestMergeUnique(t *testing.T) {
	result := mergeUnique([]string{"a", "b"}, []string{"B", "c"})
	assert.Len(t, result, 3)
	assert.Contains(t, result, "a")
	assert.Contains(t, result, "b")
	assert.Contains(t, result, "c")
}

func TestMergeUnique_Empty(t *testing.T) {
	result := mergeUnique(nil, nil)
	assert.Nil(t, result)

	result = mergeUnique([]string{"a"}, nil)
	assert.Equal(t, []string{"a"}, result)
}
