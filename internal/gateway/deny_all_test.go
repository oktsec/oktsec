package gateway

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/oktsec/oktsec/internal/config"
)

// denyAllCallIsError drives a tool through the gateway handler and returns
// whether it was denied. A policy denial returns a non-nil error result
// (IsError) with err == nil, BEFORE the backend is ever contacted, so a
// session-less stub backend is sufficient for the deny paths.
func denyAllCallIsError(t *testing.T, g *Gateway, b *Backend, originalName string) bool {
	t.Helper()
	handler := g.makeHandler(toolMapping{Backend: b, OriginalName: originalName})
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParams{Name: originalName, Arguments: map[string]any{"text": "x"}}}
	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler returned transport error: %v", err)
	}
	return result != nil && result.IsError
}

// FIX 2 gateway runtime test 2: with the deny-all allowlist (the lone sentinel),
// any NORMAL tool call is blocked at runtime before reaching the backend.
func TestGateway_DenyAllSentinelBlocksNormalTool(t *testing.T) {
	g := newTestGateway(t)
	g.cfg = &config.Config{Agents: map[string]config.Agent{
		"agent1": {AllowedTools: []string{config.DenyAllToolsSentinel}},
	}}
	b := newTestBackend("backend1", []*mcp.Tool{{Name: "search"}})
	if !denyAllCallIsError(t, g, b, "search") {
		t.Fatalf("deny-all sentinel allowlist must block a normal tool call")
	}
}

// FIX 2 gateway runtime test 3: with the deny-all allowlist, a backend tool
// literally named the reserved sentinel is ALSO blocked. The sentinel is a
// control marker, never a callable name.
func TestGateway_DenyAllSentinelBlocksSentinelNamedTool(t *testing.T) {
	g := newTestGateway(t)
	g.cfg = &config.Config{Agents: map[string]config.Agent{
		"agent1": {AllowedTools: []string{config.DenyAllToolsSentinel}},
	}}
	b := newTestBackend("backend1", []*mcp.Tool{{Name: config.DenyAllToolsSentinel}})
	if !denyAllCallIsError(t, g, b, config.DenyAllToolsSentinel) {
		t.Fatalf("a tool named the deny-all sentinel must be blocked under a deny-all allowlist")
	}
}

// FIX 2 reinforcement: a tool literally named the reserved sentinel is denied
// even when the agent's allowlist is broad and NOT the deny-all form, because the
// sentinel is never a callable name independent of allowlist contents.
func TestGateway_SentinelNamedToolBlockedEvenWithBroadAllowlist(t *testing.T) {
	g := newTestGateway(t)
	g.cfg = &config.Config{Agents: map[string]config.Agent{
		"agent1": {AllowedTools: []string{"search", config.DenyAllToolsSentinel}},
	}}
	b := newTestBackend("backend1", []*mcp.Tool{{Name: config.DenyAllToolsSentinel}})
	if !denyAllCallIsError(t, g, b, config.DenyAllToolsSentinel) {
		t.Fatalf("a tool named the deny-all sentinel must always be blocked")
	}
}

// FIX 2 defense in depth: a tool named the reserved sentinel is denied even for
// an UNKNOWN principal with no agent config entry (the sentinel-name denial is
// hoisted above the agent lookup).
func TestGateway_SentinelNamedToolBlockedForUnknownPrincipal(t *testing.T) {
	g := newTestGateway(t) // empty cfg: no agent entries
	b := newTestBackend("backend1", []*mcp.Tool{{Name: config.DenyAllToolsSentinel}})
	if !denyAllCallIsError(t, g, b, config.DenyAllToolsSentinel) {
		t.Fatalf("a tool named the deny-all sentinel must be blocked even for an unknown principal")
	}
}

// FIX 2 discovery test 5: discovery containing the reserved tool name excludes it
// (never registered as callable) while keeping normal tools.
func TestGateway_DiscoveryExcludesReservedToolName(t *testing.T) {
	g := newTestGateway(t)
	g.backends = map[string]*Backend{
		"backend1": newTestBackend("backend1", []*mcp.Tool{
			{Name: "search"},
			{Name: config.DenyAllToolsSentinel}, // reserved: must be excluded
		}),
	}
	if err := g.buildToolMap(); err != nil {
		t.Fatalf("buildToolMap: %v", err)
	}
	if _, ok := g.toolMap[config.DenyAllToolsSentinel]; ok {
		t.Fatalf("reserved sentinel tool must be excluded from discovery, toolMap=%v", g.toolMap)
	}
	if _, ok := g.toolMap["search"]; !ok {
		t.Fatalf("normal tool must still be discovered alongside an excluded reserved tool, toolMap=%v", g.toolMap)
	}
}

// FIX 2 reinforcement: a normal allowlist still allows a permitted tool, proving
// the sentinel special-case did not break normal allowlist matching.
func TestGateway_NormalAllowlistStillAllows(t *testing.T) {
	g := newTestGateway(t)
	g.cfg = &config.Config{Agents: map[string]config.Agent{
		"agent1": {AllowedTools: []string{"search"}},
	}}
	b := newTestBackend("backend1", []*mcp.Tool{{Name: "search"}})
	if denyAllCallIsError(t, g, b, "search") {
		t.Fatalf("a permitted tool must not be blocked by the sentinel special-case")
	}
}
