package gateway

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
)

// denyAllGateway builds a minimal gateway (no real backends) for exercising the
// handler's deny paths, which return BEFORE any backend session is contacted.
func denyAllGateway(t *testing.T, cfg *config.Config) *Gateway {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	scanner := engine.NewScanner("")
	t.Cleanup(scanner.Close)
	return newGatewayForTest(cfg, scanner, nil, logger)
}

// denyAllCallIsError drives a tool through the gateway handler for principal
// `agent` and reports whether it was denied. A policy denial returns a non-nil
// error result (IsError) with err == nil, BEFORE the backend is contacted, so a
// session-less stub backend is sufficient for the deny paths.
func denyAllCallIsError(t *testing.T, g *Gateway, agent, originalName string) bool {
	t.Helper()
	b := &Backend{Name: "backend1", Tools: []*mcp.Tool{{Name: originalName}}}
	handler := g.makeHandler(toolMapping{Backend: b, OriginalName: originalName})
	ctx := context.WithValue(context.Background(), agentContextKey, agent)
	res, err := handler(ctx, makeHandlerRequest(originalName, map[string]any{"text": "x"}))
	if err != nil {
		t.Fatalf("handler returned transport error: %v", err)
	}
	return res != nil && res.IsError
}

// FIX 2 gateway runtime test 2: with the deny-all allowlist (the lone sentinel),
// any NORMAL tool call is blocked at runtime before reaching the backend.
func TestGateway_DenyAllSentinelBlocksNormalTool(t *testing.T) {
	g := denyAllGateway(t, &config.Config{Agents: map[string]config.Agent{
		"agent1": {AllowedTools: []string{config.DenyAllToolsSentinel}},
	}})
	if !denyAllCallIsError(t, g, "agent1", "search") {
		t.Fatalf("deny-all sentinel allowlist must block a normal tool call")
	}
}

// FIX 2 gateway runtime test 3: with the deny-all allowlist, a backend tool
// literally named the reserved sentinel is ALSO blocked.
func TestGateway_DenyAllSentinelBlocksSentinelNamedTool(t *testing.T) {
	g := denyAllGateway(t, &config.Config{Agents: map[string]config.Agent{
		"agent1": {AllowedTools: []string{config.DenyAllToolsSentinel}},
	}})
	if !denyAllCallIsError(t, g, "agent1", config.DenyAllToolsSentinel) {
		t.Fatalf("a tool named the deny-all sentinel must be blocked under a deny-all allowlist")
	}
}

// FIX 2 reinforcement: a tool literally named the reserved sentinel is denied
// even when the agent's allowlist is broad and NOT the deny-all form.
func TestGateway_SentinelNamedToolBlockedEvenWithBroadAllowlist(t *testing.T) {
	g := denyAllGateway(t, &config.Config{Agents: map[string]config.Agent{
		"agent1": {AllowedTools: []string{"search", config.DenyAllToolsSentinel}},
	}})
	if !denyAllCallIsError(t, g, "agent1", config.DenyAllToolsSentinel) {
		t.Fatalf("a tool named the deny-all sentinel must always be blocked")
	}
}

// FIX 2 defense in depth: a tool named the reserved sentinel is denied even for
// an UNKNOWN principal with no agent config entry (the sentinel-name denial is
// hoisted above the agent lookup).
func TestGateway_SentinelNamedToolBlockedForUnknownPrincipal(t *testing.T) {
	g := denyAllGateway(t, &config.Config{}) // no agent entries
	if !denyAllCallIsError(t, g, "ghost", config.DenyAllToolsSentinel) {
		t.Fatalf("a tool named the deny-all sentinel must be blocked even for an unknown principal")
	}
}

// FIX 2 discovery test 5: discovery containing the reserved tool name excludes it
// (never registered as callable) while keeping normal tools.
func TestGateway_DiscoveryExcludesReservedToolName(t *testing.T) {
	g := denyAllGateway(t, &config.Config{})
	g.backends = map[string]*Backend{
		"backend1": {Name: "backend1", Tools: []*mcp.Tool{
			{Name: "search"},
			{Name: config.DenyAllToolsSentinel}, // reserved: must be excluded
		}},
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

// FIX 2 discovery: a NAMESPACED frontend name that collides with the reserved
// sentinel is also excluded. Backend "__oktsec" + a conflicting tool "deny_all__"
// would namespace to "__oktsec_deny_all__" (the sentinel); it must not register.
func TestGateway_DiscoveryExcludesNamespacedSentinelCollision(t *testing.T) {
	g := denyAllGateway(t, &config.Config{})
	g.backends = map[string]*Backend{
		"__oktsec": {Name: "__oktsec", Tools: []*mcp.Tool{{Name: "deny_all__"}}},
		"other":    {Name: "other", Tools: []*mcp.Tool{{Name: "deny_all__"}}},
	}
	if err := g.buildToolMap(); err != nil {
		t.Fatalf("buildToolMap: %v", err)
	}
	if _, ok := g.toolMap[config.DenyAllToolsSentinel]; ok {
		t.Fatalf("namespaced name colliding with the sentinel must be excluded, toolMap=%v", g.toolMap)
	}
	if _, ok := g.toolMap["other_deny_all__"]; !ok {
		t.Fatalf("the non-colliding conflicted tool must still register, toolMap=%v", g.toolMap)
	}
}
