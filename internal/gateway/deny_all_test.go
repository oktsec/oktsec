package gateway

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
	"github.com/stretchr/testify/require"
)

// discoveryGateway builds a gateway with synthetic (non-connected) backends for
// exercising buildToolMap discovery directly. Unlike newTestGateway it does not
// require live in-process backends, so callers can stuff arbitrary tool names
// (including the reserved sentinel) into g.backends before building the tool map.
func discoveryGateway(t *testing.T, backends map[string]*Backend) *Gateway {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	scanner := engine.NewScanner("")
	auditStore, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"), logger)
	require.NoError(t, err)
	t.Cleanup(func() {
		scanner.Close()
		_ = auditStore.Close()
	})
	g := newGatewayForTest(defaultGatewayConfig(), scanner, auditStore, logger)
	g.backends = backends
	return g
}

// denyAllCallIsError drives a tool through the gateway handler for principal
// `agent` via the given mapping and reports whether it was denied. A policy
// denial returns a non-nil error result (IsError) with err == nil. The gateway
// is built with the full newTestGateway harness so g.audit and the real backend
// session are wired (the handler logs audit and may forward on the allow path).
func denyAllCallIsError(t *testing.T, g *Gateway, agent string, m toolMapping, callName string) bool {
	t.Helper()
	handler := g.makeHandler(m)
	ctx := context.WithValue(context.Background(), agentContextKey, agent)
	res, err := handler(ctx, makeHandlerRequest(callName, map[string]any{"text": "x"}))
	if err != nil {
		t.Fatalf("handler returned transport error: %v", err)
	}
	return res != nil && res.IsError
}

// FIX 2 gateway runtime test 2: with the deny-all allowlist (the lone sentinel),
// any NORMAL tool call is blocked at runtime.
func TestGateway_DenyAllSentinelBlocksNormalTool(t *testing.T) {
	cfg := defaultGatewayConfig()
	cfg.Agents["test-agent"] = config.Agent{AllowedTools: []string{config.DenyAllToolsSentinel}}
	g := newTestGateway(t, cfg, map[string]*mcp.Server{"echo": echoServer()})
	if !denyAllCallIsError(t, g, "test-agent", g.toolMap["echo"], "echo") {
		t.Fatalf("deny-all sentinel allowlist must block a normal tool call")
	}
}

// FIX 2 gateway runtime test 3: with the deny-all allowlist, a backend tool
// literally named the reserved sentinel is ALSO blocked. The handler keys
// deny-all on OriginalName, so we route to the real echo backend (for a non-nil
// audit/session) but present the sentinel as the original tool name.
func TestGateway_DenyAllSentinelBlocksSentinelNamedTool(t *testing.T) {
	cfg := defaultGatewayConfig()
	cfg.Agents["test-agent"] = config.Agent{AllowedTools: []string{config.DenyAllToolsSentinel}}
	g := newTestGateway(t, cfg, map[string]*mcp.Server{"echo": echoServer()})
	m := g.toolMap["echo"]
	m.OriginalName = config.DenyAllToolsSentinel
	if !denyAllCallIsError(t, g, "test-agent", m, config.DenyAllToolsSentinel) {
		t.Fatalf("a tool named the deny-all sentinel must be blocked under a deny-all allowlist")
	}
}

// FIX 2 reinforcement: a tool literally named the reserved sentinel is denied
// even when the agent's allowlist is broad and NOT the deny-all form.
func TestGateway_SentinelNamedToolBlockedEvenWithBroadAllowlist(t *testing.T) {
	cfg := defaultGatewayConfig()
	cfg.Agents["test-agent"] = config.Agent{AllowedTools: []string{"echo", config.DenyAllToolsSentinel}}
	g := newTestGateway(t, cfg, map[string]*mcp.Server{"echo": echoServer()})
	m := g.toolMap["echo"]
	m.OriginalName = config.DenyAllToolsSentinel
	if !denyAllCallIsError(t, g, "test-agent", m, config.DenyAllToolsSentinel) {
		t.Fatalf("a tool named the deny-all sentinel must always be blocked")
	}
}

// FIX 2 defense in depth: a tool named the reserved sentinel is denied even for
// an UNKNOWN principal with no agent config entry (the sentinel-name denial is
// hoisted above the agent lookup).
func TestGateway_SentinelNamedToolBlockedForUnknownPrincipal(t *testing.T) {
	cfg := defaultGatewayConfig() // no agent entries
	g := newTestGateway(t, cfg, map[string]*mcp.Server{"echo": echoServer()})
	m := g.toolMap["echo"]
	m.OriginalName = config.DenyAllToolsSentinel
	if !denyAllCallIsError(t, g, "ghost", m, config.DenyAllToolsSentinel) {
		t.Fatalf("a tool named the deny-all sentinel must be blocked even for an unknown principal")
	}
}

// FIX 2 discovery test 5: discovery containing the reserved tool name excludes it
// (never registered as callable) while keeping normal tools.
func TestGateway_DiscoveryExcludesReservedToolName(t *testing.T) {
	g := discoveryGateway(t, map[string]*Backend{
		"backend1": {Name: "backend1", Tools: []*mcp.Tool{
			{Name: "search"},
			{Name: config.DenyAllToolsSentinel}, // reserved: must be excluded
		}},
	})
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
	g := discoveryGateway(t, map[string]*Backend{
		"__oktsec": {Name: "__oktsec", Tools: []*mcp.Tool{{Name: "deny_all__"}}},
		"other":    {Name: "other", Tools: []*mcp.Tool{{Name: "deny_all__"}}},
	})
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
