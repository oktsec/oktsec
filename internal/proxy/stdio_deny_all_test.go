package proxy

import (
	"testing"

	"github.com/oktsec/oktsec/internal/config"
)

// denyAllToolCall builds a JSON-RPC tools/call frame for the given tool name.
func denyAllToolCall(toolName string) []byte {
	return []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + toolName + `","arguments":{}}}`)
}

// FIX 2 stdio runtime test: with the deny-all allowlist (the lone sentinel), any
// NORMAL tool call is blocked at the stdio proxy enforcement point.
func TestStdioProxy_DenyAllSentinelBlocksNormalTool(t *testing.T) {
	p := newStdioTestSetup(t, true)
	p.SetAllowedTools([]string{config.DenyAllToolsSentinel})
	blocked, _, _ := p.inspectAndDecide(denyAllToolCall("weather"), "test-agent", "server")
	if !blocked {
		t.Fatalf("deny-all sentinel allowlist must block a normal tool call")
	}
}

// FIX 2 stdio runtime test: with the deny-all allowlist, a tool literally named
// the reserved sentinel is ALSO blocked.
func TestStdioProxy_DenyAllSentinelBlocksSentinelNamedTool(t *testing.T) {
	p := newStdioTestSetup(t, true)
	p.SetAllowedTools([]string{config.DenyAllToolsSentinel})
	blocked, _, _ := p.inspectAndDecide(denyAllToolCall(config.DenyAllToolsSentinel), "test-agent", "server")
	if !blocked {
		t.Fatalf("a tool named the deny-all sentinel must be blocked under a deny-all allowlist")
	}
}

// FIX 2 stdio: the sentinel tool name is blocked UNCONDITIONALLY, even with an
// empty allowlist (which otherwise means "all tools allowed"). The sentinel is
// never a callable tool name.
func TestStdioProxy_SentinelNamedToolBlockedWithEmptyAllowlist(t *testing.T) {
	p := newStdioTestSetup(t, true)
	// No SetAllowedTools call: empty allowlist == all tools allowed for normal names.
	blocked, _, _ := p.inspectAndDecide(denyAllToolCall(config.DenyAllToolsSentinel), "test-agent", "server")
	if !blocked {
		t.Fatalf("a tool named the deny-all sentinel must be blocked even with an empty allowlist")
	}
}

// FIX 2 stdio reinforcement: a tool literally named the reserved sentinel is
// denied even when the allowlist is broad and not the deny-all form.
func TestStdioProxy_SentinelNamedToolBlockedWithBroadAllowlist(t *testing.T) {
	p := newStdioTestSetup(t, true)
	p.SetAllowedTools([]string{"calculator", config.DenyAllToolsSentinel})
	blocked, _, _ := p.inspectAndDecide(denyAllToolCall(config.DenyAllToolsSentinel), "test-agent", "server")
	if !blocked {
		t.Fatalf("a tool named the deny-all sentinel must always be blocked")
	}
}

// FIX 2 stdio reinforcement: a normal allowlist still permits a listed tool, so
// the sentinel special-case did not break normal matching.
func TestStdioProxy_NormalAllowlistStillAllows(t *testing.T) {
	p := newStdioTestSetup(t, true)
	p.SetAllowedTools([]string{"calculator"})
	blocked, _, _ := p.inspectAndDecide(denyAllToolCall("calculator"), "test-agent", "server")
	if blocked {
		t.Fatalf("a permitted tool must not be blocked by the sentinel special-case")
	}
}
