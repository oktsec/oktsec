package proxy

import (
	"io"
	"log/slog"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
)

// FIX 2 stdio runtime test: with the deny-all allowlist (the lone sentinel), any
// NORMAL tool call is blocked at the stdio proxy enforcement point.
func TestStdioProxy_DenyAllSentinelBlocksNormalTool(t *testing.T) {
	p := NewStdioProxy("agent1", newScanner(t), newStore(t), slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	p.SetAllowedTools([]string{config.DenyAllToolsSentinel})
	blocked, _, _ := p.inspectAndDecide(buildToolCall(t, "weather"), "agent1", "server")
	if !blocked {
		t.Fatalf("deny-all sentinel allowlist must block a normal tool call")
	}
}

// FIX 2 stdio runtime test: with the deny-all allowlist, a tool literally named
// the reserved sentinel is ALSO blocked.
func TestStdioProxy_DenyAllSentinelBlocksSentinelNamedTool(t *testing.T) {
	p := NewStdioProxy("agent1", newScanner(t), newStore(t), slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	p.SetAllowedTools([]string{config.DenyAllToolsSentinel})
	blocked, _, _ := p.inspectAndDecide(buildToolCall(t, config.DenyAllToolsSentinel), "agent1", "server")
	if !blocked {
		t.Fatalf("a tool named the deny-all sentinel must be blocked under a deny-all allowlist")
	}
}

// FIX 2 stdio reinforcement: a tool literally named the reserved sentinel is
// denied even when the allowlist is broad and not the deny-all form.
func TestStdioProxy_SentinelNamedToolBlockedWithBroadAllowlist(t *testing.T) {
	p := NewStdioProxy("agent1", newScanner(t), newStore(t), slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	p.SetAllowedTools([]string{"calculator", config.DenyAllToolsSentinel})
	blocked, _, _ := p.inspectAndDecide(buildToolCall(t, config.DenyAllToolsSentinel), "agent1", "server")
	if !blocked {
		t.Fatalf("a tool named the deny-all sentinel must always be blocked")
	}
}

// FIX 2 stdio reinforcement: a normal allowlist still permits a listed tool, so
// the sentinel special-case did not break normal matching.
func TestStdioProxy_NormalAllowlistStillAllows(t *testing.T) {
	p := NewStdioProxy("agent1", newScanner(t), newStore(t), slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	p.SetAllowedTools([]string{"calculator"})
	blocked, _, _ := p.inspectAndDecide(buildToolCall(t, "calculator"), "agent1", "server")
	if blocked {
		t.Fatalf("a permitted tool must not be blocked by the sentinel special-case")
	}
}
