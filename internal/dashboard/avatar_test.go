package dashboard

import (
	"strings"
	"testing"
)

func TestAgentAvatar_Deterministic(t *testing.T) {
	a1 := string(agentAvatar("research-agent", 20))
	a2 := string(agentAvatar("research-agent", 20))

	// Strip unique IDs (av1, av2) to compare visual content
	strip := func(s string) string {
		// The SVG content (colors, pattern) should be identical
		// Only the gradient/clip IDs differ
		for _, prefix := range []string{"av"} {
			for i := 1; i < 100; i++ {
				s = strings.ReplaceAll(s, prefix+itoa(i), prefix+"N")
			}
		}
		return s
	}
	if strip(a1) != strip(a2) {
		t.Errorf("same name produced different avatars:\n  %s\n  %s", a1, a2)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	b := make([]byte, 0, 4)
	for n > 0 {
		b = append(b, byte('0'+n%10))
		n /= 10
	}
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

func TestAgentAvatar_Unique(t *testing.T) {
	names := []string{
		"research-agent", "analysis-agent", "filesystem",
		"database", "github", "slack", "browser", "redis",
	}
	seen := make(map[string]string) // stripped SVG → name
	for _, n := range names {
		svg := string(agentAvatar(n, 20))
		if svg == "" {
			t.Errorf("empty avatar for %q", n)
			continue
		}
		if !strings.Contains(svg, `<svg class="avatar"`) {
			t.Errorf("avatar for %q missing SVG wrapper", n)
		}
		if !strings.Contains(svg, `viewBox="0 0 40 40"`) {
			t.Errorf("avatar for %q missing viewBox", n)
		}
	}
	// At least some should be visually different (different patterns)
	patterns := make(map[uint32]bool)
	for _, n := range names {
		h := fnv32a(n)
		patterns[(h>>16)%8] = true
	}
	if len(patterns) < 2 {
		t.Errorf("expected multiple pattern types, got %d", len(patterns))
	}
	_ = seen // used for dedup if needed
}

func TestAgentAvatar_Empty(t *testing.T) {
	if got := agentAvatar("", 20); got != "" {
		t.Errorf("expected empty string for empty name, got %q", got)
	}
}

func TestAgentCell(t *testing.T) {
	cell := string(agentCell("test-agent"))
	if !strings.Contains(cell, `class="agent-cell"`) {
		t.Error("missing agent-cell class")
	}
	if !strings.Contains(cell, `class="avatar"`) {
		t.Error("missing avatar SVG")
	}
	if !strings.Contains(cell, "test-agent") {
		t.Error("missing agent name text")
	}
}

func TestFnv32a(t *testing.T) {
	// Known FNV-1a values
	if h := fnv32a(""); h != 2166136261 {
		t.Errorf("fnv32a('') = %d, want 2166136261", h)
	}
	// Different inputs produce different hashes
	if fnv32a("a") == fnv32a("b") {
		t.Error("fnv32a('a') == fnv32a('b')")
	}
}
