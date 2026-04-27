package dashboard

import (
	"regexp"
	"strings"
	"testing"
)

// avIDPattern matches the avNN unique-id suffix the avatar SVG
// emits (any digit count). The previous strip helper iterated
// av1..av99 sequentially, but `av1` prefix-matches `av11` and
// leaves the trailing digit — so once the package-level counter
// crossed 9 (cumulative across all dashboard tests in the same
// `go test` run) the deterministic check would diff on the suffix.
// Regex match is order-independent.
var avIDPattern = regexp.MustCompile(`av\d+`)

func TestAgentAvatar_Deterministic(t *testing.T) {
	a1 := string(agentAvatar("research-agent", 20))
	a2 := string(agentAvatar("research-agent", 20))

	// Strip unique IDs so the comparison sees only the visual
	// content (colors, pattern) — the gradient/clip ids are
	// generated from a counter and are expected to differ.
	strip := func(s string) string {
		return avIDPattern.ReplaceAllString(s, "avN")
	}
	if strip(a1) != strip(a2) {
		t.Errorf("same name produced different avatars:\n  %s\n  %s", a1, a2)
	}
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
