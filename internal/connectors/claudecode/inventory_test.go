package claudecode

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixtureHome assembles a fake $HOME with the given on-disk Claude
// state, returning the temp dir so tests can pass it as opts.HomeDir.
// Each map value names a fixture from fixtures_test.go (string consts
// rather than testdata/ files because the repo gitignores testdata/).
func fixtureHome(t *testing.T, files map[string]string) string {
	t.Helper()
	home := t.TempDir()
	for rel, src := range files {
		dst := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			t.Fatal(err)
		}
		body, ok := fixtureSources[src]
		if !ok {
			t.Fatalf("unknown fixture %q (add it to fixtures_test.go)", src)
		}
		if err := os.WriteFile(dst, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

// TestRead_NoClaudeState confirms the doctor handles a fresh box
// gracefully: no settings, no global state, no CLI -> Detected=false
// and no Problems entries blaming the operator.
func TestRead_NoClaudeState(t *testing.T) {
	home := t.TempDir()
	inv := Read(context.Background(), ReadOptions{
		HomeDir:          home,
		ClaudeBinary:     filepath.Join(home, "no-such-binary"),
		SkipVersionProbe: true,
	})

	if inv.Detected {
		t.Errorf("Detected = true, want false on a clean home")
	}
	if len(inv.Hooks) != 0 {
		t.Errorf("Hooks = %d, want 0 on a clean home", len(inv.Hooks))
	}
	if len(inv.MCPServers) != 0 {
		t.Errorf("MCPServers = %d, want 0", len(inv.MCPServers))
	}
	if inv.UserSettingsPath == "" {
		t.Error("UserSettingsPath should be reported even when missing")
	}
	if hasProblemCode(inv.Problems, "CC-HOOKS-MISSING") {
		t.Error("CC-HOOKS-MISSING should not fire when Claude itself is not detected")
	}
}

// TestRead_OktsecHookInstalled exercises the happy path: oktsec hooks
// already in user settings, gateway entry in ~/.claude.json.
func TestRead_OktsecHookInstalled(t *testing.T) {
	home := fixtureHome(t, map[string]string{
		".claude/settings.json": "user_settings_with_oktsec.json",
		".claude.json":          "claude_json.json",
	})
	inv := Read(context.Background(), ReadOptions{
		HomeDir:          home,
		SkipVersionProbe: true,
	})

	if !inv.Detected {
		t.Fatal("Detected = false, want true")
	}
	if !hasOktsecHook(inv.Hooks) {
		t.Errorf("expected at least one oktsec hook, got %+v", inv.Hooks)
	}
	if !hasOktsecGatewayMCP(inv.MCPServers) {
		t.Errorf("expected oktsec-gateway MCP entry, got %+v", inv.MCPServers)
	}
	if hasProblemCode(inv.Problems, "CC-HOOKS-MISSING") {
		t.Error("CC-HOOKS-MISSING fired despite oktsec hooks being installed")
	}

	var pre HookRef
	for _, h := range inv.Hooks {
		if h.Event == "PreToolUse" {
			pre = h
			break
		}
	}
	if !pre.IsOktsec {
		t.Errorf("PreToolUse hook IsOktsec = false, want true; ref=%+v", pre)
	}
	if !pre.BlockingCap {
		t.Error("PreToolUse should be marked BlockingCap=true")
	}
	if !pre.Expected {
		t.Error("PreToolUse should be marked Expected=true (Phase 2 manifest)")
	}
}

// TestRead_HookButNotOktsec proves we do not credit unrelated tooling
// for our coverage. Settings carry a non-oktsec command hook only.
func TestRead_HookButNotOktsec(t *testing.T) {
	home := fixtureHome(t, map[string]string{
		".claude/settings.json": "user_settings_no_oktsec.json",
	})
	inv := Read(context.Background(), ReadOptions{
		HomeDir:          home,
		SkipVersionProbe: true,
	})

	if hasOktsecHook(inv.Hooks) {
		t.Error("hasOktsecHook = true, want false (the command was a third-party linter)")
	}
	if !hasProblemCode(inv.Problems, "CC-HOOKS-MISSING") {
		t.Error("expected CC-HOOKS-MISSING to flag the gap")
	}
}

// TestRead_ProjectScopedMCPFromGlobalState exercises the
// ~/.claude.json projects[X] path. The fixture has a placeholder
// project key we rewrite to the temp dir at runtime so the parser
// matches against the real opts.ProjectDir.
func TestRead_ProjectScopedMCPFromGlobalState(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()

	rewritten := strings.ReplaceAll(fixtureSources["claude_json.json"], "/PROJECT_DIR_PLACEHOLDER", project)
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(rewritten), 0o600); err != nil {
		t.Fatal(err)
	}

	inv := Read(context.Background(), ReadOptions{
		HomeDir:          home,
		ProjectDir:       project,
		SkipVersionProbe: true,
	})

	var sawProjectScoped bool
	for _, s := range inv.MCPServers {
		if s.Name == "filesystem" && s.Scope == "global" {
			sawProjectScoped = true
		}
	}
	if !sawProjectScoped {
		t.Errorf("expected project-scoped 'filesystem' entry from global state, got %+v", inv.MCPServers)
	}
}

// TestRead_AgentMarkdownParsing verifies the static .claude/agents/*.md
// reader picks up frontmatter fields and falls back to file basename
// when name is missing.
func TestRead_AgentMarkdownParsing(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude", "agents"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, fix := range []string{"agent_code_reviewer.md", "agent_no_frontmatter.md"} {
		body, ok := fixtureSources[fix]
		if !ok {
			t.Fatalf("unknown fixture %q", fix)
		}
		dst := filepath.Join(home, ".claude", "agents", fix)
		if err := os.WriteFile(dst, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	inv := Read(context.Background(), ReadOptions{
		HomeDir:          home,
		SkipVersionProbe: true,
	})

	if len(inv.Subagents) != 2 {
		t.Fatalf("Subagents = %d, want 2", len(inv.Subagents))
	}
	byName := map[string]SubagentRef{}
	for _, s := range inv.Subagents {
		byName[s.Name] = s
	}
	rev, ok := byName["code-reviewer"]
	if !ok {
		t.Fatal("code-reviewer agent missing")
	}
	if rev.PermissionMode != "confirmActions" {
		t.Errorf("permissionMode = %q, want confirmActions", rev.PermissionMode)
	}
	if !rev.HooksPresent {
		t.Error("HooksPresent should be true when frontmatter has hooks key")
	}
	if len(rev.Tools) != 2 || rev.Tools[0] != "Read" {
		t.Errorf("Tools = %v, want [Read Grep]", rev.Tools)
	}

	if _, ok := byName["agent_no_frontmatter"]; !ok {
		t.Error("expected fallback name 'agent_no_frontmatter' for file with no name field")
	}
}

// TestRead_MalformedSettingsRecordsProblem confirms a broken JSON
// surfaces as a Problem and does not abort the rest of the scan.
func TestRead_MalformedSettingsRecordsProblem(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(home, ".claude", "settings.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	inv := Read(context.Background(), ReadOptions{
		HomeDir:          home,
		SkipVersionProbe: true,
	})

	if !hasProblemCode(inv.Problems, "CC-SETTINGS-PARSE") {
		t.Errorf("expected CC-SETTINGS-PARSE problem, got %+v", inv.Problems)
	}
	if len(inv.Hooks) != 0 {
		t.Errorf("Hooks should be empty when settings parse fails, got %+v", inv.Hooks)
	}
}

// TestMissingExpectedEvents covers the Phase 2 manifest gap report.
func TestMissingExpectedEvents(t *testing.T) {
	home := fixtureHome(t, map[string]string{
		".claude/settings.json": "user_settings_with_oktsec.json",
	})
	inv := Read(context.Background(), ReadOptions{
		HomeDir:          home,
		SkipVersionProbe: true,
	})

	missing := MissingExpectedEvents(inv.Hooks)
	// The fixture installs oktsec hooks for PreToolUse and PostToolUse,
	// so neither should appear in the missing list, but everything
	// else from the Phase 2 manifest should.
	for _, e := range missing {
		if e == "PreToolUse" || e == "PostToolUse" {
			t.Errorf("Phase 2 missing list should not contain installed event %q", e)
		}
	}
	if len(missing) == 0 {
		t.Error("expected at least one missing Phase 2 event (e.g. SubagentStart)")
	}
}

// TestDeriveHealth_StatusTransitions locks in the status mapping so
// the dashboard can rely on these strings in Phase 4.
func TestDeriveHealth_StatusTransitions(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	cases := []struct {
		name      string
		inv       Inventory
		lastEvent string
		want      string
	}{
		{
			name: "not_installed",
			inv:  Inventory{Detected: false},
			want: "not_installed",
		},
		{
			name: "disconnected when detected but no oktsec hook or gateway",
			inv:  Inventory{Detected: true},
			want: "disconnected",
		},
		{
			name: "partial when oktsec hook installed but no event yet",
			inv: Inventory{
				Detected: true,
				Hooks:    []HookRef{{IsOktsec: true, Event: "PreToolUse"}},
			},
			want: "partial",
		},
		{
			name: "ready when last event is recent",
			inv: Inventory{
				Detected: true,
				Hooks:    []HookRef{{IsOktsec: true, Event: "PreToolUse"}},
			},
			lastEvent: now.Add(-30 * time.Minute).Format(time.RFC3339),
			want:      "ready",
		},
		{
			// Past FreshEvent (30m default) but within
			// StaleAfter (24h default) — Phase 3C-0 keeps the
			// stale label here. Beyond 24h the row drops to
			// partial; that boundary is exercised by
			// TestDeriveHealth_VeryOldRuntimeEventIsPartial.
			name: "stale when last event is past fresh window",
			inv: Inventory{
				Detected: true,
				Hooks:    []HookRef{{IsOktsec: true, Event: "PreToolUse"}},
			},
			lastEvent: now.Add(-2 * time.Hour).Format(time.RFC3339),
			want:      "stale",
		},
		{
			name: "partial on garbled timestamp",
			inv: Inventory{
				Detected: true,
				Hooks:    []HookRef{{IsOktsec: true, Event: "PreToolUse"}},
			},
			lastEvent: "not-a-timestamp",
			want:      "partial",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := DeriveHealth(tc.inv, HealthOptions{
				LastEvent: tc.lastEvent,
				Now:       clock,
			})
			if h.Status != tc.want {
				t.Errorf("status = %q, want %q (reason: %s)", h.Status, tc.want, h.Reason)
			}
			if h.Reason == "" {
				t.Error("Reason should always be populated for the dashboard pill")
			}
		})
	}
}

// TestRead_NeverWritesToHome guards the Phase 1 read-only contract:
// a baseline directory snapshot before Read must equal the snapshot
// after Read. If a future change accidentally writes anything, the
// snapshot diff catches it.
func TestRead_NeverWritesToHome(t *testing.T) {
	home := fixtureHome(t, map[string]string{
		".claude/settings.json": "user_settings_with_oktsec.json",
		".claude.json":          "claude_json.json",
	})
	before := snapshotTree(t, home)

	_ = Read(context.Background(), ReadOptions{
		HomeDir:          home,
		SkipVersionProbe: true,
	})

	after := snapshotTree(t, home)
	if before != after {
		t.Errorf("Read mutated $HOME (Phase 1 must be read-only)\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// snapshotTree returns a stable string of (relpath, size, modtime)
// for every file under root. Sufficient to detect any mutation by
// Read without depending on file content order.
func snapshotTree(t *testing.T, root string) string {
	t.Helper()
	var lines []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		lines = append(lines, rel+"\t"+info.ModTime().UTC().Format(time.RFC3339Nano)+"\t"+itoaInt64(info.Size()))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(lines, "\n")
}

func itoaInt64(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func hasProblemCode(ps []ConnectorProblem, code string) bool {
	for _, p := range ps {
		if p.Code == code {
			return true
		}
	}
	return false
}
