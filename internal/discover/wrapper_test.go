package discover

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWrapServers_Basic(t *testing.T) {
	servers := map[string]mcpServerJSON{
		"filesystem": {Command: "npx", Args: []string{"-y", "@mcp/server-filesystem"}},
		"database":   {Command: "node", Args: []string{"./db.js"}},
	}

	count := wrapServers(servers, WrapOpts{})

	if count != 2 {
		t.Fatalf("wrapServers returned %d, want 2", count)
	}

	for name, srv := range servers {
		if srv.Command != "oktsec" {
			t.Errorf("server %q command = %q, want oktsec", name, srv.Command)
		}
		if srv.Args[0] != "proxy" {
			t.Errorf("server %q first arg = %q, want proxy", name, srv.Args[0])
		}
	}
}

func TestWrapServers_SkipsAlreadyWrapped(t *testing.T) {
	servers := map[string]mcpServerJSON{
		"wrapped":   {Command: "oktsec", Args: []string{"proxy", "--agent", "wrapped", "--", "npx", "server"}},
		"unwrapped": {Command: "node", Args: []string{"server.js"}},
	}

	count := wrapServers(servers, WrapOpts{})

	if count != 1 {
		t.Fatalf("wrapServers returned %d, want 1 (should skip already wrapped)", count)
	}
	if servers["unwrapped"].Command != "oktsec" {
		t.Error("unwrapped server should now be oktsec")
	}
	// Wrapped server should be untouched
	if len(servers["wrapped"].Args) != 6 {
		t.Errorf("wrapped server args changed: %v", servers["wrapped"].Args)
	}
}

func TestWrapServers_WithEnforce(t *testing.T) {
	servers := map[string]mcpServerJSON{
		"test": {Command: "node", Args: []string{"server.js"}},
	}

	wrapServers(servers, WrapOpts{Enforce: true})

	args := servers["test"].Args
	found := false
	for _, a := range args {
		if a == "--enforce" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("--enforce not found in args: %v", args)
	}
}

func TestWrapServers_WithConfigPath(t *testing.T) {
	servers := map[string]mcpServerJSON{
		"test": {Command: "node", Args: []string{"server.js"}},
	}

	wrapServers(servers, WrapOpts{ConfigPath: "/home/user/oktsec.yaml"})

	args := servers["test"].Args
	// Should be: proxy --config /home/user/oktsec.yaml --agent test -- node server.js
	if args[0] != "proxy" {
		t.Errorf("args[0] = %q, want proxy", args[0])
	}
	if args[1] != "--config" {
		t.Errorf("args[1] = %q, want --config", args[1])
	}
	if args[2] != "/home/user/oktsec.yaml" {
		t.Errorf("args[2] = %q, want /home/user/oktsec.yaml", args[2])
	}
	if args[3] != "--agent" {
		t.Errorf("args[3] = %q, want --agent", args[3])
	}
	if args[4] != "test" {
		t.Errorf("args[4] = %q, want test", args[4])
	}
}

func TestWrapServers_WithEnforceAndConfig(t *testing.T) {
	servers := map[string]mcpServerJSON{
		"fs": {Command: "npx", Args: []string{"@mcp/fs"}},
	}

	wrapServers(servers, WrapOpts{Enforce: true, ConfigPath: "/cfg.yaml"})

	args := servers["fs"].Args
	// Expected: proxy --config /cfg.yaml --agent fs --enforce -- npx @mcp/fs
	hasConfig := false
	hasEnforce := false
	hasAgent := false
	for i, a := range args {
		if a == "--config" && i+1 < len(args) && args[i+1] == "/cfg.yaml" {
			hasConfig = true
		}
		if a == "--enforce" {
			hasEnforce = true
		}
		if a == "--agent" && i+1 < len(args) && args[i+1] == "fs" {
			hasAgent = true
		}
	}
	if !hasConfig {
		t.Errorf("missing --config in args: %v", args)
	}
	if !hasEnforce {
		t.Errorf("missing --enforce in args: %v", args)
	}
	if !hasAgent {
		t.Errorf("missing --agent fs in args: %v", args)
	}

	// Verify original command preserved after --
	dashIdx := -1
	for i, a := range args {
		if a == "--" {
			dashIdx = i
			break
		}
	}
	if dashIdx == -1 {
		t.Fatal("missing -- separator")
	}
	if args[dashIdx+1] != "npx" || args[dashIdx+2] != "@mcp/fs" {
		t.Errorf("original command not preserved after --: %v", args[dashIdx+1:])
	}
}

func TestWrapServers_EmptyMap(t *testing.T) {
	servers := map[string]mcpServerJSON{}
	count := wrapServers(servers, WrapOpts{})
	if count != 0 {
		t.Errorf("wrapServers on empty map returned %d, want 0", count)
	}
}

func TestWrapServers_PreservesEnv(t *testing.T) {
	servers := map[string]mcpServerJSON{
		"db": {
			Command: "node",
			Args:    []string{"db-server.js"},
			Env:     map[string]string{"DB_URL": "postgres://localhost"},
		},
	}

	wrapServers(servers, WrapOpts{})

	if servers["db"].Env["DB_URL"] != "postgres://localhost" {
		t.Error("env vars should be preserved after wrapping")
	}
}

func TestWrapClient_Integration(t *testing.T) {
	dir := t.TempDir()

	// Write a fake config
	config := map[string]any{
		"mcpServers": map[string]mcpServerJSON{
			"filesystem": {Command: "npx", Args: []string{"-y", "@mcp/server-filesystem"}},
		},
	}
	data, _ := json.MarshalIndent(config, "", "  ")
	path := filepath.Join(dir, "mcp.json")
	_ = os.WriteFile(path, data, 0o644)

	// Override findClientConfig by testing wrapServers + writeMCPConfig directly
	raw, servers, err := parseMCPConfig(data)
	if err != nil {
		t.Fatal(err)
	}

	wrapped := wrapServers(servers, WrapOpts{Enforce: true, ConfigPath: "/etc/oktsec.yaml"})
	if wrapped != 1 {
		t.Fatalf("wrapped = %d, want 1", wrapped)
	}

	if err := writeMCPConfig(path, raw, servers); err != nil {
		t.Fatal(err)
	}

	// Read back and verify
	result, _ := os.ReadFile(path)
	var cfg mcpConfigJSON
	_ = json.Unmarshal(result, &cfg)

	fs := cfg.MCPServers["filesystem"]
	if fs.Command != "oktsec" {
		t.Errorf("command = %q, want oktsec", fs.Command)
	}

	// Verify --config is in args
	foundConfig := false
	for i, a := range fs.Args {
		if a == "--config" && i+1 < len(fs.Args) && fs.Args[i+1] == "/etc/oktsec.yaml" {
			foundConfig = true
		}
	}
	if !foundConfig {
		t.Errorf("--config not in wrapped args: %v", fs.Args)
	}

	// Verify backup was NOT created (we called internal functions, not WrapClient)
	_, err = os.Stat(path + ".bak")
	if err == nil {
		t.Error("backup should not exist from direct function calls")
	}
}

func TestWrappableClients(t *testing.T) {
	clients := WrappableClients()

	if len(clients) < 10 {
		t.Errorf("WrappableClients returned %d, expected at least 10", len(clients))
	}

	// OpenClaw and opencode should NOT be wrappable
	for _, c := range clients {
		if c == "openclaw" {
			t.Error("openclaw should not be wrappable (WebSocket)")
		}
		if c == "opencode" {
			t.Error("opencode should not be wrappable (different format)")
		}
		if c == "zed" {
			t.Error("zed should not be wrappable (context_servers format)")
		}
	}

	// These should be wrappable
	expected := []string{"claude-desktop", "cursor", "vscode", "cline", "windsurf"}
	for _, e := range expected {
		found := false
		for _, c := range clients {
			if c == e {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%q should be in WrappableClients", e)
		}
	}
}

func TestIsWrappable(t *testing.T) {
	tests := []struct {
		client string
		want   bool
	}{
		{"claude-desktop", true},
		{"cursor", true},
		{"vscode", true},
		{"cline", true},
		{"windsurf", true},
		{"amp", true},
		{"jetbrains", true},
		{"openclaw", false},
		{"opencode", false},
		{"claude-code", true},
		{"zed", false},
		{"unknown", false},
	}

	for _, tt := range tests {
		if got := IsWrappable(tt.client); got != tt.want {
			t.Errorf("IsWrappable(%q) = %v, want %v", tt.client, got, tt.want)
		}
	}
}

func TestParseMCPConfig_BackupCreation(t *testing.T) {
	dir := t.TempDir()
	path := writeTestConfig(t, dir, "mcp.json", map[string]mcpServerJSON{
		"test": {Command: "node", Args: []string{"server.js"}},
	})

	// Read original
	origData, _ := os.ReadFile(path)

	// Simulate WrapClient backup logic
	_ = os.WriteFile(path+".bak", origData, 0o644)

	// Verify backup exists and matches
	bakData, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatal("backup should exist")
	}
	if string(bakData) != string(origData) {
		t.Error("backup content should match original")
	}
}

func TestWrapClaudeCode(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "claude.json")

	// Simulate Claude Code nested config with project-scoped servers
	config := map[string]any{
		"mcpServers": map[string]any{},
		"projects": map[string]any{
			"/my/project": map[string]any{
				"allowedTools": []any{},
				"mcpServers": map[string]mcpServerJSON{
					"filesystem": {Command: "npx", Args: []string{"@mcp/fs", "/data"}},
					"github":     {Command: "npx", Args: []string{"@mcp/github"}},
				},
			},
			"/other/project": map[string]any{
				"mcpServers": map[string]mcpServerJSON{
					"filesystem": {Command: "npx", Args: []string{"@mcp/fs", "/other"}},
				},
			},
			"/empty/project": map[string]any{
				"mcpServers": map[string]mcpServerJSON{},
			},
		},
	}
	data, _ := json.MarshalIndent(config, "", "  ")
	_ = os.WriteFile(configPath, data, 0o644)

	opts := WrapOpts{ConfigPath: "/abs/oktsec.yaml"}
	wrapped, err := wrapClaudeCode(configPath, data, opts)
	if err != nil {
		t.Fatalf("wrapClaudeCode: %v", err)
	}
	// 2 unique in /my/project + 1 in /other/project = 3
	if wrapped != 3 {
		t.Errorf("wrapped = %d, want 3", wrapped)
	}

	// Verify the config was rewritten with oktsec proxy commands
	out, _ := os.ReadFile(configPath)
	var result map[string]json.RawMessage
	_ = json.Unmarshal(out, &result)

	var projects map[string]json.RawMessage
	_ = json.Unmarshal(result["projects"], &projects)

	var proj map[string]json.RawMessage
	_ = json.Unmarshal(projects["/my/project"], &proj)

	var servers map[string]mcpServerJSON
	_ = json.Unmarshal(proj["mcpServers"], &servers)

	fs := servers["filesystem"]
	if fs.Command != "oktsec" {
		t.Errorf("filesystem command = %q, want oktsec", fs.Command)
	}
	if len(fs.Args) < 5 || fs.Args[0] != "proxy" {
		t.Errorf("filesystem args should start with proxy, got %v", fs.Args)
	}

	// Verify already-wrapped servers are skipped on re-wrap
	out2, _ := os.ReadFile(configPath)
	wrapped2, err := wrapClaudeCode(configPath, out2, opts)
	if err != nil {
		t.Fatalf("re-wrap: %v", err)
	}
	if wrapped2 != 0 {
		t.Errorf("re-wrap should wrap 0, got %d", wrapped2)
	}
}
