package discover

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestConfig(t *testing.T, dir, filename string, servers map[string]mcpServerJSON) string {
	t.Helper()
	cfg := mcpConfigJSON{MCPServers: servers}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := writeTestConfig(t, dir, "mcp.json", map[string]mcpServerJSON{
		"filesystem": {Command: "npx", Args: []string{"-y", "@mcp/server-filesystem", "/data"}},
		"database":   {Command: "node", Args: []string{"./db-server.js"}, Env: map[string]string{"DB_URL": "postgres://localhost"}},
	})

	servers, err := parseConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 2 {
		t.Fatalf("got %d servers, want 2", len(servers))
	}

	found := map[string]bool{}
	for _, s := range servers {
		found[s.Name] = true
		if s.Name == "filesystem" {
			if s.Command != "npx" {
				t.Errorf("filesystem command = %q, want npx", s.Command)
			}
		}
		if s.Name == "database" {
			if s.Env["DB_URL"] != "postgres://localhost" {
				t.Errorf("database env = %v", s.Env)
			}
		}
	}
	if !found["filesystem"] || !found["database"] {
		t.Error("missing expected servers")
	}
}

func TestParseConfigFile_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(path, []byte("not json"), 0o644)

	_, err := parseConfigFile(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseConfigFile_NoFile(t *testing.T) {
	_, err := parseConfigFile("/nonexistent/path.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestParseConfigWithKey_ServersKey(t *testing.T) {
	dir := t.TempDir()
	// VS Code native MCP uses "servers" key
	config := map[string]any{
		"servers": map[string]mcpServerJSON{
			"my-tool": {Command: "node", Args: []string{"server.js"}},
		},
	}
	data, _ := json.MarshalIndent(config, "", "  ")
	path := filepath.Join(dir, "mcp.json")
	_ = os.WriteFile(path, data, 0o644)

	servers, err := parseConfigWithKey(path, "servers")
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("got %d servers, want 1", len(servers))
	}
	if servers[0].Name != "my-tool" {
		t.Errorf("name = %q, want my-tool", servers[0].Name)
	}
	if servers[0].Command != "node" {
		t.Errorf("command = %q, want node", servers[0].Command)
	}
}

func TestParseConfigWithKey_ServersKeyFallbackToMCPServers(t *testing.T) {
	dir := t.TempDir()
	// Config file with mcpServers but queried with "servers" key — should fallback
	config := map[string]any{
		"mcpServers": map[string]mcpServerJSON{
			"fallback-tool": {Command: "python", Args: []string{"serve.py"}},
		},
	}
	data, _ := json.MarshalIndent(config, "", "  ")
	path := filepath.Join(dir, "mcp.json")
	_ = os.WriteFile(path, data, 0o644)

	servers, err := parseConfigWithKey(path, "servers")
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("got %d servers, want 1", len(servers))
	}
	if servers[0].Name != "fallback-tool" {
		t.Errorf("name = %q, want fallback-tool", servers[0].Name)
	}
}

func TestParseConfigWithKey_EmptyKeyDefaultsToMCPServers(t *testing.T) {
	dir := t.TempDir()
	path := writeTestConfig(t, dir, "mcp.json", map[string]mcpServerJSON{
		"test-srv": {Command: "test"},
	})

	servers, err := parseConfigWithKey(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("got %d servers, want 1", len(servers))
	}
	if servers[0].Name != "test-srv" {
		t.Errorf("name = %q, want test-srv", servers[0].Name)
	}
}

func TestParseOpenCodeConfig(t *testing.T) {
	dir := t.TempDir()
	config := map[string]any{
		"mcp": map[string]any{
			"my-server": map[string]any{
				"command":     []string{"npx", "-y", "@mcp/server"},
				"environment": map[string]string{"API_KEY": "secret"},
			},
			"simple": map[string]any{
				"command": []string{"mcp-tool"},
			},
		},
	}
	data, _ := json.MarshalIndent(config, "", "  ")
	path := filepath.Join(dir, "opencode.json")
	_ = os.WriteFile(path, data, 0o644)

	servers, err := parseOpenCodeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 2 {
		t.Fatalf("got %d servers, want 2", len(servers))
	}

	found := map[string]MCPServer{}
	for _, s := range servers {
		found[s.Name] = s
	}

	srv := found["my-server"]
	if srv.Command != "npx" {
		t.Errorf("my-server command = %q, want npx", srv.Command)
	}
	if len(srv.Args) != 2 || srv.Args[0] != "-y" || srv.Args[1] != "@mcp/server" {
		t.Errorf("my-server args = %v, want [-y @mcp/server]", srv.Args)
	}
	if srv.Env["API_KEY"] != "secret" {
		t.Errorf("my-server env = %v", srv.Env)
	}

	simple := found["simple"]
	if simple.Command != "mcp-tool" {
		t.Errorf("simple command = %q, want mcp-tool", simple.Command)
	}
	if len(simple.Args) != 0 {
		t.Errorf("simple args = %v, want empty", simple.Args)
	}
}

func TestParseOpenCodeConfig_NoMCPKey(t *testing.T) {
	dir := t.TempDir()
	data := []byte(`{"theme": "dark"}`)
	path := filepath.Join(dir, "opencode.json")
	_ = os.WriteFile(path, data, 0o644)

	servers, err := parseOpenCodeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 0 {
		t.Errorf("got %d servers, want 0", len(servers))
	}
}

func TestParseClaudeCodeConfig(t *testing.T) {
	dir := t.TempDir()
	config := map[string]any{
		"mcpServers": map[string]any{
			"global-srv": map[string]any{
				"command": "npx",
				"args":    []string{"@mcp/global"},
			},
		},
		"projects": map[string]any{
			"/home/user/project-a": map[string]any{
				"mcpServers": map[string]any{
					"project-srv": map[string]any{
						"command": "node",
						"args":    []string{"local.js"},
					},
				},
			},
			"/home/user/project-b": map[string]any{
				"mcpServers": map[string]any{
					"global-srv": map[string]any{
						"command": "npx",
						"args":    []string{"@mcp/global"},
					},
					"another-srv": map[string]any{
						"command": "python",
						"args":    []string{"serve.py"},
					},
				},
			},
		},
	}
	data, _ := json.MarshalIndent(config, "", "  ")
	path := filepath.Join(dir, ".claude.json")
	_ = os.WriteFile(path, data, 0o644)

	servers, err := parseClaudeCodeConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	// Should have 3 unique servers: global-srv, project-srv, another-srv
	// global-srv appears in both top-level and project-b but should be deduped
	if len(servers) != 3 {
		t.Fatalf("got %d servers, want 3 (deduped)", len(servers))
	}

	found := map[string]bool{}
	for _, s := range servers {
		found[s.Name] = true
	}
	for _, name := range []string{"global-srv", "project-srv", "another-srv"} {
		if !found[name] {
			t.Errorf("missing server %q", name)
		}
	}
}

func TestParseClaudeCodeConfig_TopLevelOnly(t *testing.T) {
	dir := t.TempDir()
	config := map[string]any{
		"mcpServers": map[string]any{
			"only-srv": map[string]any{
				"command": "echo",
			},
		},
	}
	data, _ := json.MarshalIndent(config, "", "  ")
	path := filepath.Join(dir, ".claude.json")
	_ = os.WriteFile(path, data, 0o644)

	servers, err := parseClaudeCodeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("got %d servers, want 1", len(servers))
	}
	if servers[0].Name != "only-srv" {
		t.Errorf("name = %q, want only-srv", servers[0].Name)
	}
}

func TestParseClaudeCodeConfig_NoServers(t *testing.T) {
	dir := t.TempDir()
	data := []byte(`{"theme": "dark"}`)
	path := filepath.Join(dir, ".claude.json")
	_ = os.WriteFile(path, data, 0o644)

	servers, err := parseClaudeCodeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 0 {
		t.Errorf("got %d servers, want 0", len(servers))
	}
}

func TestKnownClients_Count(t *testing.T) {
	clients := KnownClients()
	// 6 original + 11 new = 17
	if len(clients) != 17 {
		t.Errorf("got %d clients, want 17", len(clients))
	}

	names := map[string]bool{}
	for _, c := range clients {
		if names[c.Name] {
			t.Errorf("duplicate client name: %s", c.Name)
		}
		names[c.Name] = true
	}
}

func TestFormatTree(t *testing.T) {
	result := &Result{
		Clients: []ClientResult{
			{
				Client: "cursor",
				Path:   "/home/user/.cursor/mcp.json",
				Servers: []MCPServer{
					{Name: "filesystem", Command: "npx", Args: []string{"@mcp/server-filesystem"}},
					{Name: "database", Command: "node", Args: []string{"./db.js"}},
				},
			},
		},
	}

	output := FormatTree(result)

	if !strings.Contains(output, "Cursor") {
		t.Error("should contain client display name")
	}
	if !strings.Contains(output, "filesystem") {
		t.Error("should contain server name")
	}
	if !strings.Contains(output, "2 MCP servers") {
		t.Error("should contain total count")
	}
}

func TestFormatTree_Empty(t *testing.T) {
	result := &Result{}
	output := FormatTree(result)
	if !strings.Contains(output, "No MCP configurations found") {
		t.Error("empty result should show 'no configs found'")
	}
	// Verify new clients are listed
	for _, name := range []string{"OpenCode", "Zed", "Amp", "Gemini CLI", "Claude Code", "BoltAI", "JetBrains"} {
		if !strings.Contains(output, name) {
			t.Errorf("empty message should list %s", name)
		}
	}
}

func TestResult_TotalServers(t *testing.T) {
	result := &Result{
		Clients: []ClientResult{
			{Servers: []MCPServer{{Name: "a"}, {Name: "b"}}},
			{Servers: []MCPServer{{Name: "c"}}},
		},
	}
	if got := result.TotalServers(); got != 3 {
		t.Errorf("TotalServers() = %d, want 3", got)
	}
}

func TestWrapUnwrap(t *testing.T) {
	dir := t.TempDir()
	path := writeTestConfig(t, dir, "mcp.json", map[string]mcpServerJSON{
		"filesystem": {Command: "npx", Args: []string{"-y", "@mcp/server-filesystem"}},
		"database":   {Command: "node", Args: []string{"./db.js"}},
	})

	// Read original
	origData, _ := os.ReadFile(path)

	// Wrap
	data, _ := os.ReadFile(path)
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(data, &raw)

	var servers map[string]mcpServerJSON
	_ = json.Unmarshal(raw["mcpServers"], &servers)

	for name, srv := range servers {
		newArgs := []string{"proxy", "--agent", name, "--"}
		newArgs = append(newArgs, srv.Command)
		newArgs = append(newArgs, srv.Args...)
		srv.Command = "oktsec"
		srv.Args = newArgs
		servers[name] = srv
	}

	serversJSON, _ := json.MarshalIndent(servers, "  ", "  ")
	raw["mcpServers"] = serversJSON
	out, _ := json.MarshalIndent(raw, "", "  ")
	_ = os.WriteFile(path, append(out, '\n'), 0o644)

	// Verify wrapped
	wrappedData, _ := os.ReadFile(path)
	var wrappedCfg mcpConfigJSON
	_ = json.Unmarshal(wrappedData, &wrappedCfg)

	fsSrv := wrappedCfg.MCPServers["filesystem"]
	if fsSrv.Command != "oktsec" {
		t.Errorf("wrapped command = %q, want oktsec", fsSrv.Command)
	}
	if fsSrv.Args[0] != "proxy" || fsSrv.Args[2] != "filesystem" {
		t.Errorf("wrapped args = %v", fsSrv.Args)
	}

	// Unwrap (restore original)
	_ = os.WriteFile(path, origData, 0o644)
	restoredData, _ := os.ReadFile(path)

	var restoredCfg mcpConfigJSON
	_ = json.Unmarshal(restoredData, &restoredCfg)

	fsSrv = restoredCfg.MCPServers["filesystem"]
	if fsSrv.Command != "npx" {
		t.Errorf("unwrapped command = %q, want npx", fsSrv.Command)
	}
}

func TestClientDisplayName_AllClients(t *testing.T) {
	expected := map[string]string{
		"claude-desktop": "Claude Desktop",
		"cursor":         "Cursor",
		"vscode":         "VS Code",
		"cline":          "Cline",
		"windsurf":       "Windsurf",
		"openclaw":       "OpenClaw",
		"opencode":       "OpenCode",
		"zed":            "Zed",
		"amp":            "Amp",
		"gemini-cli":     "Gemini CLI",
		"copilot-cli":    "Copilot CLI",
		"amazon-q":       "Amazon Q",
		"claude-code":    "Claude Code",
		"roo-code":       "Roo Code",
		"kilo-code":      "Kilo Code",
		"boltai":         "BoltAI",
		"jetbrains":      "JetBrains",
	}
	for name, want := range expected {
		if got := clientDisplayName(name); got != want {
			t.Errorf("clientDisplayName(%q) = %q, want %q", name, got, want)
		}
	}
}
