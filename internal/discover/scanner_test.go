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
