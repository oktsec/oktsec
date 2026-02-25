package discover

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// MCPServer represents a discovered MCP server from a client config.
type MCPServer struct {
	Name    string            `json:"name"`
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env,omitempty"`
}

// ClientResult holds the discovered MCP servers for a single client.
type ClientResult struct {
	Client  string      `json:"client"`
	Path    string      `json:"path"`
	Servers []MCPServer `json:"servers"`
}

// Result holds the full discovery output.
type Result struct {
	Clients []ClientResult `json:"clients"`
}

// TotalServers returns the total number of MCP servers found.
func (r *Result) TotalServers() int {
	n := 0
	for _, c := range r.Clients {
		n += len(c.Servers)
	}
	return n
}

// TotalClients returns the number of clients that have at least one server.
func (r *Result) TotalClients() int {
	n := 0
	for _, c := range r.Clients {
		if len(c.Servers) > 0 {
			n++
		}
	}
	return n
}

// AllServers returns a flat list of all discovered servers with their client name.
func (r *Result) AllServers() []struct {
	Client string
	Server MCPServer
} {
	var all []struct {
		Client string
		Server MCPServer
	}
	for _, c := range r.Clients {
		for _, s := range c.Servers {
			all = append(all, struct {
				Client string
				Server MCPServer
			}{Client: c.Client, Server: s})
		}
	}
	return all
}

// Scan checks all known MCP client config paths and extracts server definitions.
func Scan() (*Result, error) {
	result := &Result{}

	for _, client := range KnownClients() {
		for _, path := range client.Paths {
			var servers []MCPServer
			var err error

			switch {
			case client.Name == "openclaw":
				cr, oerr := scanOpenClawConfig(path)
				if oerr != nil {
					continue
				}
				if len(cr.Servers) > 0 {
					result.Clients = append(result.Clients, *cr)
				}
				continue
			case client.ConfigKey == "opencode":
				servers, err = parseOpenCodeConfig(path)
			case client.ConfigKey == "claude-code":
				servers, err = parseClaudeCodeConfig(path)
			default:
				servers, err = parseConfigWithKey(path, client.ConfigKey)
			}

			if err != nil {
				continue
			}
			if len(servers) > 0 {
				result.Clients = append(result.Clients, ClientResult{
					Client:  client.Name,
					Path:    path,
					Servers: servers,
				})
			}
		}
	}

	return result, nil
}

// mcpConfigJSON represents the common structure of MCP client config files.
type mcpConfigJSON struct {
	MCPServers map[string]mcpServerJSON `json:"mcpServers"`
}

type mcpServerJSON struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env,omitempty"`
}

// parseConfigWithKey parses a config file using the specified JSON key for the server map.
// If key is empty, defaults to "mcpServers".
// For VS Code ("servers" key), also tries "mcpServers" as fallback.
func parseConfigWithKey(path, key string) ([]MCPServer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if key == "" {
		key = "mcpServers"
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	servers := extractServersFromKey(raw, key)

	// Fallback: if primary key is "servers", also try "mcpServers" (VS Code compat)
	if len(servers) == 0 && key == "servers" {
		servers = extractServersFromKey(raw, "mcpServers")
	}

	return servers, nil
}

func extractServersFromKey(raw map[string]json.RawMessage, key string) []MCPServer {
	serversRaw, ok := raw[key]
	if !ok {
		return nil
	}

	var serverMap map[string]mcpServerJSON
	if err := json.Unmarshal(serversRaw, &serverMap); err != nil {
		return nil
	}

	var servers []MCPServer
	for name, srv := range serverMap {
		servers = append(servers, MCPServer{
			Name:    name,
			Command: srv.Command,
			Args:    srv.Args,
			Env:     srv.Env,
		})
	}
	return servers
}

// parseConfigFile is kept for backward compatibility — delegates to parseConfigWithKey.
func parseConfigFile(path string) ([]MCPServer, error) {
	return parseConfigWithKey(path, "")
}

// parseOpenCodeConfig parses OpenCode's config format where servers are under "mcp"
// and commands are arrays: {"mcp": {"name": {"command": ["cmd", "arg1"], "environment": {...}}}}
func parseOpenCodeConfig(path string) ([]MCPServer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	mcpRaw, ok := raw["mcp"]
	if !ok {
		return nil, nil
	}

	var mcpMap map[string]openCodeServer
	if err := json.Unmarshal(mcpRaw, &mcpMap); err != nil {
		return nil, fmt.Errorf("parsing mcp key in %s: %w", path, err)
	}

	var servers []MCPServer
	for name, srv := range mcpMap {
		s := MCPServer{Name: name, Env: srv.Environment}
		if len(srv.Command) > 0 {
			s.Command = srv.Command[0]
			if len(srv.Command) > 1 {
				s.Args = srv.Command[1:]
			}
		}
		servers = append(servers, s)
	}
	return servers, nil
}

type openCodeServer struct {
	Command     []string          `json:"command"`
	Environment map[string]string `json:"environment"`
}

// parseClaudeCodeConfig parses Claude Code's ~/.claude.json where mcpServers
// may be nested under scope keys: {"projects": {"/path": {"mcpServers": {...}}}, "mcpServers": {...}}
func parseClaudeCodeConfig(path string) ([]MCPServer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	seen := map[string]bool{}
	var servers []MCPServer

	// Top-level mcpServers
	if topRaw, ok := raw["mcpServers"]; ok {
		servers = append(servers, extractUniqueServers(topRaw, seen)...)
	}

	// Nested under "projects" → each project scope may have mcpServers
	if projectsRaw, ok := raw["projects"]; ok {
		var projects map[string]json.RawMessage
		if json.Unmarshal(projectsRaw, &projects) == nil {
			for _, projRaw := range projects {
				var proj map[string]json.RawMessage
				if json.Unmarshal(projRaw, &proj) == nil {
					if mcpRaw, ok := proj["mcpServers"]; ok {
						servers = append(servers, extractUniqueServers(mcpRaw, seen)...)
					}
				}
			}
		}
	}

	return servers, nil
}

func extractUniqueServers(raw json.RawMessage, seen map[string]bool) []MCPServer {
	var serverMap map[string]mcpServerJSON
	if err := json.Unmarshal(raw, &serverMap); err != nil {
		return nil
	}

	var servers []MCPServer
	for name, srv := range serverMap {
		if seen[name] {
			continue
		}
		seen[name] = true
		servers = append(servers, MCPServer{
			Name:    name,
			Command: srv.Command,
			Args:    srv.Args,
			Env:     srv.Env,
		})
	}
	return servers
}

// FormatTree returns a human-readable tree of discovered MCP servers.
func FormatTree(result *Result) string {
	if len(result.Clients) == 0 {
		return "No MCP configurations found.\n\nChecked paths for: Claude Desktop, Cursor, VS Code, Cline, Windsurf, OpenClaw, " +
			"OpenCode, Zed, Amp, Gemini CLI, Copilot CLI, Amazon Q, Claude Code, Roo Code, Kilo Code, BoltAI, JetBrains"
	}

	var b strings.Builder

	fmt.Fprintf(&b, "Found %d MCP configuration(s):\n\n", result.TotalClients())

	for _, cr := range result.Clients {
		fmt.Fprintf(&b, "  %s  %s\n", clientDisplayName(cr.Client), cr.Path)
		for i, srv := range cr.Servers {
			prefix := "├──"
			if i == len(cr.Servers)-1 {
				prefix = "└──"
			}
			cmdStr := srv.Command
			if len(srv.Args) > 0 {
				cmdStr += " " + strings.Join(srv.Args, " ")
			}
			fmt.Fprintf(&b, "    %s %-20s %s\n", prefix, srv.Name, cmdStr)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "Total: %d MCP servers across %d clients\n", result.TotalServers(), result.TotalClients())
	return b.String()
}

func clientDisplayName(name string) string {
	switch name {
	case "claude-desktop":
		return "Claude Desktop"
	case "cursor":
		return "Cursor"
	case "vscode":
		return "VS Code"
	case "cline":
		return "Cline"
	case "windsurf":
		return "Windsurf"
	case "openclaw":
		return "OpenClaw"
	case "opencode":
		return "OpenCode"
	case "zed":
		return "Zed"
	case "amp":
		return "Amp"
	case "gemini-cli":
		return "Gemini CLI"
	case "copilot-cli":
		return "Copilot CLI"
	case "amazon-q":
		return "Amazon Q"
	case "claude-code":
		return "Claude Code"
	case "roo-code":
		return "Roo Code"
	case "kilo-code":
		return "Kilo Code"
	case "boltai":
		return "BoltAI"
	case "jetbrains":
		return "JetBrains"
	default:
		return name
	}
}
