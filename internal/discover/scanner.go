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
			if client.Name == "openclaw" {
				cr, err := scanOpenClawConfig(path)
				if err != nil {
					continue
				}
				if len(cr.Servers) > 0 {
					result.Clients = append(result.Clients, *cr)
				}
				continue
			}
			servers, err := parseConfigFile(path)
			if err != nil {
				continue // File doesn't exist or can't be parsed
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

func parseConfigFile(path string) ([]MCPServer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg mcpConfigJSON
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	var servers []MCPServer
	for name, srv := range cfg.MCPServers {
		servers = append(servers, MCPServer{
			Name:    name,
			Command: srv.Command,
			Args:    srv.Args,
			Env:     srv.Env,
		})
	}
	return servers, nil
}

// FormatTree returns a human-readable tree of discovered MCP servers.
func FormatTree(result *Result) string {
	if len(result.Clients) == 0 {
		return "No MCP configurations found.\n\nChecked paths for: Claude Desktop, Cursor, VS Code, Cline, Windsurf, OpenClaw"
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
	default:
		return name
	}
}
