package claudecode

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// rawMCPServer matches the on-disk shape Claude Code uses for an MCP
// server entry across all three sources (~/.claude.json, project
// .mcp.json, and per-project entries inside ~/.claude.json). Fields
// not modeled here are ignored — the inventory only needs enough to
// identify the server, its transport, and whether it routes through
// oktsec.
type rawMCPServer struct {
	Type      string            `json:"type,omitempty"`
	Transport string            `json:"transport,omitempty"`
	Command   string            `json:"command,omitempty"`
	Args      []string          `json:"args,omitempty"`
	URL       string            `json:"url,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
}

// rawClaudeJSON is just the slice of ~/.claude.json the inventory
// touches: the global mcpServers map and the per-project nested map.
// Everything else (history, plugin state, etc.) stays as raw JSON in
// the parent map and is ignored.
type rawClaudeJSON struct {
	MCPServers map[string]rawMCPServer            `json:"mcpServers,omitempty"`
	Projects   map[string]rawClaudeJSONProject    `json:"projects,omitempty"`
}

type rawClaudeJSONProject struct {
	MCPServers map[string]rawMCPServer `json:"mcpServers,omitempty"`
}

// rawMCPJSON matches `<project>/.mcp.json` — Claude Code's
// project-scoped MCP config.
type rawMCPJSON struct {
	MCPServers map[string]rawMCPServer `json:"mcpServers,omitempty"`
}

// readMCPServers gathers (scope, server) entries from every Claude
// Code source the spec calls out:
//
//   - ~/.claude.json::mcpServers              -> scope "user"
//   - ~/.claude.json::projects[X].mcpServers   -> scope "global" (per-project, but stored centrally)
//   - <project>/.mcp.json::mcpServers          -> scope "mcp_json"
//   - <project>/.claude/settings.json::mcpServers (if present) -> scope "project"
//
// Project / mcp_json scopes are skipped when no project directory is
// supplied, so the doctor never reports cwd-relative state by accident.
func readMCPServers(opts ReadOptions) ([]MCPServerRef, []ConnectorProblem) {
	var refs []MCPServerRef
	var problems []ConnectorProblem

	// 1) ~/.claude.json (global state file).
	globalPath := filepath.Join(opts.HomeDir, ".claude.json")
	if global, prob := readClaudeJSON(globalPath); prob != nil {
		problems = append(problems, *prob)
	} else if global != nil {
		for _, name := range sortedKeys(global.MCPServers) {
			refs = append(refs, toMCPRef(name, "user", globalPath, global.MCPServers[name]))
		}
		// Per-project entries inside ~/.claude.json. We only surface
		// the entries belonging to opts.ProjectDir so a doctor run
		// scoped to one project does not leak unrelated projects.
		if opts.ProjectDir != "" {
			if proj, ok := global.Projects[opts.ProjectDir]; ok {
				for _, name := range sortedKeys(proj.MCPServers) {
					refs = append(refs, toMCPRef(name, "global", globalPath, proj.MCPServers[name]))
				}
			}
		}
	}

	// 2) Project .mcp.json.
	if opts.ProjectDir != "" {
		mcpJSON := filepath.Join(opts.ProjectDir, ".mcp.json")
		if mp, prob := readMCPJSON(mcpJSON); prob != nil {
			problems = append(problems, *prob)
		} else if mp != nil {
			for _, name := range sortedKeys(mp.MCPServers) {
				refs = append(refs, toMCPRef(name, "mcp_json", mcpJSON, mp.MCPServers[name]))
			}
		}

		// 3) Project settings.json may also carry mcpServers (newer
		// Claude builds). Reuse readSettings for consistent error paths
		// but decode into a tiny private shape: settings.go already
		// has rawSettings without mcpServers so we re-read here.
		projSettings := filepath.Join(opts.ProjectDir, ".claude", "settings.json")
		if servers, prob := readMCPFromSettings(projSettings); prob != nil {
			problems = append(problems, *prob)
		} else {
			for _, name := range sortedKeys(servers) {
				refs = append(refs, toMCPRef(name, "project", projSettings, servers[name]))
			}
		}
	}

	sort.SliceStable(refs, func(i, j int) bool {
		if refs[i].Name != refs[j].Name {
			return refs[i].Name < refs[j].Name
		}
		return refs[i].Scope < refs[j].Scope
	})
	return refs, problems
}

func readClaudeJSON(path string) (*rawClaudeJSON, *ConnectorProblem) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, &ConnectorProblem{
			Code:     "CC-CLAUDEJSON-READ",
			Severity: "warning",
			Title:    fmt.Sprintf("Unable to read %s", path),
			Detail:   err.Error(),
		}
	}
	var raw rawClaudeJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, &ConnectorProblem{
			Code:     "CC-CLAUDEJSON-PARSE",
			Severity: "warning",
			Title:    fmt.Sprintf("Unable to parse %s", path),
			Detail:   err.Error(),
		}
	}
	return &raw, nil
}

func readMCPJSON(path string) (*rawMCPJSON, *ConnectorProblem) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, &ConnectorProblem{
			Code:     "CC-MCPJSON-READ",
			Severity: "warning",
			Title:    fmt.Sprintf("Unable to read %s", path),
			Detail:   err.Error(),
		}
	}
	var raw rawMCPJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, &ConnectorProblem{
			Code:     "CC-MCPJSON-PARSE",
			Severity: "warning",
			Title:    fmt.Sprintf("Unable to parse %s", path),
			Detail:   err.Error(),
		}
	}
	return &raw, nil
}

// readMCPFromSettings extracts the optional mcpServers map from a
// Claude project settings file. Returns (nil, nil) when the file is
// missing or has no mcpServers key.
func readMCPFromSettings(path string) (map[string]rawMCPServer, *ConnectorProblem) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, &ConnectorProblem{
			Code:     "CC-SETTINGS-READ",
			Severity: "warning",
			Title:    fmt.Sprintf("Unable to read %s", path),
			Detail:   err.Error(),
		}
	}
	var shell struct {
		MCPServers map[string]rawMCPServer `json:"mcpServers,omitempty"`
	}
	if err := json.Unmarshal(data, &shell); err != nil {
		return nil, &ConnectorProblem{
			Code:     "CC-SETTINGS-PARSE",
			Severity: "warning",
			Title:    fmt.Sprintf("Unable to parse %s", path),
			Detail:   err.Error(),
		}
	}
	return shell.MCPServers, nil
}

func toMCPRef(name, scope, source string, raw rawMCPServer) MCPServerRef {
	transport := raw.Transport
	if transport == "" {
		transport = raw.Type // some configs use "type" instead of "transport"
	}
	if transport == "" {
		switch {
		case raw.URL != "":
			transport = "http"
		case raw.Command != "":
			transport = "stdio"
		}
	}
	return MCPServerRef{
		Name:      name,
		Scope:     scope,
		Source:    source,
		Transport: transport,
		Command:   raw.Command,
		Args:      raw.Args,
		URL:       raw.URL,
		Env:       raw.Env,
		IsOktsec:  isOktsecMCPServer(raw),
	}
}

// isOktsecMCPServer flags entries that route through oktsec — either
// the gateway HTTP URL or a wrapped stdio command. Conservative:
// matches only the explicit oktsec command name and the "/mcp"
// gateway endpoint to avoid claiming arbitrary HTTP MCP servers as
// oktsec-managed.
func isOktsecMCPServer(raw rawMCPServer) bool {
	if raw.Command == "oktsec" {
		return true
	}
	if raw.URL == "" {
		return false
	}
	// Gateway URLs end in the configured endpoint_path (default "/mcp").
	// We also accept "/mcp/" and any query string. Match only when the
	// host is loopback or the URL clearly points at an oktsec gateway
	// to avoid false positives.
	lower := strings.ToLower(raw.URL)
	if !strings.Contains(lower, "/mcp") {
		return false
	}
	return strings.Contains(lower, "127.0.0.1") || strings.Contains(lower, "localhost") || strings.Contains(lower, "oktsec")
}
