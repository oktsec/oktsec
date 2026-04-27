package claudecode

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// agentFrontmatter is the YAML block at the top of a .claude/agents/*.md
// file. Field set follows the public docs at
// code.claude.com/docs/en/sub-agents and only includes what the
// inventory needs to display; extra YAML keys are ignored so future
// Claude additions do not break parsing.
type agentFrontmatter struct {
	Name            string   `yaml:"name,omitempty"`
	Description     string   `yaml:"description,omitempty"`
	Tools           []string `yaml:"tools,omitempty"`
	DisallowedTools []string `yaml:"disallowedTools,omitempty"`
	MCPServers      []string `yaml:"mcpServers,omitempty"`
	PermissionMode  string   `yaml:"permissionMode,omitempty"`
	Hooks           any      `yaml:"hooks,omitempty"` // any: presence-only, we do not introspect
}

// readSubagents walks the user and project agents directories and
// emits one SubagentRef per .md file. Subagents declared at runtime
// via `claude --agents` are NOT visible from disk; Phase 3 will pick
// those up from SubagentStart hook events.
func readSubagents(opts ReadOptions) ([]SubagentRef, []ConnectorProblem) {
	var refs []SubagentRef
	var problems []ConnectorProblem

	dirs := []struct {
		source string
		path   string
	}{
		{"user", filepath.Join(opts.HomeDir, ".claude", "agents")},
	}
	if opts.ProjectDir != "" {
		dirs = append(dirs, struct {
			source string
			path   string
		}{"project", filepath.Join(opts.ProjectDir, ".claude", "agents")})
	}

	for _, d := range dirs {
		entries, err := os.ReadDir(d.path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			problems = append(problems, ConnectorProblem{
				Code:     "CC-AGENTS-READ",
				Severity: "warning",
				Title:    fmt.Sprintf("Unable to read agents directory %s", d.path),
				Detail:   err.Error(),
			})
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
				continue
			}
			full := filepath.Join(d.path, e.Name())
			ref, prob := parseSubagentFile(d.source, full)
			if prob != nil {
				problems = append(problems, *prob)
			}
			if ref != nil {
				refs = append(refs, *ref)
			}
		}
	}
	sort.SliceStable(refs, func(i, j int) bool {
		if refs[i].Name != refs[j].Name {
			return refs[i].Name < refs[j].Name
		}
		return refs[i].Source < refs[j].Source
	})
	return refs, problems
}

// parseSubagentFile reads one agent markdown and returns the SubagentRef.
// The file format is YAML frontmatter (between two `---` lines) followed
// by free-form prose; only the frontmatter is parsed.
func parseSubagentFile(source, path string) (*SubagentRef, *ConnectorProblem) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &ConnectorProblem{
			Code:     "CC-AGENT-READ",
			Severity: "warning",
			Title:    fmt.Sprintf("Unable to read agent %s", path),
			Detail:   err.Error(),
		}
	}
	front, err := extractFrontmatter(data)
	if err != nil {
		return nil, &ConnectorProblem{
			Code:     "CC-AGENT-PARSE",
			Severity: "warning",
			Title:    fmt.Sprintf("Unable to parse agent %s", path),
			Detail:   err.Error(),
		}
	}
	name := front.Name
	if name == "" {
		// Fall back to the file basename so an agent without a name
		// field still appears in the inventory.
		name = strings.TrimSuffix(filepath.Base(path), ".md")
	}
	return &SubagentRef{
		Name:            name,
		Source:          source,
		Path:            path,
		Tools:           front.Tools,
		DisallowedTools: front.DisallowedTools,
		MCPServers:      front.MCPServers,
		PermissionMode:  front.PermissionMode,
		HooksPresent:    front.Hooks != nil,
	}, nil
}

// extractFrontmatter pulls the YAML block delimited by `---` lines at
// the top of an agent markdown file. Returns an empty agentFrontmatter
// when there is no frontmatter (so the inventory still surfaces the
// file by name) and only errors on a malformed YAML block.
func extractFrontmatter(data []byte) (agentFrontmatter, error) {
	text := string(data)
	if !strings.HasPrefix(strings.TrimLeft(text, " \t\r\n"), "---") {
		return agentFrontmatter{}, nil
	}
	// Drop leading whitespace before the first delimiter.
	text = strings.TrimLeft(text, " \t\r\n")
	rest := text[3:] // skip the opening "---"
	// Skip the newline that follows "---" if present.
	rest = strings.TrimPrefix(rest, "\r\n")
	rest = strings.TrimPrefix(rest, "\n")
	end := strings.Index(rest, "\n---")
	if end < 0 {
		return agentFrontmatter{}, nil
	}
	yamlBlock := rest[:end]
	var front agentFrontmatter
	if err := yaml.Unmarshal([]byte(yamlBlock), &front); err != nil {
		return agentFrontmatter{}, err
	}
	return front, nil
}
