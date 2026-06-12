// Package claudecode is the read-only Claude Code connector inventory
// used by `oktsec doctor claude-code` and the dashboard health endpoint.
//
// Phase 1 contract (see documentation/engineering/specs/2026-04-27-
// claude-code-detection-posture-evidence-spec.md, Execution Decision):
// this package never writes to ~/.claude.json, ~/.claude/settings.json,
// project .claude/, or any other Claude state. Hook installation and
// repair belong to Phase 2 (Hook Manifest V2). The job here is to look
// at what is on disk, report it accurately, and let the operator decide
// what to fix.
//
// The package is layered so a future repair PR can plug in writers
// without touching the readers:
//
//	settings.go  -- parse user/project Claude settings JSON
//	agents.go    -- parse .claude/agents/*.md frontmatter
//	hooks.go     -- extract HookRef rows from settings (read-only)
//	mcp.go       -- parse mcpServers from ~/.claude.json + .mcp.json
//	health.go    -- derive ConnectorHealth from inventory + audit signal
package claudecode

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Inventory is the read-only snapshot of one Claude Code install on
// this machine, scoped to one project. Every field reports what was
// found on disk; nothing in this struct is a policy decision.
type Inventory struct {
	// Detected is true when the Claude CLI was found on PATH OR a
	// Claude state file (~/.claude.json or ~/.claude/settings.json)
	// exists. Either signal is enough to say "the user has used Claude
	// Code on this machine".
	Detected bool `json:"detected"`

	// ClaudeCLIPath is the absolute path to the `claude` binary, or
	// "" when not on PATH.
	ClaudeCLIPath string `json:"claude_cli_path,omitempty"`

	// ClaudeVersion is the captured `claude --version` output (best
	// effort). Empty when the CLI is not on PATH or the call failed.
	ClaudeVersion string `json:"claude_version,omitempty"`

	// UserSettingsPath / ProjectSettingsPath / LocalSettingsPath are
	// the paths the inventory inspected. They are reported even when
	// the file does not exist so the operator can see exactly which
	// path was checked.
	UserSettingsPath    string `json:"user_settings_path"`
	ProjectSettingsPath string `json:"project_settings_path,omitempty"`
	LocalSettingsPath   string `json:"local_settings_path,omitempty"`

	// GlobalStatePath is ~/.claude.json. Reported even when missing.
	GlobalStatePath string `json:"global_state_path"`

	// CurrentProjectPath is the project the inventory used as the
	// project-scope source. Empty when no project was supplied.
	CurrentProjectPath string `json:"current_project_path,omitempty"`

	// MCPServers lists every (scope, server) pair the inventory found
	// across user, project, .mcp.json, and the per-project entries
	// inside ~/.claude.json. Order is deterministic for stable output.
	MCPServers []MCPServerRef `json:"mcp_servers"`

	// Subagents are the static .claude/agents/*.md files reachable from
	// user and project scope. Subagents created at runtime via
	// `claude --agents` are NOT listed here; Phase 3 will add
	// `cli-observed` actors from hook events.
	Subagents []SubagentRef `json:"subagents"`

	// Hooks lists every hook entry the inventory found in the user and
	// project settings files. Plugin / managed / agent-frontmatter
	// hooks are not parsed in Phase 1 because they require resolving
	// plugin metadata; the spec marks that as a Phase 2 follow-up.
	Hooks []HookRef `json:"hooks"`

	// Problems are operator-actionable issues the inventory noticed
	// while reading. Severity is informational here; the doctor /
	// dashboard layer decides what to do with each one.
	Problems []ConnectorProblem `json:"problems"`
}

// MCPServerRef is one Claude Code MCP server entry.
type MCPServerRef struct {
	Name      string            `json:"name"`
	Scope     string            `json:"scope"`               // user | project | local | mcp_json | global
	Source    string            `json:"source"`              // path to the file the entry came from
	Transport string            `json:"transport,omitempty"` // stdio | http (when known)
	Command   string            `json:"command,omitempty"`
	Args      []string          `json:"args,omitempty"`
	URL       string            `json:"url,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	IsOktsec  bool              `json:"is_oktsec,omitempty"` // true when the entry routes through oktsec
}

// HookRef is one hook entry as it appears on disk. The fields capture
// just enough for the doctor to say "this hook would run X for event Y
// in scope Z" without taking any action.
type HookRef struct {
	Scope       string `json:"scope"`             // user | project | local
	Path        string `json:"path"`              // settings file the entry came from
	Event       string `json:"event"`             // PreToolUse, PostToolUse, SessionStart, etc.
	Matcher     string `json:"matcher,omitempty"` // tool-name matcher (regex/glob)
	Type        string `json:"type"`              // command | http | mcp_tool | prompt | agent
	Command     string `json:"command,omitempty"`
	URL         string `json:"url,omitempty"`
	IsOktsec    bool   `json:"is_oktsec"`    // command points at the `oktsec hook` subcommand
	Expected    bool   `json:"expected"`     // event family Phase 2 will install (informational)
	BlockingCap bool   `json:"blocking_cap"` // event family can deny the action (PreToolUse, etc.)
}

// SubagentRef is one .claude/agents/*.md file.
type SubagentRef struct {
	Name            string   `json:"name"`
	Source          string   `json:"source"` // user | project
	Path            string   `json:"path"`
	Tools           []string `json:"tools,omitempty"`
	DisallowedTools []string `json:"disallowed_tools,omitempty"`
	MCPServers      []string `json:"mcp_servers,omitempty"`
	PermissionMode  string   `json:"permission_mode,omitempty"`
	HooksPresent    bool     `json:"hooks_present"`
}

// ConnectorProblem is one issue the inventory wants the operator (or
// the doctor formatter) to know about. Severity controls how the
// dashboard groups it; FixKind is a hint for Phase 5 (AI Fix
// Assistant) about whether automation is safe.
type ConnectorProblem struct {
	Code     string `json:"code"`
	Severity string `json:"severity"` // setup | warning | risk
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
	FixKind  string `json:"fix_kind,omitempty"` // auto | guided | manual
	// FixCommand is a copy-paste snippet a future repair flow can run.
	// Phase 1 only fills it for setup/install nudges; never destructive.
	FixCommand []string `json:"fix_command,omitempty"`
}

// ReadOptions controls which paths the inventory inspects.
//
// HomeDir defaults to os.UserHomeDir; ProjectDir defaults to "" (no
// project scope). Tests inject both so they can use t.TempDir without
// touching the user's real Claude state. ClaudeBinary lets a test
// stub the version probe.
type ReadOptions struct {
	HomeDir      string
	ProjectDir   string
	ClaudeBinary string // override `claude` binary path; "" means PATH lookup
	// SkipVersionProbe avoids running `claude --version` even when the
	// binary is found. The doctor sets this in --json mode so the
	// command stays purely read-only on the filesystem.
	SkipVersionProbe bool
}

// Read inspects on-disk Claude Code state and returns an Inventory.
// It never writes to any Claude file. Errors during one reader (e.g.
// a malformed settings.json) are recorded as Problems on the returned
// Inventory rather than aborting the whole scan, so the doctor can
// still report partial state.
func Read(ctx context.Context, opts ReadOptions) Inventory {
	if opts.HomeDir == "" {
		if h, err := os.UserHomeDir(); err == nil {
			opts.HomeDir = h
		}
	}

	inv := Inventory{
		UserSettingsPath: filepath.Join(opts.HomeDir, ".claude", "settings.json"),
		GlobalStatePath:  filepath.Join(opts.HomeDir, ".claude.json"),
	}
	if opts.ProjectDir != "" {
		inv.CurrentProjectPath = opts.ProjectDir
		inv.ProjectSettingsPath = filepath.Join(opts.ProjectDir, ".claude", "settings.json")
		inv.LocalSettingsPath = filepath.Join(opts.ProjectDir, ".claude", "settings.local.json")
	}

	// Detect Claude CLI. PATH lookup honors ClaudeBinary override so
	// tests can fake an installed CLI without modifying $PATH.
	if opts.ClaudeBinary != "" {
		if _, err := os.Stat(opts.ClaudeBinary); err == nil {
			inv.ClaudeCLIPath = opts.ClaudeBinary
		}
	} else if path, err := exec.LookPath("claude"); err == nil {
		inv.ClaudeCLIPath = path
	}
	if inv.ClaudeCLIPath != "" && !opts.SkipVersionProbe {
		// Best-effort version probe. We bound execution with the
		// caller's context so a hung CLI cannot stall the doctor.
		out, err := runClaudeVersion(ctx, inv.ClaudeCLIPath)
		if err == nil {
			inv.ClaudeVersion = strings.TrimSpace(out)
		}
	}

	// Detect any signal that Claude has been used here. Either a CLI
	// on PATH or a state file is enough.
	if inv.ClaudeCLIPath != "" || pathExists(inv.UserSettingsPath) || pathExists(inv.GlobalStatePath) {
		inv.Detected = true
	}

	// Settings, hooks, MCP, agents — each reader returns its own
	// Problems entries instead of returning errors, so a single bad
	// file never silences the rest of the scan.
	hooks, settingsProblems := readHooks(opts)
	inv.Hooks = hooks
	inv.Problems = append(inv.Problems, settingsProblems...)

	servers, mcpProblems := readMCPServers(opts)
	inv.MCPServers = servers
	inv.Problems = append(inv.Problems, mcpProblems...)

	subagents, agentProblems := readSubagents(opts)
	inv.Subagents = subagents
	inv.Problems = append(inv.Problems, agentProblems...)

	// Cross-cutting hint: if Claude is detected but no oktsec hook is
	// installed yet, surface that as a setup nudge. Phase 2 will fix
	// it; Phase 1 just reports.
	if inv.Detected && !hasOktsecHook(inv.Hooks) {
		inv.Problems = append(inv.Problems, ConnectorProblem{
			Code:     "CC-HOOKS-MISSING",
			Severity: "setup",
			Title:    "No oktsec hook installed in Claude Code",
			Detail:   "Phase 2 (Hook Manifest V2) will install pre/post-tool hooks; until then no Claude Code activity reaches the gateway via hooks.",
			FixKind:  "guided",
		})
	}

	return inv
}

// runClaudeVersion is a seam tests can override (see test file). It
// uses exec.CommandContext so the doctor can cancel a hung probe.
var runClaudeVersion = func(ctx context.Context, binary string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	//nolint:gosec // binary path is resolved by exec.LookPath / explicit user override
	out, err := exec.CommandContext(ctx, binary, "--version").Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return string(ee.Stderr), err
		}
		return "", err
	}
	return string(out), nil
}

func pathExists(p string) bool {
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

func hasOktsecHook(hooks []HookRef) bool {
	for _, h := range hooks {
		if h.IsOktsec {
			return true
		}
	}
	return false
}
