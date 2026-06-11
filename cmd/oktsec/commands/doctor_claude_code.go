package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/connectors/claudecode"
	"github.com/spf13/cobra"
)

// newDoctorClaudeCodeCmd is the read-only Phase 1 diagnostic for the
// Claude Code connector. It walks the same files the spec lists in
// section 1 (Inventory) and reports state without touching anything.
//
// Phase 1 contract: NO --repair flag. Hook installation comes in
// Phase 2 (Hook Manifest V2). This command is safe to run on a fresh
// machine and on a configured one alike; it never mutates Claude
// state or oktsec config.
func newDoctorClaudeCodeCmd() *cobra.Command {
	var (
		jsonOut        bool
		projectDir     string
		installHooks   bool
		uninstallHooks bool
		emitHeartbeat  bool
		followSymlink  bool
		dryRun         bool
	)
	cmd := &cobra.Command{
		Use:   "claude-code",
		Short: "Inspect Claude Code connector state (read-only by default)",
		Long: `Reports what oktsec sees about the local Claude Code install:
the CLI binary, user/project settings paths, hooks installed in each
scope, MCP server entries (~/.claude.json, .mcp.json, project
settings.json), and static .claude/agents files.

The no-flag invocation is read-only and never writes to Claude state.
The optional flags --install-hooks, --uninstall-hooks, and
--emit-heartbeat write to disk or POST to the gateway, and are the
only paths in this command that mutate state. Each respects
--follow-symlink and --dry-run; install / uninstall always write a
backup before any mutation.`,
		Example: `  oktsec doctor claude-code
  oktsec doctor claude-code --json
  oktsec doctor claude-code --project /path/to/project
  oktsec doctor claude-code --install-hooks
  oktsec doctor claude-code --uninstall-hooks
  oktsec doctor claude-code --emit-heartbeat`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Mutually-exclusive guard: install / uninstall are
			// opposites and emit-heartbeat is a separate one-shot.
			modes := 0
			if installHooks {
				modes++
			}
			if uninstallHooks {
				modes++
			}
			if emitHeartbeat {
				modes++
			}
			if modes > 1 {
				return fmt.Errorf("--install-hooks, --uninstall-hooks, and --emit-heartbeat are mutually exclusive")
			}
			switch {
			case installHooks:
				return runDoctorClaudeCodeInstall(jsonOut, followSymlink, dryRun)
			case uninstallHooks:
				return runDoctorClaudeCodeUninstall(jsonOut, followSymlink, dryRun)
			case emitHeartbeat:
				return runDoctorClaudeCodeHeartbeat(jsonOut)
			}
			return runDoctorClaudeCode(jsonOut, projectDir)
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit machine-readable JSON")
	cmd.Flags().StringVar(&projectDir, "project", "", "project directory to scope project/local settings to (defaults to cwd when reading project state)")
	cmd.Flags().BoolVar(&installHooks, "install-hooks", false, "write the Phase 2 hook manifest into ~/.claude/settings.json (creates a timestamped backup first)")
	cmd.Flags().BoolVar(&uninstallHooks, "uninstall-hooks", false, "remove every oktsec hook entry from ~/.claude/settings.json (creates a timestamped backup first)")
	cmd.Flags().BoolVar(&emitHeartbeat, "emit-heartbeat", false, "post a synthetic SessionStart event to the local gateway and report round-trip latency")
	cmd.Flags().BoolVar(&followSymlink, "follow-symlink", false, "write through ~/.claude/settings.json even when it is a symlink (default: refuse)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "preview install/uninstall actions without touching disk")
	return cmd
}

func runDoctorClaudeCode(jsonOut bool, projectDir string) error {
	if projectDir == "" {
		// Default to cwd ONLY when the user passes nothing. This keeps
		// the `--json` behavior from depending on which directory the
		// shell happened to be in unless the operator opted in.
		if cwd, err := os.Getwd(); err == nil {
			projectDir = cwd
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	inv := claudecode.Read(ctx, claudecode.ReadOptions{
		ProjectDir: projectDir,
		// SkipVersionProbe defaults false — we want the version when we
		// can get it, but the 10s timeout above guards against a hung
		// CLI.
	})

	// Best-effort last-seen lookup. The audit DB may not exist yet on
	// a fresh install; that is fine — DeriveHealth handles "" as "no
	// event observed".
	lastEvent := lookupLastEvent()

	health := claudecode.DeriveHealth(inv, claudecode.HealthOptions{
		LastEvent: lastEvent,
	})

	if jsonOut {
		return emitDoctorJSON(inv, health)
	}
	emitDoctorHuman(inv, health)
	if health.Status == "disconnected" || health.Status == "not_installed" {
		return fmt.Errorf("claude code connector is %s", health.Status)
	}
	return nil
}

// lookupLastEvent opens the configured audit DB read-only and asks
// for the most recent event attributed to the "claude-code"
// principal on the hooks surface. Returns "" on any error so a
// missing or stale DB never breaks the doctor.
func lookupLastEvent() string {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return ""
	}
	dbPath := cfg.DBPath
	if dbPath == "" {
		dbPath = config.DefaultDBPath()
	}
	if _, err := os.Stat(dbPath); err != nil {
		return ""
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := audit.NewStoreReadOnly(dbPath, logger)
	if err != nil {
		return ""
	}
	defer func() { _ = store.Close() }()

	return claudecode.LookupLastEvent(store)
}

// emitDoctorJSON wraps the inventory + health together so external
// tooling (the dashboard repair flow, future Phase 5 AI assistant)
// can consume one stable shape.
func emitDoctorJSON(inv claudecode.Inventory, health claudecode.ConnectorHealth) error {
	out := struct {
		Inventory claudecode.Inventory       `json:"inventory"`
		Health    claudecode.ConnectorHealth `json:"health"`
	}{Inventory: inv, Health: health}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func emitDoctorHuman(inv claudecode.Inventory, health claudecode.ConnectorHealth) {
	bold := color.New(color.Bold).SprintFunc()
	dim := color.New(color.Faint).SprintFunc()

	fmt.Println()
	fmt.Printf("  %s\n", bold("oktsec doctor claude-code"))
	fmt.Println("  ────────────────────────────────────────")

	// Status pill mirrors the dashboard color contract: ready=green,
	// stale=yellow, partial=yellow, disconnected/not_installed=red.
	var pill string
	switch health.Status {
	case "ready":
		pill = color.GreenString(health.Status)
	case "partial", "stale":
		pill = color.YellowString(health.Status)
	default:
		pill = color.RedString(health.Status)
	}
	fmt.Printf("  Status: %s — %s\n", pill, health.Reason)
	fmt.Println()

	fmt.Printf("  %s\n", bold("Detected"))
	fmt.Printf("    CLI:           %s\n", orDash(inv.ClaudeCLIPath))
	if inv.ClaudeVersion != "" {
		fmt.Printf("    Version:       %s\n", strings.SplitN(inv.ClaudeVersion, "\n", 2)[0])
	}
	fmt.Printf("    User settings: %s %s\n", inv.UserSettingsPath, dim(existsTag(inv.UserSettingsPath)))
	fmt.Printf("    Global state:  %s %s\n", inv.GlobalStatePath, dim(existsTag(inv.GlobalStatePath)))
	if inv.CurrentProjectPath != "" {
		fmt.Printf("    Project:       %s\n", inv.CurrentProjectPath)
		fmt.Printf("    Project sett.: %s %s\n", inv.ProjectSettingsPath, dim(existsTag(inv.ProjectSettingsPath)))
		fmt.Printf("    Local sett.:   %s %s\n", inv.LocalSettingsPath, dim(existsTag(inv.LocalSettingsPath)))
	}
	fmt.Println()

	fmt.Printf("  %s (%d)\n", bold("Hooks"), len(inv.Hooks))
	if len(inv.Hooks) == 0 {
		fmt.Println("    none installed")
	}
	for _, h := range inv.Hooks {
		marker := "  "
		if h.IsOktsec {
			marker = color.GreenString("✓ ")
		}
		desc := h.Type
		if h.Command != "" {
			desc = fmt.Sprintf("%s %s", h.Type, truncate(h.Command, 60))
		} else if h.URL != "" {
			desc = fmt.Sprintf("%s %s", h.Type, h.URL)
		}
		fmt.Printf("    %s%-20s %-8s %s\n", marker, h.Event, h.Scope, desc)
	}
	if missing := health.MissingExpectedEvents; len(missing) > 0 {
		fmt.Printf("    %s %s\n", dim("missing (Phase 2 manifest):"), strings.Join(missing, ", "))
	}
	fmt.Println()

	fmt.Printf("  %s (%d)\n", bold("MCP servers"), len(inv.MCPServers))
	if len(inv.MCPServers) == 0 {
		fmt.Println("    none configured")
	}
	for _, s := range inv.MCPServers {
		marker := "  "
		if s.IsOktsec {
			marker = color.GreenString("✓ ")
		}
		ref := s.Command
		if s.URL != "" {
			ref = s.URL
		}
		fmt.Printf("    %s%-20s %-8s %-6s %s\n", marker, s.Name, s.Scope, s.Transport, truncate(ref, 60))
	}
	fmt.Println()

	fmt.Printf("  %s (%d)\n", bold("Subagents"), len(inv.Subagents))
	if len(inv.Subagents) == 0 {
		fmt.Println("    no .claude/agents/*.md files found")
	}
	for _, sa := range inv.Subagents {
		fmt.Printf("    %-24s %-8s %s\n", sa.Name, sa.Source, truncate(sa.Path, 60))
	}
	fmt.Println()

	if len(inv.Problems) > 0 {
		fmt.Printf("  %s\n", bold("Issues"))
		yellow := color.New(color.FgYellow).SprintFunc()
		for _, p := range inv.Problems {
			fmt.Printf("    %s\n", yellow(fmt.Sprintf("[%s] %s", p.Severity, p.Title)))
			if p.Detail != "" {
				fmt.Printf("        %s\n", p.Detail)
			}
		}
		fmt.Println()
	}

	if health.LastEvent != "" {
		fmt.Printf("  Last event observed: %s\n", health.LastEvent)
	} else {
		fmt.Println("  Last event observed: never (oktsec has not received Claude Code activity yet)")
	}
	fmt.Println()
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func existsTag(path string) string {
	if _, err := os.Stat(path); err == nil {
		return "(exists)"
	}
	return "(not present)"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

// runDoctorClaudeCodeInstall executes the Phase 2 installer with
// the same gateway port the running config uses. It is the only
// flag on this command (along with uninstall) that mutates Claude
// state on disk; tests cover the refusal paths.
func runDoctorClaudeCodeInstall(jsonOut, followSymlink, dryRun bool) error {
	port := resolveGatewayPort()
	exe, err := os.Executable()
	if err != nil || exe == "" {
		return fmt.Errorf("resolving oktsec binary path: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, instErr := claudecode.InstallV2(ctx, claudecode.InstallOptions{
		BinaryPath:    exe,
		GatewayPort:   port,
		FollowSymlink: followSymlink,
		DryRun:        dryRun,
	})
	if jsonOut {
		out := map[string]any{"result": res}
		if instErr != nil {
			out["error"] = instErr.Error()
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return instErr
	}
	emitInstallHuman(res, instErr)
	return instErr
}

func runDoctorClaudeCodeUninstall(jsonOut, followSymlink, dryRun bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, uninstErr := claudecode.UninstallV2(ctx, claudecode.UninstallOptions{
		FollowSymlink:   followSymlink,
		DryRun:          dryRun,
		IncludeLegacyV1: true,
	})
	if jsonOut {
		out := map[string]any{"result": res}
		if uninstErr != nil {
			out["error"] = uninstErr.Error()
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return uninstErr
	}
	emitUninstallHuman(res, uninstErr)
	return uninstErr
}

func runDoctorClaudeCodeHeartbeat(jsonOut bool) error {
	port := resolveGatewayPort()
	id, latency, err := EmitHeartbeat(port)
	if jsonOut {
		out := map[string]any{
			"event_id":     id,
			"latency_ms":   latency.Milliseconds(),
			"gateway_port": port,
		}
		if err != nil {
			out["error"] = err.Error()
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return err
	}
	if err != nil {
		fmt.Printf("  heartbeat failed: %v\n", err)
		return err
	}
	fmt.Printf("  heartbeat ok — event %s, %dms round-trip via gateway port %d\n",
		id, latency.Milliseconds(), port)
	return nil
}

// resolveGatewayPort honors the loaded config when present and
// falls back to the gateway default. Centralised so install /
// heartbeat / hook share one resolution rule.
func resolveGatewayPort() int {
	if cfg, err := config.Load(cfgFile); err == nil && cfg.Gateway.Port > 0 {
		return cfg.Gateway.Port
	}
	return 9090
}

func emitInstallHuman(res claudecode.InstallResult, err error) {
	bold := color.New(color.Bold).SprintFunc()
	fmt.Println()
	fmt.Printf("  %s\n", bold("oktsec doctor claude-code --install-hooks"))
	fmt.Println("  ────────────────────────────────────────")
	fmt.Printf("  Settings:   %s\n", res.SettingsPath)
	if res.BackupPath != "" {
		fmt.Printf("  Backup:     %s\n", res.BackupPath)
	}
	if err != nil {
		fmt.Printf("  %s %v\n", color.RedString("error:"), err)
		return
	}
	if res.Skipped != "" {
		fmt.Printf("  %s %s\n", color.YellowString("skipped:"), res.Skipped)
	}
	if res.Wrote {
		fmt.Printf("  %s %d planned hook(s) written\n", color.GreenString("ok:"), len(res.Plan))
		if res.UpgradedV1 > 0 {
			fmt.Printf("  upgraded %d legacy v1 hook(s) in place\n", res.UpgradedV1)
		}
	}
	fmt.Println()
}

func emitUninstallHuman(res claudecode.UninstallResult, err error) {
	bold := color.New(color.Bold).SprintFunc()
	fmt.Println()
	fmt.Printf("  %s\n", bold("oktsec doctor claude-code --uninstall-hooks"))
	fmt.Println("  ────────────────────────────────────────")
	fmt.Printf("  Settings:   %s\n", res.SettingsPath)
	if res.BackupPath != "" {
		fmt.Printf("  Backup:     %s\n", res.BackupPath)
	}
	if err != nil {
		fmt.Printf("  %s %v\n", color.RedString("error:"), err)
		return
	}
	if res.Skipped != "" {
		fmt.Printf("  %s %s\n", color.YellowString("skipped:"), res.Skipped)
	}
	if res.Wrote {
		fmt.Printf("  %s removed %d v2 + %d v1 hook(s)\n",
			color.GreenString("ok:"), res.RemovedV2, res.RemovedV1)
	}
	fmt.Println()
}
