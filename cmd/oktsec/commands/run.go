package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/fatih/color"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/dashboard"
	"github.com/oktsec/oktsec/internal/discover"
	"github.com/oktsec/oktsec/internal/gateway"
	"github.com/oktsec/oktsec/internal/hooks"
	"github.com/oktsec/oktsec/internal/identity"
	"github.com/oktsec/oktsec/internal/observability"
	"github.com/oktsec/oktsec/internal/proxy"
	"github.com/oktsec/oktsec/internal/telemetry"
	"github.com/oktsec/oktsec/internal/tui"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

type runOpts struct {
	port      int
	bind      string
	enforce   bool
	skipWrap  bool
	noBrowser bool
}

func newRunCmd() *cobra.Command {
	var opts runOpts

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Setup and start oktsec in one step",
		Long: `Discovers MCP servers, generates config, and starts the proxy server.

If no config file exists, runs first-time setup automatically:
  1. Scans for MCP clients and servers on this machine
  2. Generates config with observe-mode defaults
  3. Generates Ed25519 keypairs for each discovered agent
  4. Wraps discovered MCP servers through oktsec proxy
  5. Starts the proxy server with dashboard

If a config already exists, starts the server directly.

Config is resolved in order: --config flag, $OKTSEC_CONFIG env var,
./oktsec.yaml (local), ~/.oktsec/config.yaml (home).

Telemetry: oktsec sends a single anonymous ping per version to count
installations. No user data is collected. Opt out with OKTSEC_NO_TELEMETRY=1
or create ~/.oktsec/.no-telemetry. Details: https://oktsec.com/telemetry`,
		Example: `  oktsec run
  oktsec run --port 9000
  oktsec run --enforce
  oktsec run --skip-wrap`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return executeRun(opts)
		},
	}

	cmd.Flags().IntVar(&opts.port, "port", 0, "override server port")
	cmd.Flags().StringVar(&opts.bind, "bind", "", "address to bind (default: 127.0.0.1)")
	cmd.Flags().BoolVar(&opts.enforce, "enforce", false, "start in enforcement mode (block malicious requests)")
	cmd.Flags().BoolVar(&opts.skipWrap, "skip-wrap", false, "generate config only, don't modify MCP client configs")
	cmd.Flags().BoolVar(&opts.noBrowser, "no-browser", false, "don't open dashboard in browser")
	return cmd
}

func executeRun(opts runOpts) error {
	configPath := cfgFile

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		bold := color.New(color.Bold).SprintFunc()
		fmt.Println()
		fmt.Printf("  %s\n", bold("oktsec — first-time setup"))
		fmt.Println("  ────────────────────────────────────────")
		fmt.Println()

		if err := autoSetup(configPath, opts); err != nil {
			return fmt.Errorf("setup failed: %w", err)
		}
	}

	return startServer(configPath, opts)
}

func autoSetup(configPath string, opts runOpts) error {
	// Ensure parent directory exists (e.g. ~/.oktsec/)
	if dir := filepath.Dir(configPath); dir != "." {
		_ = os.MkdirAll(dir, 0o700)
	}

	// Step 1: Discover
	fmt.Printf("  %s\n", color.New(color.Bold).Sprint("Scanning for MCP servers..."))
	result, err := discover.Scan()
	if err != nil {
		return err
	}

	if result.TotalServers() == 0 {
		fmt.Println("  No MCP servers found.")
		fmt.Println()
		fmt.Println("  Starting with empty config (0 agents).")
		fmt.Println("  Add agents via the dashboard after startup.")
		fmt.Println()
		if err := writeMinimalConfig(configPath); err != nil {
			return err
		}
		return ensureSecrets(configPath)
	}

	fmt.Printf("  Found %s across %d client(s):\n\n", color.GreenString("%d server(s)", result.TotalServers()), result.TotalClients())
	for _, cr := range result.Clients {
		if len(cr.Servers) == 0 {
			continue
		}
		names := make([]string, len(cr.Servers))
		for i, s := range cr.Servers {
			names[i] = s.Name
		}
		fmt.Printf("    %-16s  %s\n", discover.ClientDisplayName(cr.Client), strings.Join(names, ", "))
	}
	fmt.Println()

	// Step 2: Generate config + keypairs
	keysDir := config.DefaultKeysDir()
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return fmt.Errorf("creating keys directory: %w", err)
	}

	type agentYAML struct {
		CanMessage []string `yaml:"can_message,flow"`
		Source     string   `yaml:"source"`
		RiskLevel  string   `yaml:"risk_level"`
	}

	agents := make(map[string]agentYAML)
	for _, entry := range result.AllServers() {
		name := entry.Server.Name
		risk := assessRisk(entry.Server)
		agents[name] = agentYAML{
			CanMessage: []string{"*"},
			Source:     entry.Client,
			RiskLevel:  risk,
		}

		kp, err := identity.GenerateKeypair(name)
		if err != nil {
			return fmt.Errorf("generating keypair for %s: %w", name, err)
		}
		if err := kp.Save(keysDir); err != nil {
			return fmt.Errorf("saving keypair for %s: %w", name, err)
		}
	}

	absConfig, err := filepath.Abs(configPath)
	if err != nil {
		absConfig = configPath
	}

	dbPath := config.DefaultDBPath()

	port := 8080
	if opts.port != 0 {
		port = opts.port
	}

	// Build mcp_servers from discovered servers (deduplicated by name).
	// The gateway will front these backends so all tool calls go through the pipeline.
	mcpServers := make(map[string]any)
	seen := make(map[string]bool)
	for _, entry := range result.AllServers() {
		name := entry.Server.Name
		if seen[name] {
			continue
		}
		seen[name] = true
		srv := map[string]any{
			"transport": "stdio",
			"command":   entry.Server.Command,
			"args":      entry.Server.Args,
		}
		if len(entry.Server.Env) > 0 {
			srv["env"] = entry.Server.Env
		}
		mcpServers[name] = srv
	}

	cfgMap := map[string]any{
		"version": "1",
		"server": map[string]any{
			"port":      port,
			"log_level": "info",
		},
		"identity": map[string]any{
			"keys_dir":          keysDir,
			"require_signature": false,
		},
		"db_path": dbPath,
		"agents":  agents,
		"rules":   []map[string]any{},
		"gateway": map[string]any{
			"enabled":       true,
			"port":          9090,
			"endpoint_path": "/mcp",
		},
		"mcp_servers": mcpServers,
		"quarantine": map[string]any{
			"enabled":        true,
			"expiry_hours":   24,
			"retention_days": 90,
		},
		"rate_limit": map[string]any{
			"per_agent": 100,
			"window":    60,
		},
		"anomaly": map[string]any{
			"risk_threshold": 80,
			"check_interval": 60,
			"min_messages":   10,
		},
		"forward_proxy": map[string]any{
			"enabled":        true,
			"scan_requests":  true,
			"scan_responses": false,
		},
	}

	data, err := yaml.Marshal(cfgMap)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	header := "# Generated by oktsec run\n# Mode: observe (audit-only, no blocking)\n"
	if err := os.WriteFile(configPath, append([]byte(header), data...), 0o600); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	fmt.Println("  Generated:")
	fmt.Printf("    Config:   %s\n", absConfig)
	fmt.Printf("    Keys:     %s/\n", keysDir)
	fmt.Printf("    Audit DB: %s\n", dbPath)
	fmt.Println()

	// Step 3: Generate secrets (.env)
	if err := ensureSecrets(configPath); err != nil {
		return err
	}

	// Step 4: Connect clients
	if !opts.skipWrap {
		fmt.Println("  Connecting MCP clients...")

		totalConnected := 0

		// Claude Code: register gateway via HTTP MCP transport (preferred over wrapping)
		if hasClaudeCLI() {
			if err := autoConnectClaudeCode(9090, "/mcp"); err != nil {
				fmt.Printf("    %-16s  error: %s\n", "Claude Code", err)
			} else {
				fmt.Printf("    %-16s  connected via gateway\n", "Claude Code")
				totalConnected++
			}
		}

		// Other clients: wrap stdio servers through oktsec proxy
		wrapOpts := discover.WrapOpts{
			Enforce:    opts.enforce,
			ConfigPath: absConfig,
		}
		for _, cr := range result.Clients {
			// Skip claude-code (handled above via gateway)
			if cr.Client == "claude-code" || !discover.IsWrappable(cr.Client) || len(cr.Servers) == 0 {
				continue
			}
			wrapped, err := discover.WrapClient(cr.Client, wrapOpts)
			name := discover.ClientDisplayName(cr.Client)
			if err != nil {
				fmt.Printf("    %-16s  error: %s\n", name, err)
				continue
			}
			if wrapped > 0 {
				fmt.Printf("    %-16s  %d server(s) wrapped\n", name, wrapped)
				totalConnected += wrapped
			}
		}

		if totalConnected > 0 {
			fmt.Printf("\n    %d client(s) now routing through oktsec.\n", totalConnected)
		}
		fmt.Println()
	}

	fmt.Println("  " + color.GreenString("Setup complete.") + " Starting server...")
	fmt.Println()
	return nil
}


// hasClaudeCLI checks if the `claude` CLI is available on the system.
func hasClaudeCLI() bool {
	_, err := exec.LookPath("claude")
	return err == nil
}

// autoConnectClaudeCode registers the oktsec gateway as an HTTP MCP server in Claude Code
// and configures hooks to capture all tool-call telemetry.
func autoConnectClaudeCode(port int, endpoint string) error {
	url := fmt.Sprintf("http://127.0.0.1:%d%s", port, endpoint)

	//nolint:gosec // args are not user-controlled
	out, err := exec.Command(
		"claude", "mcp", "add",
		"--transport", "http",
		"--header", "X-Oktsec-Agent: claude-code",
		"--scope", "user",
		"oktsec-gateway", url,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("claude mcp add: %w\n%s", err, string(out))
	}

	// Configure hooks to capture all tool-call telemetry.
	if err := configureClaudeCodeHooks(port); err != nil {
		// Non-fatal: gateway still works without hooks.
		fmt.Printf("    %-16s  hooks: %s\n", "", err)
	}

	return nil
}

// configureClaudeCodeHooks writes PreToolUse/PostToolUse hooks to Claude Code's
// user settings so all tool calls are forwarded to the oktsec gateway.
func configureClaudeCodeHooks(gatewayPort int) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	settingsPath := filepath.Join(home, ".claude", "settings.json")

	// Read existing settings (or start fresh).
	var settings map[string]any
	if data, err := os.ReadFile(settingsPath); err == nil {
		_ = json.Unmarshal(data, &settings)
	}
	if settings == nil {
		settings = make(map[string]any)
	}

	// Use a command hook instead of HTTP so that if oktsec is not running,
	// the hook exits silently with code 0 — no error shown to the user.
	exe, _ := os.Executable()
	if exe == "" {
		exe = "oktsec" // fallback to PATH lookup
	}

	hookEntry := []any{
		map[string]any{
			"matcher": ".*",
			"hooks": []any{
				map[string]any{
					"type":    "command",
					"command": fmt.Sprintf("%s hook --port %d", exe, gatewayPort),
				},
			},
		},
	}

	hooksMap, _ := settings["hooks"].(map[string]any)
	if hooksMap == nil {
		hooksMap = make(map[string]any)
	}
	hooksMap["PreToolUse"] = hookEntry
	hooksMap["PostToolUse"] = hookEntry
	settings["hooks"] = hooksMap

	// Ensure directory exists.
	_ = os.MkdirAll(filepath.Dir(settingsPath), 0o700)

	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(settingsPath, append(data, '\n'), 0o600)
}

// ensureSecrets creates the .env file with auto-generated secrets if it doesn't exist.
func ensureSecrets(configPath string) error {
	envPath := filepath.Join(filepath.Dir(configPath), ".env")
	if err := config.EnsureEnvFile(envPath); err != nil {
		return fmt.Errorf("creating secrets file: %w", err)
	}
	return nil
}

func writeMinimalConfig(configPath string) error {
	dbPath := config.DefaultDBPath()
	keysDir := config.DefaultKeysDir()
	cfgMap := map[string]any{
		"version": "1",
		"server": map[string]any{
			"port":      8080,
			"log_level": "info",
		},
		"identity": map[string]any{
			"keys_dir":          keysDir,
			"require_signature": false,
		},
		"db_path": dbPath,
		"agents": map[string]any{},
		"rules":  []map[string]any{},
		"quarantine": map[string]any{
			"enabled":        true,
			"expiry_hours":   24,
			"retention_days": 90,
		},
		"rate_limit": map[string]any{
			"per_agent": 100,
			"window":    60,
		},
		"anomaly": map[string]any{
			"risk_threshold": 80,
			"check_interval": 60,
			"min_messages":   10,
		},
		"gateway": map[string]any{
			"enabled":       true,
			"port":          9090,
			"endpoint_path": "/mcp",
		},
	}

	data, err := yaml.Marshal(cfgMap)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	header := "# Generated by oktsec run\n# No MCP servers found. Add agents via the dashboard.\n"
	return os.WriteFile(configPath, append([]byte(header), data...), 0o600)
}


func startServer(configPath string, opts runOpts) error {

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n  Warning: could not load %s (%v)\n", configPath, err)
		fmt.Fprintf(os.Stderr, "  Starting with default config.\n\n")
		cfg = config.Defaults()
	}

	// Load secrets from .env (adjacent to config)
	envPath := filepath.Join(filepath.Dir(configPath), ".env")
	if env, _ := config.LoadEnv(envPath); env != nil {
		config.ApplyEnv(cfg, env)
	}

	if opts.port != 0 {
		cfg.Server.Port = opts.port
	}
	if opts.bind != "" {
		cfg.Server.Bind = opts.bind
	}

	if err := cfg.Validate(); err != nil {
		return err
	}

	level := slog.LevelWarn
	switch cfg.Server.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "error":
		level = slog.LevelError
	}

	// When TUI is active, redirect logs to a file to prevent display corruption.
	// Otherwise, log to stderr as usual.
	var logWriter io.Writer = os.Stderr
	var logFile *os.File
	if term.IsTerminal(int(os.Stdout.Fd())) {
		lf, err := os.OpenFile(filepath.Join(filepath.Dir(configPath), "oktsec.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err == nil {
			logWriter = lf
			logFile = lf
		}
	}
	logger := slog.New(slog.NewTextHandler(logWriter, &slog.HandlerOptions{Level: level}))

	// OpenTelemetry. Always initialized so traceparent headers propagate
	// even when local recording is off; tracingCfg.Enabled is what gates
	// the exporter. Shutdown is deferred so batched spans flush on exit.
	tracingShutdown, err := observability.Init(observability.TracingConfig{
		Enabled:       cfg.Telemetry.Tracing.Enabled,
		Exporter:      cfg.Telemetry.Tracing.Exporter,
		SamplingRatio: cfg.Telemetry.Tracing.SamplingRatio,
		ServiceName:   cfg.Telemetry.Tracing.ServiceName,
	}, logger)
	if err != nil {
		logger.Warn("tracing init failed, continuing without recording", "error", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tracingShutdown(ctx)
	}()

	dashboard.Version = version
	proxy.Version = version
	gateway.Version = version
	srv, err := proxy.NewServer(cfg, configPath, logger)
	if err != nil {
		return err
	}

	// Don't auto-open browser when TUI is active; the dashboard URL
	// is shown in the TUI and clickable in most terminals.
	if !opts.noBrowser && !term.IsTerminal(int(os.Stdout.Fd())) {
		openDashboard(cfg)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	// Anonymous install ping (once per installation, opt-out with OKTSEC_NO_TELEMETRY=1)
	go telemetry.Ping(telemetry.Info{
		Version:        version,
		Agents:         len(cfg.Agents),
		Rules:          len(cfg.Rules),
		Gateway:        cfg.Gateway.Enabled,
		LLM:            cfg.LLM.Enabled,
		Enforce:        cfg.Identity.RequireSignature,
		ConfigDisabled: cfg.Telemetry.Disabled,
	}, filepath.Dir(configPath))

	// Start embedded gateway if enabled (needed for hooks even without backends).
	// Share the proxy's audit store so all events (proxy + gateway + hooks) feed
	// into a single Hub. This fixes the dual-store issue where TUI and dashboard
	// would show different events.
	var gw *gateway.Gateway
	auditStore := srv.AuditStore()
	if cfg.Gateway.Enabled {
		var gwErr error
		gw, gwErr = gateway.NewGateway(cfg, logger, auditStore)
		if gwErr != nil {
			logger.Warn("gateway failed to initialize", "error", gwErr)
		} else {
			gw.SetCfgPath(configPath)
			hh := hooks.NewHandler(gw.Scanner(), gw.AuditStore(), cfg, logger)
			gw.SetHooksHandler(hh)
			// Wire tool classification to dashboard
			gwRef := gw
			srv.Dashboard().SetGatewayToolsFunc(func() []dashboard.GatewayToolInfo {
				var tools []dashboard.GatewayToolInfo
				for _, ti := range gwRef.ListToolInfo() {
					tools = append(tools, dashboard.GatewayToolInfo{
						FrontendName: ti.FrontendName,
						BackendName:  ti.BackendName,
						Description:  ti.Description,
						ImpactTier:   string(ti.Classification.ImpactTier),
						Generality:   string(ti.Classification.Generality),
						RiskTier:     string(ti.Classification.RiskTier),
					})
				}
				return tools
			})

			go func() {
				if e := gw.Start(ctx); e != nil {
					logger.Error("gateway error", "error", e)
				}
			}()
		}
	}

	// Build dashboard URL
	bindAddr := cfg.Server.Bind
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}
	dashURL := fmt.Sprintf("http://%s:%d/dashboard", bindAddr, cfg.Server.Port)

	mode := "observe"
	if cfg.Identity.RequireSignature {
		mode = "enforce"
	}

	// Use TUI if running in a terminal, otherwise fall back to static banner.
	if term.IsTerminal(int(os.Stdout.Fd())) {
		tuiModel := tui.New(tui.Config{
			Version:    version,
			Mode:       mode,
			DashURL:    dashURL,
			DashCode:   srv.DashboardCode(),
			AgentCount: len(cfg.Agents),
			Hub:        auditStore,
			Stats:      auditStore,
			LiveCfg:    cfg,
		})

		p := tea.NewProgram(tuiModel, tea.WithAltScreen())

		go func() {
			if _, err := p.Run(); err != nil {
				fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
			}
			stop()
		}()
	} else {
		printBanner(cfg, srv.DashboardCode())
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		stop()

		// Redirect stderr to suppress log noise after TUI restores terminal.
		devNull, _ := os.Open(os.DevNull)
		if devNull != nil {
			os.Stderr = devNull
			defer func() { _ = devNull.Close() }()
		}

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		if gw != nil {
			_ = gw.Shutdown(shutdownCtx)
		}
		_ = srv.Shutdown(shutdownCtx)
		if logFile != nil {
			_ = logFile.Close()
		}
		return nil
	}
}
