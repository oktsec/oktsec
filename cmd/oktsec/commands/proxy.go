package commands

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
	"github.com/oktsec/oktsec/internal/proxy"
	"github.com/spf13/cobra"
)

// defaultDBPath returns a shared DB location so proxy and serve share the same audit trail.
func defaultDBPath() string {
	return config.DefaultDBPath()
}

func newProxyCmd() *cobra.Command {
	var agent string
	var enforce bool
	var inspectResponses bool

	cmd := &cobra.Command{
		Use:   "proxy --agent <name> -- <command> [args...]",
		Short: "Wrap an MCP server with oktsec interception",
		Long:  "Starts a child process and intercepts its stdio (JSON-RPC 2.0), scanning each message through the Aguara engine and logging to the audit trail.",
		Example: `  oktsec proxy --agent filesystem -- npx @mcp/server-filesystem /data
  oktsec proxy --agent database -- node ./db-server.js
  oktsec proxy --enforce --agent filesystem -- npx @mcp/server-filesystem /data`,
		Args:               cobra.MinimumNArgs(1),
		DisableFlagParsing: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

			scanner := engine.NewScanner("")
			defer scanner.Close()

			// Resolve DB path: config > default shared location
			dbPath := defaultDBPath()
			configPath, _ := cmd.Flags().GetString("config")
			var cfg *config.Config
			if configPath != "" {
				if loaded, err := config.Load(configPath); err == nil {
					cfg = loaded
					if cfg.DBPath != "" {
						dbPath = cfg.DBPath
					}
				}
			}

			auditStore, err := audit.NewStore(dbPath, logger)
			if err != nil {
				return err
			}
			defer func() { _ = auditStore.Close() }()

			p := proxy.NewStdioProxy(agent, scanner, auditStore, logger, enforce)
			if inspectResponses {
				p.SetInspectResponses(true)
			}

			// Load allowed_tools from config if available
			if cfg != nil {
				if agentCfg, ok := cfg.Agents[agent]; ok && len(agentCfg.AllowedTools) > 0 {
					p.SetAllowedTools(agentCfg.AllowedTools)
					logger.Info("tool allowlist active", "agent", agent, "tools", len(agentCfg.AllowedTools))
				}
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			command := args[0]
			var cmdArgs []string
			if len(args) > 1 {
				cmdArgs = args[1:]
			}

			return p.Run(ctx, command, cmdArgs)
		},
	}

	cmd.Flags().StringVar(&agent, "agent", "", "agent name for this MCP server")
	cmd.Flags().BoolVar(&enforce, "enforce", false, "block malicious requests instead of observe-only")
	cmd.Flags().BoolVar(&inspectResponses, "inspect-responses", false, "also inspect and block malicious server responses (requires --enforce)")
	_ = cmd.MarkFlagRequired("agent")
	return cmd
}
