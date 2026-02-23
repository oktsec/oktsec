package commands

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/engine"
	"github.com/oktsec/oktsec/internal/proxy"
	"github.com/spf13/cobra"
)

func newProxyCmd() *cobra.Command {
	var agent string
	var enforce bool

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

			// Use a shared audit store location
			dbPath := filepath.Join(os.TempDir(), "oktsec.db")
			auditStore, err := audit.NewStore(dbPath, logger)
			if err != nil {
				return err
			}
			defer func() { _ = auditStore.Close() }()

			p := proxy.NewStdioProxy(agent, scanner, auditStore, logger, enforce)

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
	_ = cmd.MarkFlagRequired("agent")
	return cmd
}
