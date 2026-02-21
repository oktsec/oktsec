package commands

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
	"github.com/oktsec/oktsec/internal/identity"
	mcpserver "github.com/oktsec/oktsec/internal/mcp"
	"github.com/spf13/cobra"
)

func newMCPCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Start oktsec as an MCP server (stdio)",
		Long: `Exposes oktsec as an MCP tool server. Add to your MCP client config:

  {
    "mcpServers": {
      "oktsec": {
        "command": "oktsec",
        "args": ["mcp", "--config", "./oktsec.yaml"]
      }
    }
  }

Tools: scan_message, list_agents, audit_query, get_policy, verify_agent`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				cfg = config.Defaults()
			}

			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

			scanner := engine.NewScanner("")
			defer scanner.Close()

			dbPath := filepath.Join(os.TempDir(), "oktsec.db")
			auditStore, err := audit.NewStore(dbPath, logger)
			if err != nil {
				return err
			}
			defer func() { _ = auditStore.Close() }()

			// Load keys for verify_agent tool
			keys := identity.NewKeyStore()
			if cfg.Identity.KeysDir != "" {
				_ = keys.LoadFromDir(cfg.Identity.KeysDir) // best-effort
			}

			s := mcpserver.NewServer(cfg, scanner, auditStore, keys, logger)
			return mcpserver.Serve(s)
		},
	}
}
