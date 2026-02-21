package commands

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/identity"
	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show proxy status and configuration summary",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			mode := "observe"
			if cfg.Identity.RequireSignature {
				mode = "enforce"
			}

			fmt.Println()
			fmt.Println("  oktsec status")
			fmt.Println("  ────────────────────────────────────────")
			fmt.Printf("  Mode:          %s\n", mode)
			fmt.Printf("  Agents:        %d configured\n", len(cfg.Agents))
			fmt.Printf("  Signatures:    %s\n", boolToRequired(cfg.Identity.RequireSignature))
			fmt.Printf("  Port:          %d\n", cfg.Server.Port)
			fmt.Printf("  Config:        %s\n", cfgFile)

			// Key stats
			if cfg.Identity.KeysDir != "" {
				keys := identity.NewKeyStore()
				if err := keys.LoadFromDir(cfg.Identity.KeysDir); err == nil {
					fmt.Printf("  Keys:          %d loaded\n", keys.Count())
				}
			}

			// Audit stats
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
			store, err := audit.NewStore("oktsec.db", logger)
			if err == nil {
				defer func() { _ = store.Close() }()

				all, _ := store.Query(audit.QueryOpts{Limit: 100000})
				var delivered, blocked, rejected, quarantined int
				for _, e := range all {
					switch e.Status {
					case "delivered":
						delivered++
					case "blocked":
						blocked++
					case "rejected":
						rejected++
					case "quarantined":
						quarantined++
					}
				}

				fmt.Println("  ────────────────────────────────────────")
				fmt.Printf("  Total msgs:    %d\n", len(all))
				fmt.Printf("  Delivered:     %d\n", delivered)
				fmt.Printf("  Blocked:       %d\n", blocked)
				fmt.Printf("  Rejected:      %d\n", rejected)
				fmt.Printf("  Quarantined:   %d\n", quarantined)

				revoked, _ := store.ListRevokedKeys()
				if len(revoked) > 0 {
					fmt.Printf("  Revoked keys:  %d\n", len(revoked))
				}
			}

			fmt.Println()
			return nil
		},
	}
}

func boolToRequired(b bool) string {
	if b {
		return "required"
	}
	return "optional"
}
