package commands

import (
	"fmt"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/spf13/cobra"
)

func newVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Validate the oktsec configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("validation error: %w", err)
			}

			fmt.Printf("Config %s is valid\n", cfgFile)
			fmt.Printf("  Port: %d\n", cfg.Server.Port)
			fmt.Printf("  Require signature: %v\n", cfg.Identity.RequireSignature)
			fmt.Printf("  Keys dir: %s\n", cfg.Identity.KeysDir)
			fmt.Printf("  Agents: %d\n", len(cfg.Agents))
			fmt.Printf("  Rules: %d\n", len(cfg.Rules))
			fmt.Printf("  Webhooks: %d\n", len(cfg.Webhooks))
			return nil
		},
	}
}
