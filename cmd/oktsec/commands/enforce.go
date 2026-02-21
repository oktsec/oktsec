package commands

import (
	"fmt"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/spf13/cobra"
)

func newEnforceCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enforce [on|off]",
		Short: "Toggle between enforce and observe mode",
		Long: `Toggle the proxy between enforce mode (require_signature: true) and
observe mode (require_signature: false).

  oktsec enforce       — show current mode
  oktsec enforce on    — switch to enforce mode
  oktsec enforce off   — switch to observe mode

After toggling, send SIGHUP to the running proxy to apply changes.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			if len(args) == 0 {
				mode := "observe"
				if cfg.Identity.RequireSignature {
					mode = "enforce"
				}
				fmt.Printf("Current mode: %s\n", mode)
				fmt.Println()
				fmt.Println("Usage: oktsec enforce [on|off]")
				return nil
			}

			switch args[0] {
			case "on":
				cfg.Identity.RequireSignature = true
			case "off":
				cfg.Identity.RequireSignature = false
			default:
				return fmt.Errorf("invalid argument %q: use 'on' or 'off'", args[0])
			}

			if err := cfg.Save(cfgFile); err != nil {
				return err
			}

			mode := "observe"
			if cfg.Identity.RequireSignature {
				mode = "enforce"
			}
			fmt.Printf("Mode set to: %s\n", mode)
			fmt.Println("Send SIGHUP to the running proxy to apply, or restart.")
			return nil
		},
	}
}
