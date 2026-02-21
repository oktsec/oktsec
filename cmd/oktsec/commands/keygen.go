package commands

import (
	"fmt"

	"github.com/oktsec/oktsec/internal/identity"
	"github.com/spf13/cobra"
)

func newKeygenCmd() *cobra.Command {
	var agents []string
	var outDir string

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate Ed25519 keypairs for agents",
		Example: `  oktsec keygen --agent research-agent --out ./keys/
  oktsec keygen --agent agent-a --agent agent-b --out ./keys/`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(agents) == 0 {
				return fmt.Errorf("at least one --agent is required")
			}

			for _, name := range agents {
				kp, err := identity.GenerateKeypair(name)
				if err != nil {
					return fmt.Errorf("generating keypair for %s: %w", name, err)
				}
				if err := kp.Save(outDir); err != nil {
					return fmt.Errorf("saving keypair for %s: %w", name, err)
				}
				fp := identity.Fingerprint(kp.PublicKey)
				fmt.Printf("Generated keypair for %s\n", name)
				fmt.Printf("  Private: %s/%s.key\n", outDir, name)
				fmt.Printf("  Public:  %s/%s.pub\n", outDir, name)
				fmt.Printf("  Fingerprint: %s\n\n", fp[:16]+"...")
			}
			return nil
		},
	}

	cmd.Flags().StringSliceVar(&agents, "agent", nil, "agent name(s) to generate keys for")
	cmd.Flags().StringVar(&outDir, "out", "./keys", "output directory for keys")
	return cmd
}
