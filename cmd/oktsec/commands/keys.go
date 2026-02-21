package commands

import (
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/identity"
	"github.com/spf13/cobra"
)

func newKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Manage agent keypairs",
		Long:  "List, rotate, and revoke agent Ed25519 keypairs.",
	}

	cmd.AddCommand(
		newKeysListCmd(),
		newKeysRotateCmd(),
		newKeysRevokeCmd(),
	)
	return cmd
}

func newKeysListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all registered agent keypairs",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			keysDir := cfg.Identity.KeysDir
			if keysDir == "" {
				return fmt.Errorf("no keys_dir configured")
			}

			keys := identity.NewKeyStore()
			if err := keys.LoadFromDir(keysDir); err != nil {
				return fmt.Errorf("loading keys: %w", err)
			}

			// Check for revoked keys
			revokedDir := filepath.Join(keysDir, "revoked")
			var revokedNames []string
			if entries, err := os.ReadDir(revokedDir); err == nil {
				for _, e := range entries {
					name := e.Name()
					if filepath.Ext(name) == ".pub" {
						revokedNames = append(revokedNames, name[:len(name)-4])
					}
				}
			}

			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintf(tw, "AGENT\tFINGERPRINT\tSTATUS\n") //nolint:errcheck
			for _, name := range keys.Names() {
				pub, _ := keys.Get(name)
				fp := identity.Fingerprint(pub)
				fmt.Fprintf(tw, "%s\t%s...\tactive\n", name, fp[:16]) //nolint:errcheck
			}
			for _, name := range revokedNames {
				fmt.Fprintf(tw, "%s\t-\trevoked\n", name) //nolint:errcheck
			}
			return tw.Flush()
		},
	}
}

func newKeysRotateCmd() *cobra.Command {
	var agent string
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Rotate an agent's keypair",
		Long:  "Generates a new keypair for the agent, moving the old one to keys/revoked/.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			keysDir := cfg.Identity.KeysDir
			if keysDir == "" {
				return fmt.Errorf("no keys_dir configured")
			}

			// Get old fingerprint before moving
			var oldFingerprint string
			if oldPub, err := identity.LoadPublicKey(keysDir, agent); err == nil {
				oldFingerprint = identity.Fingerprint(oldPub)
			}

			// Move old keys to revoked/
			revokedDir := filepath.Join(keysDir, "revoked")
			if err := os.MkdirAll(revokedDir, 0o700); err != nil {
				return fmt.Errorf("creating revoked directory: %w", err)
			}

			for _, ext := range []string{".key", ".pub"} {
				old := filepath.Join(keysDir, agent+ext)
				if _, err := os.Stat(old); err == nil {
					dst := filepath.Join(revokedDir, agent+ext)
					if err := os.Rename(old, dst); err != nil {
						return fmt.Errorf("moving %s: %w", old, err)
					}
				}
			}

			// Persist revocation in audit DB
			if oldFingerprint != "" {
				persistRevocation(oldFingerprint, agent, "key rotated")
			}

			// Generate new keypair
			kp, err := identity.GenerateKeypair(agent)
			if err != nil {
				return fmt.Errorf("generating keypair: %w", err)
			}
			if err := kp.Save(keysDir); err != nil {
				return fmt.Errorf("saving keypair: %w", err)
			}

			fp := identity.Fingerprint(ed25519.PublicKey(kp.PublicKey))
			fmt.Printf("Rotated keypair for %s\n", agent)
			fmt.Printf("  New fingerprint: %s\n", fp)
			fmt.Printf("  Old keys moved to: %s/\n", revokedDir)
			fmt.Println()
			fmt.Println("Restart oktsec to load the new key.")
			return nil
		},
	}
	cmd.Flags().StringVar(&agent, "agent", "", "agent name to rotate")
	_ = cmd.MarkFlagRequired("agent")
	return cmd
}

func newKeysRevokeCmd() *cobra.Command {
	var agent string
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke an agent's keypair",
		Long:  "Moves the agent's keys to keys/revoked/. The proxy will reject messages signed with revoked keys.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			keysDir := cfg.Identity.KeysDir
			if keysDir == "" {
				return fmt.Errorf("no keys_dir configured")
			}

			// Get fingerprint before moving
			var fp string
			if pub, err := identity.LoadPublicKey(keysDir, agent); err == nil {
				fp = identity.Fingerprint(pub)
			}

			revokedDir := filepath.Join(keysDir, "revoked")
			if err := os.MkdirAll(revokedDir, 0o700); err != nil {
				return fmt.Errorf("creating revoked directory: %w", err)
			}

			moved := 0
			for _, ext := range []string{".key", ".pub"} {
				old := filepath.Join(keysDir, agent+ext)
				if _, err := os.Stat(old); err == nil {
					dst := filepath.Join(revokedDir, agent+ext)
					if err := os.Rename(old, dst); err != nil {
						return fmt.Errorf("moving %s: %w", old, err)
					}
					moved++
				}
			}

			if moved == 0 {
				return fmt.Errorf("no keys found for agent %q in %s", agent, keysDir)
			}

			// Persist revocation in audit DB
			if fp != "" {
				persistRevocation(fp, agent, "manually revoked")
			}

			fmt.Printf("Revoked keys for %s\n", agent)
			fmt.Printf("  Keys moved to: %s/\n", revokedDir)
			fmt.Println()
			fmt.Println("Restart oktsec to apply. Messages from this agent will be rejected.")
			return nil
		},
	}
	cmd.Flags().StringVar(&agent, "agent", "", "agent name to revoke")
	_ = cmd.MarkFlagRequired("agent")
	return cmd
}

// persistRevocation records a key revocation in the audit database.
func persistRevocation(fingerprint, agentName, reason string) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := audit.NewStore("oktsec.db", logger)
	if err != nil {
		return
	}
	defer func() { _ = store.Close() }()
	_ = store.RevokeKey(fingerprint, agentName, reason)
}
