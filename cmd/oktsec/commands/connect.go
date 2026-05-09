package commands

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/discover"
	"github.com/oktsec/oktsec/internal/identity"
	"github.com/spf13/cobra"
)

// claudeCodeLifecycleDepsForCmd is overridable in tests so the connect /
// disconnect commands can run without invoking the real claude CLI or
// touching ~/.claude/settings.json. Production callers use the default.
var claudeCodeLifecycleDepsForCmd = defaultClaudeCodeLifecycleDeps

func newConnectCmd() *cobra.Command {
	var keysDir string

	cmd := &cobra.Command{
		Use:   "connect <client>",
		Short: "Connect an MCP client to the oktsec gateway",
		Long: `Registers the client as an agent, generates Ed25519 keys, and configures
the client to route MCP traffic through the oktsec gateway.

For Claude Code, this uses native HTTP MCP transport (no wrapper needed).
For other clients, this wraps their MCP servers through the oktsec proxy.`,
		Example: `  oktsec connect claude-code
  oktsec connect cursor
  oktsec connect claude-desktop`,
		Args:      cobra.ExactArgs(1),
		ValidArgs: discover.WrappableClients(),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := args[0]

			if !discover.IsWrappable(client) {
				return fmt.Errorf("unsupported client %q\n\nSupported clients: %v", client, discover.WrappableClients())
			}

			// Load config
			cfg, err := config.Load(cfgFile)
			if err != nil {
				if !os.IsNotExist(err) {
					return fmt.Errorf("loading config: %w", err)
				}
				// Config doesn't exist yet -- use defaults
				cfg = config.Defaults()
			}

			// Check gateway is configured (required for claude-code HTTP transport)
			if client == "claude-code" && !cfg.Gateway.Enabled {
				fmt.Println("Note: Gateway is not enabled in config. Claude Code connects via HTTP MCP")
				fmt.Println("transport, which requires the gateway. Enable it with:")
				fmt.Println()
				fmt.Printf("  gateway:\n    enabled: true\n    port: 9090\n")
				fmt.Println()
				fmt.Println("Proceeding with agent registration and key generation...")
				fmt.Println()
			}

			// Resolve keys directory from config or flag
			if keysDir == "" {
				keysDir = cfg.Identity.KeysDir
			}
			if keysDir == "" {
				keysDir = config.DefaultKeysDir()
			}

			// Auto-register agent if not present
			if cfg.Agents == nil {
				cfg.Agents = make(map[string]config.Agent)
			}
			if _, exists := cfg.Agents[client]; !exists {
				cfg.Agents[client] = config.Agent{
					CanMessage:  []string{"*"},
					Description: "Auto-registered by oktsec connect",
				}
				fmt.Printf("Registered agent %q in config.\n", client)
			} else {
				fmt.Printf("Agent %q already registered in config.\n", client)
			}

			// Generate keypair if not present
			keyPath := filepath.Join(keysDir, client+".key")
			if _, err := os.Stat(keyPath); os.IsNotExist(err) {
				kp, err := identity.GenerateKeypair(client)
				if err != nil {
					return fmt.Errorf("generating keypair: %w", err)
				}
				if err := kp.Save(keysDir); err != nil {
					return fmt.Errorf("saving keypair: %w", err)
				}
				fp := identity.Fingerprint(kp.PublicKey)
				fmt.Printf("Generated keypair for %s\n", client)
				fmt.Printf("  Private: %s/%s.key\n", keysDir, client)
				fmt.Printf("  Public:  %s/%s.pub\n", keysDir, client)
				fmt.Printf("  Fingerprint: %s\n", fp[:16]+"...")
			} else {
				fmt.Printf("Keypair already exists at %s\n", keyPath)
			}

			// Connect the client
			fmt.Println()
			if client == "claude-code" {
				if err := connectClaudeCode(cfg); err != nil {
					return err
				}
			} else {
				if err := connectStdioClient(client); err != nil {
					return err
				}
			}

			// Save config
			if err := cfg.Save(cfgFile); err != nil {
				return fmt.Errorf("saving config: %w", err)
			}
			fmt.Printf("\nConfig saved to %s\n", cfgFile)

			// Instructions
			fmt.Println()
			fmt.Printf("Restart %s to activate the connection.\n", clientDisplay(client))
			fmt.Println("Then run 'oktsec logs --live' to watch traffic in real time.")

			return nil
		},
	}

	cmd.Flags().StringVar(&keysDir, "keys", "", "directory for keypairs (default: from config or ./keys)")
	return cmd
}

// connectClaudeCode registers the oktsec gateway entry and installs the V2
// hook manifest through the shared Claude Code lifecycle helper. Strict mode:
// gateway add failure or hook install failure both return a non-nil error so
// the operator can trust that a successful return means Claude Code is fully
// connected as a runtime surface.
func connectClaudeCode(cfg *config.Config) error {
	port := cfg.Gateway.Port
	if port == 0 {
		port = 9090
	}
	endpoint := cfg.Gateway.EndpointPath
	if endpoint == "" {
		endpoint = "/mcp"
	}

	url := fmt.Sprintf("http://127.0.0.1:%d%s", port, endpoint)
	fmt.Printf("Connecting Claude Code to gateway at %s...\n", url)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := connectClaudeCodeRuntime(ctx, claudeCodeConnectOptions{
		Port:     port,
		Endpoint: endpoint,
		Mode:     claudeConnectStrict,
	}, claudeCodeLifecycleDepsForCmd())
	if err != nil {
		fmt.Println()
		fmt.Println("Connection incomplete. Run `oktsec doctor claude-code` for the full inventory.")
		return err
	}

	fmt.Println("Gateway entry added; HTTP MCP transport configured.")
	if res.InstallResult != nil {
		switch {
		case res.InstallResult.Wrote:
			fmt.Printf("Installed %d hook(s) via the V2 manifest installer.\n", len(res.InstallResult.Plan))
			if res.InstallResult.UpgradedV1 > 0 {
				fmt.Printf("Upgraded %d legacy V1 hook(s) in place.\n", res.InstallResult.UpgradedV1)
			}
			if res.InstallResult.BackupPath != "" {
				fmt.Printf("Backup: %s\n", res.InstallResult.BackupPath)
			}
		case res.InstallResult.Skipped != "":
			fmt.Printf("Hook manifest already in place (%s).\n", res.InstallResult.Skipped)
		}
	}
	return nil
}

// connectStdioClient wraps the client's MCP servers through oktsec proxy.
func connectStdioClient(client string) error {
	path := discover.ClientConfigPath(client)
	if path == "" {
		return fmt.Errorf("no config found for %q -- is it installed?", client)
	}

	absConfig, err := filepath.Abs(cfgFile)
	if err != nil {
		absConfig = cfgFile
	}

	opts := discover.WrapOpts{
		ConfigPath: absConfig,
	}

	fmt.Printf("Wrapping %s MCP servers through oktsec proxy...\n", clientDisplay(client))

	wrapped, err := discover.WrapClient(client, opts)
	if err != nil {
		return err
	}

	if wrapped == 0 {
		fmt.Println("All servers already wrapped.")
	} else {
		fmt.Printf("%d server(s) wrapped.\n", wrapped)
	}
	fmt.Printf("Backup saved: %s.bak\n", path)

	return nil
}

func newDisconnectCmd() *cobra.Command {
	var removeAgent bool

	cmd := &cobra.Command{
		Use:   "disconnect <client>",
		Short: "Disconnect an MCP client from the oktsec gateway",
		Long: `Reverses the connection made by 'oktsec connect'.

For Claude Code, this removes the oktsec-gateway MCP server entry.
For other clients, this restores the original MCP config from backup.`,
		Example: `  oktsec disconnect claude-code
  oktsec disconnect cursor
  oktsec disconnect cursor --remove-agent`,
		Args:      cobra.ExactArgs(1),
		ValidArgs: discover.WrappableClients(),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := args[0]

			if !discover.IsWrappable(client) {
				return fmt.Errorf("unsupported client %q", client)
			}

			// Disconnect the client
			if client == "claude-code" {
				if err := disconnectClaudeCode(); err != nil {
					return err
				}
			} else {
				if err := discover.UnwrapClient(client); err != nil {
					return err
				}
				fmt.Printf("Restored original config for %s.\n", clientDisplay(client))
			}

			// Optionally remove agent from config
			if removeAgent {
				cfg, err := config.Load(cfgFile)
				if err == nil {
					if _, exists := cfg.Agents[client]; exists {
						delete(cfg.Agents, client)
						if err := cfg.Save(cfgFile); err != nil {
							return fmt.Errorf("saving config: %w", err)
						}
						fmt.Printf("Removed agent %q from config.\n", client)
					}
				}
			}

			fmt.Printf("\nRestart %s to apply.\n", clientDisplay(client))
			return nil
		},
	}

	cmd.Flags().BoolVar(&removeAgent, "remove-agent", false, "also remove the agent from oktsec.yaml")
	return cmd
}

// disconnectClaudeCode removes the oktsec-gateway entry and uninstalls every
// Oktsec-owned hook (V2 plus legacy V1) through the shared Claude Code
// lifecycle helper. Hook uninstall always runs even when gateway removal
// reports the entry as already absent, so a partial state never leaves
// Oktsec hook commands behind in settings.json.
func disconnectClaudeCode() error {
	fmt.Println("Disconnecting Claude Code (gateway + Oktsec-owned hooks)...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := disconnectClaudeCodeRuntime(ctx, claudeCodeDisconnectOptions{}, claudeCodeLifecycleDepsForCmd())
	if err != nil {
		fmt.Println()
		fmt.Println("Disconnect incomplete. Run `oktsec doctor claude-code` for the full inventory.")
		return err
	}

	if res.GatewayAttempted && res.GatewayOK {
		fmt.Println("Removed oktsec-gateway entry.")
	}
	if res.UninstallResult != nil {
		switch {
		case res.UninstallResult.Wrote:
			fmt.Printf("Removed %d V2 + %d legacy V1 hook(s).\n",
				res.UninstallResult.RemovedV2, res.UninstallResult.RemovedV1)
			if res.UninstallResult.BackupPath != "" {
				fmt.Printf("Backup: %s\n", res.UninstallResult.BackupPath)
			}
		case res.UninstallResult.Skipped != "":
			fmt.Printf("No Oktsec-owned hooks to remove (%s).\n", res.UninstallResult.Skipped)
		}
	}
	for _, w := range res.Warnings {
		fmt.Printf("warn: %s\n", w)
	}
	return nil
}

