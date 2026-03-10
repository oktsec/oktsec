package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/discover"
	"github.com/oktsec/oktsec/internal/identity"
	"github.com/spf13/cobra"
)

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
				keysDir = "./keys"
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

// connectClaudeCode runs `claude mcp add` to register the oktsec gateway as an HTTP MCP server.
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

	//nolint:gosec // args are not user-controlled
	out, err := exec.Command(
		"claude", "mcp", "add",
		"--transport", "http",
		"--header", "X-Oktsec-Agent: claude-code",
		"--scope", "user",
		"oktsec-gateway", url,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("running 'claude mcp add': %w\n%s", err, string(out))
	}

	fmt.Println("Claude Code configured with HTTP MCP transport.")
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

// disconnectClaudeCode runs `claude mcp remove` to unregister the oktsec gateway.
func disconnectClaudeCode() error {
	fmt.Println("Removing oktsec-gateway from Claude Code...")

	//nolint:gosec // args are not user-controlled
	out, err := exec.Command("claude", "mcp", "remove", "oktsec-gateway").CombinedOutput()
	if err != nil {
		return fmt.Errorf("running 'claude mcp remove': %w\n%s", err, string(out))
	}

	fmt.Println("Removed oktsec-gateway from Claude Code.")
	return nil
}

