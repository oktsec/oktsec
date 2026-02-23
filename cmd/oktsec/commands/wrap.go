package commands

import (
	"fmt"

	"github.com/oktsec/oktsec/internal/discover"
	"github.com/spf13/cobra"
)

var supportedClients = []string{"claude-desktop", "cursor", "vscode", "cline", "windsurf", "openclaw"}

func newWrapCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "wrap <client>",
		Short: "Route a client's MCP servers through oktsec proxy",
		Long:  "Modifies the MCP config of the specified client so each server runs through 'oktsec proxy'. A backup is saved as .bak.",
		Example: `  oktsec wrap claude-desktop
  oktsec wrap cursor`,
		Args:      cobra.ExactArgs(1),
		ValidArgs: supportedClients,
		RunE: func(cmd *cobra.Command, args []string) error {
			client := args[0]

			if client == "openclaw" {
				return fmt.Errorf("OpenClaw uses a WebSocket gateway (not MCP stdio), so 'wrap' is not supported.\n\nUse 'oktsec scan-openclaw' to analyze your OpenClaw installation instead")
			}

			path := discover.ClientConfigPath(client)
			if path == "" {
				return fmt.Errorf("no config found for %q — is it installed?", client)
			}

			fmt.Printf("Wrapping %s MCP servers...\n\n", clientDisplay(client))

			wrapped, err := discover.WrapClient(client)
			if err != nil {
				return err
			}

			if wrapped == 0 {
				fmt.Println("  All servers already wrapped.")
			} else {
				fmt.Printf("  %d server(s) wrapped.\n", wrapped)
			}

			fmt.Printf("\n  Backup saved: %s.bak\n", path)
			fmt.Printf("\n  Restart %s to activate.\n", clientDisplay(client))
			fmt.Println("  Run 'oktsec logs --live' to watch in real time.")
			return nil
		},
	}
}

func newUnwrapCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unwrap <client>",
		Short: "Restore original MCP config from backup",
		Long:  "Restores the original MCP config file from the .bak backup created by 'oktsec wrap'.",
		Example: `  oktsec unwrap claude-desktop
  oktsec unwrap cursor`,
		Args:      cobra.ExactArgs(1),
		ValidArgs: supportedClients,
		RunE: func(cmd *cobra.Command, args []string) error {
			client := args[0]

			if err := discover.UnwrapClient(client); err != nil {
				return err
			}

			fmt.Printf("Restored original config for %s.\n", clientDisplay(client))
			fmt.Printf("Restart %s to apply.\n", clientDisplay(client))
			return nil
		},
	}
}

func clientDisplay(name string) string {
	switch name {
	case "claude-desktop":
		return "Claude Desktop"
	case "cursor":
		return "Cursor"
	case "vscode":
		return "VS Code"
	case "cline":
		return "Cline"
	case "windsurf":
		return "Windsurf"
	case "openclaw":
		return "OpenClaw"
	default:
		return name
	}
}
