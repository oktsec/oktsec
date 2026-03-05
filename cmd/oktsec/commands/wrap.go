package commands

import (
	"fmt"

	"github.com/oktsec/oktsec/internal/discover"
	"github.com/spf13/cobra"
)

func newWrapCmd() *cobra.Command {
	var enforce bool
	var all bool

	cmd := &cobra.Command{
		Use:   "wrap [client]",
		Short: "Route MCP servers through oktsec proxy",
		Long:  "Modifies the MCP config of the specified client (or all clients with --all) so each server runs through 'oktsec proxy'. A backup is saved as .bak.",
		Example: `  oktsec wrap claude-desktop
  oktsec wrap --all
  oktsec wrap --enforce --all
  oktsec wrap --enforce cursor`,
		ValidArgs: discover.WrappableClients(),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !all && len(args) == 0 {
				return fmt.Errorf("specify a client name or use --all")
			}
			if all && len(args) > 0 {
				return fmt.Errorf("--all and a client name are mutually exclusive")
			}

			opts := discover.WrapOpts{
				Enforce:    enforce,
				ConfigPath: cfgFile,
			}

			if all {
				return wrapAll(opts)
			}

			client := args[0]
			if client == "openclaw" {
				return fmt.Errorf("OpenClaw uses a WebSocket gateway (not MCP stdio), so 'wrap' is not supported.\n\nUse 'oktsec scan-openclaw' to analyze your OpenClaw installation instead")
			}

			path := discover.ClientConfigPath(client)
			if path == "" {
				return fmt.Errorf("no config found for %q — is it installed?", client)
			}

			fmt.Printf("Wrapping %s MCP servers...\n\n", clientDisplay(client))

			wrapped, err := discover.WrapClient(client, opts)
			if err != nil {
				return err
			}

			if wrapped == 0 {
				fmt.Println("  All servers already wrapped.")
			} else {
				fmt.Printf("  %d server(s) wrapped.\n", wrapped)
				if enforce {
					fmt.Println("  Enforcement mode: malicious requests will be blocked.")
				}
			}

			fmt.Printf("\n  Backup saved: %s.bak\n", path)
			fmt.Printf("\n  Restart %s to activate.\n", clientDisplay(client))
			fmt.Println("  Run 'oktsec logs --live' to watch in real time.")
			return nil
		},
	}

	cmd.Flags().BoolVar(&enforce, "enforce", false, "enable enforcement mode (block malicious requests)")
	cmd.Flags().BoolVar(&all, "all", false, "wrap all discovered clients at once")
	return cmd
}

func wrapAll(opts discover.WrapOpts) error {
	results := discover.WrapAllClients(opts)

	if len(results) == 0 {
		fmt.Println("No wrappable MCP clients found.")
		fmt.Println("Run 'oktsec discover' to see what's installed.")
		return nil
	}

	totalWrapped := 0
	for _, r := range results {
		name := clientDisplay(r.Client)
		if r.Error != nil {
			fmt.Printf("  %-16s  error: %s\n", name, *r.Error)
			continue
		}
		if r.Wrapped == 0 {
			fmt.Printf("  %-16s  %d servers (already wrapped)\n", name, r.Servers)
		} else {
			fmt.Printf("  %-16s  %d server(s) wrapped\n", name, r.Wrapped)
			totalWrapped += r.Wrapped
		}
	}

	fmt.Println()
	if totalWrapped > 0 {
		fmt.Printf("  %d server(s) wrapped across %d client(s).\n", totalWrapped, len(results))
		if opts.Enforce {
			fmt.Println("  Enforcement mode: malicious requests will be blocked.")
		}
		fmt.Println()
		fmt.Println("  Restart your MCP clients to activate.")
		fmt.Println("  Run 'oktsec logs --live' to watch in real time.")
	} else {
		fmt.Println("  All servers already wrapped.")
	}

	return nil
}

func newUnwrapCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unwrap <client>",
		Short: "Restore original MCP config from backup",
		Long:  "Restores the original MCP config file from the .bak backup created by 'oktsec wrap'.",
		Example: `  oktsec unwrap claude-desktop
  oktsec unwrap cursor`,
		Args:      cobra.ExactArgs(1),
		ValidArgs: discover.WrappableClients(),
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
	return discover.ClientDisplayName(name)
}
