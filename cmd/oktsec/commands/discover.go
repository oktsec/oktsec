package commands

import (
	"fmt"

	"github.com/oktsec/oktsec/internal/discover"
	"github.com/spf13/cobra"
)

func newDiscoverCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "discover",
		Short: "Scan for MCP server configurations on this machine",
		Long:  "Discovers MCP configurations for Claude Desktop, Cursor, VS Code, Cline, and Windsurf.",
		Example: `  oktsec discover
  oktsec discover | oktsec init`,
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := discover.Scan()
			if err != nil {
				return err
			}

			fmt.Print(discover.FormatTree(result))

			if result.TotalServers() > 0 {
				fmt.Println()
				fmt.Println("Run 'oktsec init' to generate configuration and start observing.")
			}

			return nil
		},
	}
}
