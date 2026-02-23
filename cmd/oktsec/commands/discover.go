package commands

import (
	"fmt"
	"strings"

	"github.com/oktsec/oktsec/internal/discover"
	"github.com/spf13/cobra"
)

func newDiscoverCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "discover",
		Short: "Scan for MCP server configurations on this machine",
		Long:  "Discovers MCP configurations for Claude Desktop, Cursor, VS Code, Cline, Windsurf, and OpenClaw.",
		Example: `  oktsec discover
  oktsec discover | oktsec init`,
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := discover.Scan()
			if err != nil {
				return err
			}

			fmt.Print(discover.FormatTree(result))

			// Check for OpenClaw risk
			for _, cr := range result.Clients {
				if cr.Client == "openclaw" {
					risk, err := discover.AssessOpenClawRisk(cr.Path)
					if err == nil && len(risk.Reasons) > 0 {
						fmt.Printf("\n  OpenClaw risk: %s\n", strings.ToUpper(risk.Level))
						for _, reason := range risk.Reasons {
							fmt.Printf("    [!] %s\n", reason)
						}
						fmt.Println("\n  Run 'oktsec scan-openclaw' for full analysis.")
					}
				}
			}

			if result.TotalServers() > 0 {
				fmt.Println()
				fmt.Println("Run 'oktsec init' to generate configuration and start observing.")
			}

			return nil
		},
	}
}
