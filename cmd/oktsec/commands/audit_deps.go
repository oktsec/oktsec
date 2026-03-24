package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/oktsec/oktsec/internal/deps"
	"github.com/spf13/cobra"
)

func newAuditDepsCmd() *cobra.Command {
	var (
		jsonOutput bool
		strict     bool
	)

	cmd := &cobra.Command{
		Use:   "deps [path]",
		Short: "Audit MCP server dependencies for supply chain risks",
		Long:  "Scans dependency manifests (requirements.txt, package.json, go.mod) against known vulnerability databases.",
		Example: `  oktsec audit deps /path/to/mcp-server/
  oktsec audit deps . --json
  oktsec audit deps /path/to/server --strict`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAuditDeps(args[0], jsonOutput, strict)
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output results as JSON")
	cmd.Flags().BoolVar(&strict, "strict", false, "exit 1 on any WARNING or higher")

	return cmd
}

func runAuditDeps(path string, jsonOutput, strict bool) error {
	scanner := deps.NewScanner(nil)

	result, err := scanner.Scan(path)
	if err != nil {
		return exitError(2, err.Error())
	}

	if jsonOutput {
		return printDepsJSON(result)
	}
	printDepsTerminal(result)

	// Exit codes
	if result.Risk == "critical" {
		os.Exit(1)
	}
	if strict {
		for _, f := range result.Findings {
			if f.Severity == "warning" || f.Severity == "critical" {
				os.Exit(1)
			}
		}
	}

	return nil
}

func printDepsTerminal(result *deps.ScanResult) {
	fmt.Println()
	fmt.Printf("  MCP Server: %s\n", result.Path)

	if len(result.Manifests) == 0 {
		fmt.Println("  No dependency manifests found.")
		fmt.Println()
		return
	}

	fmt.Println("  Manifests found:")
	totalPkgs := 0
	for _, m := range result.Manifests {
		totalPkgs += m.Packages
		if m.Unpinned > 0 {
			fmt.Printf("    %s (%d packages, %d unpinned)\n", m.File, m.Packages, m.Unpinned)
		} else {
			fmt.Printf("    %s (%d packages)\n", m.File, m.Packages)
		}
	}

	if totalPkgs > 0 {
		fmt.Printf("\n  Checking %d packages against OSV.dev...\n", totalPkgs)
	}

	if len(result.Findings) > 0 {
		fmt.Println()
		fmt.Println("  FINDINGS:")
		for _, f := range result.Findings {
			label := strings.ToUpper(f.Severity)
			if f.Package != "" {
				detail := f.Message
				if f.VulnID != "" {
					detail = fmt.Sprintf("%s: %s", f.VulnID, f.Message)
				}
				fmt.Printf("    %-8s  %s==%s — %s\n", label, f.Package, f.Version, detail)
			} else {
				fmt.Printf("    %-8s  %s\n", label, f.Message)
			}
		}
	}

	fmt.Println()
	fmt.Printf("  Risk: %s\n", strings.ToUpper(result.Risk))
	fmt.Println()
}

func printDepsJSON(result *deps.ScanResult) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
