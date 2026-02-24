package commands

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oktsec/oktsec/internal/discover"
	"github.com/oktsec/oktsec/internal/engine"
	"github.com/spf13/cobra"
)

func newScanOpenClawCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "scan-openclaw",
		Short: "Analyze an OpenClaw installation for security risks",
		Long:  "Scans the OpenClaw configuration and workspace files (SOUL.md, AGENTS.md, TOOLS.md, USER.md) for security risks and prompt injection vectors.",
		Example: `  oktsec scan-openclaw
  oktsec scan-openclaw --path ~/.openclaw/openclaw.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Auto-detect config path if not given
			if configPath == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return fmt.Errorf("cannot determine home directory: %w", err)
				}
				configPath = filepath.Join(home, ".openclaw", "openclaw.json")
			}

			if _, err := os.Stat(configPath); err != nil {
				return fmt.Errorf("OpenClaw config not found at %s\n\nSpecify the path with --path", configPath)
			}

			fmt.Printf("Scanning OpenClaw installation: %s\n\n", configPath)

			// 1. Risk assessment
			risk, err := discover.AssessOpenClawRisk(configPath)
			if err != nil {
				return fmt.Errorf("parsing config: %w", err)
			}

			printRiskSummary(risk)

			// 2. Scan config file through OCLAW rules
			scanner := engine.NewScanner("")
			defer scanner.Close()

			var totalFindings int
			var scannedFiles int

			configData, err := os.ReadFile(configPath)
			if err == nil {
				scannedFiles++
				outcome, scanErr := scanner.ScanContentAs(context.Background(), string(configData), "openclaw.json")
				if scanErr != nil {
					fmt.Printf("  [!] Error scanning config: %v\n", scanErr)
				} else if len(outcome.Findings) > 0 {
					totalFindings += len(outcome.Findings)
					fmt.Printf("  openclaw.json  %d finding(s)\n", len(outcome.Findings))
					for _, f := range outcome.Findings {
						fmt.Printf("    %-12s %-10s %s\n", f.RuleID, strings.ToUpper(f.Severity), f.Name)
					}
					fmt.Println()
				}
			}

			// 3. Scan workspace files with Aguara engine
			configDir := filepath.Dir(configPath)
			workspaceFiles := []string{"SOUL.md", "AGENTS.md", "TOOLS.md", "USER.md"}

			for _, name := range workspaceFiles {
				fpath := filepath.Join(configDir, name)
				data, err := os.ReadFile(fpath)
				if err != nil {
					continue // File doesn't exist, skip
				}

				scannedFiles++
				outcome, err := scanner.ScanContent(context.Background(), string(data))
				if err != nil {
					fmt.Printf("  [!] Error scanning %s: %v\n", name, err)
					continue
				}

				if len(outcome.Findings) == 0 {
					continue
				}

				totalFindings += len(outcome.Findings)
				fmt.Printf("  %s  %d finding(s)\n", name, len(outcome.Findings))
				for _, f := range outcome.Findings {
					fmt.Printf("    %-12s %-10s %s\n", f.RuleID, strings.ToUpper(f.Severity), f.Name)
				}
				fmt.Println()
			}

			// 4. Summary
			fmt.Println(strings.Repeat("─", 60))
			fmt.Printf("\nSummary:\n")
			fmt.Printf("  Config risk:     %s\n", strings.ToUpper(risk.Level))
			fmt.Printf("  Risk factors:    %d\n", len(risk.Reasons))
			fmt.Printf("  Workspace files: %d scanned\n", scannedFiles)
			fmt.Printf("  Content issues:  %d finding(s)\n", totalFindings)

			if risk.Level == "critical" || risk.Level == "high" {
				fmt.Println("\n  Run 'oktsec rules list --category openclaw-config' to see detection rules.")
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "path", "", "path to openclaw.json (auto-detected if not set)")
	return cmd
}

func printRiskSummary(risk *discover.OpenClawRisk) {
	label := strings.ToUpper(risk.Level)
	fmt.Printf("  Risk Level: %s\n\n", label)

	if len(risk.Reasons) == 0 {
		fmt.Println("  No risk factors detected.")
		fmt.Println()
		return
	}

	for _, reason := range risk.Reasons {
		fmt.Printf("  [!] %s\n", reason)
	}
	fmt.Println()
}
