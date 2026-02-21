package commands

import (
	"context"
	"fmt"
	"os"

	"github.com/garagon/aguara"
	"github.com/oktsec/oktsec/internal/engine"
	"github.com/spf13/cobra"
)

func newRulesCmd() *cobra.Command {
	var explain string

	cmd := &cobra.Command{
		Use:   "rules",
		Short: "List or explain detection rules",
		Example: `  oktsec rules
  oktsec rules --explain IAP-001`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Extract IAP rules so they're visible alongside Aguara's
			iapDir, err := engine.ExtractRulesDir()
			if err != nil {
				return fmt.Errorf("extracting IAP rules: %w", err)
			}
			defer os.RemoveAll(iapDir) //nolint:errcheck // best-effort cleanup

			opts := []aguara.Option{aguara.WithCustomRules(iapDir)}

			if explain != "" {
				detail, err := aguara.ExplainRule(explain, opts...)
				if err != nil {
					return err
				}
				fmt.Printf("Rule: %s\n", detail.ID)
				fmt.Printf("Name: %s\n", detail.Name)
				fmt.Printf("Severity: %s\n", detail.Severity)
				fmt.Printf("Category: %s\n", detail.Category)
				fmt.Printf("Description: %s\n", detail.Description)
				fmt.Println("\nPatterns:")
				for _, p := range detail.Patterns {
					fmt.Printf("  %s\n", p)
				}
				return nil
			}

			allRules := aguara.ListRules(opts...)
			fmt.Printf("Loaded %d detection rules:\n\n", len(allRules))
			for _, r := range allRules {
				fmt.Printf("  %-12s %-10s %s\n", r.ID, r.Severity, r.Name)
			}

			// Verify the engine is working
			result, err := aguara.ScanContent(context.Background(), "test", "test.md", opts...)
			if err != nil {
				return fmt.Errorf("engine check: %w", err)
			}
			fmt.Printf("\nEngine status: OK (%d rules loaded)\n", result.RulesLoaded)
			return nil
		},
	}

	cmd.Flags().StringVar(&explain, "explain", "", "explain a specific rule by ID")
	return cmd
}
