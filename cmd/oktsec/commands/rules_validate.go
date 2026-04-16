package commands

import (
	"context"
	"fmt"
	"os"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/engine"
	"github.com/spf13/cobra"
)

func newRulesValidateCmd() *cobra.Command {
	var testDir string

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate detection rules against test cases",
		Long: `Runs all test cases in the specified directory against the current
rule set. Reports confirmed true/false positives and regressions.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cases, err := audit.LoadTestcases(testDir)
			if err != nil {
				return fmt.Errorf("loading testcases from %s: %w", testDir, err)
			}

			if len(cases) == 0 {
				fmt.Printf("No test cases found in %s/\n", testDir)
				fmt.Println("Run 'oktsec rules testgen' first to generate test cases.")
				return nil
			}

			scanner := engine.NewScanner("")
			defer scanner.Close()

			var confirmed, regressions, fpConfirmed, fpStillFiring int

			for _, tc := range cases {
				outcome, err := scanner.ScanContent(context.Background(), tc.Content)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  error scanning %s: %v\n", tc.RuleID, err)
					continue
				}

				ruleTriggered := false
				for _, f := range outcome.Findings {
					if f.RuleID == tc.RuleID {
						ruleTriggered = true
						break
					}
				}

				switch tc.Type {
				case "true_positive":
					if ruleTriggered {
						confirmed++
					} else {
						regressions++
						fmt.Printf("  REGRESSION: %s did not trigger on content from %s/%s\n",
							tc.RuleID, tc.Agent, tc.Tool)
					}
				case "false_positive":
					if !ruleTriggered {
						fpConfirmed++
					} else {
						fpStillFiring++
						fmt.Printf("  FP STILL FIRING: %s still triggers on content from %s/%s\n",
							tc.RuleID, tc.Agent, tc.Tool)
					}
				}
			}

			fmt.Println()
			fmt.Printf("Results: %d test cases\n", len(cases))
			fmt.Printf("  True positives confirmed:  %d\n", confirmed)
			fmt.Printf("  Regressions:               %d\n", regressions)
			fmt.Printf("  False positives fixed:     %d\n", fpConfirmed)
			fmt.Printf("  False positives remaining: %d\n", fpStillFiring)

			if regressions > 0 {
				return fmt.Errorf("%d regression(s) found", regressions)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&testDir, "dir", "d", "rules/testcases", "directory containing test cases")
	return cmd
}
