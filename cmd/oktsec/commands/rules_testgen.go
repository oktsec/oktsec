package commands

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func newRulesTestgenCmd() *cobra.Command {
	var outDir string

	cmd := &cobra.Command{
		Use:   "testgen",
		Short: "Generate rule test cases from production blocked/quarantined events",
		Long: `Reads exported testcases from ~/.oktsec/testcases/ and generates
deduplicated Aguara-format YAML test cases for inclusion in the test suite.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			tcDir, err := audit.TestcaseDir()
			if err != nil {
				return err
			}

			cases, err := audit.LoadTestcases(tcDir)
			if err != nil {
				return fmt.Errorf("loading testcases: %w", err)
			}

			if len(cases) == 0 {
				fmt.Println("No testcases found. Enable export with audit.export_blocked: true in config.")
				return nil
			}

			// Deduplicate by rule_id + content hash
			type key struct {
				ruleID      string
				contentHash string
			}
			seen := make(map[key]bool)
			var unique []audit.Testcase

			for _, tc := range cases {
				h := fmt.Sprintf("%x", sha256.Sum256([]byte(tc.Content)))[:16]
				k := key{ruleID: tc.RuleID, contentHash: h}
				if !seen[k] {
					seen[k] = true
					unique = append(unique, tc)
				}
			}

			// Create output dir
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return fmt.Errorf("creating output dir: %w", err)
			}

			written := 0
			for i, tc := range unique {
				safeRule := strings.ReplaceAll(strings.ToLower(tc.RuleID), "/", "-")
				filename := fmt.Sprintf("%s-%s-%03d.yaml", tc.Type, safeRule, i+1)
				path := filepath.Join(outDir, filename)

				data, err := yaml.Marshal(tc)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  skip %s: %v\n", tc.RuleID, err)
					continue
				}

				if err := os.WriteFile(path, data, 0o644); err != nil {
					fmt.Fprintf(os.Stderr, "  skip %s: %v\n", path, err)
					continue
				}
				written++
			}

			fmt.Printf("Generated %d test cases from %d events (%d deduplicated) in %s/\n",
				written, len(cases), len(cases)-len(unique), outDir)
			return nil
		},
	}

	cmd.Flags().StringVarP(&outDir, "output", "o", "rules/testcases", "output directory")
	return cmd
}
