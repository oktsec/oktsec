package commands

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/identity"
	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show proxy status and configuration summary",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			mode := "observe"
			if cfg.Identity.RequireSignature {
				mode = "enforce"
			}

			fmt.Println()
			fmt.Println("  oktsec status")
			fmt.Println("  ────────────────────────────────────────")
			fmt.Printf("  Mode:          %s\n", mode)
			fmt.Printf("  Agents:        %d configured\n", len(cfg.Agents))
			fmt.Printf("  Signatures:    %s\n", boolToRequired(cfg.Identity.RequireSignature))
			fmt.Printf("  Port:          %d\n", cfg.Server.Port)
			fmt.Printf("  Config:        %s\n", cfgFile)

			// Key stats
			if cfg.Identity.KeysDir != "" {
				keys := identity.NewKeyStore()
				if err := keys.LoadFromDir(cfg.Identity.KeysDir); err == nil {
					fmt.Printf("  Keys:          %d loaded\n", keys.Count())
				}
			}

			// Health score
			configDir := filepath.Dir(cfgFile)
			if configDir == "." {
				if wd, err := os.Getwd(); err == nil {
					configDir = wd
				}
			}
			findings, detected := runAuditChecks(cfg, configDir)
			score, grade := computeHealthScore(findings)
			fmt.Printf("  Health:        %d/100 (%s)\n", score, grade)
			if len(detected) > 0 {
				fmt.Printf("  Detected:      %s\n", joinDetected(detected))
			}

			// Audit stats
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
			store, err := audit.NewStore("oktsec.db", logger)
			if err == nil {
				defer func() { _ = store.Close() }()

				all, _ := store.Query(audit.QueryOpts{Limit: 100000})
				var delivered, blocked, rejected, quarantined int
				for _, e := range all {
					switch e.Status {
					case "delivered":
						delivered++
					case "blocked":
						blocked++
					case "rejected":
						rejected++
					case "quarantined":
						quarantined++
					}
				}

				fmt.Println("  ────────────────────────────────────────")
				fmt.Printf("  Total msgs:    %d\n", len(all))
				fmt.Printf("  Delivered:     %d\n", delivered)
				fmt.Printf("  Blocked:       %d\n", blocked)
				fmt.Printf("  Rejected:      %d\n", rejected)
				fmt.Printf("  Quarantined:   %d\n", quarantined)

				revoked, _ := store.ListRevokedKeys()
				if len(revoked) > 0 {
					fmt.Printf("  Revoked keys:  %d\n", len(revoked))
				}
			}

			// Top issues if not perfect
			if score < 100 {
				printTopIssues(findings)
			}

			fmt.Println()
			return nil
		},
	}
}

func joinDetected(detected []string) string {
	if len(detected) == 0 {
		return "none"
	}
	s := detected[0]
	for i := 1; i < len(detected); i++ {
		s += ", " + detected[i]
	}
	return s
}

// computeHealthScore calculates a 0-100 score from audit findings.
// Penalties: critical=-25, high=-15, medium=-5, low=-2, info=0.
func computeHealthScore(findings []AuditFinding) (int, string) {
	score := 100
	for _, f := range findings {
		switch f.Severity {
		case AuditCritical:
			score -= 25
		case AuditHigh:
			score -= 15
		case AuditMedium:
			score -= 5
		case AuditLow:
			score -= 2
		}
	}
	if score < 0 {
		score = 0
	}

	var grade string
	switch {
	case score >= 90:
		grade = "A"
	case score >= 75:
		grade = "B"
	case score >= 60:
		grade = "C"
	case score >= 40:
		grade = "D"
	default:
		grade = "F"
	}
	return score, grade
}

// printTopIssues shows the top 3 critical/high findings as a quick summary.
func printTopIssues(findings []AuditFinding) {
	fmt.Println("  ────────────────────────────────────────")
	fmt.Println("  Top issues:")
	shown := 0
	for _, f := range findings {
		if f.Severity < AuditHigh {
			continue
		}
		prefix := "!!"
		if f.Severity == AuditCritical {
			prefix = "!!"
		}
		product := ""
		if f.Product != "" {
			product = " (" + f.Product + ")"
		}
		fmt.Printf("    %s [%s] %s%s\n", prefix, f.CheckID, f.Title, product)
		shown++
		if shown >= 3 {
			remaining := 0
			for _, rf := range findings[shown:] {
				if rf.Severity >= AuditHigh {
					remaining++
				}
			}
			if remaining > 0 {
				fmt.Printf("       ... and %d more (run 'oktsec audit' for details)\n", remaining)
			}
			break
		}
	}
}

func boolToRequired(b bool) string {
	if b {
		return "required"
	}
	return "optional"
}
