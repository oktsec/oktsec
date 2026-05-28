package commands

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/auditcheck"
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

			// Health score. RunChecks returns findings for oktsec itself
			// *and* for every external tool it detects (OpenClaw, MCP
			// servers, NanoClaw, …). The status CLI should report on
			// oktsec first; folding third-party misconfigurations into
			// the headline score pins an otherwise-healthy oktsec
			// install at a C just because the operator has a legacy
			// OpenClaw config elsewhere on disk. Those findings are
			// still surfaced on the dashboard Security Posture page.
			configDir := filepath.Dir(cfgFile)
			if configDir == "." {
				if wd, err := os.Getwd(); err == nil {
					configDir = wd
				}
			}
			findings, detected, _ := auditcheck.RunChecks(cfg, configDir)
			var ownFindings, envFindings []auditcheck.Finding
			for _, f := range findings {
				if f.Product == "" || f.Product == "oktsec" {
					ownFindings = append(ownFindings, f)
				} else {
					envFindings = append(envFindings, f)
				}
			}
			score, grade := auditcheck.ComputeHealthScore(ownFindings)
			fmt.Printf("  Health:        %d/100 (%s)\n", score, grade)
			if len(envFindings) > 0 {
				fmt.Printf("  Environment:   %d finding(s) across detected tools (see dashboard audit page)\n", len(envFindings))
			}
			if len(detected) > 0 {
				fmt.Printf("  Detected:      %s\n", joinDetected(detected))
			}

			// Audit stats. status is read-only: it must never create or
			// migrate the audit DB. If the DB does not exist yet, report
			// nothing rather than materializing an empty file (which would
			// also desync read-only evidence tools like `node snapshot`).
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
			dbPath := defaultDBPath()
			store, err := openReadOnlyAuditStoreIfPresent(dbPath, logger)
			if err == nil && store != nil {
				defer func() { _ = store.Close() }()

				all, qErr := store.Query(audit.QueryOpts{Limit: 100000})
				fmt.Println("  ────────────────────────────────────────")
				if qErr != nil {
					// Strict read-only deliberately skips migrations, so an
					// older DB can hold rows but lack columns the query selects.
					// Never print zero counts in that case — that silently
					// under-reports real data. Report it as unavailable instead.
					fmt.Printf("  Audit stats:   unavailable (%v)\n", qErr)
				} else {
					var delivered, blocked, rejected, quarantined int
					for _, e := range all {
						switch e.Status {
						case audit.StatusDelivered:
							delivered++
						case audit.StatusBlocked:
							blocked++
						case audit.StatusRejected:
							rejected++
						case audit.StatusQuarantined:
							quarantined++
						}
					}

					fmt.Printf("  Total msgs:    %d\n", len(all))
					fmt.Printf("  Delivered:     %d\n", delivered)
					fmt.Printf("  Blocked:       %d\n", blocked)
					fmt.Printf("  Rejected:      %d\n", rejected)
					fmt.Printf("  Quarantined:   %d\n", quarantined)

					if revoked, rErr := store.ListRevokedKeys(); rErr == nil && len(revoked) > 0 {
						fmt.Printf("  Revoked keys:  %d\n", len(revoked))
					}
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

// openReadOnlyAuditStoreIfPresent opens the audit DB strictly read-only and
// only when it already exists. A missing DB returns (nil, nil) so callers can
// skip stats without creating the file. The strict constructor performs no
// schema creation, ANALYZE, or migration, so reporting status never grows or
// migrates an existing (possibly empty or old) DB.
func openReadOnlyAuditStoreIfPresent(dbPath string, logger *slog.Logger) (*audit.Store, error) {
	if _, err := os.Stat(dbPath); err != nil {
		return nil, nil //nolint:nilnil // "absent" is a valid, non-error state here
	}
	return audit.NewStoreReadOnlyStrict(dbPath, logger)
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

// printTopIssues shows the top 3 critical/high findings as a quick summary.
func printTopIssues(findings []auditcheck.Finding) {
	fmt.Println("  ────────────────────────────────────────")
	fmt.Println("  Top issues:")
	shown := 0
	for _, f := range findings {
		if f.Severity < auditcheck.High {
			continue
		}
		prefix := "!!"
		if f.Severity == auditcheck.Critical {
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
				if rf.Severity >= auditcheck.High {
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
