package commands

import (
	"fmt"
	"log/slog"
	"os"
	"text/tabwriter"
	"time"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/spf13/cobra"
)

func newLogsCmd() *cobra.Command {
	var status, agent, since string
	var unverified bool
	var limit int

	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Query the audit log",
		Example: `  oktsec logs
  oktsec logs --status blocked
  oktsec logs --agent research-agent
  oktsec logs --unverified
  oktsec logs --since 1h`,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

			store, err := audit.NewStore("oktsec.db", logger)
			if err != nil {
				return fmt.Errorf("opening audit db: %w", err)
			}
			defer store.Close() //nolint:errcheck // best-effort cleanup

			var sinceTime string
			if since != "" {
				dur, err := time.ParseDuration(since)
				if err != nil {
					return fmt.Errorf("invalid duration %q: %w", since, err)
				}
				sinceTime = time.Now().Add(-dur).UTC().Format(time.RFC3339)
			}

			entries, err := store.Query(audit.QueryOpts{
				Status:     status,
				Agent:      agent,
				Unverified: unverified,
				Since:      sinceTime,
				Limit:      limit,
			})
			if err != nil {
				return err
			}

			if len(entries) == 0 {
				fmt.Println("No audit entries found.")
				return nil
			}

			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintf(tw, "TIME\tFROM\tTO\tSTATUS\tDECISION\tVERIFIED\tLATENCY\n") //nolint:errcheck // CLI output
			for _, e := range entries {
				verified := "unsigned"
				switch e.SignatureVerified {
				case 1:
					verified = "yes"
				case -1:
					verified = "INVALID"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%dms\n", //nolint:errcheck // CLI output
					e.Timestamp, e.FromAgent, e.ToAgent, e.Status, e.PolicyDecision, verified, e.LatencyMs)
			}
			return tw.Flush()
		},
	}

	cmd.Flags().StringVar(&status, "status", "", "filter by status (delivered, blocked, quarantined, rejected)")
	cmd.Flags().StringVar(&agent, "agent", "", "filter by agent name")
	cmd.Flags().BoolVar(&unverified, "unverified", false, "show only unverified messages")
	cmd.Flags().StringVar(&since, "since", "", "show entries since duration (e.g. 1h, 30m)")
	cmd.Flags().IntVar(&limit, "limit", 50, "max entries to return")
	return cmd
}
