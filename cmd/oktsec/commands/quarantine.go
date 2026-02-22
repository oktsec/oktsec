package commands

import (
	"fmt"
	"log/slog"
	"os"
	"text/tabwriter"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/spf13/cobra"
)

func newQuarantineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "quarantine",
		Short: "Manage the quarantine queue",
		Long:  "List, inspect, approve, or reject quarantined messages held for human review.",
	}

	cmd.AddCommand(
		newQuarantineListCmd(),
		newQuarantineDetailCmd(),
		newQuarantineApproveCmd(),
		newQuarantineRejectCmd(),
	)

	return cmd
}

func newQuarantineListCmd() *cobra.Command {
	var status string
	var limit int

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List quarantined items",
		Example: `  oktsec quarantine list
  oktsec quarantine list --status approved
  oktsec quarantine list --limit 10`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := openAuditStore()
			if err != nil {
				return err
			}
			defer store.Close() //nolint:errcheck

			items, err := store.QuarantineQuery(status, "", limit)
			if err != nil {
				return err
			}

			if len(items) == 0 {
				fmt.Println("No quarantine items found.")
				return nil
			}

			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintf(tw, "ID\tFROM\tTO\tSTATUS\tCREATED\tEXPIRES\n") //nolint:errcheck
			for _, item := range items {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", //nolint:errcheck
					item.ID, item.FromAgent, item.ToAgent, item.Status, item.CreatedAt, item.ExpiresAt)
			}
			return tw.Flush()
		},
	}

	cmd.Flags().StringVar(&status, "status", "pending", "filter by status (pending, approved, rejected, expired)")
	cmd.Flags().IntVar(&limit, "limit", 50, "max items to return")
	return cmd
}

func newQuarantineDetailCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "detail <id>",
		Short: "Show quarantine item details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := openAuditStore()
			if err != nil {
				return err
			}
			defer store.Close() //nolint:errcheck

			item, err := store.QuarantineByID(args[0])
			if err != nil {
				return err
			}
			if item == nil {
				return fmt.Errorf("quarantine item %q not found", args[0])
			}

			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintf(tw, "ID:\t%s\n", item.ID)             //nolint:errcheck
			fmt.Fprintf(tw, "From:\t%s\n", item.FromAgent)    //nolint:errcheck
			fmt.Fprintf(tw, "To:\t%s\n", item.ToAgent)        //nolint:errcheck
			fmt.Fprintf(tw, "Status:\t%s\n", item.Status)     //nolint:errcheck
			fmt.Fprintf(tw, "Created:\t%s\n", item.CreatedAt) //nolint:errcheck
			fmt.Fprintf(tw, "Expires:\t%s\n", item.ExpiresAt) //nolint:errcheck
			if item.ReviewedBy != "" {
				fmt.Fprintf(tw, "Reviewed By:\t%s\n", item.ReviewedBy) //nolint:errcheck
				fmt.Fprintf(tw, "Reviewed At:\t%s\n", item.ReviewedAt) //nolint:errcheck
			}
			if item.RulesTriggered != "" && item.RulesTriggered != "[]" {
				fmt.Fprintf(tw, "Rules:\t%s\n", item.RulesTriggered) //nolint:errcheck
			}
			_ = tw.Flush()

			fmt.Println("\n--- Content ---")
			fmt.Println(item.Content)
			return nil
		},
	}
}

func newQuarantineApproveCmd() *cobra.Command {
	var reviewer string

	cmd := &cobra.Command{
		Use:   "approve <id>",
		Short: "Approve a quarantined message for delivery",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := openAuditStore()
			if err != nil {
				return err
			}
			defer store.Close() //nolint:errcheck

			if err := store.QuarantineApprove(args[0], reviewer); err != nil {
				return err
			}
			fmt.Printf("Approved: %s\n", args[0])
			return nil
		},
	}

	cmd.Flags().StringVar(&reviewer, "reviewer", "cli", "name of the reviewer")
	return cmd
}

func newQuarantineRejectCmd() *cobra.Command {
	var reviewer string

	cmd := &cobra.Command{
		Use:   "reject <id>",
		Short: "Reject a quarantined message",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := openAuditStore()
			if err != nil {
				return err
			}
			defer store.Close() //nolint:errcheck

			if err := store.QuarantineReject(args[0], reviewer); err != nil {
				return err
			}
			fmt.Printf("Rejected: %s\n", args[0])
			return nil
		},
	}

	cmd.Flags().StringVar(&reviewer, "reviewer", "cli", "name of the reviewer")
	return cmd
}

func openAuditStore() (*audit.Store, error) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := audit.NewStore("oktsec.db", logger)
	if err != nil {
		return nil, fmt.Errorf("opening audit db: %w", err)
	}
	return store, nil
}
