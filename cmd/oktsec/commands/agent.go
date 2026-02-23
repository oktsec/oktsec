package commands

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/spf13/cobra"
)

func newAgentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Manage agent lifecycle (suspend, unsuspend, list)",
	}

	cmd.AddCommand(
		newAgentSuspendCmd(),
		newAgentUnsuspendCmd(),
		newAgentListCmd(),
	)

	return cmd
}

func newAgentSuspendCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "suspend <name>",
		Short: "Suspend an agent (reject all messages)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return setAgentSuspended(args[0], true)
		},
	}
}

func newAgentUnsuspendCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unsuspend <name>",
		Short: "Unsuspend an agent (allow messages again)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return setAgentSuspended(args[0], false)
		},
	}
}

func newAgentListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all configured agents and their status",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return err
			}

			if len(cfg.Agents) == 0 {
				fmt.Println("No agents configured.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tSTATUS\tCAN MESSAGE\tBLOCKED CONTENT")

			names := make([]string, 0, len(cfg.Agents))
			for name := range cfg.Agents {
				names = append(names, name)
			}
			sort.Strings(names)

			for _, name := range names {
				agent := cfg.Agents[name]
				status := "active"
				if agent.Suspended {
					status = "suspended"
				}
				canMsg := "*"
				if len(agent.CanMessage) > 0 {
					canMsg = fmt.Sprintf("%v", agent.CanMessage)
				}
				blocked := "-"
				if len(agent.BlockedContent) > 0 {
					blocked = fmt.Sprintf("%v", agent.BlockedContent)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", name, status, canMsg, blocked)
			}
			return w.Flush()
		},
	}
}

func setAgentSuspended(name string, suspended bool) error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return err
	}

	agent, ok := cfg.Agents[name]
	if !ok {
		return fmt.Errorf("agent %q not found in config", name)
	}

	agent.Suspended = suspended
	cfg.Agents[name] = agent

	if err := cfg.Save(cfgFile); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	if suspended {
		fmt.Printf("Agent %q suspended. All messages will be rejected.\n", name)
	} else {
		fmt.Printf("Agent %q unsuspended. Messages will be processed normally.\n", name)
	}
	return nil
}
