package commands

import (
	"github.com/spf13/cobra"
)

var cfgFile string

func NewRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "oktsec",
		Short: "Security proxy for inter-agent communication",
		Long:  "Oktsec — Identity verification, policy enforcement, and audit trail for AI agent messaging. No LLM. Single binary.",
	}

	root.PersistentFlags().StringVar(&cfgFile, "config", "oktsec.yaml", "config file path")

	root.AddCommand(
		newServeCmd(),
		newGatewayCmd(),
		newKeygenCmd(),
		newKeysCmd(),
		newVerifyCmd(),
		newLogsCmd(),
		newRulesCmd(),
		newDiscoverCmd(),
		newInitCmd(),
		newWrapCmd(),
		newUnwrapCmd(),
		newProxyCmd(),
		newMCPCmd(),
		newEnforceCmd(),
		newStatusCmd(),
		newVersionCmd(),
		newQuarantineCmd(),
		newScanOpenClawCmd(),
		newAuditCmd(),
		newAgentCmd(),
	)

	return root
}
