package commands

import (
	"github.com/oktsec/oktsec/internal/config"
	"github.com/spf13/cobra"
)

var cfgFile string

func NewRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "oktsec",
		Short: "Security proxy for inter-agent communication",
		Long:  "Oktsec — Identity verification, policy enforcement, and audit trail for AI agent messaging. Deterministic-first security with optional LLM-augmented analysis. Single binary.",
		// Bare "oktsec" (no subcommand) runs the same flow as "oktsec run"
		RunE: func(cmd *cobra.Command, args []string) error {
			port, _ := cmd.Flags().GetInt("port")
			bind, _ := cmd.Flags().GetString("bind")
			enforce, _ := cmd.Flags().GetBool("enforce")
			skipWrap, _ := cmd.Flags().GetBool("skip-wrap")
			return executeRun(runOpts{
				port:     port,
				bind:     bind,
				enforce:  enforce,
				skipWrap: skipWrap,
			})
		},
	}

	root.PersistentFlags().StringVar(&cfgFile, "config", "", "config file path (default: cascading resolution)")

	// Resolve config path before any command runs
	root.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		flagExplicit := cmd.Flags().Changed("config")
		resolved, _ := config.ResolveConfigPath(cfgFile, flagExplicit)
		cfgFile = resolved
		return nil
	}

	// Flags for bare "oktsec" invocation (mirrors "oktsec run")
	root.Flags().Int("port", 0, "override server port")
	root.Flags().String("bind", "", "address to bind (default: 127.0.0.1)")
	root.Flags().Bool("enforce", false, "start in enforcement mode")
	root.Flags().Bool("skip-wrap", false, "generate config only, don't modify MCP client configs")

	// Primary command
	root.AddCommand(newRunCmd())

	// Deprecated commands — still work but point to "run"
	setupCmd := newSetupCmd()
	setupCmd.Deprecated = "use 'oktsec run' instead (setup + serve in one step)"
	root.AddCommand(setupCmd)

	serveCmd := newServeCmd()
	serveCmd.Deprecated = "use 'oktsec run' instead (setup + serve in one step)"
	root.AddCommand(serveCmd)

	initCmd := newInitCmd()
	initCmd.Deprecated = "use 'oktsec run' instead (setup + serve in one step)"
	root.AddCommand(initCmd)

	// User-facing commands
	root.AddCommand(
		newDiscoverCmd(),
		newDoctorCmd(),
		newWrapCmd(),
		newUnwrapCmd(),
		newRulesCmd(),
		newLogsCmd(),
		newStatusCmd(),
		newVersionCmd(),
		newQuarantineCmd(),
		newAuditCmd(),
		newAgentCmd(),
		newEnforceCmd(),
		newConnectCmd(),
		newDisconnectCmd(),
		newScanOpenClawCmd(),
	)

	// Internal/advanced commands — hidden from help
	gatewayCmd := newGatewayCmd()
	gatewayCmd.Hidden = true
	root.AddCommand(gatewayCmd)

	proxyCmd := newProxyCmd()
	proxyCmd.Hidden = true
	root.AddCommand(proxyCmd)

	mcpCmd := newMCPCmd()
	mcpCmd.Hidden = true
	root.AddCommand(mcpCmd)

	keygenCmd := newKeygenCmd()
	keygenCmd.Hidden = true
	root.AddCommand(keygenCmd)

	keysCmd := newKeysCmd()
	keysCmd.Hidden = true
	root.AddCommand(keysCmd)

	verifyCmd := newVerifyCmd()
	verifyCmd.Hidden = true
	root.AddCommand(verifyCmd)

	return root
}
