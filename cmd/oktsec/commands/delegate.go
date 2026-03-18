package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/oktsec/oktsec/internal/identity"
	"github.com/spf13/cobra"
)

func newDelegateCmd() *cobra.Command {
	var (
		delegator    string
		delegate     string
		scope        []string
		tools        []string
		ttl          string
		keysDir      string
		parentToken  string
		chainDepth   int
		maxDepth     int
		outputFormat string
	)

	cmd := &cobra.Command{
		Use:   "delegate",
		Short: "Create a signed delegation token",
		Long: `Creates a cryptographically signed delegation token that authorizes
one agent to act on behalf of another. Tokens can be chained to create
a verifiable authorization path from human to any sub-agent.

The delegator's private key (from --keys-dir) signs the token.`,
		Example: `  # Root delegation: human authorizes agent-a
  oktsec delegate --from human --to agent-a --scope "*" --ttl 4h

  # Chained: agent-a delegates to agent-b with narrower scope
  oktsec delegate --from agent-a --to agent-b --scope target-x --tools Read,Write \
    --parent <token-id-from-previous> --depth 1

  # Output as base64 for X-Oktsec-Delegation header
  oktsec delegate --from human --to agent-a --scope "*" --format header`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if delegator == "" || delegate == "" {
				return fmt.Errorf("--from and --to are required")
			}

			dir := keysDir
			if dir == "" {
				dir = "keys"
			}

			// Load delegator's private key
			kp, err := identity.LoadKeypair(dir, delegator)
			if err != nil {
				return fmt.Errorf("loading %s keypair from %s: %w", delegator, dir, err)
			}

			// Parse TTL
			ttlDur := 4 * time.Hour
			if ttl != "" {
				ttlDur, err = time.ParseDuration(ttl)
				if err != nil {
					return fmt.Errorf("invalid TTL %q: %w", ttl, err)
				}
			}

			if len(scope) == 0 {
				scope = []string{"*"}
			}

			token := identity.CreateChainedDelegation(
				kp.PrivateKey, delegator, delegate,
				scope, tools, ttlDur,
				parentToken, chainDepth, maxDepth,
			)

			switch outputFormat {
			case "header":
				// Output as base64 for use in X-Oktsec-Delegation header
				chain := identity.DelegationChain{*token}
				data, _ := json.Marshal(chain)
				fmt.Println(base64.StdEncoding.EncodeToString(data))
			case "json":
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				_ = enc.Encode(token)
			default:
				fmt.Printf("Token ID:    %s\n", token.TokenID)
				fmt.Printf("Delegator:   %s\n", token.Delegator)
				fmt.Printf("Delegate:    %s\n", token.Delegate)
				fmt.Printf("Scope:       %v\n", token.Scope)
				if len(token.AllowedTools) > 0 {
					fmt.Printf("Tools:       %v\n", token.AllowedTools)
				}
				fmt.Printf("Depth:       %d / %d\n", token.ChainDepth, token.MaxDepth)
				fmt.Printf("Expires:     %s\n", token.ExpiresAt.Format(time.RFC3339))
				if token.ParentTokenID != "" {
					fmt.Printf("Parent:      %s\n", token.ParentTokenID[:16]+"...")
				}
				fmt.Printf("\nUse --format json or --format header for machine output.\n")
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&delegator, "from", "", "delegator agent name (must have keypair)")
	cmd.Flags().StringVar(&delegate, "to", "", "delegate agent name")
	cmd.Flags().StringSliceVar(&scope, "scope", nil, "allowed recipients (default: *)")
	cmd.Flags().StringSliceVar(&tools, "tools", nil, "allowed tools (default: all)")
	cmd.Flags().StringVar(&ttl, "ttl", "4h", "token TTL (e.g., 1h, 30m)")
	cmd.Flags().StringVar(&keysDir, "keys-dir", "", "directory with agent keypairs")
	cmd.Flags().StringVar(&parentToken, "parent", "", "parent token ID for chain linking")
	cmd.Flags().IntVar(&chainDepth, "depth", 0, "chain depth (0 for root)")
	cmd.Flags().IntVar(&maxDepth, "max-depth", 3, "maximum delegation depth")
	cmd.Flags().StringVar(&outputFormat, "format", "text", "output format: text, json, header")

	return cmd
}
