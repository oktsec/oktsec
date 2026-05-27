package commands

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/oktsec/oktsec/internal/apply"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/policybundle"
	"github.com/oktsec/oktsec/internal/safefile"
	"github.com/spf13/cobra"
)

// maxPolicyBundleApplyBytes caps the signed bundle file the apply path reads.
const maxPolicyBundleApplyBytes = 1 << 20 // 1 MiB

// newPolicyCmd builds `oktsec policy`. Order 7A.2 ships `apply --dry-run`:
// it verifies a signed policy_bundle.v1 and projects its supported subset
// onto the local config in memory, reporting the exact changes WITHOUT
// writing anything. The safe in-place write lands in a later slice.
func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Apply signed policy bundles to the local Oktsec runtime config",
	}
	cmd.AddCommand(newPolicyApplyCmd())
	return cmd
}

func newPolicyApplyCmd() *cobra.Command {
	var (
		bundlePath   string
		trustFP      string
		agent        string
		dryRun       bool
		jsonOut      bool
		allowPartial bool
	)
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Project a signed policy bundle onto the local config (dry-run)",
		Long: "Verify a signed policy_bundle.v1 against a trust fingerprint and project its " +
			"supported subset (rules globally; gateway tools and egress for one --agent) onto " +
			"the local config. Order 7A.2 supports --dry-run only: it computes and validates the " +
			"target config in memory and prints the exact changes, writing nothing.",
		Example: "  oktsec policy apply --bundle voice-ai-prod.signed.json \\\n" +
			"    --trust-fingerprint sha256:<policy-key-fp> --config oktsec.yaml \\\n" +
			"    --agent voice-ai --dry-run --json",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !dryRun {
				return fmt.Errorf("policy apply currently supports --dry-run only (in-place apply lands in a later release)")
			}
			if agent == "" {
				return fmt.Errorf("--agent <name> is required (apply targets exactly one agent for gateway/egress scope)")
			}
			if bundlePath == "" {
				return fmt.Errorf("--bundle <path> is required")
			}
			if trustFP == "" {
				return fmt.Errorf("--trust-fingerprint sha256:<fp> is required")
			}

			if err := safefile.RejectSymlink(bundlePath); err != nil {
				return fmt.Errorf("bundle path not usable: %w", err)
			}
			raw, err := safefile.ReadFileMax(bundlePath, maxPolicyBundleApplyBytes)
			if err != nil {
				return fmt.Errorf("read bundle: %w", err)
			}

			v, verr := policybundle.VerifyBundle(raw, trustFP)
			if verr != nil {
				return emitApplyFailure(cmd, jsonOut, verr)
			}

			// cfgFile is the root's cascading-resolved config path (honors
			// --config, $OKTSEC_CONFIG, and the home default) set by
			// PersistentPreRunE — do not shadow it with a command-local flag.
			if cfgFile == "" {
				return fmt.Errorf("could not resolve a config path (set --config or $OKTSEC_CONFIG)")
			}
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("load config %q: %w", cfgFile, err)
			}
			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("current config %q is invalid: %w", cfgFile, err)
			}

			plan, perr := apply.DryRun(v, cfg, agent, cfgFile)
			if perr != nil && !errors.Is(perr, apply.ErrUnsupported) {
				// Missing agent or an invalid projected config: no plan to show.
				return emitApplyFailure(cmd, jsonOut, perr)
			}
			// On ErrUnsupported the plan is non-nil and lists the offending
			// semantics; print it, then fail unless --allow-partial.
			emitPlan(cmd, jsonOut, plan)
			if errors.Is(perr, apply.ErrUnsupported) && !allowPartial {
				return perr
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&bundlePath, "bundle", "", "path to the signed policy_bundle.v1 JSON")
	f.StringVar(&trustFP, "trust-fingerprint", "", "sha256:<fp> the bundle's signing key must match")
	f.StringVar(&agent, "agent", "", "the single agent gateway/egress changes apply to")
	f.BoolVar(&dryRun, "dry-run", false, "compute and print the projection without writing (required)")
	f.BoolVar(&jsonOut, "json", false, "emit the plan as JSON")
	f.BoolVar(&allowPartial, "allow-partial", false, "proceed (exit 0) even when the bundle has unsupported semantics")
	return cmd
}

// emitPlan prints the dry-run plan as JSON (when --json) or a short summary.
func emitPlan(cmd *cobra.Command, jsonOut bool, p *apply.Plan) {
	out := cmd.OutOrStdout()
	if jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(p)
		return
	}
	fmt.Fprintf(out, "dry-run: %s v%s (%s) → %s, agent %s\n", p.PolicyID, p.PolicyVersion, p.Mode, p.TargetConfig, p.Agent)
	fmt.Fprintf(out, "  %d change(s), %d unsupported\n", len(p.Changes), len(p.Unsupported))
	for _, c := range p.Changes {
		switch c.Kind {
		case "rule_override":
			fmt.Fprintf(out, "  - rule %s → %s\n", c.ID, c.Action)
		case "rule_reset_default":
			fmt.Fprintf(out, "  - rule %s → severity default (local override removed)\n", c.ID)
		default:
			fmt.Fprintf(out, "  - %s (agent %s): %d\n", c.Kind, c.Agent, c.Count)
		}
	}
	for _, u := range p.Unsupported {
		fmt.Fprintf(out, "  ! unsupported: %s — %s\n", u.Kind, u.Detail)
	}
}

// emitApplyFailure prints a structured JSON failure (with a stable reject_code
// for bundle-verification errors) and returns the error so the exit is
// non-zero.
func emitApplyFailure(cmd *cobra.Command, jsonOut bool, err error) error {
	if jsonOut {
		failure := map[string]any{"applied": false, "dry_run": true, "error": err.Error()}
		var re *policybundle.RejectError
		if errors.As(err, &re) {
			failure["reject_code"] = string(re.Code)
		}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		_ = enc.Encode(failure)
	}
	return err
}
