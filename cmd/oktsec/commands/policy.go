package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/oktsec/oktsec/internal/apply"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/policybundle"
	"github.com/oktsec/oktsec/internal/safefile"
	"github.com/spf13/cobra"
)

// maxPolicyBundleApplyBytes caps the signed bundle file the apply path reads.
const maxPolicyBundleApplyBytes = 1 << 20 // 1 MiB

// newPolicyCmd builds `oktsec policy`. `apply` verifies a signed
// policy_bundle.v1 and projects its supported subset onto the local config:
// `--dry-run` reports the exact changes without writing; without `--dry-run`
// it safely writes the config in place (backup + atomic replace).
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
		Short: "Project a signed policy bundle onto the local config (dry-run or in place)",
		Long: "Verify a signed policy_bundle.v1 against a trust fingerprint and project its " +
			"supported subset (rules globally; gateway tools and egress for one --agent) onto " +
			"the local config. With --dry-run it computes and validates the target config in " +
			"memory and prints the exact changes, writing nothing. Without --dry-run it writes " +
			"the config in place after verification and validation, creating a timestamped " +
			"backup first and replacing the file atomically. A no-op writes nothing; a missing " +
			"config is an error (apply never creates a config).",
		Example: "  oktsec policy apply --bundle voice-ai-prod.signed.json \\\n" +
			"    --trust-fingerprint sha256:<policy-key-fp> --config oktsec.yaml \\\n" +
			"    --agent voice-ai --dry-run --json",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
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
				return emitApplyFailure(cmd, jsonOut, dryRun, verr)
			}

			// cfgFile is the root's cascading-resolved config path (honors
			// --config, $OKTSEC_CONFIG, and the home default) set by
			// PersistentPreRunE — do not shadow it with a command-local flag.
			if cfgFile == "" {
				return fmt.Errorf("could not resolve a config path (set --config or $OKTSEC_CONFIG)")
			}
			// Real apply mutates the config, so it requires an explicit
			// --config target — never a cascaded default (cwd/home) the
			// operator did not name. It must also be a writable regular file
			// BEFORE reading it; a missing config is a hard error (apply never
			// creates a config — spec 7A.3 §5.2).
			if !dryRun {
				if !cfgFileExplicit {
					return fmt.Errorf("real apply requires an explicit, non-empty --config <path> (refusing to mutate a cascaded default config)")
				}
				if err := ensureWritableConfigPath(cfgFile); err != nil {
					return emitApplyFailure(cmd, jsonOut, false, err)
				}
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
				return emitApplyFailure(cmd, jsonOut, dryRun, perr)
			}

			if dryRun {
				// Print the plan; fail on unsupported unless --allow-partial.
				emitPlan(cmd, jsonOut, plan)
				if errors.Is(perr, apply.ErrUnsupported) && !allowPartial {
					return perr
				}
				return nil
			}

			// --- Real in-place apply (spec 7A.3). ---
			// Unsupported semantics always fail with no write; --allow-partial
			// is a dry-run-only affordance and never enables a partial apply.
			if errors.Is(perr, apply.ErrUnsupported) {
				emitApplyResult(cmd, jsonOut, plan, "", false)
				return perr
			}
			// No changes: write nothing, no backup, report changed:false.
			if len(plan.Changes) == 0 {
				emitApplyResult(cmd, jsonOut, plan, "", false)
				return nil
			}
			backupPath, cerr := apply.Commit(plan, cfgFile)
			if cerr != nil {
				return emitApplyFailure(cmd, jsonOut, false, cerr)
			}
			emitApplyResult(cmd, jsonOut, plan, backupPath, true)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&bundlePath, "bundle", "", "path to the signed policy_bundle.v1 JSON")
	f.StringVar(&trustFP, "trust-fingerprint", "", "sha256:<fp> the bundle's signing key must match")
	f.StringVar(&agent, "agent", "", "the single agent gateway/egress changes apply to")
	f.BoolVar(&dryRun, "dry-run", false, "compute and print the projection without writing; omit to apply in place")
	f.BoolVar(&jsonOut, "json", false, "emit the plan/result as JSON")
	f.BoolVar(&allowPartial, "allow-partial", false, "dry-run only: exit 0 even when the bundle has unsupported semantics")
	return cmd
}

// ensureWritableConfigPath checks the config path is a writable regular file
// before a real apply: a missing config is a hard error (apply never creates a
// config), and symlinks/directories are rejected so no write follows a link.
func ensureWritableConfigPath(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("config %q does not exist; policy apply does not create configs (run setup first)", path)
		}
		return fmt.Errorf("stat config %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("config %q is a symlink (rejected for security)", path)
	}
	if info.IsDir() {
		return fmt.Errorf("config %q is a directory, not a file", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("config %q is not a regular file", path)
	}
	return nil
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

// applyOutcome is the JSON contract for a real `policy apply` (write or no-op).
type applyOutcome struct {
	Applied       bool                `json:"applied"`
	DryRun        bool                `json:"dry_run"`
	Changed       bool                `json:"changed"`
	PolicyHash    string              `json:"policy_hash"`
	PolicyID      string              `json:"policy_id"`
	PolicyVersion string              `json:"policy_version"`
	Mode          string              `json:"mode"`
	TargetConfig  string              `json:"target_config"`
	Agent         string              `json:"agent"`
	BackupPath    string              `json:"backup_path"`
	Changes       []apply.Change      `json:"changes"`
	Unsupported   []apply.Unsupported `json:"unsupported"`
}

// emitApplyResult prints the real-apply outcome as JSON (when --json) or a
// concise human summary. applied==true means the config was written; a backup
// path is present only then.
func emitApplyResult(cmd *cobra.Command, jsonOut bool, p *apply.Plan, backupPath string, applied bool) {
	out := cmd.OutOrStdout()
	if jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(applyOutcome{
			Applied:       applied,
			DryRun:        false,
			Changed:       applied,
			PolicyHash:    p.PolicyHash,
			PolicyID:      p.PolicyID,
			PolicyVersion: p.PolicyVersion,
			Mode:          p.Mode,
			TargetConfig:  p.TargetConfig,
			Agent:         p.Agent,
			BackupPath:    backupPath,
			Changes:       p.Changes,
			Unsupported:   p.Unsupported,
		})
		return
	}
	if !applied {
		if len(p.Unsupported) > 0 {
			fmt.Fprintf(out, "not applied: %d unsupported semantic(s), config unchanged\n", len(p.Unsupported))
			for _, u := range p.Unsupported {
				fmt.Fprintf(out, "  ! %s — %s\n", u.Kind, u.Detail)
			}
			return
		}
		fmt.Fprintf(out, "no changes: config already on policy %s v%s, nothing written\n", p.PolicyID, p.PolicyVersion)
		return
	}
	fmt.Fprintf(out, "policy applied\n")
	fmt.Fprintf(out, "  policy_hash: %s\n", p.PolicyHash)
	fmt.Fprintf(out, "  agent: %s\n", p.Agent)
	fmt.Fprintf(out, "  backup_path: %s\n", backupPath)
	fmt.Fprintf(out, "  changes: %d\n", len(p.Changes))
}

// emitApplyFailure prints a structured JSON failure (with a stable reject_code
// for bundle-verification errors) and returns the error so the exit is
// non-zero. dryRun records which mode the failure occurred in.
func emitApplyFailure(cmd *cobra.Command, jsonOut, dryRun bool, err error) error {
	if jsonOut {
		failure := map[string]any{"applied": false, "dry_run": dryRun, "error": err.Error()}
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
