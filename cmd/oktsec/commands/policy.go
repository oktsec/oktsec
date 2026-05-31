package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

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
		nodeID       string
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
			if bundlePath == "" {
				return fmt.Errorf("--bundle <path> is required")
			}
			if trustFP == "" {
				return fmt.Errorf("--trust-fingerprint sha256:<fp> is required")
			}
			if allowPartial && !dryRun {
				return fmt.Errorf("--allow-partial is only valid with --dry-run; a real apply never applies partially")
			}

			if err := safefile.RejectSymlink(bundlePath); err != nil {
				return fmt.Errorf("bundle path not usable: %w", err)
			}
			raw, err := safefile.ReadFileMax(bundlePath, maxPolicyBundleApplyBytes)
			if err != nil {
				return fmt.Errorf("read bundle: %w", err)
			}

			// Dispatch by schema_version: a v1 bundle takes the unchanged v1 path
			// (which requires --agent); a v2 bundle takes the v2 path (governance
			// carries selectors, so --agent is ignored and --node-id binds the
			// target).
			res, verr := policybundle.Verify(raw, trustFP)
			if verr != nil {
				return emitApplyFailure(cmd, jsonOut, dryRun, verr)
			}
			if res.SchemaVersion == policybundle.SchemaVersionV2 {
				return runPolicyApplyV2(cmd, res.V2, nodeID, dryRun, jsonOut, allowPartial)
			}

			if agent == "" {
				return fmt.Errorf("--agent <name> is required (apply targets exactly one agent for gateway/egress scope)")
			}
			v := res.V1

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
	f.StringVar(&agent, "agent", "", "v1 only: the single agent gateway/egress changes apply to (ignored for v2 bundles, which carry selectors)")
	f.StringVar(&nodeID, "node-id", "", "v2 only: this node's id, used to bind a node-scoped bundle's target (required when the bundle is node-scoped)")
	f.BoolVar(&dryRun, "dry-run", false, "compute and print the projection without writing; omit to apply in place")
	f.BoolVar(&jsonOut, "json", false, "emit the plan/result as JSON")
	f.BoolVar(&allowPartial, "allow-partial", false, "dry-run only: exit 0 even when the bundle has unsupported semantics")
	return cmd
}

// runPolicyApplyV2 handles a verified policy_bundle.v2: target binding,
// projection, anti-rollback against the adjacent state file, no-partial apply,
// and the post-success state write. Same flag contract as v1 (--dry-run,
// --allow-partial dry-run only, --json), plus --node-id for target binding.
func runPolicyApplyV2(cmd *cobra.Command, v *policybundle.VerifiedBundleV2, nodeID string, dryRun, jsonOut, allowPartial bool) error {
	if cfgFile == "" {
		return fmt.Errorf("could not resolve a config path (set --config or $OKTSEC_CONFIG)")
	}
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

	// Projection. Target binding (scope/node_id) is checked inside DryRunV2
	// before any work, so a mismatch yields no plan and no write.
	plan, perr := apply.DryRunV2(v, cfg, nodeID, cfgFile)
	if perr != nil && !errors.Is(perr, apply.ErrUnsupported) {
		// Target mismatch, missing agent, or invalid projected config: no plan.
		return emitApplyFailure(cmd, jsonOut, dryRun, perr)
	}
	// Some ErrUnsupported failures occur BEFORE a plan is built (the deny-all
	// sentinel collision in the local config fails closed in DryRunV2 and returns
	// nil, ErrUnsupported). The plan emitters below dereference plan, so route a
	// nil plan through emitApplyFailure rather than panicking.
	if plan == nil {
		return emitApplyFailure(cmd, jsonOut, dryRun, perr)
	}

	if dryRun {
		emitPlanV2(cmd, jsonOut, plan)
		if errors.Is(perr, apply.ErrUnsupported) && !allowPartial {
			return perr
		}
		return nil
	}

	// Real apply. Unsupported semantics always fail with no write.
	if errors.Is(perr, apply.ErrUnsupported) {
		emitApplyResultV2(cmd, jsonOut, plan, "", false)
		return perr
	}

	// Anti-rollback: read state BEFORE writing; advance it only after success.
	state, serr := apply.LoadPolicyState(cfgFile)
	if serr != nil {
		return emitApplyFailure(cmd, jsonOut, false, serr)
	}
	switch state.EvaluateRollback(plan.Scope, plan.NodeID, plan.AssignmentID, plan.RollbackOf, plan.Sequence) {
	case apply.RollbackRefuse:
		// Emit a single structured failure (no preceding result object), so
		// --json stdout stays one JSON document.
		err := fmt.Errorf("%w: sequence %d is not greater than the last applied sequence for this target and rollback_of does not name the current assignment",
			apply.ErrPolicyRollbackRefused, plan.Sequence)
		return emitApplyFailure(cmd, jsonOut, false, err)
	default:
		// fresh, advance, signed rollback, or idempotent reapply: proceed.
	}

	// No config change: write no config and no backup, but STILL advance the
	// anti-rollback state. The bundle passed the rollback gate (it is
	// target-bound and at or above the recorded sequence), so the assignment was
	// accepted; if the persisted sequence did not advance here, a later bundle
	// with a sequence lower than this accepted no-op but higher than the stale
	// state could pass EvaluateRollback and overwrite the policy. Advancing on a
	// no-op writes only the state file (atomic, 0600), never the config. A failed
	// state write is surfaced loudly.
	if len(plan.Changes) == 0 {
		state.Record(plan.Scope, plan.NodeID, plan.AssignmentID, time.Now().UTC().Format(time.RFC3339), plan.Sequence)
		if err := apply.SavePolicyState(cfgFile, state); err != nil {
			return emitApplyFailure(cmd, jsonOut, false,
				fmt.Errorf("no config change, but anti-rollback state write failed: %w", err))
		}
		emitApplyResultV2(cmd, jsonOut, plan, "", false)
		return nil
	}

	backupPath, cerr := apply.CommitV2(plan, cfgFile)
	if cerr != nil {
		return emitApplyFailure(cmd, jsonOut, false, cerr)
	}

	// Advance the anti-rollback state ONLY after CommitV2 succeeded.
	state.Record(plan.Scope, plan.NodeID, plan.AssignmentID, time.Now().UTC().Format(time.RFC3339), plan.Sequence)
	if err := apply.SavePolicyState(cfgFile, state); err != nil {
		// The config was written but the state failed to persist. Surface it
		// loudly: a re-apply of the same bundle is idempotent, and a later stale
		// bundle is still refused on the NEXT successful state write, but the
		// operator must know the state file did not advance.
		return emitApplyFailure(cmd, jsonOut, false,
			fmt.Errorf("config applied (backup %q) but anti-rollback state write failed: %w", backupPath, err))
	}
	emitApplyResultV2(cmd, jsonOut, plan, backupPath, true)
	return nil
}

// emitPlanV2 prints the v2 dry-run plan as JSON (when --json) or a short summary.
func emitPlanV2(cmd *cobra.Command, jsonOut bool, p *apply.PlanV2) {
	out := cmd.OutOrStdout()
	if jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(p)
		return
	}
	fmt.Fprintf(out, "dry-run (v2): %s v%s (%s) -> %s\n", p.PolicyID, p.PolicyVersion, p.Mode, p.TargetConfig)
	fmt.Fprintf(out, "  assignment %s, scope %s, node %q, sequence %d\n", p.AssignmentID, p.Scope, p.NodeID, p.Sequence)
	fmt.Fprintf(out, "  %d change(s), %d unsupported\n", len(p.Changes), len(p.Unsupported))
	for _, c := range p.Changes {
		switch c.Kind {
		case "rule_override":
			fmt.Fprintf(out, "  - [%s] rule %s -> %s\n", c.DimMode, c.ID, c.Action)
		case "rule_reset_default":
			fmt.Fprintf(out, "  - [%s] rule %s -> severity default (local override removed)\n", c.DimMode, c.ID)
		case "agent_suspended":
			fmt.Fprintf(out, "  - [%s] %s (agent %s): %v\n", c.DimMode, c.Kind, c.Agent, c.BoolValue)
		case "agent_scan_profile":
			fmt.Fprintf(out, "  - [%s] %s (agent %s): %s\n", c.DimMode, c.Kind, c.Agent, c.Value)
		default:
			fmt.Fprintf(out, "  - [%s] %s (agent %s): %d\n", c.DimMode, c.Kind, c.Agent, c.Count)
		}
	}
	for _, u := range p.Unsupported {
		fmt.Fprintf(out, "  ! unsupported: %s - %s\n", u.Kind, u.Detail)
	}
}

// applyOutcomeV2 is the JSON contract for a real v2 `policy apply`.
type applyOutcomeV2 struct {
	Applied       bool                `json:"applied"`
	DryRun        bool                `json:"dry_run"`
	Changed       bool                `json:"changed"`
	SchemaVersion string              `json:"schema_version"`
	PolicyHash    string              `json:"policy_hash"`
	PolicyID      string              `json:"policy_id"`
	PolicyVersion string              `json:"policy_version"`
	Mode          string              `json:"mode"`
	TargetConfig  string              `json:"target_config"`
	AssignmentID  string              `json:"assignment_id"`
	Scope         string              `json:"scope"`
	NodeID        string              `json:"node_id"`
	Sequence      int64               `json:"sequence"`
	BackupPath    string              `json:"backup_path"`
	Changes       []apply.ChangeV2    `json:"changes"`
	Unsupported   []apply.Unsupported `json:"unsupported"`
}

// emitApplyResultV2 prints the real v2-apply outcome as JSON or a human summary.
func emitApplyResultV2(cmd *cobra.Command, jsonOut bool, p *apply.PlanV2, backupPath string, applied bool) {
	out := cmd.OutOrStdout()
	if jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(applyOutcomeV2{
			Applied:       applied,
			DryRun:        false,
			Changed:       applied,
			SchemaVersion: p.SchemaVersion,
			PolicyHash:    p.PolicyHash,
			PolicyID:      p.PolicyID,
			PolicyVersion: p.PolicyVersion,
			Mode:          p.Mode,
			TargetConfig:  p.TargetConfig,
			AssignmentID:  p.AssignmentID,
			Scope:         p.Scope,
			NodeID:        p.NodeID,
			Sequence:      p.Sequence,
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
				fmt.Fprintf(out, "  ! %s - %s\n", u.Kind, u.Detail)
			}
			return
		}
		fmt.Fprintf(out, "no changes: config already on policy %s v%s, nothing written\n", p.PolicyID, p.PolicyVersion)
		return
	}
	fmt.Fprintf(out, "policy applied (v2)\n")
	fmt.Fprintf(out, "  policy_hash: %s\n", p.PolicyHash)
	fmt.Fprintf(out, "  assignment: %s (seq %d)\n", p.AssignmentID, p.Sequence)
	fmt.Fprintf(out, "  backup_path: %s\n", backupPath)
	fmt.Fprintf(out, "  changes: %d\n", len(p.Changes))
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
		fmt.Fprintf(out, "  ! unsupported: %s - %s\n", u.Kind, u.Detail)
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
				fmt.Fprintf(out, "  ! %s - %s\n", u.Kind, u.Detail)
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
