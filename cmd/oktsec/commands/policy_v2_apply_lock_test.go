package commands

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oktsec/oktsec/internal/apply"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/policybundle"
)

// errAfterCommitInjected is the sentinel a test injects through the
// savePolicyStateAfterCommit seam to simulate a state-write failure that occurs
// after CommitV2 has written the config.
var errAfterCommitInjected = errors.New("injected state persist failure")

// fleetBundleAtSeq builds, signs, and writes a fleet-scoped v2 bundle at the
// given sequence with a unique assignment id, returning its on-disk path and
// the trust fingerprint to verify it. The bundle's voice-ai allowed_tools is set
// to a value unique to the assignment id, so each distinct apply produces a real
// config change (not a no-op), exercising the real-change persist path.
func fleetBundleAtSeq(t *testing.T, dir string, seq int64, assignID string) (bundlePath, fp string) {
	t.Helper()
	body := supportedAgentBodyV2("fleet", "")
	body.Assignment.Sequence = seq
	body.Assignment.AssignmentID = assignID
	// Make the projected change unique per assignment so the apply is never a
	// no-op (which would skip the real-change persist path and its lock-spanned
	// recovery).
	g := agentGovV2cmd("voice-ai")
	g.AllowedTools = policybundle.DimStringSetV2{Mode: "replace", Values: []string{"tool." + assignID}}
	body.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	raw, trustFP := signV2Bundle(t, body)
	p := filepath.Join(dir, "bundle-"+assignID+".signed.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return p, trustFP
}

// applyFleetSeq applies a fleet bundle at seq against configPath and returns the
// command error (nil on success).
func applyFleetSeq(t *testing.T, dir, configPath string, seq int64, assignID string) error {
	t.Helper()
	bundlePath, fp := fleetBundleAtSeq(t, dir, seq, assignID)
	_, err := runPolicyApply(t,
		"--bundle", bundlePath, "--trust-fingerprint", fp,
		"--config", configPath, "--json",
	)
	return err
}

// fleetReplayFloor reads the persisted anti-rollback ReplayFloor for the fleet
// target. The floor is the monotonic high-water that gates plain applies.
func fleetReplayFloor(t *testing.T, configPath string) int64 {
	t.Helper()
	st, err := apply.LoadPolicyState(configPath)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	rec, ok := st.Targets[apply.TargetKey("fleet", "")]
	if !ok {
		return -1
	}
	return rec.ReplayFloor
}

// persistFleetSeqOutOfBand records a fleet apply at seq directly, simulating a
// concurrent apply that landed between a stale pre-lock snapshot and our lock
// acquisition.
func persistFleetSeqOutOfBand(t *testing.T, configPath string, seq int64, assignID string) {
	t.Helper()
	st, err := apply.LoadPolicyState(configPath)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	st.Record("fleet", "", assignID, "2026-01-01T00:00:00Z", seq)
	if err := apply.SavePolicyState(configPath, st); err != nil {
		t.Fatalf("save out-of-band state: %v", err)
	}
}

// Regression 1: a stale pre-lock snapshot must not let a lower sequence roll the
// node back. We seed the baseline, take a snapshot as a pre-lock reader would,
// land seq 10 out-of-band (a concurrent apply that won the race), then run the
// seq 9 apply. The real apply re-reads state UNDER the lock, sees seq 10, and
// refuses. Final floor is never 9 after a 10 has landed.
func TestPolicyApplyV2_StaleSnapshotCannotRollBack(t *testing.T) {
	dir, configPath := writeV2ApplyConfig(t)

	if err := applyFleetSeq(t, dir, configPath, 1, "seq1"); err != nil {
		t.Fatalf("baseline seq 1: %v", err)
	}

	// Stale snapshot a pre-lock reader would hold (floor == 1).
	if got := fleetReplayFloor(t, configPath); got != 1 {
		t.Fatalf("snapshot floor = %d, want 1", got)
	}

	// Out-of-band, a concurrent apply lands seq 10 after the snapshot.
	persistFleetSeqOutOfBand(t, configPath, 10, "seq10")

	// The seq 9 apply must be refused by the post-lock re-read (9 < floor 10),
	// not accepted from the stale snapshot (9 > stale 1).
	err := applyFleetSeq(t, dir, configPath, 9, "seq9")
	if err == nil {
		t.Fatal("seq 9 must be refused after seq 10 landed")
	}
	if got := fleetReplayFloor(t, configPath); got != 10 {
		t.Fatalf("final floor = %d, want 10 (a lower sequence won)", got)
	}
}

// Regression 2: a lower sequence after a higher one is rejected by the post-lock
// re-read (state actually persisted between the two real applies).
func TestPolicyApplyV2_LowerAfterHigherRejected(t *testing.T) {
	dir, configPath := writeV2ApplyConfig(t)

	if err := applyFleetSeq(t, dir, configPath, 10, "hi"); err != nil {
		t.Fatalf("apply seq 10: %v", err)
	}
	if err := applyFleetSeq(t, dir, configPath, 9, "lo"); err == nil {
		t.Fatal("seq 9 must be refused after seq 10")
	}
	if got := fleetReplayFloor(t, configPath); got != 10 {
		t.Fatalf("final floor = %d, want 10", got)
	}
}

// Regression 3: a higher sequence after a lower one succeeds and advances the
// high-water.
func TestPolicyApplyV2_HigherAfterLowerSucceeds(t *testing.T) {
	dir, configPath := writeV2ApplyConfig(t)

	if err := applyFleetSeq(t, dir, configPath, 2, "two"); err != nil {
		t.Fatalf("apply seq 2: %v", err)
	}
	if err := applyFleetSeq(t, dir, configPath, 7, "seven"); err != nil {
		t.Fatalf("apply seq 7: %v", err)
	}
	if got := fleetReplayFloor(t, configPath); got != 7 {
		t.Fatalf("final floor = %d, want 7", got)
	}
}

// Regression 4 + 5: a state-persistence failure AFTER the config write must not
// advance the high-water, must roll the config back, and must never report
// success. The failure is injected through the savePolicyStateAfterCommit seam
// (a package var that wraps the real persist on the real-change path), which
// fires only AFTER CommitV2 has written the config, exactly the partial-failure
// window we must recover from.
func TestPolicyApplyV2_StatePersistFailureRollsBackConfigNoAdvance(t *testing.T) {
	dir, configPath := writeV2ApplyConfig(t)

	// Land a baseline at seq 3.
	if err := applyFleetSeq(t, dir, configPath, 3, "base3"); err != nil {
		t.Fatalf("baseline seq 3: %v", err)
	}
	configBefore, err := os.ReadFile(configPath) //nolint:gosec // test path
	if err != nil {
		t.Fatalf("read config before: %v", err)
	}
	floorBefore := fleetReplayFloor(t, configPath)

	// Inject a state-persist failure for the next apply (seq 8).
	orig := savePolicyStateAfterCommit
	savePolicyStateAfterCommit = func(string, *apply.PolicyState) error {
		return errAfterCommitInjected
	}
	defer func() { savePolicyStateAfterCommit = orig }()

	bundlePath, fp := fleetBundleAtSeq(t, dir, 8, "seq8")
	out, err := runPolicyApply(t,
		"--bundle", bundlePath, "--trust-fingerprint", fp,
		"--config", configPath, "--json",
	)
	if err == nil {
		t.Fatal("apply must return an error when state persistence fails")
	}
	if applied, _ := out["applied"].(bool); applied {
		t.Fatalf("must not report applied:true on state-persist failure: %v", out)
	}

	// High-water must NOT have advanced.
	if got := fleetReplayFloor(t, configPath); got != floorBefore {
		t.Fatalf("floor advanced to %d on persist failure, want %d", got, floorBefore)
	}
	// Config must have been rolled back to the prior contents.
	configAfter, err := os.ReadFile(configPath) //nolint:gosec // test path
	if err != nil {
		t.Fatalf("read config after: %v", err)
	}
	if string(configAfter) != string(configBefore) {
		t.Fatal("config must be rolled back to prior contents after persist failure")
	}
	// The lock must have been released despite the error.
	if _, err := os.Lstat(apply.ApplyLockPath(configPath)); !os.IsNotExist(err) {
		t.Fatalf("lock must be released after persist failure, lstat err=%v", err)
	}
}

// Regression 6: a refused or errored apply releases the lock so the next
// legitimate apply can acquire it. After a refusal there must be no leftover
// lock file, and a subsequent valid apply must succeed.
func TestPolicyApplyV2_LockReleasedAfterRefusal(t *testing.T) {
	dir, configPath := writeV2ApplyConfig(t)
	lockPath := apply.ApplyLockPath(configPath)

	if err := applyFleetSeq(t, dir, configPath, 5, "five"); err != nil {
		t.Fatalf("apply seq 5: %v", err)
	}
	// Refused lower sequence.
	if err := applyFleetSeq(t, dir, configPath, 4, "four"); err == nil {
		t.Fatal("seq 4 must be refused")
	}
	if _, err := os.Lstat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("no leftover lock expected after refusal, lstat err=%v", err)
	}
	// A subsequent legitimate apply acquires the lock and succeeds.
	if err := applyFleetSeq(t, dir, configPath, 6, "six"); err != nil {
		t.Fatalf("apply seq 6 must succeed after lock release: %v", err)
	}
	if got := fleetReplayFloor(t, configPath); got != 6 {
		t.Fatalf("final floor = %d, want 6", got)
	}
}

// Concurrency smoke: while one apply holds the lock, a concurrent apply attempt
// for the same target fails to acquire it rather than interleaving. Holding the
// lock directly and attempting the apply synchronously is fully deterministic.
func TestPolicyApplyV2_HeldLockBlocksConcurrentApply(t *testing.T) {
	dir, configPath := writeV2ApplyConfig(t)

	lock, err := apply.AcquireApplyLock(configPath)
	if err != nil {
		t.Fatalf("acquire lock: %v", err)
	}

	if err := applyFleetSeq(t, dir, configPath, 1, "blocked"); err == nil {
		t.Fatal("apply must fail while the lock is held")
	} else if !strings.Contains(err.Error(), "another apply holds the lock") {
		t.Fatalf("expected held-lock error, got %v", err)
	}

	if err := lock.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	// After release a fresh apply succeeds.
	if err := applyFleetSeq(t, dir, configPath, 1, "afterrelease"); err != nil {
		t.Fatalf("apply after release: %v", err)
	}
}

// fleetBundleSuspend builds a fleet-scoped v2 bundle at seq that sets voice-ai's
// suspended flag to the given value (a real change when it differs from config).
func fleetBundleSuspend(t *testing.T, dir string, seq int64, assignID string, suspended bool) (bundlePath, fp string) {
	t.Helper()
	body := supportedAgentBodyV2("fleet", "")
	body.Assignment.Sequence = seq
	body.Assignment.AssignmentID = assignID
	g := agentGovV2cmd("voice-ai")
	g.Suspended = policybundle.DimScalarBoolV2{Mode: "replace", Value: suspended}
	body.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	raw, trustFP := signV2Bundle(t, body)
	p := filepath.Join(dir, "suspend-"+assignID+".signed.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return p, trustFP
}

// TestPolicyApplyV2_ProjectionUnderLock_ConfigAndStateNeverDiverge is the FIX A
// (P1) regression: the no-op-vs-commit decision and the committed projection
// must BOTH be derived from the config observed UNDER the lock, so the config
// the recorded sequence corresponds to is always the config on disk.
//
// Deterministic construction of the Codex race. The baseline config has voice-ai
// NOT suspended. Apply a lower-seq bundle (seq 5) that suspends it -> commits,
// config suspended=true, floor 5. Then apply a HIGHER-seq bundle (seq 10) whose
// desired suspended value is false -- i.e. exactly the baseline's original value,
// so projected against the BASELINE it would be a no-op. Because the projection
// now runs under the lock against the on-disk (post-seq-5) config, the higher
// bundle sees suspended=true and actually applies suspended=false, committing the
// config AND advancing the floor to 10. Config and state agree.
//
// Before FIX A the higher bundle, projected against a stale baseline snapshot,
// would have taken the no-op path: the floor would advance to 10 while the config
// stayed suspended=true (seq 5's policy) -- a divergence that this test forbids.
func TestPolicyApplyV2_ProjectionUnderLock_ConfigAndStateNeverDiverge(t *testing.T) {
	dir, configPath := writeV2ApplyConfig(t)

	// Sanity: baseline voice-ai is not suspended (the value the higher bundle
	// will request, so it would be a no-op against the baseline).
	base, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	if base.Agents["voice-ai"].Suspended {
		t.Fatalf("baseline voice-ai must start not suspended for this race construction")
	}

	// Lower seq 5: suspend voice-ai (real change true).
	lowPath, lowFP := fleetBundleSuspend(t, dir, 5, "low", true)
	if _, err := runPolicyApply(t,
		"--bundle", lowPath, "--trust-fingerprint", lowFP,
		"--config", configPath, "--json",
	); err != nil {
		t.Fatalf("low apply (seq 5): %v", err)
	}
	if got := fleetReplayFloor(t, configPath); got != 5 {
		t.Fatalf("floor after seq 5 = %d, want 5", got)
	}

	// Higher seq 10: desired suspended=false == baseline value. A no-op vs the
	// baseline, a real change vs the on-disk post-seq-5 config.
	highPath, highFP := fleetBundleSuspend(t, dir, 10, "high", false)
	if _, err := runPolicyApply(t,
		"--bundle", highPath, "--trust-fingerprint", highFP,
		"--config", configPath, "--json",
	); err != nil {
		t.Fatalf("high apply (seq 10): %v", err)
	}

	// Config must reflect the higher bundle's desired value: suspended=false.
	after, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if after.Agents["voice-ai"].Suspended {
		t.Fatalf("config and state diverged: config shows suspended=true (seq-5 policy) but the higher seq-10 bundle desired suspended=false")
	}

	// State must record the higher sequence, corresponding to the config on disk.
	if got := fleetReplayFloor(t, configPath); got != 10 {
		t.Fatalf("floor after seq 10 = %d, want 10", got)
	}
}

// TestPolicyApplyV2_RealApplyHonorsMalformedStateFailClosed exercises FIX A + B
// together at the command layer: a present-but-malformed state file makes a real
// apply refuse with no config write and no state advance (the loader fails
// closed under the lock).
func TestPolicyApplyV2_RealApplyHonorsMalformedStateFailClosed(t *testing.T) {
	dir, configPath := writeV2ApplyConfig(t)
	before, _ := os.ReadFile(configPath)
	// Seed a present-but-malformed state file (wrong version).
	if err := os.WriteFile(apply.PolicyStatePath(configPath), []byte(`{"version": 99, "targets": {}}`), 0o600); err != nil {
		t.Fatalf("seed malformed state: %v", err)
	}
	if err := applyFleetSeq(t, dir, configPath, 1, "one"); err == nil {
		t.Fatalf("apply must refuse on a malformed state file")
	}
	after, _ := os.ReadFile(configPath)
	if string(before) != string(after) {
		t.Fatalf("config must be unchanged when the state is malformed")
	}
}
