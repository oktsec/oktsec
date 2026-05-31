package apply

// Order 9A.2 anti-rollback state. The last-applied sequence per target is
// persisted in a state file ADJACENT to the explicit config:
// "<config>.policy-state.json", mode 0600, written atomically AFTER a
// successful apply only. A failed write must NOT advance the sequence, so the
// command reads the state before projection and writes it only after CommitV2
// returns success.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/oktsec/oktsec/internal/safefile"
)

// maxStateBytes caps the state file the rollback check reads.
const maxStateBytes = 1 << 20 // 1 MiB

// PolicyStateFileSuffix is appended to the explicit config path to form the
// state file path. It is exported so the command help and tests can reference
// the exact name.
const PolicyStateFileSuffix = ".policy-state.json"

// PolicyStateVersion tags the state file shape so a future change is detectable.
const PolicyStateVersion = 1

// TargetRecord is the per-target last-applied record.
//
// Two sequences are tracked on purpose:
//   - ReplayFloor is the anti-rollback gate and is MONOTONIC: it never
//     decreases, so a sequence at or below the highest ever applied can never be
//     replayed as a plain apply (a signed rollback to a lower sequence does not
//     re-open the sequences above it).
//   - LastSequence is the sequence of the assignment CURRENTLY applied (which a
//     signed rollback can lower below the floor). It pairs with LastAssignmentID
//     so an idempotent reapply of the current bundle, and a further signed
//     rollback of it, both work even after the floor moved ahead.
type TargetRecord struct {
	ReplayFloor      int64  `json:"replay_floor"`
	LastSequence     int64  `json:"last_sequence"`
	LastAssignmentID string `json:"last_assignment_id"`
	AppliedAt        string `json:"applied_at"` // canonical UTC, set by the command
}

// PolicyState is the on-disk anti-rollback state: a map of target-key to the
// last-applied record. Target-key separates fleet and node scopes so they track
// independently (see TargetKey).
type PolicyState struct {
	Version int                     `json:"version"`
	Targets map[string]TargetRecord `json:"targets"`
}

// TargetKey is the state map key for a (scope, node_id). Fleet and node
// assignments track separately: a fleet apply never advances a node target's
// sequence and vice versa.
func TargetKey(scope, nodeID string) string {
	if scope == "node" {
		return "node:" + nodeID
	}
	return "fleet:"
}

// PolicyStatePath returns the state file path for an explicit config path.
func PolicyStatePath(configPath string) string {
	return configPath + PolicyStateFileSuffix
}

// LoadPolicyState reads the state file beside configPath. A missing file is not
// an error: it returns an empty state (first apply for every target). The path
// must not be a symlink (no write or read follows a link).
func LoadPolicyState(configPath string) (*PolicyState, error) {
	path := PolicyStatePath(configPath)
	// A non-existent file is fine (first apply); only a real symlink is rejected
	// so no read follows a link. ReadFileMax also uses O_NOFOLLOW.
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("policy state %q is a symlink (rejected for security)", path)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("policy state %q is not a regular file", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("stat policy state %q: %w", path, err)
	}
	data, err := safefile.ReadFileMax(path, maxStateBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &PolicyState{Version: PolicyStateVersion, Targets: map[string]TargetRecord{}}, nil
		}
		return nil, fmt.Errorf("read policy state: %w", err)
	}
	var st PolicyState
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return nil, fmt.Errorf("decode policy state %q: %w", path, err)
	}
	if st.Targets == nil {
		st.Targets = map[string]TargetRecord{}
	}
	return &st, nil
}

// RollbackDecision is the outcome of the anti-rollback evaluation.
type RollbackDecision int

const (
	// RollbackProceedFresh: no state for this target yet (first apply).
	RollbackProceedFresh RollbackDecision = iota
	// RollbackProceedAdvance: sequence strictly greater than last applied.
	RollbackProceedAdvance
	// RollbackProceedSigned: sequence <= last applied, but rollback_of names the
	// currently-applied assignment for this target (an explicit signed rollback).
	RollbackProceedSigned
	// RollbackProceedReapply: the exact currently-applied assignment at its
	// recorded sequence is being applied again (idempotent retry / drift repair).
	RollbackProceedReapply
	// RollbackRefuse: stale sequence with no valid rollback_of.
	RollbackRefuse
)

// EvaluateRollback decides whether an assignment with the given sequence and
// rollback_of may apply against the recorded state for its target. It does not
// mutate state; the command records a new record only after CommitV2 succeeds.
func (st *PolicyState) EvaluateRollback(scope, nodeID, assignmentID, rollbackOf string, sequence int64) RollbackDecision {
	rec, ok := st.Targets[TargetKey(scope, nodeID)]
	if !ok {
		return RollbackProceedFresh
	}
	// Advance: strictly above the monotonic replay floor (the highest ever
	// applied). This is the only path that may raise the floor.
	if sequence > rec.ReplayFloor {
		return RollbackProceedAdvance
	}
	// Idempotent reapply: the SAME assignment at the SAME sequence it was applied
	// at is a retry or drift repair, not a rollback. This stays valid even after
	// the floor moved past that sequence (e.g. a signed rollback whose bundle is
	// re-applied), because it is keyed on the currently-applied assignment, not
	// the floor.
	if assignmentID == rec.LastAssignmentID && sequence == rec.LastSequence {
		return RollbackProceedReapply
	}
	// sequence <= floor: only a signed rollback of the currently-applied
	// assignment is allowed.
	if rollbackOf != "" && rollbackOf == rec.LastAssignmentID {
		return RollbackProceedSigned
	}
	return RollbackRefuse
}

// Record sets the last-applied record for a target. The caller persists via
// SavePolicyState only after CommitV2 succeeds.
//
// ReplayFloor is monotonic (max of existing and the applied sequence), so a
// signed rollback to a lower sequence never re-opens the sequences above it to a
// plain apply. LastSequence/LastAssignmentID record the assignment now actually
// applied (which a rollback can put below the floor), so an idempotent reapply
// of it, and a further signed rollback of it, both still resolve correctly.
func (st *PolicyState) Record(scope, nodeID, assignmentID, appliedAt string, sequence int64) {
	if st.Targets == nil {
		st.Targets = map[string]TargetRecord{}
	}
	st.Version = PolicyStateVersion
	key := TargetKey(scope, nodeID)
	floor := sequence
	if prev, ok := st.Targets[key]; ok && prev.ReplayFloor > floor {
		floor = prev.ReplayFloor
	}
	st.Targets[key] = TargetRecord{
		ReplayFloor:      floor,
		LastSequence:     sequence,
		LastAssignmentID: assignmentID,
		AppliedAt:        appliedAt,
	}
}

// SavePolicyState writes the state beside configPath atomically with mode 0600:
// write to an exclusive temp in the same dir, fsync, then rename over the state
// file, then fsync the dir. It refuses to write through a symlink at the state
// path. It is called ONLY after a successful CommitV2.
func SavePolicyState(configPath string, st *PolicyState) error {
	path := PolicyStatePath(configPath)
	// Never write through a symlink at the state path.
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("policy state %q is a symlink (rejected for security)", path)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("policy state %q is not a regular file", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat policy state %q: %w", path, err)
	}

	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("encode policy state: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create state temp: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write state temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("fsync state temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close state temp: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		cleanup()
		return fmt.Errorf("chmod state temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("atomic replace state %q: %w", path, err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
