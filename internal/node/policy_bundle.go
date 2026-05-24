package node

import (
	"encoding/json"
	"os"
	"time"

	"github.com/oktsec/oktsec/internal/safefile"
)

// maxPolicyBundleBytes caps how much of a --policy-bundle file the
// snapshot reads. Policy bundles are small signed JSON documents; the
// cap keeps a planted multi-gigabyte file from stalling a snapshot.
const maxPolicyBundleBytes = 1 << 20 // 1 MiB

// rawPolicyBundle is the minimal, tolerant projection of an Enterprise
// signed policy bundle that Order 4B needs. Community is parse-only
// here: it does NOT own the policy bundle contract, so the decode is
// deliberately tolerant (no DisallowUnknownFields) and ignores the
// signature block entirely.
//
// NOTE (4B.2 follow-up): the authoritative bundle field names live in
// the Enterprise policy_bundle schema. These tags are taken from the
// Order 4B decisions; the cross-repo fixture that proves this reader and
// the Enterprise bundle agree lands when Enterprise pins the 4B.1 anchor.
type rawPolicyBundle struct {
	SchemaVersion string `json:"schema_version"`
	BundleVersion int    `json:"bundle_version"`
	PolicyHash    string `json:"policy_hash"`
	Policy        struct {
		PolicyID      string `json:"policy_id"`
		PolicyVersion string `json:"policy_version"`
	} `json:"policy"`
}

// buildPolicySection produces the additive Order 4B policy block from
// the supplied --policy-bundle path. It is declarative and read-only:
// it reads and parses the bundle, echoes the declared policy_hash, and
// never verifies the signature, recomputes the hash, or applies policy.
//
// Returned block is never nil for a 4B+ node — the none case is an
// explicit PolicyStatusNone block, not an absent one. Any unreadable
// path is reported as PolicyStatusUnreadable plus a warning so a
// consumer can tell "could not read" from "no policy here".
func buildPolicySection(bundlePath string) (*SnapshotPolicy, []Warning) {
	if bundlePath == "" {
		return &SnapshotPolicy{
			ActivePolicySource:   PolicySourceNone,
			ActivePolicyVerified: false,
			PolicyStatus:         PolicyStatusNone,
		}, nil
	}

	unreadable := func(msg string) (*SnapshotPolicy, []Warning) {
		return &SnapshotPolicy{
				ActivePolicySource:   PolicySourceLocalFile,
				ActivePolicyVerified: false,
				PolicyStatus:         PolicyStatusUnreadable,
			}, []Warning{{
				Code:    WarnPolicyBundleUnreadable,
				Message: "Policy bundle could not be read as a declared active policy: " + msg,
			}}
	}

	// RejectSymlink uses Lstat, so this also catches a missing path
	// or a path the node cannot stat — the err text disambiguates the
	// symlink case from the not-found case.
	if err := safefile.RejectSymlink(bundlePath); err != nil {
		return unreadable("path not usable: " + err.Error())
	}
	data, err := safefile.ReadFileMax(bundlePath, maxPolicyBundleBytes)
	if err != nil {
		return unreadable("read failed: " + err.Error())
	}
	var bundle rawPolicyBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return unreadable("invalid JSON: " + err.Error())
	}
	// A bundle that does not declare the minimal identity Enterprise
	// compares against (hash + id) is not a usable active policy.
	if bundle.PolicyHash == "" {
		return unreadable("bundle declares no policy_hash")
	}
	if bundle.Policy.PolicyID == "" {
		return unreadable("bundle declares no policy.policy_id")
	}

	return &SnapshotPolicy{
		ActivePolicyHash:     bundle.PolicyHash,
		ActivePolicyID:       bundle.Policy.PolicyID,
		ActivePolicyVersion:  bundle.Policy.PolicyVersion,
		ActivePolicySource:   PolicySourceLocalFile,
		ActivePolicyLoadedAt: policyBundleLoadedAt(bundlePath),
		ActivePolicyVerified: false,
		PolicyStatus:         PolicyStatusActive,
	}, nil
}

// policyBundleLoadedAt returns the bundle file's modification time as
// UTC RFC3339 — when the bundle landed on the node, a staleness signal.
// Returns "" if the time cannot be read; the field is omitempty so an
// unknown mtime simply drops out of the JSON rather than emitting a
// misleading zero time.
func policyBundleLoadedAt(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return info.ModTime().UTC().Format(time.RFC3339)
}
