package node

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// writePolicyBundle drops a bundle JSON file into a temp dir and
// returns its path. mtime is pinned so loaded_at assertions are
// deterministic.
func writePolicyBundle(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.signed.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	mtime := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	return path
}

const validBundleJSON = `{
  "schema_version": "policy_bundle_envelope.v1",
  "bundle_version": 1,
  "policy_hash": "sha256:deadbeef",
  "signature": {"alg": "Ed25519", "value": "ignored-in-4b"},
  "policy": {"policy_id": "voice-ai-prod", "policy_version": "1", "rules": ["ignored"]}
}`

func TestBuildPolicySection_NoPath(t *testing.T) {
	sec, warns := buildPolicySection("", "")
	if sec == nil {
		t.Fatal("policy block must never be nil for a 4B+ node")
	}
	if sec.PolicyStatus != PolicyStatusNone {
		t.Errorf("status = %q, want %q", sec.PolicyStatus, PolicyStatusNone)
	}
	if sec.ActivePolicySource != PolicySourceNone {
		t.Errorf("source = %q, want %q", sec.ActivePolicySource, PolicySourceNone)
	}
	if sec.ActivePolicyHash != "" {
		t.Errorf("hash = %q, want empty", sec.ActivePolicyHash)
	}
	if sec.ActivePolicyVerified {
		t.Error("verified must be false in 4B")
	}
	if len(warns) != 0 {
		t.Errorf("no-path case must not warn, got %v", warns)
	}
}

func TestBuildPolicySection_ValidBundle(t *testing.T) {
	path := writePolicyBundle(t, validBundleJSON)
	sec, warns := buildPolicySection(path, "")
	if len(warns) != 0 {
		t.Errorf("valid bundle must not warn, got %v", warns)
	}
	if sec.PolicyStatus != PolicyStatusActive {
		t.Errorf("status = %q, want %q", sec.PolicyStatus, PolicyStatusActive)
	}
	if sec.ActivePolicySource != PolicySourceLocalFile {
		t.Errorf("source = %q, want %q", sec.ActivePolicySource, PolicySourceLocalFile)
	}
	if sec.ActivePolicyHash != "sha256:deadbeef" {
		t.Errorf("hash = %q, want echoed bundle hash", sec.ActivePolicyHash)
	}
	if sec.ActivePolicyID != "voice-ai-prod" {
		t.Errorf("id = %q", sec.ActivePolicyID)
	}
	if sec.ActivePolicyVersion != "1" {
		t.Errorf("version = %q", sec.ActivePolicyVersion)
	}
	if sec.ActivePolicyLoadedAt != "2026-05-24T12:00:00Z" {
		t.Errorf("loaded_at = %q, want file mtime", sec.ActivePolicyLoadedAt)
	}
	if sec.ActivePolicyVerified {
		t.Error("verified must be false in 4B even for a parseable bundle")
	}
}

func TestBuildPolicySection_Unreadable(t *testing.T) {
	cases := map[string]string{
		"bad json":         `{not json`,
		"missing hash":     `{"policy": {"policy_id": "x"}}`,
		"empty hash":       `{"policy_hash": "", "policy": {"policy_id": "x"}}`,
		"missing id":       `{"policy_hash": "sha256:abc", "policy": {}}`,
		"empty everything": `{}`,
	}
	for name, contents := range cases {
		t.Run(name, func(t *testing.T) {
			path := writePolicyBundle(t, contents)
			sec, warns := buildPolicySection(path, "")
			if sec.PolicyStatus != PolicyStatusUnreadable {
				t.Errorf("status = %q, want %q", sec.PolicyStatus, PolicyStatusUnreadable)
			}
			if sec.ActivePolicySource != PolicySourceLocalFile {
				t.Errorf("source = %q, want %q (a path was supplied)", sec.ActivePolicySource, PolicySourceLocalFile)
			}
			if sec.ActivePolicyHash != "" {
				t.Errorf("unreadable must not echo a hash, got %q", sec.ActivePolicyHash)
			}
			if len(warns) != 1 || warns[0].Code != WarnPolicyBundleUnreadable {
				t.Errorf("expected one %q warning, got %v", WarnPolicyBundleUnreadable, warns)
			}
		})
	}
}

func TestBuildPolicySection_MissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.json")
	sec, warns := buildPolicySection(path, "")
	if sec.PolicyStatus != PolicyStatusUnreadable {
		t.Errorf("status = %q, want %q", sec.PolicyStatus, PolicyStatusUnreadable)
	}
	if len(warns) != 1 || warns[0].Code != WarnPolicyBundleUnreadable {
		t.Errorf("expected one %q warning, got %v", WarnPolicyBundleUnreadable, warns)
	}
}

func TestBuildPolicySection_Symlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privileged on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "real.json")
	if err := os.WriteFile(target, []byte(validBundleJSON), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported here: %v", err)
	}
	sec, warns := buildPolicySection(link, "")
	if sec.PolicyStatus != PolicyStatusUnreadable {
		t.Errorf("symlinked bundle must be unreadable, got %q", sec.PolicyStatus)
	}
	if len(warns) != 1 || warns[0].Code != WarnPolicyBundleUnreadable {
		t.Errorf("expected one %q warning, got %v", WarnPolicyBundleUnreadable, warns)
	}
}

// TestCanonicalSnapshotBytes_NilPolicyOmitted is the backward-compat
// guard: a snapshot with no policy block (pre-4B shape) must canonicalize
// without a "policy" key so existing signed envelopes keep verifying.
func TestCanonicalSnapshotBytes_NilPolicyOmitted(t *testing.T) {
	_, id := seedIdentity(t)
	snap := baseSnapshot(id)
	snap.Policy = nil
	canon, err := CanonicalSnapshotBytes(snap)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if strings.Contains(string(canon), `"policy":`) {
		t.Fatalf("nil policy must be omitted from canonical bytes; got:\n%s", canon)
	}
}

// TestBuild_PolicyBlock_NoneByDefault verifies node.Build always emits
// the policy block (never nil) and reports none when no bundle path is
// supplied — the block must be present on every 4B+ snapshot.
func TestBuild_PolicyBlock_NoneByDefault(t *testing.T) {
	snap := buildAt(t, Options{ConfigPath: filepath.Join(t.TempDir(), "missing.yaml")})
	if snap.Policy == nil {
		t.Fatal("Build must always populate the policy block for a 4B+ node")
	}
	if snap.Policy.PolicyStatus != PolicyStatusNone {
		t.Fatalf("default policy_status = %q, want %q", snap.Policy.PolicyStatus, PolicyStatusNone)
	}
}

// TestBuild_PolicyBlock_ActiveFromBundle verifies Options.PolicyBundlePath
// is wired through Build into the reported active policy.
func TestBuild_PolicyBlock_ActiveFromBundle(t *testing.T) {
	path := writePolicyBundle(t, validBundleJSON)
	snap := buildAt(t, Options{
		ConfigPath:       filepath.Join(t.TempDir(), "missing.yaml"),
		PolicyBundlePath: path,
	})
	if snap.Policy == nil || snap.Policy.PolicyStatus != PolicyStatusActive {
		t.Fatalf("expected active policy block, got %+v", snap.Policy)
	}
	if snap.Policy.ActivePolicyHash != "sha256:deadbeef" {
		t.Errorf("hash = %q, want echoed bundle hash", snap.Policy.ActivePolicyHash)
	}
	if snap.Policy.ActivePolicyVerified {
		t.Error("verified must be false in 4B")
	}
}

// TestSealSnapshotEnvelope_WithPolicyBlock proves the envelope still
// signs and self-verifies when the additive policy block is present,
// and that the block survives into the embedded snapshot.
func TestSealSnapshotEnvelope_WithPolicyBlock(t *testing.T) {
	store, id := seedIdentity(t)
	snap := baseSnapshot(id)
	snap.Policy = &SnapshotPolicy{
		ActivePolicyHash:     "sha256:deadbeef",
		ActivePolicyID:       "voice-ai-prod",
		ActivePolicyVersion:  "1",
		ActivePolicySource:   PolicySourceLocalFile,
		ActivePolicyLoadedAt: "2026-05-24T12:00:00Z",
		ActivePolicyVerified: false,
		PolicyStatus:         PolicyStatusActive,
	}
	env, err := SealSnapshotEnvelope(store, snap, time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("seal with policy block: %v", err)
	}
	if env.Snapshot.Policy == nil || env.Snapshot.Policy.PolicyStatus != PolicyStatusActive {
		t.Fatalf("policy block did not survive into the envelope snapshot")
	}
	canon, err := CanonicalSnapshotBytes(snap)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if !strings.Contains(string(canon), `"policy":`) {
		t.Fatalf("populated policy block must appear in canonical bytes")
	}
}
