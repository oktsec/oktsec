package commands

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
)

// policyBundleFixture is a deterministically signed policy_bundle.v1
// (vendored from the upstream signer) the apply dry-run tests project.
//
//go:embed policy_bundle_v1_fixture.json
var policyBundleFixture []byte

// fixtureTrustFP returns the fixture's self-declared signing fingerprint,
// which the verifier requires --trust-fingerprint to match.
func fixtureTrustFP(t *testing.T) string {
	t.Helper()
	var b struct {
		Signature struct {
			PublicKeyFingerprint string `json:"public_key_fingerprint"`
		} `json:"signature"`
	}
	if err := json.Unmarshal(policyBundleFixture, &b); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return b.Signature.PublicKeyFingerprint
}

// writePolicyApplyInputs drops the bundle + a minimal config with a
// voice-ai agent into a temp dir and returns their paths.
func writePolicyApplyInputs(t *testing.T) (bundlePath, configPath string) {
	t.Helper()
	dir := t.TempDir()
	bundlePath = filepath.Join(dir, "voice-ai-prod.signed.json")
	if err := os.WriteFile(bundlePath, policyBundleFixture, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	configPath = filepath.Join(dir, "oktsec.yaml")
	cfg := []byte("version: \"1\"\nserver:\n  port: 8080\nidentity:\n  require_signature: false\nagents:\n  voice-ai:\n    allowed_tools: [old.tool]\nrules: []\n")
	if err := os.WriteFile(configPath, cfg, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return bundlePath, configPath
}

// runPolicyApply runs `oktsec policy apply ...` through the real root command
// so the persistent --config flag and its cascading resolution
// (PersistentPreRunE) apply, exactly as in production.
func runPolicyApply(t *testing.T, args ...string) (map[string]any, error) {
	t.Helper()
	root := NewRoot()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs(append([]string{"policy", "apply"}, args...))
	err := root.Execute()
	var got map[string]any
	if out.Len() > 0 {
		_ = json.Unmarshal(out.Bytes(), &got)
	}
	return got, err
}

func TestPolicyApply_DryRunProjectsAndWritesNothing(t *testing.T) {
	bundlePath, configPath := writePolicyApplyInputs(t)
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	got, err := runPolicyApply(t,
		"--bundle", bundlePath, "--trust-fingerprint", fixtureTrustFP(t),
		"--config", configPath, "--agent", "voice-ai", "--dry-run", "--json",
	)
	if err != nil {
		t.Fatalf("dry-run apply must succeed: %v", err)
	}
	if got["applied"] != false || got["dry_run"] != true {
		t.Fatalf("applied/dry_run = %v/%v, want false/true", got["applied"], got["dry_run"])
	}
	if got["policy_id"] == "" || got["policy_hash"] == "" {
		t.Fatalf("plan missing policy identity: %v", got)
	}
	if changes, ok := got["changes"].([]any); !ok || len(changes) == 0 {
		t.Fatalf("plan must report changes: %v", got["changes"])
	}

	// The config file must be byte-identical — dry-run writes nothing.
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("dry-run apply modified the config file")
	}
}

func TestPolicyApply_RejectsUntrustedBundle(t *testing.T) {
	bundlePath, configPath := writePolicyApplyInputs(t)
	got, err := runPolicyApply(t,
		"--bundle", bundlePath,
		"--trust-fingerprint", "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"--config", configPath, "--agent", "voice-ai", "--dry-run", "--json",
	)
	if err == nil {
		t.Fatal("apply with a wrong trust fingerprint must fail")
	}
	if got["reject_code"] != "policy_signing_key_mismatch" {
		t.Fatalf("reject_code = %v, want policy_signing_key_mismatch", got["reject_code"])
	}
}

func TestPolicyApply_RequiresAgent(t *testing.T) {
	bundlePath, configPath := writePolicyApplyInputs(t)
	// Missing --agent fails in both dry-run and real apply.
	if _, err := runPolicyApply(t, "--bundle", bundlePath, "--trust-fingerprint", fixtureTrustFP(t),
		"--config", configPath, "--dry-run"); err == nil {
		t.Fatal("apply without --agent must fail")
	}
	if _, err := runPolicyApply(t, "--bundle", bundlePath, "--trust-fingerprint", fixtureTrustFP(t),
		"--config", configPath); err == nil {
		t.Fatal("real apply without --agent must fail")
	}
}

func TestPolicyApply_RealApplyWritesBacksUpAndIsIdempotent(t *testing.T) {
	bundlePath, configPath := writePolicyApplyInputs(t)
	original, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	// First real apply (no --dry-run) writes the projection.
	got, err := runPolicyApply(t,
		"--bundle", bundlePath, "--trust-fingerprint", fixtureTrustFP(t),
		"--config", configPath, "--agent", "voice-ai", "--json",
	)
	if err != nil {
		t.Fatalf("real apply must succeed: %v", err)
	}
	if got["applied"] != true || got["changed"] != true || got["dry_run"] != false {
		t.Fatalf("applied/changed/dry_run = %v/%v/%v, want true/true/false", got["applied"], got["changed"], got["dry_run"])
	}
	backupPath, _ := got["backup_path"].(string)
	if backupPath == "" {
		t.Fatal("real apply must report a backup_path")
	}

	// The backup holds the EXACT original bytes.
	backup, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if !bytes.Equal(backup, original) {
		t.Fatal("backup is not the exact original config")
	}

	// The config changed and still loads + validates.
	afterFirst, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if bytes.Equal(afterFirst, original) {
		t.Fatal("real apply did not modify the config")
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("applied config must load: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("applied config must validate: %v", err)
	}

	// Second apply is a no-op: changed:false, no backup, bytes unchanged.
	got2, err := runPolicyApply(t,
		"--bundle", bundlePath, "--trust-fingerprint", fixtureTrustFP(t),
		"--config", configPath, "--agent", "voice-ai", "--json",
	)
	if err != nil {
		t.Fatalf("second apply must succeed: %v", err)
	}
	if got2["applied"] != false || got2["changed"] != false {
		t.Fatalf("idempotent apply: applied/changed = %v/%v, want false/false", got2["applied"], got2["changed"])
	}
	if bp, _ := got2["backup_path"].(string); bp != "" {
		t.Fatalf("no-op apply must not create a backup, got %q", bp)
	}
	afterSecond, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !bytes.Equal(afterFirst, afterSecond) {
		t.Fatal("no-op apply rewrote the config")
	}
}

func TestPolicyApply_RealApplyRequiresExplicitConfig(t *testing.T) {
	bundlePath, _ := writePolicyApplyInputs(t)
	// No --config: real apply must refuse rather than mutate a cascaded default.
	if _, err := runPolicyApply(t,
		"--bundle", bundlePath, "--trust-fingerprint", fixtureTrustFP(t),
		"--agent", "voice-ai", "--json",
	); err == nil {
		t.Fatal("real apply without an explicit --config must fail")
	}
}

func TestPolicyApply_RealApplyMatchesDryRun(t *testing.T) {
	bundlePath, configPath := writePolicyApplyInputs(t)
	dry, err := runPolicyApply(t,
		"--bundle", bundlePath, "--trust-fingerprint", fixtureTrustFP(t),
		"--config", configPath, "--agent", "voice-ai", "--dry-run", "--json",
	)
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	real, err := runPolicyApply(t,
		"--bundle", bundlePath, "--trust-fingerprint", fixtureTrustFP(t),
		"--config", configPath, "--agent", "voice-ai", "--json",
	)
	if err != nil {
		t.Fatalf("real apply: %v", err)
	}
	// Same inputs must yield the same change set.
	dc, _ := json.Marshal(dry["changes"])
	rc, _ := json.Marshal(real["changes"])
	if string(dc) != string(rc) {
		t.Fatalf("apply changes %s != dry-run changes %s", rc, dc)
	}
}

func TestPolicyApply_MissingConfigRejectedNoWrite(t *testing.T) {
	bundlePath, configPath := writePolicyApplyInputs(t)
	missing := configPath + ".does-not-exist"
	if _, err := runPolicyApply(t,
		"--bundle", bundlePath, "--trust-fingerprint", fixtureTrustFP(t),
		"--config", missing, "--agent", "voice-ai", "--json",
	); err == nil {
		t.Fatal("real apply against a missing config must fail")
	}
	if _, statErr := os.Stat(missing); !os.IsNotExist(statErr) {
		t.Fatal("apply must not create the missing config")
	}
}

func TestPolicyApply_DirectoryConfigRejected(t *testing.T) {
	bundlePath, configPath := writePolicyApplyInputs(t)
	if _, err := runPolicyApply(t,
		"--bundle", bundlePath, "--trust-fingerprint", fixtureTrustFP(t),
		"--config", filepath.Dir(configPath), "--agent", "voice-ai", "--json",
	); err == nil {
		t.Fatal("real apply against a directory must fail")
	}
}

func TestPolicyApply_SymlinkConfigRejectedNoWrite(t *testing.T) {
	bundlePath, configPath := writePolicyApplyInputs(t)
	link := configPath + ".link"
	if err := os.Symlink(configPath, link); err != nil {
		t.Skipf("symlink unsupported on this platform: %v", err)
	}
	original, _ := os.ReadFile(configPath)
	if _, err := runPolicyApply(t,
		"--bundle", bundlePath, "--trust-fingerprint", fixtureTrustFP(t),
		"--config", link, "--agent", "voice-ai", "--json",
	); err == nil {
		t.Fatal("real apply through a symlink must fail")
	}
	after, _ := os.ReadFile(configPath)
	if !bytes.Equal(original, after) {
		t.Fatal("symlinked apply must not write through to the target")
	}
}
