package commands

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
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

func runPolicyApply(t *testing.T, args ...string) (map[string]any, error) {
	t.Helper()
	cmd := newPolicyCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(append([]string{"apply"}, args...))
	err := cmd.Execute()
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

func TestPolicyApply_RequiresDryRunAndAgent(t *testing.T) {
	bundlePath, configPath := writePolicyApplyInputs(t)
	// Missing --dry-run.
	if _, err := runPolicyApply(t, "--bundle", bundlePath, "--trust-fingerprint", fixtureTrustFP(t),
		"--config", configPath, "--agent", "voice-ai"); err == nil {
		t.Fatal("apply without --dry-run must fail in this release")
	}
	// Missing --agent.
	if _, err := runPolicyApply(t, "--bundle", bundlePath, "--trust-fingerprint", fixtureTrustFP(t),
		"--config", configPath, "--dry-run"); err == nil {
		t.Fatal("apply without --agent must fail")
	}
}
