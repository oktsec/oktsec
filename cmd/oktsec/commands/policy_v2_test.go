package commands

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/policybundle"
)

// These are COMMAND-LEVEL (CLI integration) tests for `oktsec policy apply`
// against a policy_bundle.v2. They invoke the REAL root command through
// runPolicyApply (defined in policy_test.go), so they exercise the actual
// dispatch by schema_version, the v2 --node-id target binding, the
// <config>.policy-state.json file, and the no-partial contract at the command
// boundary - not the internal projector directly.
//
// The command calls policybundle.Verify, so each test needs a genuinely SIGNED
// v2 bundle. The upstream signer/generator was deleted after the fixture was
// vendored and its signing helpers are unexported, so a small test-only signer
// is reproduced here from the EXPORTED policybundle types and frozen constants.
// It mirrors the canonical body encoding (typed-struct JSON, HTML escaping off,
// trailing newline trimmed) and the v2 signing-payload byte layout exactly; the
// in-package TestV2_SigningPayloadStable / TestV2_HashMatchesContract tests are
// the source of truth those bytes must match. Reusing the vendored node-scoped
// fixture is not enough here: the cases need a fleet-scoped bundle, a wrong-node
// target, a supported-only bundle, and a bundle that governs an unsupported
// dimension, each requiring a distinct signed body.

// v2SignerKey is a deterministic Ed25519 key seeded with bytes 1..32, matching
// the seed convention used elsewhere in the repo's v2 tests, so the signer is
// reproducible and self-describing.
func v2SignerKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	return priv, "sha256:" + hex.EncodeToString(sum[:])
}

// canonicalBodyV2 reproduces policybundle.canonicalPolicyBodyBytesV2: the typed
// struct encoded with HTML escaping off and the trailing newline trimmed. This
// is the exact byte layout policy_hash and the signature cover.
func canonicalBodyV2(t *testing.T, body policybundle.PolicyBodyV2) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		t.Fatalf("encode canonical v2 body: %v", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n")
}

// signingPayloadV2 reproduces policybundle.policyBundleV2SigningPayload byte for
// byte (see TestV2_SigningPayloadStable for the frozen layout).
func signingPayloadV2(body policybundle.PolicyBodyV2, policyHash, signedAt, keyID, fp string) []byte {
	lines := []string{
		"oktsec." + policybundle.SchemaVersionV2,
		"bundle_version:2",
		"policy_id:" + body.PolicyID,
		"policy_version:" + body.PolicyVersion,
		"policy_hash:" + policyHash,
		"canonicalization:" + policybundle.CanonicalizationV2,
		"assignment_id:" + body.Assignment.AssignmentID,
		"target_scope:" + body.Assignment.Target.Scope,
		"target_node_id:" + body.Assignment.Target.NodeID,
		"issued_at:" + body.Assignment.IssuedAt,
		"signed_at:" + signedAt,
		"sequence:" + strconv.FormatInt(body.Assignment.Sequence, 10),
		"rollback_of:" + body.Assignment.RollbackOf,
		"signature_key_id:" + keyID,
		"signature_public_key_fingerprint:" + fp,
	}
	out := lines[0]
	for _, l := range lines[1:] {
		out += "\n" + l
	}
	return []byte(out)
}

// signV2Bundle marshals a fully-populated PolicyBodyV2 into a signed
// policy_bundle.v2 JSON artifact and returns it plus the trust fingerprint the
// command must be given.
func signV2Bundle(t *testing.T, body policybundle.PolicyBodyV2) (raw []byte, trustFP string) {
	t.Helper()
	priv, fp := v2SignerKey(t)
	pub := priv.Public().(ed25519.PublicKey)
	const (
		keyID    = "command-test-v2-key"
		signedAt = "2026-05-30T12:00:01Z"
	)
	canon := canonicalBodyV2(t, body)
	sum := sha256.Sum256(canon)
	policyHash := "sha256:" + hex.EncodeToString(sum[:])

	payload := signingPayloadV2(body, policyHash, signedAt, keyID, fp)
	sig := ed25519.Sign(priv, payload)

	bundle := policybundle.PolicyBundleV2{
		SchemaVersion:    policybundle.SchemaVersionV2,
		BundleVersion:    policybundle.BundleVersionV2,
		PolicyHash:       policyHash,
		Canonicalization: policybundle.CanonicalizationV2,
		Policy:           body,
		Signature: policybundle.PolicySignature{
			Alg:                  "Ed25519",
			KeyID:                keyID,
			PublicKey:            base64.StdEncoding.EncodeToString(pub),
			PublicKeyFingerprint: fp,
			SignedAt:             signedAt,
			Value:                base64.StdEncoding.EncodeToString(sig),
		},
	}
	out, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal signed v2 bundle: %v", err)
	}
	// Sanity: the freshly minted bundle must verify against its own fingerprint
	// before any test relies on it, so a signer drift fails here, not deep in a
	// case assertion.
	if _, err := policybundle.Verify(out, fp); err != nil {
		t.Fatalf("minted v2 bundle must verify: %v", err)
	}
	return out, fp
}

// baseBodyV2 returns a canonical-shape PolicyBodyV2 with every dimension
// unmanaged and every container present as []/{} (the verifier rejects nil
// containers). Callers set the target scope and a per-agent change per case.
func baseBodyV2() policybundle.PolicyBodyV2 {
	return policybundle.PolicyBodyV2{
		PolicyID:      "voice-ai-prod",
		PolicyVersion: "1",
		Mode:          "enforce",
		Assignment: policybundle.AssignmentV2{
			AssignmentID: "assign-cmd-1",
			Target:       policybundle.TargetV2{Scope: "fleet"},
			IssuedAt:     "2026-05-30T12:00:00Z",
			Sequence:     1,
			RollbackOf:   "",
		},
		Rules:   policybundle.DimRulesV2{Mode: "unmanaged", Enabled: []string{}, Disabled: []string{}, Overrides: map[string]policybundle.PolicyRuleOverride{}},
		Gateway: policybundle.DimGatewayV2{Mode: "unmanaged", ToolsAllowed: []string{}, ToolsDenied: []string{}},
		Egress:  policybundle.DimEgressV2{Mode: "unmanaged", DomainsAllowed: []string{}, DomainsDenied: []string{}},
		Governance: policybundle.GovernanceV2{
			Server: policybundle.ServerGovernanceV2{Mode: "unmanaged"},
			Agents: []policybundle.AgentGovernanceV2{},
		},
		Redaction: policybundle.DimRedactionV2{Mode: "unmanaged", Level: "analyst"},
		Metadata:  policybundle.PolicyMetadata{CreatedAt: "2026-05-30T12:00:00Z", CreatedBy: "command-test", Reason: "command-level v2 apply test"},
	}
}

// agentGovV2cmd returns a per-agent governance entry for name with every
// dimension unmanaged and every container present as []/{}.
func agentGovV2cmd(name string) policybundle.AgentGovernanceV2 {
	return policybundle.AgentGovernanceV2{
		Selector:        policybundle.SelectorV2{Name: name, Labels: map[string]string{}},
		ACLs:            policybundle.DimACLsV2{Mode: "unmanaged", AllowedRecipients: []string{}, BlockedRecipients: []string{}},
		AllowedTools:    policybundle.DimStringSetV2{Mode: "unmanaged", Values: []string{}},
		ToolPolicies:    policybundle.DimToolPoliciesV2{Mode: "unmanaged", ByTool: map[string]policybundle.ToolPolicyV2{}},
		ToolConstraints: policybundle.DimToolConstraintsV2{Mode: "unmanaged", Items: []policybundle.ToolConstraintV2{}},
		ToolChainRules:  policybundle.DimToolChainRulesV2{Mode: "unmanaged", Items: []policybundle.ToolChainRuleV2{}},
		BlockedContent:  policybundle.DimStringSetV2{Mode: "unmanaged", Values: []string{}},
		ScanProfile:     policybundle.DimScalarStringV2{Mode: "unmanaged"},
		Suspended:       policybundle.DimScalarBoolV2{Mode: "unmanaged"},
		Egress: policybundle.DimAgentEgressV2{
			Mode: "unmanaged", AllowedDomains: []string{}, BlockedDomains: []string{},
			ToolRestrictions: map[string][]string{}, ScanRequests: "unset", ScanResponses: "unset",
			BlockedCategories: []string{}, Integrations: []string{},
		},
	}
}

// supportedAgentBodyV2 returns a body that, projected against the test config's
// voice-ai agent, yields a real, SUPPORTED change (allowed_tools replace).
// scope/nodeID set the assignment target.
func supportedAgentBodyV2(scope, nodeID string) policybundle.PolicyBodyV2 {
	b := baseBodyV2()
	b.Assignment.Target = policybundle.TargetV2{Scope: scope, NodeID: nodeID}
	g := agentGovV2cmd("voice-ai")
	g.AllowedTools = policybundle.DimStringSetV2{Mode: "replace", Values: []string{"calendar.read", "voice.dial"}}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	return b
}

// writeV2ApplyConfig writes a minimal valid config with a voice-ai agent and
// returns the temp dir and config path. The header comment lets the
// preserve-on-commit behavior be observable, mirroring the apply package tests.
func writeV2ApplyConfig(t *testing.T) (dir, configPath string) {
	t.Helper()
	dir = t.TempDir()
	configPath = filepath.Join(dir, "oktsec.yaml")
	cfg := []byte("# operator config\nversion: \"1\"\nserver:\n  port: 8080\nidentity:\n  require_signature: false\nagents:\n  voice-ai:\n    allowed_tools: [old.tool]\nrules: []\n")
	if err := os.WriteFile(configPath, cfg, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return dir, configPath
}

func writeBundle(t *testing.T, dir string, raw []byte) string {
	t.Helper()
	p := filepath.Join(dir, "bundle.signed.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return p
}

// statePath returns the adjacent <config>.policy-state.json path.
func statePath(configPath string) string { return configPath + ".policy-state.json" }

// backupCount returns how many timestamped backup files exist next to the config
// (apply writes "<config>.bak.<timestamp>" on a real config rewrite).
func backupCount(t *testing.T, configPath string) int {
	t.Helper()
	matches, err := filepath.Glob(configPath + ".bak.*")
	if err != nil {
		t.Fatalf("glob backups: %v", err)
	}
	return len(matches)
}

// 1. v2 dry-run via CLI does NOT require --agent: a v2 bundle dry-run is not
// rejected for a missing --agent (v2 scopes agents via in-bundle selectors), it
// prints the plan, and it writes nothing (no config change, no state file).
func TestPolicyApplyV2_DryRunNoAgentRequiredWritesNothing(t *testing.T) {
	dir, configPath := writeV2ApplyConfig(t)
	raw, fp := signV2Bundle(t, supportedAgentBodyV2("fleet", ""))
	bundlePath := writeBundle(t, dir, raw)
	before, _ := os.ReadFile(configPath)

	got, err := runPolicyApply(t,
		"--bundle", bundlePath, "--trust-fingerprint", fp,
		"--config", configPath, "--dry-run", "--json",
	)
	if err != nil {
		t.Fatalf("v2 dry-run without --agent must succeed: %v", err)
	}
	if changes, ok := got["changes"].([]any); !ok || len(changes) == 0 {
		t.Fatalf("v2 dry-run must print a plan with changes: %v", got["changes"])
	}
	after, _ := os.ReadFile(configPath)
	if !bytes.Equal(before, after) {
		t.Fatal("v2 dry-run modified the config")
	}
	if _, err := os.Stat(statePath(configPath)); !os.IsNotExist(err) {
		t.Fatal("v2 dry-run must not create a policy-state file")
	}
	if backupCount(t, configPath) != 0 {
		t.Fatal("v2 dry-run must not create a backup")
	}
}

// 2. v2 node-scoped real apply WITHOUT --node-id fails and writes nothing.
func TestPolicyApplyV2_NodeScopedWithoutNodeIDFailsNoWrite(t *testing.T) {
	dir, configPath := writeV2ApplyConfig(t)
	raw, fp := signV2Bundle(t, supportedAgentBodyV2("node", "node-east-1"))
	bundlePath := writeBundle(t, dir, raw)
	before, _ := os.ReadFile(configPath)

	if _, err := runPolicyApply(t,
		"--bundle", bundlePath, "--trust-fingerprint", fp,
		"--config", configPath, "--json", // no --node-id
	); err == nil {
		t.Fatal("node-scoped v2 apply without --node-id must fail")
	}
	after, _ := os.ReadFile(configPath)
	if !bytes.Equal(before, after) {
		t.Fatal("failed node-scoped apply must not modify the config")
	}
	if _, err := os.Stat(statePath(configPath)); !os.IsNotExist(err) {
		t.Fatal("failed node-scoped apply must not create a policy-state file")
	}
	if backupCount(t, configPath) != 0 {
		t.Fatal("failed node-scoped apply must not create a backup")
	}
}

// 3. v2 target mismatch (--node-id != bundle's node target) fails, writes
// nothing: config unchanged, no state file, no backup.
func TestPolicyApplyV2_TargetMismatchFailsNoWrite(t *testing.T) {
	dir, configPath := writeV2ApplyConfig(t)
	raw, fp := signV2Bundle(t, supportedAgentBodyV2("node", "node-east-1"))
	bundlePath := writeBundle(t, dir, raw)
	before, _ := os.ReadFile(configPath)

	if _, err := runPolicyApply(t,
		"--bundle", bundlePath, "--trust-fingerprint", fp,
		"--config", configPath, "--node-id", "node-west-9", "--json",
	); err == nil {
		t.Fatal("v2 apply with a mismatched --node-id must fail")
	}
	after, _ := os.ReadFile(configPath)
	if !bytes.Equal(before, after) {
		t.Fatal("target-mismatch apply must not modify the config")
	}
	if _, err := os.Stat(statePath(configPath)); !os.IsNotExist(err) {
		t.Fatal("target-mismatch apply must not create a policy-state file")
	}
	if backupCount(t, configPath) != 0 {
		t.Fatal("target-mismatch apply must not create a backup")
	}
}

// 4. v2 real apply success (node-scoped, correct --node-id) writes config +
// creates <config>.policy-state.json (0600, records the applied sequence and
// assignment) + a backup.
func TestPolicyApplyV2_NodeScopedSuccessWritesConfigAndState(t *testing.T) {
	dir, configPath := writeV2ApplyConfig(t)
	original, _ := os.ReadFile(configPath)
	body := supportedAgentBodyV2("node", "node-east-1")
	body.Assignment.AssignmentID = "assign-cmd-4"
	body.Assignment.Sequence = 7
	raw, fp := signV2Bundle(t, body)
	bundlePath := writeBundle(t, dir, raw)

	got, err := runPolicyApply(t,
		"--bundle", bundlePath, "--trust-fingerprint", fp,
		"--config", configPath, "--node-id", "node-east-1", "--json",
	)
	if err != nil {
		t.Fatalf("node-scoped v2 apply must succeed: %v", err)
	}
	if got["applied"] != true || got["changed"] != true || got["dry_run"] != false {
		t.Fatalf("applied/changed/dry_run = %v/%v/%v, want true/true/false", got["applied"], got["changed"], got["dry_run"])
	}
	if got["node_id"] != "node-east-1" || got["scope"] != "node" {
		t.Fatalf("result scope/node = %v/%v, want node/node-east-1", got["scope"], got["node_id"])
	}
	bp, _ := got["backup_path"].(string)
	if bp == "" {
		t.Fatal("real v2 apply must report a backup_path")
	}
	if backupCount(t, configPath) != 1 {
		t.Fatalf("real v2 apply must create exactly one backup, got %d", backupCount(t, configPath))
	}
	if backup, _ := os.ReadFile(bp); !bytes.Equal(backup, original) {
		t.Fatal("backup must hold the exact original config")
	}

	// Config changed and still loads + validates.
	after, _ := os.ReadFile(configPath)
	if bytes.Equal(after, original) {
		t.Fatal("real v2 apply did not modify the config")
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("applied config must load: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("applied config must validate: %v", err)
	}

	// State file exists, is 0600, and records the applied sequence/assignment.
	sp := statePath(configPath)
	info, err := os.Stat(sp)
	if err != nil {
		t.Fatalf("state file must exist: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode = %v, want 0600", info.Mode().Perm())
	}
	var st struct {
		Version int `json:"version"`
		Targets map[string]struct {
			LastSequence     int64  `json:"last_sequence"`
			LastAssignmentID string `json:"last_assignment_id"`
		} `json:"targets"`
	}
	data, _ := os.ReadFile(sp)
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("decode state file: %v", err)
	}
	rec, ok := st.Targets["node:node-east-1"]
	if !ok {
		t.Fatalf("state file missing node target, got %+v", st.Targets)
	}
	if rec.LastSequence != 7 || rec.LastAssignmentID != "assign-cmd-4" {
		t.Fatalf("state record = seq %d / %q, want 7 / assign-cmd-4", rec.LastSequence, rec.LastAssignmentID)
	}
}

// 5. v2 no-op real apply (re-applying the same bundle) advances/refreshes the
// policy-state but does NOT rewrite the config and does NOT create a new backup.
func TestPolicyApplyV2_NoopAdvancesStateNoConfigRewriteNoBackup(t *testing.T) {
	dir, configPath := writeV2ApplyConfig(t)
	body := supportedAgentBodyV2("fleet", "")
	body.Assignment.AssignmentID = "assign-cmd-5"
	body.Assignment.Sequence = 3
	raw, fp := signV2Bundle(t, body)
	bundlePath := writeBundle(t, dir, raw)

	// First apply writes the config + state + one backup.
	if _, err := runPolicyApply(t,
		"--bundle", bundlePath, "--trust-fingerprint", fp,
		"--config", configPath, "--json",
	); err != nil {
		t.Fatalf("first v2 apply must succeed: %v", err)
	}
	afterFirst, _ := os.ReadFile(configPath)
	if backupCount(t, configPath) != 1 {
		t.Fatalf("first apply must create one backup, got %d", backupCount(t, configPath))
	}

	// Second apply of the SAME bundle is a no-op: config already on policy.
	got2, err := runPolicyApply(t,
		"--bundle", bundlePath, "--trust-fingerprint", fp,
		"--config", configPath, "--json",
	)
	if err != nil {
		t.Fatalf("second (no-op) v2 apply must succeed: %v", err)
	}
	if got2["applied"] != false || got2["changed"] != false {
		t.Fatalf("no-op apply: applied/changed = %v/%v, want false/false", got2["applied"], got2["changed"])
	}
	if bp, _ := got2["backup_path"].(string); bp != "" {
		t.Fatalf("no-op apply must not report a backup_path, got %q", bp)
	}
	// Config bytes unchanged and no NEW backup created.
	afterSecond, _ := os.ReadFile(configPath)
	if !bytes.Equal(afterFirst, afterSecond) {
		t.Fatal("no-op v2 apply rewrote the config")
	}
	if backupCount(t, configPath) != 1 {
		t.Fatalf("no-op apply must not create a new backup, total = %d", backupCount(t, configPath))
	}
	// State still reflects the (re)applied assignment at its sequence.
	var st struct {
		Targets map[string]struct {
			LastSequence     int64  `json:"last_sequence"`
			LastAssignmentID string `json:"last_assignment_id"`
		} `json:"targets"`
	}
	data, _ := os.ReadFile(statePath(configPath))
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("decode state file: %v", err)
	}
	rec, ok := st.Targets["fleet:"]
	if !ok || rec.LastSequence != 3 || rec.LastAssignmentID != "assign-cmd-5" {
		t.Fatalf("no-op state record = %+v, want seq 3 / assign-cmd-5", st.Targets)
	}
}

// 6. v2 unsupported-dimension real apply fails, writes no config, no backup, and
// does NOT create the policy-state file (the unsupported check precedes the state
// read/write). Uses an ACLs replace, which the projector fails closed on.
func TestPolicyApplyV2_UnsupportedDimensionFailsNoWriteNoState(t *testing.T) {
	dir, configPath := writeV2ApplyConfig(t)
	b := baseBodyV2()
	b.Assignment.Target = policybundle.TargetV2{Scope: "fleet"}
	g := agentGovV2cmd("voice-ai")
	g.ACLs = policybundle.DimACLsV2{Mode: "replace", AllowedRecipients: []string{"billing-agent"}, BlockedRecipients: []string{}}
	b.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	raw, fp := signV2Bundle(t, b)
	bundlePath := writeBundle(t, dir, raw)
	before, _ := os.ReadFile(configPath)

	if _, err := runPolicyApply(t,
		"--bundle", bundlePath, "--trust-fingerprint", fp,
		"--config", configPath, "--json",
	); err == nil {
		t.Fatal("v2 apply governing an unsupported dimension must fail")
	}
	after, _ := os.ReadFile(configPath)
	if !bytes.Equal(before, after) {
		t.Fatal("unsupported-dimension apply must not modify the config")
	}
	if backupCount(t, configPath) != 0 {
		t.Fatal("unsupported-dimension apply must not create a backup")
	}
	if _, err := os.Stat(statePath(configPath)); !os.IsNotExist(err) {
		t.Fatal("unsupported-dimension apply must not create a policy-state file")
	}
}

// 6b. If the state file already exists from a prior successful apply, an
// unsupported-dimension apply must NOT advance its sequence (fails before the
// state write).
func TestPolicyApplyV2_UnsupportedDoesNotAdvanceExistingState(t *testing.T) {
	dir, configPath := writeV2ApplyConfig(t)

	// Prior successful fleet apply records seq 2.
	good := supportedAgentBodyV2("fleet", "")
	good.Assignment.AssignmentID = "assign-good"
	good.Assignment.Sequence = 2
	goodRaw, fp := signV2Bundle(t, good)
	goodPath := writeBundle(t, dir, goodRaw)
	if _, err := runPolicyApply(t,
		"--bundle", goodPath, "--trust-fingerprint", fp,
		"--config", configPath, "--json",
	); err != nil {
		t.Fatalf("seed apply must succeed: %v", err)
	}
	stateBefore, _ := os.ReadFile(statePath(configPath))

	// A later unsupported-dimension bundle at a higher sequence must fail and
	// leave the state untouched.
	bad := baseBodyV2()
	bad.Assignment.Target = policybundle.TargetV2{Scope: "fleet"}
	bad.Assignment.AssignmentID = "assign-bad"
	bad.Assignment.Sequence = 5
	g := agentGovV2cmd("voice-ai")
	g.ACLs = policybundle.DimACLsV2{Mode: "replace", AllowedRecipients: []string{"x"}, BlockedRecipients: []string{}}
	bad.Governance.Agents = []policybundle.AgentGovernanceV2{g}
	badRaw, _ := signV2Bundle(t, bad)
	badPath := writeBundle(t, dir, badRaw)
	if _, err := runPolicyApply(t,
		"--bundle", badPath, "--trust-fingerprint", fp,
		"--config", configPath, "--json",
	); err == nil {
		t.Fatal("unsupported-dimension apply must fail")
	}
	stateAfter, _ := os.ReadFile(statePath(configPath))
	if !bytes.Equal(stateBefore, stateAfter) {
		t.Fatal("unsupported-dimension apply advanced the existing policy-state")
	}
}

// 7. v1 unchanged regression: a v1 bundle still REQUIRES --agent and does not
// require/use --node-id. This confirms the v1 path is behaviorally identical to
// before the v2 branch.
func TestPolicyApplyV1_StillRequiresAgentIgnoresNodeID(t *testing.T) {
	bundlePath, configPath := writePolicyApplyInputs(t)

	// v1 dry-run without --agent still fails (even with a --node-id present,
	// which the v1 path ignores).
	if _, err := runPolicyApply(t,
		"--bundle", bundlePath, "--trust-fingerprint", fixtureTrustFP(t),
		"--config", configPath, "--node-id", "node-east-1", "--dry-run", "--json",
	); err == nil {
		t.Fatal("v1 apply without --agent must still fail")
	}

	// v1 dry-run WITH --agent still succeeds and a stray --node-id is ignored
	// (no node binding on the v1 path), proving behavior is unchanged.
	before, _ := os.ReadFile(configPath)
	got, err := runPolicyApply(t,
		"--bundle", bundlePath, "--trust-fingerprint", fixtureTrustFP(t),
		"--config", configPath, "--agent", "voice-ai", "--node-id", "node-east-1", "--dry-run", "--json",
	)
	if err != nil {
		t.Fatalf("v1 dry-run with --agent (and a stray --node-id) must succeed: %v", err)
	}
	if got["agent"] != "voice-ai" {
		t.Fatalf("v1 plan agent = %v, want voice-ai", got["agent"])
	}
	if _, hasNode := got["node_id"]; hasNode {
		t.Fatal("v1 plan must not carry a node_id field")
	}
	after, _ := os.ReadFile(configPath)
	if !bytes.Equal(before, after) {
		t.Fatal("v1 dry-run modified the config")
	}
	// v1 never writes a v2-style policy-state file.
	if _, err := os.Stat(statePath(configPath)); !os.IsNotExist(err) {
		t.Fatal("v1 path must not create a policy-state file")
	}
}
