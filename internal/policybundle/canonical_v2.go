package policybundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// canonicalPolicyBodyBytesV2 returns the exact byte layout that policy_hash
// and the Ed25519 signature cover for a v2 body: a typed-struct JSON
// projection, HTML escaping off, no trailing newline. Encoding the typed
// struct (never a map[string]any) fixes field order; map keys
// (rules.overrides, selector.labels, tool_policies.by_tool, tool_constraint
// parameters, per-agent egress.tool_restrictions) serialize alphabetically
// under encoding/json, so the canonical bytes are deterministic without explicit
// sorting.
//
// Timestamps are NOT normalized here (same rule as v1): the verifier hashes
// the exact wire strings. validateCanonicalPolicyTimestamp enforces the single
// accepted form before the hash is recomputed.
//
// Number canonicalization: monetary/limit values that are float64 in
// config.ToolPolicy are carried as decimal STRINGS on the v2 wire, never JSON
// numbers. Go's float formatting is not portably guaranteed to round-trip to a
// single byte sequence, so a float in the signed body would be a stable-hash
// hazard. Integer counts stay JSON integers, which encoding/json formats
// deterministically.
func canonicalPolicyBodyBytesV2(body PolicyBodyV2) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		return nil, fmt.Errorf("encode canonical v2 body: %w", err)
	}
	// Encode appends a trailing newline; strip it so the hashed bytes are
	// exactly the marshaled JSON.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// policyHashHexV2 returns the sha256 hex of the canonical v2 body bytes with
// the "sha256:" wire prefix, plus the canonical bytes themselves.
func policyHashHexV2(body PolicyBodyV2) (string, []byte, error) {
	canon, err := canonicalPolicyBodyBytesV2(body)
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(sum[:]), canon, nil
}

// policyBundleV2SigningPayload returns the exact bytes the Ed25519 signature
// covers for a v2 bundle: domain-separated labeled lines, newline-joined, no
// trailing newline. Beyond the v1 fields it binds the assignment, target,
// sequence, issued_at, and rollback_of, so a store cannot rewrite a signed
// bundle's binding or anti-rollback metadata without breaking the signature.
// signed_at is NOT part of this payload (it lives in the v1 payload but v2
// binds issued_at instead as the authoritative time). The signer and this
// verifier MUST produce identical bytes or every signature fails to verify.
func policyBundleV2SigningPayload(
	policyID, policyVersion, policyHash,
	assignmentID, targetScope, targetNodeID, issuedAt string,
	sequence int64,
	rollbackOf, keyID, publicKeyFingerprint string,
) []byte {
	lines := []string{
		"oktsec." + SchemaVersionV2,
		fmt.Sprintf("bundle_version:%d", BundleVersionV2),
		"policy_id:" + policyID,
		"policy_version:" + policyVersion,
		"policy_hash:" + policyHash,
		"canonicalization:" + CanonicalizationV2,
		"assignment_id:" + assignmentID,
		"target_scope:" + targetScope,
		"target_node_id:" + targetNodeID,
		"issued_at:" + issuedAt,
		"sequence:" + strconv.FormatInt(sequence, 10),
		"rollback_of:" + rollbackOf,
		"signature_key_id:" + keyID,
		"signature_public_key_fingerprint:" + publicKeyFingerprint,
	}
	return []byte(strings.Join(lines, "\n"))
}

// policy_bundle.v2 enum value sets for fields that are part of the signed
// policy model. An out-of-set value is policy_schema_invalid: the verifier
// must not label a bundle "verified" with a value the v2 schema does not
// define, since apply (or a reader) could otherwise fail open.
//
// validDimModes deliberately omits "merge": merge semantics are DEFERRED in
// 9A. A bundle declaring mode "merge" anywhere is rejected as out-of-range
// until the merge contract is designed.
var (
	validDimModes    = map[string]bool{"unmanaged": true, "replace": true, "clear": true}
	validTargetScope = map[string]bool{"fleet": true, "node": true}
	// validTriState is the closed-set string form for config.EgressPolicy's
	// *bool fields (scan_requests, scan_responses), carried on the v2 wire as a
	// string so the canonical bytes never contain null. "unset" preserves the
	// nil-pointer (fall back to global) semantics; apply is 9A.2.
	validTriState = map[string]bool{"unset": true, "true": true, "false": true}
	// validScanProfileValues is the closed set of agent scan_profile values the
	// runtime accepts (config ScanProfile* constants), plus "" for unset. A v2
	// bundle declaring an out-of-set scan_profile cannot be safely projected, so
	// the verifier rejects it rather than label it verified.
	validScanProfileValues = map[string]bool{"": true, "strict": true, "content-aware": true, "minimal": true}
)

// canonicalDecimal is the single accepted decimal-string wire form for v2
// monetary/limit values: an optional minus, integer part with no leading
// zeros (or a single "0"), and an optional fractional part with at least one
// digit. No exponent, no thousands separators, no leading "+". This is a
// stable byte form so the hash is deterministic; numeric interpretation is
// deferred to 9A.2 apply.
var canonicalDecimal = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?$`)

// validateCanonicalDecimal rejects a v2 decimal-string value that is not in
// the single canonical wire form. An empty string is allowed and means
// "unset" (the field carries no value); a present value must be canonical.
//
// Non-negative is also required for the monetary/limit fields it guards: the
// runtime tool-policy enforcer treats a non-positive limit as "unset", so a
// signed bundle carrying a negative limit would silently DISABLE a limit if
// applied. Rejecting it at verify time keeps a "verified" bundle from meaning
// the opposite of what it declares. (A leading "-" is the only way to express a
// negative here; canonicalDecimal already forbids "-0".)
func validateCanonicalDecimal(field, s string) error {
	if s == "" {
		return nil // unset
	}
	if !canonicalDecimal.MatchString(s) {
		return fmt.Errorf("%s %q is not a canonical decimal string", field, s)
	}
	if strings.HasPrefix(s, "-") {
		return fmt.Errorf("%s %q must not be negative", field, s)
	}
	return nil
}

// validateCanonicalPolicyContainersV2 requires every list/map container in the
// v2 body to be present in its canonical empty form ([] / {}), never null or
// omitted. The official signer always emits []/{} for empty sections, so the
// verifier refuses a null or absent container as a non-canonical artifact
// (policy_schema_invalid). This covers ALL v2 containers, including the
// per-agent governance sub-containers.
func validateCanonicalPolicyContainersV2(body PolicyBodyV2) error {
	var nilFields []string
	add := func(cond bool, name string) {
		if cond {
			nilFields = append(nilFields, name)
		}
	}

	add(body.Rules.Enabled == nil, "rules.enabled")
	add(body.Rules.Disabled == nil, "rules.disabled")
	add(body.Rules.Overrides == nil, "rules.overrides")
	add(body.Gateway.ToolsAllowed == nil, "gateway.tools_allowed")
	add(body.Gateway.ToolsDenied == nil, "gateway.tools_denied")
	add(body.Egress.DomainsAllowed == nil, "egress.domains_allowed")
	add(body.Egress.DomainsDenied == nil, "egress.domains_denied")
	add(body.Governance.Agents == nil, "governance.agents")

	for i := range body.Governance.Agents {
		a := &body.Governance.Agents[i]
		p := fmt.Sprintf("governance.agents[%d]", i)
		add(a.Selector.Labels == nil, p+".selector.labels")
		add(a.ACLs.AllowedRecipients == nil, p+".acls.allowed_recipients")
		add(a.ACLs.BlockedRecipients == nil, p+".acls.blocked_recipients")
		add(a.AllowedTools.Values == nil, p+".allowed_tools.values")
		add(a.ToolPolicies.ByTool == nil, p+".tool_policies.by_tool")
		add(a.ToolConstraints.Items == nil, p+".tool_constraints.items")
		add(a.ToolChainRules.Items == nil, p+".tool_chain_rules.items")
		add(a.BlockedContent.Values == nil, p+".blocked_content.values")
		add(a.Egress.AllowedDomains == nil, p+".egress.allowed_domains")
		add(a.Egress.BlockedDomains == nil, p+".egress.blocked_domains")
		add(a.Egress.ToolRestrictions == nil, p+".egress.tool_restrictions")
		add(a.Egress.BlockedCategories == nil, p+".egress.blocked_categories")
		add(a.Egress.Integrations == nil, p+".egress.integrations")
		for dom, vals := range a.Egress.ToolRestrictions {
			add(vals == nil, fmt.Sprintf("%s.egress.tool_restrictions[%q]", p, dom))
		}

		for j := range a.ToolConstraints.Items {
			c := &a.ToolConstraints.Items[j]
			cp := fmt.Sprintf("%s.tool_constraints.items[%d]", p, j)
			add(c.Parameters == nil, cp+".parameters")
			for name, pc := range c.Parameters {
				add(pc.AllowedPatterns == nil, fmt.Sprintf("%s.parameters[%q].allowed_patterns", cp, name))
				add(pc.BlockedPatterns == nil, fmt.Sprintf("%s.parameters[%q].blocked_patterns", cp, name))
			}
		}
		for j := range a.ToolChainRules.Items {
			r := &a.ToolChainRules.Items[j]
			add(r.Then == nil, fmt.Sprintf("%s.tool_chain_rules.items[%d].then", p, j))
		}
	}

	if len(nilFields) > 0 {
		return fmt.Errorf("container(s) must be present as [] or {}, not null or omitted: %s",
			strings.Join(nilFields, ", "))
	}
	return nil
}
