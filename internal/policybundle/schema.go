package policybundle

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// rejectDuplicateKeys walks the JSON token stream and fails if any object
// anywhere in the bundle declares the same key twice. Go's encoding/json
// keeps the last duplicate silently, which is unacceptable for a signed
// artifact that gates apply: a bundle could present one value to a human
// reviewer (first occurrence) and another to the verifier (last). This runs
// before the typed decode trusts any field.
func rejectDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	return checkNoDuplicateKeys(dec)
}

// checkNoDuplicateKeys consumes exactly one JSON value, recursing into
// objects and arrays. Trailing content after the value is the typed
// decoder's concern (EOF check), not this scan's.
func checkNoDuplicateKeys(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // scalar
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyTok.(string)
			if !ok {
				return fmt.Errorf("object key is not a string")
			}
			if _, dup := seen[key]; dup {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = struct{}{}
			if err := checkNoDuplicateKeys(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token() // consume '}'
		return err
	case '[':
		for dec.More() {
			if err := checkNoDuplicateKeys(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token() // consume ']'
		return err
	}
	return nil
}

// policy_bundle.v1 enum value sets for fields that are part of the signed
// policy model. An out-of-set value is policy_schema_invalid: the verifier
// must not label a bundle "verified" with a mode/action/level the v1 schema
// does not define, since apply (or a reader) could otherwise fail open.
var (
	validModes           = map[string]bool{"enforce": true, "observe": true}
	validOverrideActions = map[string]bool{"flag": true, "quarantine": true, "block": true}
	validRedactionLevels = map[string]bool{"full": true, "analyst": true, "external": true}
)

// validatePolicySchema enforces required-non-empty scalar fields and the
// signed-model enum value sets. Returns an error (mapped to
// policy_schema_invalid by the caller) on the first violation. Container
// presence and timestamp canonical form are validated separately. Fields
// already covered by other checks are not re-validated here: schema/
// canonicalization/alg tags (constant checks), policy_hash (hash recompute),
// signed_at/created_at (timestamp checks), public_key/fingerprint/value
// (signature checks).
func validatePolicySchema(b *PolicyBundle) error {
	for _, f := range []struct{ name, val string }{
		{"policy.policy_id", b.Policy.PolicyID},
		{"policy.policy_version", b.Policy.PolicyVersion},
		{"policy.metadata.created_by", b.Policy.Metadata.CreatedBy},
		{"policy.metadata.reason", b.Policy.Metadata.Reason},
		{"signature.key_id", b.Signature.KeyID},
	} {
		if f.val == "" {
			return fmt.Errorf("%s must not be empty", f.name)
		}
	}
	if !validModes[b.Policy.Mode] {
		return fmt.Errorf("policy.mode %q not in {enforce, observe}", b.Policy.Mode)
	}
	if !validRedactionLevels[b.Policy.Redaction.Level] {
		return fmt.Errorf("policy.redaction.level %q not in {full, analyst, external}", b.Policy.Redaction.Level)
	}
	for id, ov := range b.Policy.Rules.Overrides {
		if !validOverrideActions[ov.Action] {
			return fmt.Errorf("policy.rules.overrides[%q].action %q not in {flag, quarantine, block}", id, ov.Action)
		}
	}
	return nil
}
