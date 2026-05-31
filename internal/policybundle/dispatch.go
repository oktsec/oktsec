package policybundle

import (
	"bytes"
	"encoding/json"
)

// schemaDiscriminator is the minimal shape used to peek a bundle's declared
// schema_version before committing to a typed verifier. It is a structural
// sniff only: it does not validate anything else, and an unknown or absent
// schema_version routes nowhere (RejectUnsupportedBundle).
type schemaDiscriminator struct {
	SchemaVersion string `json:"schema_version"`
}

// peekSchemaVersion decodes just the schema_version field from a bundle. A
// decode error is surfaced as a decode reject so callers get a stable
// RejectCode rather than a raw json error.
func peekSchemaVersion(raw []byte) (string, error) {
	var d schemaDiscriminator
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&d); err != nil {
		return "", reject(RejectDecode, "decode schema_version discriminator: %s", err)
	}
	return d.SchemaVersion, nil
}

// VerifyResult is the schema-tagged result of Verify. Exactly one of V1 or V2
// is non-nil, matching SchemaVersion. Callers that already know the schema can
// keep using VerifyBundle / VerifyBundleV2 directly; Verify is the dispatch
// entry point for callers handed an artifact of unknown version.
type VerifyResult struct {
	SchemaVersion string
	V1            *VerifiedBundle
	V2            *VerifiedBundleV2
}

// Verify peeks the declared schema_version and routes to the matching typed
// verifier. A v1 body reaches only the v1 verifier and a v2 body only the v2
// verifier, so a body of one schema can never be accepted by the other: each
// typed verifier re-checks the schema constant and rejects a mismatch. An
// unrecognized schema_version is RejectUnsupportedBundle.
//
// This does not change VerifyBundle (v1) or VerifyBundleV2: both remain
// exported and behaviorally unchanged for callers that know the schema.
func Verify(raw []byte, trustFingerprint string) (*VerifyResult, error) {
	if trustFingerprint == "" {
		return nil, ErrTrustFingerprintRequired
	}
	sv, err := peekSchemaVersion(raw)
	if err != nil {
		return nil, err
	}
	switch sv {
	case SchemaVersion:
		v, err := VerifyBundle(raw, trustFingerprint)
		if err != nil {
			return nil, err
		}
		return &VerifyResult{SchemaVersion: sv, V1: v}, nil
	case SchemaVersionV2:
		v, err := VerifyBundleV2(raw, trustFingerprint)
		if err != nil {
			return nil, err
		}
		return &VerifyResult{SchemaVersion: sv, V2: v}, nil
	default:
		return nil, reject(RejectUnsupportedBundle, "unsupported schema_version %q", sv)
	}
}
