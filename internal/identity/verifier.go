package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// VerifyResult captures the outcome of signature verification.
type VerifyResult struct {
	Verified    bool   // true if signature is valid
	Fingerprint string // SHA-256 fingerprint of the public key used
	Error       error  // non-nil if verification failed
}

// VerifyMessage checks the v1 Ed25519 signature on a message.
// Kept for backward compatibility with SDKs that haven't adopted versioned
// signing. Handlers that know the agent's key_version should prefer
// VerifyMessageV2.
func VerifyMessage(publicKey ed25519.PublicKey, from, to, content, timestamp, signatureB64 string) VerifyResult {
	return verifyAgainstPayload(publicKey, signatureB64, canonicalPayload(from, to, content, timestamp))
}

// VerifyMessageV2 verifies a signature that commits to a specific key
// version. The caller is responsible for asserting keyVersion matches the
// agent's expected version — this function only proves the signature
// covered the claimed version.
func VerifyMessageV2(publicKey ed25519.PublicKey, from, to, content, timestamp string, keyVersion int64, signatureB64 string) VerifyResult {
	return verifyAgainstPayload(publicKey, signatureB64, canonicalPayloadV2(from, to, content, timestamp, keyVersion))
}

func verifyAgainstPayload(publicKey ed25519.PublicKey, signatureB64 string, payload []byte) VerifyResult {
	sigBytes, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return VerifyResult{
			Verified: false,
			Error:    fmt.Errorf("invalid base64 signature: %w", err),
		}
	}

	ok := ed25519.Verify(publicKey, payload, sigBytes)

	fp := Fingerprint(publicKey)
	if !ok {
		return VerifyResult{
			Verified:    false,
			Fingerprint: fp,
			Error:       fmt.Errorf("signature verification failed"),
		}
	}
	return VerifyResult{
		Verified:    true,
		Fingerprint: fp,
	}
}
