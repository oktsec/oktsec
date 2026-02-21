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

// VerifyMessage checks the Ed25519 signature on a message.
func VerifyMessage(publicKey ed25519.PublicKey, from, to, content, timestamp, signatureB64 string) VerifyResult {
	sigBytes, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return VerifyResult{
			Verified: false,
			Error:    fmt.Errorf("invalid base64 signature: %w", err),
		}
	}

	payload := canonicalPayload(from, to, content, timestamp)
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
