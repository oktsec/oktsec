package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// SignMessage signs the canonical (v1) representation of a message.
// The signature covers: from + to + content + timestamp.
//
// Prefer SignMessageV2 when the agent's config declares a key_version —
// v1 signatures are accepted for backward compatibility but do not commit
// to a specific key version, so they cannot protect against an attacker
// replaying a signature after key rotation.
func SignMessage(privateKey ed25519.PrivateKey, from, to, content, timestamp string) string {
	payload := canonicalPayload(from, to, content, timestamp)
	sig := ed25519.Sign(privateKey, payload)
	return base64.StdEncoding.EncodeToString(sig)
}

// SignMessageV2 binds the signature to a specific key version. Verifiers
// that accept the message must also check that the version matches the
// agent's current key_version — this is what makes post-rotation replay
// impossible.
func SignMessageV2(privateKey ed25519.PrivateKey, from, to, content, timestamp string, keyVersion int64) string {
	payload := canonicalPayloadV2(from, to, content, timestamp, keyVersion)
	sig := ed25519.Sign(privateKey, payload)
	return base64.StdEncoding.EncodeToString(sig)
}

// canonicalPayload builds the deterministic v1 byte sequence.
func canonicalPayload(from, to, content, timestamp string) []byte {
	return []byte(fmt.Sprintf("%s\n%s\n%s\n%s", from, to, content, timestamp))
}

// canonicalPayloadV2 extends v1 with the trailing key version so rotated
// keys produce non-forgeable signatures.
func canonicalPayloadV2(from, to, content, timestamp string, keyVersion int64) []byte {
	return []byte(fmt.Sprintf("%s\n%s\n%s\n%s\n%d", from, to, content, timestamp, keyVersion))
}
