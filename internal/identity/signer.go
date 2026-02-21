package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// SignMessage signs the canonical representation of a message.
// The signature covers: from + to + content + timestamp.
func SignMessage(privateKey ed25519.PrivateKey, from, to, content, timestamp string) string {
	payload := canonicalPayload(from, to, content, timestamp)
	sig := ed25519.Sign(privateKey, payload)
	return base64.StdEncoding.EncodeToString(sig)
}

// canonicalPayload builds the deterministic byte sequence that gets signed/verified.
func canonicalPayload(from, to, content, timestamp string) []byte {
	return []byte(fmt.Sprintf("%s\n%s\n%s\n%s", from, to, content, timestamp))
}
