package node

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

// PEM block types for the node identity keypair. Intentionally distinct
// from agent/principal keys ("OKTSEC ED25519 PRIVATE KEY") so a node
// key cannot be mistaken for, or loaded as, an agent key by the
// identity package.
const (
	NodePrivateKeyPEMType = "OKTSEC NODE ED25519 PRIVATE KEY"
	NodePublicKeyPEMType  = "OKTSEC NODE ED25519 PUBLIC KEY"
)

// File names inside the node identity directory.
const (
	identityFileName  = "identity.json"
	privateKeyFile    = "node.key"
	publicKeyFile     = "node.pub"
	maxIdentityBytes  = 64 * 1024
	maxKeyBytes       = 64 * 1024
	nodeIDRandomBytes = 18 // 24 base32 chars after encoding
)

// Signature is the result of NodeIdentity.Sign. The Base64 field is
// the raw 64-byte Ed25519 signature std-base64-encoded.
type Signature struct {
	Base64 string
}

// errIdentityMissing is returned when no identity files are present.
// Callers convert this into structured warnings via Status; CLI uses
// it to decide between exit codes.
var errIdentityMissing = errors.New("node identity missing")

// IsErrIdentityMissing reports whether err is the canonical
// "identity files not present" error.
func IsErrIdentityMissing(err error) bool {
	return errors.Is(err, errIdentityMissing)
}

// newNodeID generates a non-secret, stable, random node ID with a
// "node_" prefix. The body is base32-without-padding so it is URL-safe
// and avoids ambiguous characters; nothing in the ID is derived from
// hostname, username, or path.
func newNodeID() (string, error) {
	buf := make([]byte, nodeIDRandomBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("node id rand: %w", err)
	}
	// Lowercase hex keeps the ID short and avoids confusion with the
	// hashed fingerprints, which are sha256-prefixed.
	return "node_" + hex.EncodeToString(buf), nil
}

// computeHostFingerprint hashes coarse, non-secret host facts.
// Hostname is intentionally NOT used directly to avoid leaking
// machine names; we hash hostname + OS + arch together so the result
// is opaque but stable across runs on the same machine.
func computeHostFingerprint() string {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
	}
	// Lowercase so case-insensitive macOS hostnames produce a stable
	// fingerprint across reboots.
	hostname = strings.ToLower(hostname)
	payload := hostname + "|" + runtime.GOOS + "|" + runtime.GOARCH
	sum := sha256.Sum256([]byte(payload))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// fingerprintPublicKey returns "sha256:<hex>" for an Ed25519 public
// key. Mirrors identity.Fingerprint's hash but with the "sha256:"
// prefix so callers can tell hash families apart in JSON output.
func fingerprintPublicKey(pub ed25519.PublicKey) string {
	if len(pub) == 0 {
		return ""
	}
	sum := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// signWithKey produces an Ed25519 signature over payload using priv.
func signWithKey(priv ed25519.PrivateKey, payload []byte) Signature {
	sig := ed25519.Sign(priv, payload)
	return Signature{Base64: base64.StdEncoding.EncodeToString(sig)}
}

// nowUTCRFC3339 returns the current time as an RFC3339 UTC string.
// Wrapped so tests can avoid passing time.Now everywhere; the
// snapshot/identity flows always want UTC.
func nowUTCRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}
