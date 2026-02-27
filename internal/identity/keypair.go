// Package identity provides Ed25519 key generation, message signing,
// and signature verification for agent-to-agent authentication.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/oktsec/oktsec/internal/safefile"
)

// Keypair holds an Ed25519 key pair for an agent.
type Keypair struct {
	Name       string
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// GenerateKeypair creates a new Ed25519 key pair for the named agent.
func GenerateKeypair(name string) (*Keypair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating keypair: %w", err)
	}
	return &Keypair{
		Name:       name,
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}

// Save writes the keypair to disk as PEM files.
// Creates <dir>/<name>.key (private) and <dir>/<name>.pub (public).
func (kp *Keypair) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating keys directory: %w", err)
	}

	// Save private key
	privBlock := &pem.Block{
		Type:  "OKTSEC ED25519 PRIVATE KEY",
		Bytes: kp.PrivateKey,
	}
	privPath := filepath.Join(dir, kp.Name+".key")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(privBlock), 0o600); err != nil {
		return fmt.Errorf("writing private key: %w", err)
	}

	// Save public key
	pubBlock := &pem.Block{
		Type:  "OKTSEC ED25519 PUBLIC KEY",
		Bytes: kp.PublicKey,
	}
	pubPath := filepath.Join(dir, kp.Name+".pub")
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(pubBlock), 0o644); err != nil {
		return fmt.Errorf("writing public key: %w", err)
	}

	return nil
}

// LoadKeypair loads a full keypair (private + public) from disk.
// Key files must not be symlinks and must not exceed 64 KB.
func LoadKeypair(dir, name string) (*Keypair, error) {
	privPath := filepath.Join(dir, name+".key")
	privPEM, err := safefile.ReadFileMax(privPath, 64*1024)
	if err != nil {
		return nil, fmt.Errorf("reading private key: %w", err)
	}
	privBlock, _ := pem.Decode(privPEM)
	if privBlock == nil {
		return nil, fmt.Errorf("invalid PEM in %s", privPath)
	}
	priv := ed25519.PrivateKey(privBlock.Bytes)

	pub, err := LoadPublicKey(dir, name)
	if err != nil {
		// Derive public key from private key
		pub = priv.Public().(ed25519.PublicKey)
	}

	return &Keypair{
		Name:       name,
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}

// LoadPublicKey loads only the public key from disk.
// The file must not be a symlink and must not exceed 64 KB.
func LoadPublicKey(dir, name string) (ed25519.PublicKey, error) {
	pubPath := filepath.Join(dir, name+".pub")
	pubPEM, err := safefile.ReadFileMax(pubPath, 64*1024)
	if err != nil {
		return nil, fmt.Errorf("reading public key: %w", err)
	}
	pubBlock, _ := pem.Decode(pubPEM)
	if pubBlock == nil {
		return nil, fmt.Errorf("invalid PEM in %s", pubPath)
	}
	return ed25519.PublicKey(pubBlock.Bytes), nil
}

// LoadPublicKeys loads all .pub files from a directory, keyed by agent name.
func LoadPublicKeys(dir string) (map[string]ed25519.PublicKey, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading keys directory: %w", err)
	}

	keys := make(map[string]ed25519.PublicKey)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".pub" {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			continue // skip symlinks
		}
		name := entry.Name()[:len(entry.Name())-4] // strip .pub
		pub, err := LoadPublicKey(dir, name)
		if err != nil {
			return nil, fmt.Errorf("loading key for %s: %w", name, err)
		}
		keys[name] = pub
	}
	return keys, nil
}

// Fingerprint returns the SHA-256 hex fingerprint of a public key.
func Fingerprint(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])
}
