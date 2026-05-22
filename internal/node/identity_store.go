package node

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/safefile"
)

// IdentityStore is the file-backed local node identity. The directory
// holds:
//
//	identity.json   metadata + public-key fingerprint
//	node.key        Ed25519 private key (PEM, 0600)
//	node.pub        Ed25519 public key  (PEM, 0644)
//
// Init/Load/Sign all refuse symlinked files and refuse to follow
// symlinks for the directory itself.
type IdentityStore struct {
	Dir string
}

// DefaultIdentityStore returns the canonical node identity store at
// config.HomeDir()/node/.
func DefaultIdentityStore() IdentityStore {
	return IdentityStore{Dir: filepath.Join(config.HomeDir(), "node")}
}

// Status reports whether the local identity is present, missing, or
// invalid. Always non-nil even for missing identity so the CLI can
// JSON-serialize the result without a special case.
func (s IdentityStore) Status() IdentityStatus {
	id, err := s.Load()
	switch {
	case err == nil:
		return IdentityStatus{Status: "present", Identity: id}
	case IsErrIdentityMissing(err):
		return IdentityStatus{
			Status: "missing",
			Warnings: []Warning{{
				Code:    WarnNodeIdentityMissing,
				Message: "Run `oktsec node init` to sign future checkpoints.",
			}},
		}
	default:
		return IdentityStatus{
			Status: "invalid",
			Warnings: []Warning{{
				Code:    WarnNodeIdentityInvalid,
				Message: err.Error(),
			}},
		}
	}
}

// Init creates the identity directory and writes identity.json,
// node.key, node.pub. Idempotent: if a valid identity already exists,
// the loaded identity is returned unchanged. The InstallProfile field
// is updated on re-init only if it differs (the rest of the record
// is preserved).
//
// Init refuses symlinked target paths. Files are written with
// 0o600/0o644 modes and the directory is 0o700.
func (s IdentityStore) Init(profile string) (*Identity, error) {
	if s.Dir == "" {
		return nil, errors.New("node: identity store dir is empty")
	}
	if profile == "" {
		profile = ProfileLocal
	}

	if err := ensureDirSafe(s.Dir); err != nil {
		return nil, err
	}

	// Idempotency: a complete identity stays; we never rotate the
	// keypair from Init. force-rotate is intentionally not in Order 1.
	if existing, err := s.Load(); err == nil {
		if profile != "" && existing.InstallProfile != profile {
			existing.InstallProfile = profile
			if err := s.writeIdentity(existing); err != nil {
				return nil, err
			}
		}
		return existing, nil
	} else if !IsErrIdentityMissing(err) {
		// A partial/corrupt identity is a refuse-to-overwrite case.
		// The operator must `oktsec node init --force-rotate` (future)
		// or manually remove the file. We never silently destroy keys.
		return nil, fmt.Errorf("node identity present but invalid (refusing to overwrite): %w", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating node keypair: %w", err)
	}

	if err := writePEMSafe(filepath.Join(s.Dir, privateKeyFile), NodePrivateKeyPEMType, priv, 0o600); err != nil {
		return nil, err
	}
	if err := writePEMSafe(filepath.Join(s.Dir, publicKeyFile), NodePublicKeyPEMType, pub, 0o644); err != nil {
		return nil, err
	}

	nodeID, err := newNodeID()
	if err != nil {
		return nil, err
	}
	id := &Identity{
		SchemaVersion:        SchemaIdentity,
		NodeID:               nodeID,
		CreatedAt:            nowUTCRFC3339(),
		PublicKeyFingerprint: fingerprintPublicKey(pub),
		HostFingerprint:      computeHostFingerprint(),
		InstallProfile:       profile,
	}
	if err := s.writeIdentity(id); err != nil {
		return nil, err
	}
	return id, nil
}

// Load reads identity.json AND verifies that node.key + node.pub
// exist and are consistent with the fingerprint in identity.json.
//
// The signed-checkpoint contract that future Enterprise depends on
// requires all three to be usable together: identity.json on its own
// (without keys, or with mismatched keys) must not be reported as
// present. If only identity.json exists, Load returns a real error
// — not errIdentityMissing — so the CLI marks the install "invalid"
// rather than "missing" (which would imply a clean uninitialized
// node).
//
// Treatment of the three files:
//
//	all three absent          -> errIdentityMissing (status: missing)
//	identity.json only        -> error                (status: invalid)
//	identity.json + keys but
//	      fingerprint mismatch -> error                (status: invalid)
//	all three present, valid  -> *Identity, nil       (status: present)
func (s IdentityStore) Load() (*Identity, error) {
	idPath := filepath.Join(s.Dir, identityFileName)
	privPath := filepath.Join(s.Dir, privateKeyFile)
	pubPath := filepath.Join(s.Dir, publicKeyFile)

	idExists := fileExists(idPath)
	privExists := fileExists(privPath)
	pubExists := fileExists(pubPath)
	if !idExists && !privExists && !pubExists {
		return nil, errIdentityMissing
	}

	if !idExists {
		return nil, fmt.Errorf("node key files present but identity.json missing")
	}
	data, err := safefile.ReadFileMax(idPath, maxIdentityBytes)
	if err != nil {
		return nil, fmt.Errorf("reading node identity: %w", err)
	}

	var id Identity
	if err := json.Unmarshal(data, &id); err != nil {
		return nil, fmt.Errorf("parsing node identity: %w", err)
	}
	if id.NodeID == "" || id.SchemaVersion == "" {
		return nil, fmt.Errorf("node identity missing required fields")
	}
	if id.SchemaVersion != SchemaIdentity {
		return nil, fmt.Errorf("unsupported node identity schema %q", id.SchemaVersion)
	}
	if id.InstallProfile == "" {
		id.InstallProfile = ProfileLocal
	}

	// Keys must both exist and match the fingerprint in identity.json.
	// Anything else means the install cannot sign checkpoints and must
	// be reported as invalid, not present.
	if !privExists {
		return nil, fmt.Errorf("node private key missing at %s", privateKeyFile)
	}
	if !pubExists {
		return nil, fmt.Errorf("node public key missing at %s", publicKeyFile)
	}
	priv, err := readPrivateKey(privPath)
	if err != nil {
		return nil, fmt.Errorf("node identity unusable: %w", err)
	}
	pub, err := readPublicKey(pubPath)
	if err != nil {
		return nil, fmt.Errorf("node identity unusable: %w", err)
	}
	// Cross-check: the private key's derived public half must match
	// the on-disk public key and the fingerprint recorded earlier.
	derived, ok := priv.Public().(ed25519.PublicKey)
	if !ok || !pubKeysEqual(derived, pub) {
		return nil, fmt.Errorf("node identity unusable: public key does not match private key")
	}
	if id.PublicKeyFingerprint != "" && fingerprintPublicKey(pub) != id.PublicKeyFingerprint {
		return nil, fmt.Errorf("node identity unusable: public key fingerprint mismatch")
	}
	return &id, nil
}

// fileExists reports whether path exists as a non-symlink file.
// Symlinks are treated as "does not exist" so a planted link never
// causes Load to read content through it; the symlink-rejecting
// readers further down still cover the read path.
func fileExists(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	return !info.IsDir()
}

// pubKeysEqual compares two Ed25519 public keys byte-by-byte.
func pubKeysEqual(a, b ed25519.PublicKey) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// PublicKey loads and returns the node's Ed25519 public key.
func (s IdentityStore) PublicKey() (ed25519.PublicKey, error) {
	return readPublicKey(filepath.Join(s.Dir, publicKeyFile))
}

// Sign produces an Ed25519 signature over payload using the on-disk
// private key. Returns an error if the identity is missing or the key
// file is unreadable. The private key is loaded fresh on every call so
// the store does not have to keep secret material in memory; callers
// that sign in tight loops should batch payloads upstream.
func (s IdentityStore) Sign(payload []byte) (Signature, error) {
	priv, err := readPrivateKey(filepath.Join(s.Dir, privateKeyFile))
	if err != nil {
		return Signature{}, err
	}
	return signWithKey(priv, payload), nil
}

// writeIdentity serializes id as JSON and writes it under
// identity.json with 0o600 perms via an atomic rename.
func (s IdentityStore) writeIdentity(id *Identity) error {
	data, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding node identity: %w", err)
	}
	// json.MarshalIndent omits the trailing newline; most tools
	// expect one. Adding it here keeps the file editor-friendly
	// without changing the parsed value.
	data = append(data, '\n')
	return writeFileSafe(filepath.Join(s.Dir, identityFileName), data, 0o600)
}

// readPrivateKey loads the Ed25519 private key PEM and validates the
// PEM type so an agent key cannot stand in for the node key.
func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := safefile.ReadFileMax(path, maxKeyBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errIdentityMissing
		}
		return nil, fmt.Errorf("reading node private key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("node private key: invalid PEM in %s", path)
	}
	if block.Type != NodePrivateKeyPEMType {
		return nil, fmt.Errorf("node private key: unexpected PEM type %q", block.Type)
	}
	if len(block.Bytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("node private key: wrong size (%d)", len(block.Bytes))
	}
	return ed25519.PrivateKey(block.Bytes), nil
}

// readPublicKey loads the Ed25519 public key PEM and validates the
// PEM type so an agent key cannot stand in for the node key.
func readPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := safefile.ReadFileMax(path, maxKeyBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errIdentityMissing
		}
		return nil, fmt.Errorf("reading node public key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("node public key: invalid PEM in %s", path)
	}
	if block.Type != NodePublicKeyPEMType {
		return nil, fmt.Errorf("node public key: unexpected PEM type %q", block.Type)
	}
	if len(block.Bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("node public key: wrong size (%d)", len(block.Bytes))
	}
	return ed25519.PublicKey(block.Bytes), nil
}

// ensureDirSafe creates dir with 0o700 if it does not exist and
// refuses to proceed if dir (or its parent) is a symlink. Existing
// directories keep their mode.
func ensureDirSafe(dir string) error {
	if dir == "" {
		return errors.New("node: empty directory")
	}
	// Reject a symlinked parent (so an attacker can't redirect
	// future writes by swapping ~/.oktsec for a link).
	parent := filepath.Dir(dir)
	if parent != "." && parent != "" {
		if info, err := os.Lstat(parent); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("node: parent directory is a symlink: %s", parent)
			}
		}
	}
	info, err := os.Lstat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return os.MkdirAll(dir, 0o700)
	case err != nil:
		return fmt.Errorf("node: stat %s: %w", dir, err)
	default:
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("node: identity directory is a symlink: %s", dir)
		}
		if !info.IsDir() {
			return fmt.Errorf("node: %s exists and is not a directory", dir)
		}
		return nil
	}
}

// writeFileSafe writes data to path atomically. It refuses to write to
// an existing symlink and uses rename(2) to avoid partial writes.
// File perms are applied via chmod after the rename so the umask does
// not weaken them.
func writeFileSafe(path string, data []byte, perm os.FileMode) error {
	if err := refuseExistingSymlink(path); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := ensureDirSafe(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".node-"+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("node: create temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("node: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		// Sync failures are non-fatal on some filesystems; log via
		// the returned error chain so tests can see them but do not
		// block the write — Order 1 does not require fsync semantics.
		_ = tmp.Close()
		return fmt.Errorf("node: sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("node: close temp: %w", err)
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return fmt.Errorf("node: chmod temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("node: rename: %w", err)
	}
	cleanup = false
	return nil
}

// writePEMSafe wraps writeFileSafe with PEM encoding.
func writePEMSafe(path, pemType string, body []byte, perm os.FileMode) error {
	block := &pem.Block{Type: pemType, Bytes: body}
	return writeFileSafe(path, pem.EncodeToMemory(block), perm)
}

// refuseExistingSymlink returns an error if path exists AND is a
// symlink. A non-existent path is fine — Init expects that.
func refuseExistingSymlink(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("node: stat %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("node: refusing to overwrite symlink: %s", path)
	}
	return nil
}
