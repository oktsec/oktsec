package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
)

// depManifests lists dependency manifest filenames to look for.
var depManifests = []string{
	"requirements.txt",
	"Pipfile.lock",
	"package.json",
	"package-lock.json",
	"yarn.lock",
	"pnpm-lock.yaml",
	"go.sum",
	"go.mod",
}

// DepChange describes a dependency manifest that changed between runs.
type DepChange struct {
	ServerName string
	File       string
	OldHash    string // empty on first run
	NewHash    string
}

// depHashStore manages SHA-256 hashes of MCP server dependency manifests.
// Hashes are persisted to a JSON file between runs.
type depHashStore struct {
	path   string                       // e.g. ~/.oktsec/dep-hashes.json
	hashes map[string]map[string]string // server name -> filename -> sha256 hex
}

// newDepHashStore loads existing hashes from the JSON file, or creates an empty store.
func newDepHashStore(storePath string) *depHashStore {
	s := &depHashStore{
		path:   storePath,
		hashes: make(map[string]map[string]string),
	}
	data, err := os.ReadFile(storePath)
	if err != nil {
		// File doesn't exist or can't be read — start fresh.
		return s
	}
	_ = json.Unmarshal(data, &s.hashes)
	if s.hashes == nil {
		s.hashes = make(map[string]map[string]string)
	}
	return s
}

// Check hashes dependency manifests in workingDir and compares them to stored
// values. Returns a DepChange for each file that is new or changed.
func (s *depHashStore) Check(serverName, workingDir string) []DepChange {
	old := s.hashes[serverName]
	if old == nil {
		old = make(map[string]string)
	}

	current := make(map[string]string)
	var changes []DepChange

	for _, name := range depManifests {
		p := filepath.Join(workingDir, name)
		data, err := os.ReadFile(p)
		if err != nil {
			continue // file doesn't exist or unreadable — skip
		}
		sum := sha256.Sum256(data)
		h := hex.EncodeToString(sum[:])
		current[name] = h

		if oldH, seen := old[name]; !seen {
			// First time seeing this file.
			changes = append(changes, DepChange{
				ServerName: serverName,
				File:       name,
				NewHash:    h,
			})
		} else if oldH != h {
			// File changed since last run.
			changes = append(changes, DepChange{
				ServerName: serverName,
				File:       name,
				OldHash:    oldH,
				NewHash:    h,
			})
		}
	}

	// Store the current hashes for this server.
	s.hashes[serverName] = current
	return changes
}

// Save persists the hash store to its JSON file with 0600 permissions.
// Creates the parent directory if it doesn't exist.
func (s *depHashStore) Save() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.hashes, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o600)
}

// defaultDepHashPath returns ~/.oktsec/dep-hashes.json.
func defaultDepHashPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".oktsec", "dep-hashes.json")
}
