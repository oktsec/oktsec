package identity

import (
	"crypto/ed25519"
	"fmt"
	"sync"
)

// KeyStore holds loaded public keys, keyed by agent name.
type KeyStore struct {
	mu   sync.RWMutex
	keys map[string]ed25519.PublicKey
}

// NewKeyStore creates an empty key store.
func NewKeyStore() *KeyStore {
	return &KeyStore{
		keys: make(map[string]ed25519.PublicKey),
	}
}

// LoadFromDir loads all .pub files from a directory into the store.
func (ks *KeyStore) LoadFromDir(dir string) error {
	loaded, err := LoadPublicKeys(dir)
	if err != nil {
		return fmt.Errorf("loading keys from %s: %w", dir, err)
	}
	ks.mu.Lock()
	defer ks.mu.Unlock()
	for name, key := range loaded {
		ks.keys[name] = key
	}
	return nil
}

// ReloadFromDir clears all keys and reloads .pub files from the directory.
func (ks *KeyStore) ReloadFromDir(dir string) error {
	loaded, err := LoadPublicKeys(dir)
	if err != nil {
		return fmt.Errorf("reloading keys from %s: %w", dir, err)
	}
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.keys = loaded
	return nil
}

// Get returns the public key for an agent.
func (ks *KeyStore) Get(name string) (ed25519.PublicKey, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	key, ok := ks.keys[name]
	return key, ok
}

// Count returns the number of loaded keys.
func (ks *KeyStore) Count() int {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return len(ks.keys)
}

// Names returns the names of all loaded agents.
func (ks *KeyStore) Names() []string {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	names := make([]string, 0, len(ks.keys))
	for name := range ks.keys {
		names = append(names, name)
	}
	return names
}
