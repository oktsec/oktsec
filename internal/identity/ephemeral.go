package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

// EphemeralKeypair is a task-scoped keypair that expires automatically.
// Reduces blast radius of compromised keys — an attacker can only use
// the key until it expires, not indefinitely.
type EphemeralKeypair struct {
	Keypair
	TaskID    string    `json:"task_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	ParentKey string    `json:"parent_key"` // fingerprint of the fixed key that issued this
}

// IsExpired returns true if the ephemeral key has expired.
func (ek *EphemeralKeypair) IsExpired() bool {
	return time.Now().UTC().After(ek.ExpiresAt)
}

// TTLRemaining returns the time until expiry (negative if expired).
func (ek *EphemeralKeypair) TTLRemaining() time.Duration {
	return time.Until(ek.ExpiresAt)
}

// EphemeralKeyStore is an in-memory store for task-scoped ephemeral keys.
// Keys are automatically evicted when they expire. No disk persistence —
// ephemeral keys live only in memory and die with the process.
type EphemeralKeyStore struct {
	mu         sync.RWMutex
	keys       map[string]*EphemeralKeypair // keyed by fingerprint
	byTask     map[string][]string          // taskID -> fingerprints
	maxPerTask int
	maxTTL     time.Duration
	stopCh     chan struct{}
}

// NewEphemeralKeyStore creates a store with eviction loop.
func NewEphemeralKeyStore(maxPerTask int, maxTTL time.Duration) *EphemeralKeyStore {
	if maxPerTask <= 0 {
		maxPerTask = 10
	}
	if maxTTL <= 0 {
		maxTTL = 24 * time.Hour
	}
	ek := &EphemeralKeyStore{
		keys:       make(map[string]*EphemeralKeypair),
		byTask:     make(map[string][]string),
		maxPerTask: maxPerTask,
		maxTTL:     maxTTL,
		stopCh:     make(chan struct{}),
	}
	go ek.evictLoop()
	return ek
}

// Issue generates a new ephemeral keypair bound to a task.
// parentFingerprint is the fixed key that authorized this issuance.
// Returns the keypair (caller sends the private key to the agent).
func (s *EphemeralKeyStore) Issue(taskID, parentFingerprint string, ttl time.Duration) (*EphemeralKeypair, error) {
	if ttl > s.maxTTL {
		ttl = s.maxTTL
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("TTL must be positive")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check per-task limit
	if len(s.byTask[taskID]) >= s.maxPerTask {
		return nil, fmt.Errorf("task %q has %d ephemeral keys (max %d)", taskID, len(s.byTask[taskID]), s.maxPerTask)
	}

	// Generate keypair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral key: %w", err)
	}

	now := time.Now().UTC()
	kp := &EphemeralKeypair{
		Keypair: Keypair{
			Name:       fmt.Sprintf("ephemeral-%s-%d", taskID, now.UnixMilli()),
			PublicKey:  pub,
			PrivateKey: priv,
		},
		TaskID:    taskID,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		ParentKey: parentFingerprint,
	}

	fp := Fingerprint(pub)
	s.keys[fp] = kp
	s.byTask[taskID] = append(s.byTask[taskID], fp)

	return kp, nil
}

// Verify checks if a public key is a valid, non-expired ephemeral key.
// Returns the keypair if valid, nil if not found or expired.
func (s *EphemeralKeyStore) Verify(pub ed25519.PublicKey) *EphemeralKeypair {
	fp := Fingerprint(pub)

	s.mu.RLock()
	defer s.mu.RUnlock()

	kp, ok := s.keys[fp]
	if !ok {
		return nil
	}
	if kp.IsExpired() {
		return nil
	}
	return kp
}

// VerifyByFingerprint checks if a fingerprint belongs to a valid ephemeral key.
func (s *EphemeralKeyStore) VerifyByFingerprint(fingerprint string) *EphemeralKeypair {
	s.mu.RLock()
	defer s.mu.RUnlock()

	kp, ok := s.keys[fingerprint]
	if !ok || kp.IsExpired() {
		return nil
	}
	return kp
}

// RevokeByTask removes all ephemeral keys for a task.
func (s *EphemeralKeyStore) RevokeByTask(taskID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	fps := s.byTask[taskID]
	for _, fp := range fps {
		delete(s.keys, fp)
	}
	delete(s.byTask, taskID)
	return len(fps)
}

// Revoke removes a specific ephemeral key by fingerprint.
func (s *EphemeralKeyStore) Revoke(fingerprint string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	kp, ok := s.keys[fingerprint]
	if !ok {
		return false
	}

	delete(s.keys, fingerprint)

	// Remove from byTask
	fps := s.byTask[kp.TaskID]
	for i, fp := range fps {
		if fp == fingerprint {
			s.byTask[kp.TaskID] = append(fps[:i], fps[i+1:]...)
			break
		}
	}
	if len(s.byTask[kp.TaskID]) == 0 {
		delete(s.byTask, kp.TaskID)
	}

	return true
}

// ActiveCount returns the number of non-expired ephemeral keys.
func (s *EphemeralKeyStore) ActiveCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, kp := range s.keys {
		if !kp.IsExpired() {
			count++
		}
	}
	return count
}

// TaskCount returns the number of tasks with active ephemeral keys.
func (s *EphemeralKeyStore) TaskCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byTask)
}

// Close stops the eviction loop.
func (s *EphemeralKeyStore) Close() {
	close(s.stopCh)
}

// evictLoop periodically removes expired keys.
func (s *EphemeralKeyStore) evictLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.evictExpired()
		case <-s.stopCh:
			return
		}
	}
}

func (s *EphemeralKeyStore) evictExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for fp, kp := range s.keys {
		if kp.IsExpired() {
			delete(s.keys, fp)

			// Clean byTask
			fps := s.byTask[kp.TaskID]
			for i, f := range fps {
				if f == fp {
					s.byTask[kp.TaskID] = append(fps[:i], fps[i+1:]...)
					break
				}
			}
			if len(s.byTask[kp.TaskID]) == 0 {
				delete(s.byTask, kp.TaskID)
			}
		}
	}
}
