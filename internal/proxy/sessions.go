package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

const sessionDefaultTTL = 30 * time.Minute

// agentSession tracks an active session for a single agent.
type agentSession struct {
	ID       string
	Agent    string
	StartAt  time.Time
	LastSeen time.Time
}

// sessionStore is a thread-safe in-memory store that maps agent names to
// sessions. Sessions expire after the configured TTL of inactivity.
type sessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*agentSession // agent name → session
	ttl      time.Duration
	done     chan struct{}
}

// newSessionStore creates a session store with the given TTL and starts
// a background goroutine that evicts expired sessions every 60 seconds.
func newSessionStore(ttl time.Duration) *sessionStore {
	if ttl <= 0 {
		ttl = sessionDefaultTTL
	}
	s := &sessionStore{
		sessions: make(map[string]*agentSession),
		ttl:      ttl,
		done:     make(chan struct{}),
	}
	go s.evictLoop()
	return s
}

// Resolve returns the session ID for the given agent. If the agent has an
// active session (last seen within TTL), its ID is returned and the last-seen
// timestamp is refreshed. Otherwise a new session is created.
func (s *sessionStore) Resolve(agent string) string {
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	if sess, ok := s.sessions[agent]; ok {
		if now.Sub(sess.LastSeen) <= s.ttl {
			sess.LastSeen = now
			return sess.ID
		}
		// Expired — fall through to create new session
	}

	id := generateSessionID()
	s.sessions[agent] = &agentSession{
		ID:       id,
		Agent:    agent,
		StartAt:  now,
		LastSeen: now,
	}
	return id
}

// Stop terminates the background eviction goroutine. Safe to call multiple times.
func (s *sessionStore) Stop() {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
}

// evictLoop periodically removes sessions that have not been seen within the TTL.
func (s *sessionStore) evictLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.evict()
		}
	}
}

// evict removes all sessions whose LastSeen is older than the TTL.
func (s *sessionStore) evict() {
	cutoff := time.Now().Add(-s.ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	for agent, sess := range s.sessions {
		if sess.LastSeen.Before(cutoff) {
			delete(s.sessions, agent)
		}
	}
}

// generateSessionID returns a hex-encoded 16-byte random string (32 hex chars).
func generateSessionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand should never fail on supported platforms.
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
