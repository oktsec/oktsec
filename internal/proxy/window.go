package proxy

import (
	"hash/fnv"
	"strings"
	"sync"
	"time"
)

const mwShardCount = 64

// windowEntry is a single buffered message.
type windowEntry struct {
	content string
	added   time.Time
}

// mwShard is one partition of the MessageWindow's state.
type mwShard struct {
	mu      sync.Mutex
	entries map[string][]windowEntry
}

// MessageWindow is a per-sender sliding window buffer for detecting
// split injection attacks across multiple messages.
// Internally it uses sharded locks to reduce contention.
type MessageWindow struct {
	maxSize int
	maxAge  time.Duration
	shards  [mwShardCount]mwShard
	done    chan struct{}
}

// NewMessageWindow creates a window buffer.
// maxSize is the maximum number of messages to keep per sender.
// maxAge is the maximum age of a message before it is evicted.
func NewMessageWindow(maxSize int, maxAge time.Duration) *MessageWindow {
	w := &MessageWindow{
		maxSize: maxSize,
		maxAge:  maxAge,
		done:    make(chan struct{}),
	}
	for i := range w.shards {
		w.shards[i].entries = make(map[string][]windowEntry)
	}
	// Evict stale sender entries periodically. The interval is 2x the
	// maxAge (minimum 30s) so we don't spin for very small windows.
	evictInterval := maxAge * 2
	if evictInterval < 30*time.Second {
		evictInterval = 30 * time.Second
	}
	go w.evictLoop(evictInterval)
	return w
}

// Add appends a message from the given agent and evicts old entries.
func (w *MessageWindow) Add(agent, content string) {
	s := &w.shards[w.shardIndex(agent)]
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	entries := s.entries[agent]

	// Evict by age
	cutoff := now.Add(-w.maxAge)
	fresh := entries[:0]
	for _, e := range entries {
		if e.added.After(cutoff) {
			fresh = append(fresh, e)
		}
	}

	// Evict by size (keep most recent maxSize-1 to make room for new entry)
	if len(fresh) >= w.maxSize {
		fresh = fresh[len(fresh)-w.maxSize+1:]
	}

	s.entries[agent] = append(fresh, windowEntry{content: content, added: now})
}

// Concatenated returns all buffered messages for the agent joined with a separator.
// Returns "" if there are fewer than 2 messages (no cross-message context to check).
func (w *MessageWindow) Concatenated(agent string) string {
	s := &w.shards[w.shardIndex(agent)]
	s.mu.Lock()
	defer s.mu.Unlock()

	entries := s.entries[agent]
	if len(entries) < 2 {
		return ""
	}

	parts := make([]string, len(entries))
	for i, e := range entries {
		parts[i] = e.content
	}
	return strings.Join(parts, "\n---\n")
}

// Stop terminates the background eviction goroutine. Safe to call multiple times.
func (w *MessageWindow) Stop() {
	select {
	case <-w.done:
	default:
		close(w.done)
	}
}

// shardIndex returns the shard index for the given key.
func (w *MessageWindow) shardIndex(key string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return h.Sum32() % mwShardCount
}

// evictLoop periodically removes sender entries where all messages are stale.
func (w *MessageWindow) evictLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-w.done:
			return
		case <-ticker.C:
			w.evict()
		}
	}
}

// evict removes entries from all shards where every message is older than
// 2x the maxAge duration.
func (w *MessageWindow) evict() {
	cutoff := time.Now().Add(-2 * w.maxAge)
	for i := range w.shards {
		s := &w.shards[i]
		s.mu.Lock()
		for agent, entries := range s.entries {
			if len(entries) == 0 || entries[len(entries)-1].added.Before(cutoff) {
				delete(s.entries, agent)
			}
		}
		s.mu.Unlock()
	}
}
