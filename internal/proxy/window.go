package proxy

import (
	"strings"
	"sync"
	"time"
)

// windowEntry is a single buffered message.
type windowEntry struct {
	content string
	added   time.Time
}

// MessageWindow is a per-sender sliding window buffer for detecting
// split injection attacks across multiple messages.
type MessageWindow struct {
	mu      sync.Mutex
	maxSize int
	maxAge  time.Duration
	entries map[string][]windowEntry
}

// NewMessageWindow creates a window buffer.
// maxSize is the maximum number of messages to keep per sender.
// maxAge is the maximum age of a message before it is evicted.
func NewMessageWindow(maxSize int, maxAge time.Duration) *MessageWindow {
	return &MessageWindow{
		maxSize: maxSize,
		maxAge:  maxAge,
		entries: make(map[string][]windowEntry),
	}
}

// Add appends a message from the given agent and evicts old entries.
func (w *MessageWindow) Add(agent, content string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()
	entries := w.entries[agent]

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

	w.entries[agent] = append(fresh, windowEntry{content: content, added: now})
}

// Concatenated returns all buffered messages for the agent joined with a separator.
// Returns "" if there are fewer than 2 messages (no cross-message context to check).
func (w *MessageWindow) Concatenated(agent string) string {
	w.mu.Lock()
	defer w.mu.Unlock()

	entries := w.entries[agent]
	if len(entries) < 2 {
		return ""
	}

	parts := make([]string, len(entries))
	for i, e := range entries {
		parts[i] = e.content
	}
	return strings.Join(parts, "\n---\n")
}
