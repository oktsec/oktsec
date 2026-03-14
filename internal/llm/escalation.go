package llm

import (
	"log/slog"
	"sync"
	"time"
)

// EscalationEntry tracks an active LLM-driven escalation for an agent.
type EscalationEntry struct {
	Agent     string    `json:"agent"`
	RiskScore float64   `json:"risk_score"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	MessageID string    `json:"message_id"` // LLM analysis that triggered escalation
}

// EscalationTracker manages TTL-based verdict escalation entries driven by
// async LLM threat analysis. When the LLM detects a high-risk threat for an
// agent (risk_score >= threshold), all future verdicts for that agent are
// escalated one level for a configurable TTL window.
//
// Thread-safe for concurrent use by LLM result callbacks and the proxy/gateway
// security pipeline.
type EscalationTracker struct {
	mu        sync.RWMutex
	entries   map[string]EscalationEntry // agent -> entry
	threshold float64
	ttl       time.Duration
	logger    *slog.Logger
	stopOnce  sync.Once
	stopCh    chan struct{}
}

// NewEscalationTracker creates a tracker with the given risk threshold and TTL.
// Starts a background goroutine to evict expired entries every 30 seconds.
func NewEscalationTracker(threshold float64, ttl time.Duration, logger *slog.Logger) *EscalationTracker {
	t := &EscalationTracker{
		entries:   make(map[string]EscalationEntry),
		threshold: threshold,
		ttl:       ttl,
		logger:    logger,
		stopCh:    make(chan struct{}),
	}
	go t.evictLoop()
	return t
}

// HandleResult is an OnResult callback for the LLM queue.
// If the result's RiskScore >= threshold, an escalation entry is created
// (or refreshed) for the agent.
func (t *EscalationTracker) HandleResult(result AnalysisResult) {
	if result.RiskScore < t.threshold {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	entry := EscalationEntry{
		Agent:     result.FromAgent,
		RiskScore: result.RiskScore,
		ExpiresAt: now.Add(t.ttl),
		CreatedAt: now,
		MessageID: result.MessageID,
	}

	existing, exists := t.entries[result.FromAgent]
	t.entries[result.FromAgent] = entry

	if !exists {
		escalationsActive.Inc()
	}
	escalationsTotal.Inc()

	if exists {
		t.logger.Info("llm escalation refreshed",
			"agent", result.FromAgent,
			"risk_score", result.RiskScore,
			"previous_risk", existing.RiskScore,
			"ttl", t.ttl,
		)
	} else {
		t.logger.Warn("llm escalation activated",
			"agent", result.FromAgent,
			"risk_score", result.RiskScore,
			"message_id", result.MessageID,
			"ttl", t.ttl,
		)
	}
}

// IsEscalated returns true if the agent currently has an active escalation.
func (t *EscalationTracker) IsEscalated(agent string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	entry, ok := t.entries[agent]
	if !ok {
		return false
	}
	return time.Now().Before(entry.ExpiresAt)
}

// ActiveEntries returns a snapshot of all active (non-expired) escalation entries.
func (t *EscalationTracker) ActiveEntries() []EscalationEntry {
	t.mu.RLock()
	defer t.mu.RUnlock()

	now := time.Now()
	var result []EscalationEntry
	for _, e := range t.entries {
		if now.Before(e.ExpiresAt) {
			result = append(result, e)
		}
	}
	return result
}

// ActiveCount returns the number of currently active escalation entries.
func (t *EscalationTracker) ActiveCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	now := time.Now()
	count := 0
	for _, e := range t.entries {
		if now.Before(e.ExpiresAt) {
			count++
		}
	}
	return count
}

// Stop terminates the background eviction goroutine.
func (t *EscalationTracker) Stop() {
	t.stopOnce.Do(func() {
		close(t.stopCh)
	})
}

// evictLoop runs every 30 seconds to remove expired entries.
func (t *EscalationTracker) evictLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			t.evict()
		}
	}
}

func (t *EscalationTracker) evict() {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	for agent, entry := range t.entries {
		if now.After(entry.ExpiresAt) {
			delete(t.entries, agent)
			escalationsActive.Dec()
			t.logger.Info("llm escalation expired",
				"agent", agent,
				"risk_score", entry.RiskScore,
			)
		}
	}
}
