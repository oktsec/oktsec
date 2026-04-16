package gateway

import (
	"context"
	"sync"

	"github.com/oktsec/oktsec/internal/config"
)

// Defaults when an Agent config omits a cap. Both numbers are intentionally
// conservative: the gateway is the shared path through which N sub-agents
// hit M backends, so a single rogue agent blasting concurrency hurts peers.
// Operators who need more can override per-agent or pass < 0 for unlimited.
const (
	defaultMaxConcurrentCalls = 5
	defaultMaxDelegationDepth = 3
)

// concurrencyLimiter hands out per-agent semaphore slots. Slots are created
// lazily on first use and never deleted (the set of agent names is bounded
// by gateway auto-register, cap=500). This trades a small steady-state
// memory cost for a lock-free fast path on every tool call.
type concurrencyLimiter struct {
	mu    sync.Mutex
	slots map[string]chan struct{}
	cfg   *config.Config
}

func newConcurrencyLimiter(cfg *config.Config) *concurrencyLimiter {
	return &concurrencyLimiter{
		slots: make(map[string]chan struct{}),
		cfg:   cfg,
	}
}

// resolveLimit picks the effective cap for an agent. A per-agent override of
// <0 disables the cap; 0 falls back to the default.
func (cl *concurrencyLimiter) resolveLimit(agent string) int {
	if cl.cfg == nil {
		return defaultMaxConcurrentCalls
	}
	if ac, ok := cl.cfg.Agents[agent]; ok {
		switch {
		case ac.MaxConcurrentCalls < 0:
			return -1
		case ac.MaxConcurrentCalls > 0:
			return ac.MaxConcurrentCalls
		}
	}
	return defaultMaxConcurrentCalls
}

// acquire blocks until a slot is available or ctx is cancelled. Returns a
// release func; if limit is unlimited, release is a no-op and no channel is
// allocated. Callers must always invoke release (even on error paths).
func (cl *concurrencyLimiter) acquire(ctx context.Context, agent string) (func(), error) {
	limit := cl.resolveLimit(agent)
	if limit <= 0 {
		return func() {}, nil
	}

	cl.mu.Lock()
	sem, ok := cl.slots[agent]
	if !ok {
		sem = make(chan struct{}, limit)
		cl.slots[agent] = sem
	}
	cl.mu.Unlock()

	select {
	case sem <- struct{}{}:
		return func() { <-sem }, nil
	case <-ctx.Done():
		return func() {}, ctx.Err()
	}
}

// resolveDelegationDepth picks the effective delegation depth cap for an agent.
func resolveDelegationDepth(cfg *config.Config, agent string) int {
	if cfg == nil {
		return defaultMaxDelegationDepth
	}
	if ac, ok := cfg.Agents[agent]; ok {
		switch {
		case ac.MaxDelegationDepth < 0:
			return -1
		case ac.MaxDelegationDepth > 0:
			return ac.MaxDelegationDepth
		}
	}
	return defaultMaxDelegationDepth
}
