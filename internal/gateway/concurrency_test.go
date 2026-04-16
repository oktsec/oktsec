package gateway

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oktsec/oktsec/internal/config"
)

func TestConcurrencyLimiter_EnforcesPerAgentCap(t *testing.T) {
	cfg := &config.Config{
		Agents: map[string]config.Agent{
			"bob": {MaxConcurrentCalls: 2},
		},
	}
	cl := newConcurrencyLimiter(cfg)

	var inFlight, peak atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			release, err := cl.acquire(context.Background(), "bob")
			if err != nil {
				t.Error(err)
				return
			}
			defer release()
			cur := inFlight.Add(1)
			for {
				p := peak.Load()
				if cur <= p || peak.CompareAndSwap(p, cur) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			inFlight.Add(-1)
		}()
	}
	close(start)
	wg.Wait()

	if peak.Load() > 2 {
		t.Fatalf("peak concurrency %d exceeds cap 2", peak.Load())
	}
}

func TestConcurrencyLimiter_UnlimitedWhenNegative(t *testing.T) {
	cfg := &config.Config{
		Agents: map[string]config.Agent{
			"bob": {MaxConcurrentCalls: -1},
		},
	}
	cl := newConcurrencyLimiter(cfg)

	release, err := cl.acquire(context.Background(), "bob")
	if err != nil {
		t.Fatal(err)
	}
	release()

	if cl.resolveLimit("bob") != -1 {
		t.Fatalf("expected -1 (unlimited), got %d", cl.resolveLimit("bob"))
	}
}

func TestConcurrencyLimiter_DefaultApplied(t *testing.T) {
	cfg := &config.Config{Agents: map[string]config.Agent{}}
	cl := newConcurrencyLimiter(cfg)
	if got := cl.resolveLimit("unknown-agent"); got != defaultMaxConcurrentCalls {
		t.Fatalf("expected default %d for unknown agent, got %d", defaultMaxConcurrentCalls, got)
	}
}

func TestConcurrencyLimiter_ContextCancel(t *testing.T) {
	cfg := &config.Config{
		Agents: map[string]config.Agent{"bob": {MaxConcurrentCalls: 1}},
	}
	cl := newConcurrencyLimiter(cfg)

	hold, err := cl.acquire(context.Background(), "bob")
	if err != nil {
		t.Fatal(err)
	}
	defer hold()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = cl.acquire(ctx, "bob")
	if err == nil {
		t.Fatal("expected context deadline error when slot is held")
	}
}

func TestResolveDelegationDepth(t *testing.T) {
	cfg := &config.Config{
		Agents: map[string]config.Agent{
			"narrow": {MaxDelegationDepth: 1},
			"wide":   {MaxDelegationDepth: -1},
		},
	}
	if got := resolveDelegationDepth(cfg, "narrow"); got != 1 {
		t.Fatalf("narrow: got %d want 1", got)
	}
	if got := resolveDelegationDepth(cfg, "wide"); got != -1 {
		t.Fatalf("wide: got %d want -1 (unlimited)", got)
	}
	if got := resolveDelegationDepth(cfg, "default"); got != defaultMaxDelegationDepth {
		t.Fatalf("default: got %d want %d", got, defaultMaxDelegationDepth)
	}
}
