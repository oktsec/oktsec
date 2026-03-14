package llm

import (
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestEscalationTracker_HandleResult_BelowThreshold(t *testing.T) {
	tracker := NewEscalationTracker(80, 30*time.Minute, testLogger())
	defer tracker.Stop()

	tracker.HandleResult(AnalysisResult{
		FromAgent: "agent-a",
		RiskScore: 50,
		MessageID: "msg-1",
	})

	if tracker.IsEscalated("agent-a") {
		t.Fatal("agent should not be escalated when risk_score < threshold")
	}
}

func TestEscalationTracker_HandleResult_AboveThreshold(t *testing.T) {
	tracker := NewEscalationTracker(80, 30*time.Minute, testLogger())
	defer tracker.Stop()

	tracker.HandleResult(AnalysisResult{
		FromAgent: "agent-a",
		RiskScore: 85,
		MessageID: "msg-1",
	})

	if !tracker.IsEscalated("agent-a") {
		t.Fatal("agent should be escalated when risk_score >= threshold")
	}
	if tracker.IsEscalated("agent-b") {
		t.Fatal("unrelated agent should not be escalated")
	}
}

func TestEscalationTracker_HandleResult_ExactThreshold(t *testing.T) {
	tracker := NewEscalationTracker(80, 30*time.Minute, testLogger())
	defer tracker.Stop()

	tracker.HandleResult(AnalysisResult{
		FromAgent: "agent-a",
		RiskScore: 80,
		MessageID: "msg-1",
	})

	if !tracker.IsEscalated("agent-a") {
		t.Fatal("agent should be escalated when risk_score == threshold")
	}
}

func TestEscalationTracker_TTLExpiry(t *testing.T) {
	tracker := NewEscalationTracker(80, 50*time.Millisecond, testLogger())
	defer tracker.Stop()

	tracker.HandleResult(AnalysisResult{
		FromAgent: "agent-a",
		RiskScore: 90,
		MessageID: "msg-1",
	})

	if !tracker.IsEscalated("agent-a") {
		t.Fatal("agent should be escalated immediately after high-risk result")
	}

	time.Sleep(100 * time.Millisecond)

	if tracker.IsEscalated("agent-a") {
		t.Fatal("escalation should have expired after TTL")
	}
}

func TestEscalationTracker_Refresh(t *testing.T) {
	tracker := NewEscalationTracker(80, 100*time.Millisecond, testLogger())
	defer tracker.Stop()

	tracker.HandleResult(AnalysisResult{
		FromAgent: "agent-a",
		RiskScore: 85,
		MessageID: "msg-1",
	})

	time.Sleep(60 * time.Millisecond)

	// Refresh before TTL expires
	tracker.HandleResult(AnalysisResult{
		FromAgent: "agent-a",
		RiskScore: 90,
		MessageID: "msg-2",
	})

	time.Sleep(60 * time.Millisecond)

	// Should still be escalated because the second result refreshed the TTL
	if !tracker.IsEscalated("agent-a") {
		t.Fatal("escalation should be refreshed by a new high-risk result")
	}
}

func TestEscalationTracker_ActiveEntries(t *testing.T) {
	tracker := NewEscalationTracker(80, 30*time.Minute, testLogger())
	defer tracker.Stop()

	tracker.HandleResult(AnalysisResult{FromAgent: "agent-a", RiskScore: 85, MessageID: "msg-1"})
	tracker.HandleResult(AnalysisResult{FromAgent: "agent-b", RiskScore: 90, MessageID: "msg-2"})
	tracker.HandleResult(AnalysisResult{FromAgent: "agent-c", RiskScore: 50, MessageID: "msg-3"}) // below threshold

	entries := tracker.ActiveEntries()
	if len(entries) != 2 {
		t.Fatalf("expected 2 active entries, got %d", len(entries))
	}
	if tracker.ActiveCount() != 2 {
		t.Fatalf("expected ActiveCount 2, got %d", tracker.ActiveCount())
	}
}

func TestEscalationTracker_Eviction(t *testing.T) {
	tracker := NewEscalationTracker(80, 30*time.Millisecond, testLogger())
	defer tracker.Stop()

	tracker.HandleResult(AnalysisResult{FromAgent: "agent-a", RiskScore: 85, MessageID: "msg-1"})

	// Manually trigger eviction after expiry
	time.Sleep(50 * time.Millisecond)
	tracker.evict()

	tracker.mu.RLock()
	_, exists := tracker.entries["agent-a"]
	tracker.mu.RUnlock()

	if exists {
		t.Fatal("expired entry should be evicted")
	}
}

func TestEscalationTracker_ConcurrentAccess(t *testing.T) {
	tracker := NewEscalationTracker(80, 30*time.Minute, testLogger())
	defer tracker.Stop()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			tracker.HandleResult(AnalysisResult{
				FromAgent: "agent-a",
				RiskScore: float64(50 + n%60), // some above, some below threshold
				MessageID: "msg",
			})
			tracker.IsEscalated("agent-a")
			tracker.ActiveEntries()
			tracker.ActiveCount()
		}(i)
	}
	wg.Wait()
}

func TestEscalationTracker_StopIdempotent(t *testing.T) {
	tracker := NewEscalationTracker(80, 30*time.Minute, testLogger())
	tracker.Stop()
	tracker.Stop() // should not panic
}
