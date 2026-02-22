package audit

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := NewStore(dbPath, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestQueryEdgeStats(t *testing.T) {
	store := newTestStore(t)

	entries := []Entry{
		{ID: "e1", Timestamp: time.Now().UTC().Format(time.RFC3339), FromAgent: "a", ToAgent: "b", ContentHash: "h", Status: "delivered", PolicyDecision: "allow"},
		{ID: "e2", Timestamp: time.Now().UTC().Format(time.RFC3339), FromAgent: "a", ToAgent: "b", ContentHash: "h", Status: "delivered", PolicyDecision: "allow"},
		{ID: "e3", Timestamp: time.Now().UTC().Format(time.RFC3339), FromAgent: "a", ToAgent: "b", ContentHash: "h", Status: "blocked", PolicyDecision: "content_blocked"},
		{ID: "e4", Timestamp: time.Now().UTC().Format(time.RFC3339), FromAgent: "b", ToAgent: "c", ContentHash: "h", Status: "delivered", PolicyDecision: "allow"},
		{ID: "e5", Timestamp: time.Now().UTC().Format(time.RFC3339), FromAgent: "c", ToAgent: "a", ContentHash: "h", Status: "quarantined", PolicyDecision: "content_quarantined"},
	}
	for _, e := range entries {
		store.Log(e)
	}
	time.Sleep(150 * time.Millisecond)

	stats, err := store.QueryEdgeStats()
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 3 {
		t.Fatalf("got %d edges, want 3", len(stats))
	}

	// Find a→b edge (should have highest total = 3)
	var ab *EdgeStat
	for i := range stats {
		if stats[i].From == "a" && stats[i].To == "b" {
			ab = &stats[i]
			break
		}
	}
	if ab == nil {
		t.Fatal("a→b edge not found")
	}
	if ab.Total != 3 {
		t.Errorf("a→b total = %d, want 3", ab.Total)
	}
	if ab.Delivered != 2 {
		t.Errorf("a→b delivered = %d, want 2", ab.Delivered)
	}
	if ab.Blocked != 1 {
		t.Errorf("a→b blocked = %d, want 1", ab.Blocked)
	}
}

func TestStoreLogAndQuery(t *testing.T) {
	store := newTestStore(t)

	store.Log(Entry{
		ID:                "msg-1",
		Timestamp:         "2026-02-22T10:00:00Z",
		FromAgent:         "agent-a",
		ToAgent:           "agent-b",
		ContentHash:       "abc123",
		SignatureVerified: 1,
		PubkeyFingerprint: "fp123",
		Status:            "delivered",
		PolicyDecision:    "allow",
		LatencyMs:         5,
	})

	store.Log(Entry{
		ID:                "msg-2",
		Timestamp:         "2026-02-22T10:01:00Z",
		FromAgent:         "agent-c",
		ToAgent:           "agent-b",
		ContentHash:       "def456",
		SignatureVerified: -1,
		Status:            "rejected",
		PolicyDecision:    "identity_rejected",
		LatencyMs:         0,
	})

	// Wait for async writes
	time.Sleep(100 * time.Millisecond)

	// Query all
	entries, err := store.Query(QueryOpts{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("got %d entries, want 2", len(entries))
	}

	// Query by status
	blocked, err := store.Query(QueryOpts{Status: "rejected"})
	if err != nil {
		t.Fatal(err)
	}
	if len(blocked) != 1 {
		t.Errorf("got %d rejected, want 1", len(blocked))
	}

	// Query unverified
	unverified, err := store.Query(QueryOpts{Unverified: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(unverified) != 1 {
		t.Errorf("got %d unverified, want 1", len(unverified))
	}

	// Query by agent
	agentEntries, err := store.Query(QueryOpts{Agent: "agent-a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(agentEntries) != 1 {
		t.Errorf("got %d entries for agent-a, want 1", len(agentEntries))
	}
}
