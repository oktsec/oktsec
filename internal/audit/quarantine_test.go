package audit

import (
	"testing"
	"time"
)

func TestEnqueueAndQueryPending(t *testing.T) {
	store := newTestStore(t)

	item := QuarantineItem{
		ID:             "q-1",
		AuditEntryID:   "q-1",
		Content:        "suspicious message content",
		FromAgent:      "agent-a",
		ToAgent:        "agent-b",
		Status:         "pending",
		ExpiresAt:      time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
		RulesTriggered: `[{"rule_id":"PROMPT-001","name":"Prompt injection","severity":"high"}]`,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
	}

	if err := store.Enqueue(item); err != nil {
		t.Fatal(err)
	}

	// Query pending
	pending, err := store.QuarantinePending(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("got %d pending, want 1", len(pending))
	}
	if pending[0].ID != "q-1" {
		t.Errorf("id = %q, want q-1", pending[0].ID)
	}
	if pending[0].Content != "suspicious message content" {
		t.Errorf("content not preserved")
	}
}

func TestQuarantineByID(t *testing.T) {
	store := newTestStore(t)

	item := QuarantineItem{
		ID:           "q-detail",
		AuditEntryID: "q-detail",
		Content:      "test content",
		FromAgent:    "a",
		ToAgent:      "b",
		Status:       "pending",
		ExpiresAt:    time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
	}

	if err := store.Enqueue(item); err != nil {
		t.Fatal(err)
	}

	// Found
	got, err := store.QuarantineByID("q-detail")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected item, got nil")
	}
	if got.FromAgent != "a" {
		t.Errorf("from_agent = %q, want 'a'", got.FromAgent)
	}

	// Not found
	got, err = store.QuarantineByID("nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Error("expected nil for nonexistent ID")
	}
}

func TestApproveReject(t *testing.T) {
	store := newTestStore(t)

	// Insert audit entry first (for the FK-like update)
	store.Log(Entry{
		ID:             "q-approve",
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		FromAgent:      "a",
		ToAgent:        "b",
		ContentHash:    "h",
		Status:         "quarantined",
		PolicyDecision: "content_quarantined",
	})
	time.Sleep(100 * time.Millisecond)

	if err := store.Enqueue(QuarantineItem{
		ID:           "q-approve",
		AuditEntryID: "q-approve",
		Content:      "approve me",
		FromAgent:    "a",
		ToAgent:      "b",
		Status:       "pending",
		ExpiresAt:    time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}

	// Approve
	if err := store.QuarantineApprove("q-approve", "test-reviewer"); err != nil {
		t.Fatal(err)
	}

	item, _ := store.QuarantineByID("q-approve")
	if item.Status != "approved" {
		t.Errorf("status = %q, want approved", item.Status)
	}
	if item.ReviewedBy != "test-reviewer" {
		t.Errorf("reviewed_by = %q, want test-reviewer", item.ReviewedBy)
	}

	// Audit entry should be updated
	entry, _ := store.QueryByID("q-approve")
	if entry != nil && entry.Status != "delivered" {
		t.Errorf("audit status = %q, want delivered", entry.Status)
	}

	// Reject test
	if err := store.Enqueue(QuarantineItem{
		ID:           "q-reject",
		AuditEntryID: "q-reject",
		Content:      "reject me",
		FromAgent:    "a",
		ToAgent:      "b",
		Status:       "pending",
		ExpiresAt:    time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}

	if err := store.QuarantineReject("q-reject", "test-reviewer"); err != nil {
		t.Fatal(err)
	}

	item, _ = store.QuarantineByID("q-reject")
	if item.Status != "rejected" {
		t.Errorf("status = %q, want rejected", item.Status)
	}
}

func TestExpireOld(t *testing.T) {
	store := newTestStore(t)

	// Insert an already-expired item
	if err := store.Enqueue(QuarantineItem{
		ID:           "q-expired",
		AuditEntryID: "q-expired",
		Content:      "old content",
		FromAgent:    "a",
		ToAgent:      "b",
		Status:       "pending",
		ExpiresAt:    time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339), // already expired
		CreatedAt:    time.Now().Add(-25 * time.Hour).UTC().Format(time.RFC3339),
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}

	// Insert a non-expired item
	if err := store.Enqueue(QuarantineItem{
		ID:           "q-fresh",
		AuditEntryID: "q-fresh",
		Content:      "fresh content",
		FromAgent:    "a",
		ToAgent:      "b",
		Status:       "pending",
		ExpiresAt:    time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}

	n, err := store.QuarantineExpireOld()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expired %d, want 1", n)
	}

	// Verify states
	expired, _ := store.QuarantineByID("q-expired")
	if expired.Status != "expired" {
		t.Errorf("status = %q, want expired", expired.Status)
	}

	fresh, _ := store.QuarantineByID("q-fresh")
	if fresh.Status != "pending" {
		t.Errorf("status = %q, want pending", fresh.Status)
	}
}

func TestQuarantineStats(t *testing.T) {
	store := newTestStore(t)

	for _, item := range []QuarantineItem{
		{ID: "s1", AuditEntryID: "s1", Content: "c", FromAgent: "a", ToAgent: "b", Status: "pending", ExpiresAt: "2099-01-01T00:00:00Z", CreatedAt: "2026-01-01T00:00:00Z", Timestamp: "2026-01-01T00:00:00Z"},
		{ID: "s2", AuditEntryID: "s2", Content: "c", FromAgent: "a", ToAgent: "b", Status: "pending", ExpiresAt: "2099-01-01T00:00:00Z", CreatedAt: "2026-01-01T00:00:00Z", Timestamp: "2026-01-01T00:00:00Z"},
		{ID: "s3", AuditEntryID: "s3", Content: "c", FromAgent: "a", ToAgent: "b", Status: "approved", ExpiresAt: "2099-01-01T00:00:00Z", CreatedAt: "2026-01-01T00:00:00Z", Timestamp: "2026-01-01T00:00:00Z"},
		{ID: "s4", AuditEntryID: "s4", Content: "c", FromAgent: "a", ToAgent: "b", Status: "rejected", ExpiresAt: "2099-01-01T00:00:00Z", CreatedAt: "2026-01-01T00:00:00Z", Timestamp: "2026-01-01T00:00:00Z"},
	} {
		if err := store.Enqueue(item); err != nil {
			t.Fatal(err)
		}
	}

	stats, err := store.QuarantineStats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 4 {
		t.Errorf("total = %d, want 4", stats.Total)
	}
	if stats.Pending != 2 {
		t.Errorf("pending = %d, want 2", stats.Pending)
	}
	if stats.Approved != 1 {
		t.Errorf("approved = %d, want 1", stats.Approved)
	}
	if stats.Rejected != 1 {
		t.Errorf("rejected = %d, want 1", stats.Rejected)
	}
}

func TestPurgeOldEntries(t *testing.T) {
	store := newTestStore(t)

	// Insert entries: 2 recent, 2 old (40 days ago)
	now := time.Now().UTC()
	old := now.AddDate(0, 0, -40)

	for _, e := range []Entry{
		{ID: "recent-1", Timestamp: now.Format(time.RFC3339), FromAgent: "a", ToAgent: "b", ContentHash: "h", Status: "delivered", PolicyDecision: "allowed"},
		{ID: "recent-2", Timestamp: now.Add(-time.Hour).Format(time.RFC3339), FromAgent: "a", ToAgent: "b", ContentHash: "h", Status: "delivered", PolicyDecision: "allowed"},
		{ID: "old-1", Timestamp: old.Format(time.RFC3339), FromAgent: "a", ToAgent: "b", ContentHash: "h", Status: "delivered", PolicyDecision: "allowed"},
		{ID: "old-2", Timestamp: old.Add(-time.Hour).Format(time.RFC3339), FromAgent: "a", ToAgent: "b", ContentHash: "h", Status: "blocked", PolicyDecision: "blocked"},
	} {
		store.Log(e)
	}
	time.Sleep(100 * time.Millisecond) // wait for async writes

	// Purge entries older than 30 days
	n, err := store.PurgeOldEntries(30)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("purged %d, want 2", n)
	}

	// Verify recent entries remain
	stats, err := store.QueryStats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 2 {
		t.Errorf("remaining = %d, want 2", stats.Total)
	}

	// Purge with 0 days should be no-op
	n, err = store.PurgeOldEntries(0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("purged %d with 0 days, want 0", n)
	}
}

func TestQuarantineQuery_FilterByAgent(t *testing.T) {
	store := newTestStore(t)

	for _, item := range []QuarantineItem{
		{ID: "qa1", AuditEntryID: "qa1", Content: "c", FromAgent: "alpha", ToAgent: "beta", Status: "pending", ExpiresAt: "2099-01-01T00:00:00Z", CreatedAt: "2026-01-01T00:00:00Z", Timestamp: "2026-01-01T00:00:00Z"},
		{ID: "qa2", AuditEntryID: "qa2", Content: "c", FromAgent: "gamma", ToAgent: "alpha", Status: "pending", ExpiresAt: "2099-01-01T00:00:00Z", CreatedAt: "2026-01-01T00:00:00Z", Timestamp: "2026-01-01T00:00:00Z"},
		{ID: "qa3", AuditEntryID: "qa3", Content: "c", FromAgent: "gamma", ToAgent: "delta", Status: "pending", ExpiresAt: "2099-01-01T00:00:00Z", CreatedAt: "2026-01-01T00:00:00Z", Timestamp: "2026-01-01T00:00:00Z"},
	} {
		if err := store.Enqueue(item); err != nil {
			t.Fatal(err)
		}
	}

	items, err := store.QuarantineQuery("", "alpha", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Errorf("got %d items for alpha, want 2", len(items))
	}
}
