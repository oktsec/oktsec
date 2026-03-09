package audit

import (
	"fmt"
	"log/slog"
	"testing"
	"time"
)

func TestLogAlert_QueryAlerts(t *testing.T) {
	store, err := NewStore(":memory:", slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	// Insert alerts
	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		err := store.LogAlert(AlertEntry{
			ID:        fmt.Sprintf("alert-%d", i),
			Timestamp: now.Add(time.Duration(i) * time.Minute).Format(time.RFC3339),
			Event:     "blocked",
			Severity:  "high",
			Agent:     "agent-a",
			MessageID: fmt.Sprintf("msg-%d", i),
			Detail:    fmt.Sprintf("test alert %d", i),
			Channel:   "slack-alerts",
			Status:    "sent",
		})
		if err != nil {
			t.Fatalf("LogAlert failed: %v", err)
		}
	}

	// Query all
	alerts, err := store.QueryAlerts(10, 0)
	if err != nil {
		t.Fatalf("QueryAlerts failed: %v", err)
	}
	if len(alerts) != 5 {
		t.Errorf("expected 5 alerts, got %d", len(alerts))
	}

	// Newest first
	if alerts[0].ID != "alert-4" {
		t.Errorf("expected newest first, got %s", alerts[0].ID)
	}

	// Query with limit
	alerts2, err := store.QueryAlerts(2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts2) != 2 {
		t.Errorf("expected 2 alerts, got %d", len(alerts2))
	}

	// Query with offset
	alerts3, err := store.QueryAlerts(10, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts3) != 2 {
		t.Errorf("expected 2 alerts, got %d", len(alerts3))
	}
}

func TestAlertStats(t *testing.T) {
	store, err := NewStore(":memory:", slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	now := time.Now().UTC()

	// Mix of event types and severities
	entries := []AlertEntry{
		{ID: "a1", Timestamp: now.Format(time.RFC3339), Event: "blocked", Severity: "high", Agent: "a", Status: "sent"},
		{ID: "a2", Timestamp: now.Format(time.RFC3339), Event: "blocked", Severity: "high", Agent: "b", Status: "sent"},
		{ID: "a3", Timestamp: now.Format(time.RFC3339), Event: "llm_threat", Severity: "critical", Agent: "a", Status: "sent"},
		{ID: "a4", Timestamp: now.Add(-48 * time.Hour).Format(time.RFC3339), Event: "anomaly", Severity: "medium", Agent: "c", Status: "failed"},
	}

	for _, e := range entries {
		if err := store.LogAlert(e); err != nil {
			t.Fatal(err)
		}
	}

	stats, err := store.AlertStats()
	if err != nil {
		t.Fatal(err)
	}

	if stats.Total != 4 {
		t.Errorf("Total = %d, want 4", stats.Total)
	}
	if stats.Last24h != 3 {
		t.Errorf("Last24h = %d, want 3", stats.Last24h)
	}
	if stats.ByEvent["blocked"] != 2 {
		t.Errorf("ByEvent[blocked] = %d, want 2", stats.ByEvent["blocked"])
	}
	if stats.ByEvent["llm_threat"] != 1 {
		t.Errorf("ByEvent[llm_threat] = %d, want 1", stats.ByEvent["llm_threat"])
	}
	if stats.BySeverity["high"] != 2 {
		t.Errorf("BySeverity[high] = %d, want 2", stats.BySeverity["high"])
	}
	if stats.BySeverity["critical"] != 1 {
		t.Errorf("BySeverity[critical] = %d, want 1", stats.BySeverity["critical"])
	}
}

func TestLogAlert_DuplicateID(t *testing.T) {
	store, err := NewStore(":memory:", slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	a := AlertEntry{
		ID:        "dup-1",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Event:     "blocked",
		Severity:  "high",
		Agent:     "x",
		Status:    "sent",
	}

	if err := store.LogAlert(a); err != nil {
		t.Fatal(err)
	}
	// Duplicate should not error (INSERT OR IGNORE)
	if err := store.LogAlert(a); err != nil {
		t.Fatalf("duplicate insert should not error: %v", err)
	}

	alerts, _ := store.QueryAlerts(10, 0)
	if len(alerts) != 1 {
		t.Errorf("expected 1 alert (deduped), got %d", len(alerts))
	}
}
