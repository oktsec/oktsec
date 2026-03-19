package audit

import (
	"time"
)

// AlertEntry represents a persisted alert notification.
type AlertEntry struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
	Event     string `json:"event"`     // blocked, quarantined, llm_threat, anomaly, agent_suspended, budget_warning
	Severity  string `json:"severity"`  // critical, high, medium, low, info
	Agent     string `json:"agent"`     // primary agent involved
	MessageID string `json:"message_id,omitempty"`
	Detail    string `json:"detail"`    // human-readable description
	Channel   string `json:"channel"`   // webhook name or URL (truncated)
	Status    string `json:"status"`    // sent, failed
}

// AlertStats holds aggregated alert counts.
type AlertStats struct {
	Total    int `json:"total"`
	Last24h  int `json:"last_24h"`
	ByEvent  map[string]int `json:"by_event"`
	BySeverity map[string]int `json:"by_severity"`
}

// LogAlert persists an alert entry.
func (s *Store) LogAlert(a AlertEntry) error {
	if a.Timestamp == "" {
		a.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	_, err := s.db.Exec(
		s.dialect.InsertIgnoreAlert(),
		a.ID, a.Timestamp, a.Event, a.Severity, a.Agent, a.MessageID, a.Detail, a.Channel, a.Status,
	)
	return err
}

// QueryAlerts returns the most recent alerts, newest first.
func (s *Store) QueryAlerts(limit, offset int) ([]AlertEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(
		`SELECT id, timestamp, event, severity, agent, message_id, detail, channel, status
		 FROM alerts ORDER BY timestamp DESC LIMIT ? OFFSET ?`,
		limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var alerts []AlertEntry
	for rows.Next() {
		var a AlertEntry
		if err := rows.Scan(&a.ID, &a.Timestamp, &a.Event, &a.Severity, &a.Agent, &a.MessageID, &a.Detail, &a.Channel, &a.Status); err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

// AlertStats returns aggregated alert statistics in a single query.
func (s *Store) AlertStats() (AlertStats, error) {
	stats := AlertStats{
		ByEvent:    make(map[string]int),
		BySeverity: make(map[string]int),
	}

	cutoff := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	rows, err := s.db.Query(
		`SELECT event, severity, COUNT(*) as cnt,
			COUNT(CASE WHEN timestamp > ? THEN 1 END) as recent
		 FROM alerts GROUP BY event, severity`, cutoff)
	if err != nil {
		return stats, err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var event, sev string
		var cnt, recent int
		if err := rows.Scan(&event, &sev, &cnt, &recent); err != nil {
			return stats, err
		}
		stats.Total += cnt
		stats.Last24h += recent
		stats.ByEvent[event] += cnt
		stats.BySeverity[sev] += cnt
	}
	return stats, rows.Err()
}
