package audit

import (
	"database/sql"
	"time"
)

// LLMAnalysis stores the result of an async LLM analysis.
type LLMAnalysis struct {
	ID                string  `json:"id"`
	MessageID         string  `json:"message_id"`
	Timestamp         string  `json:"timestamp"`
	FromAgent         string  `json:"from_agent"`
	ToAgent           string  `json:"to_agent"`
	Provider          string  `json:"provider"`
	Model             string  `json:"model"`
	RiskScore         float64 `json:"risk_score"`
	RecommendedAction string  `json:"recommended_action"`
	Confidence        float64 `json:"confidence"`
	ThreatsJSON       string  `json:"threats_json"`
	IntentJSON        string  `json:"intent_json"`
	LatencyMs         int64   `json:"latency_ms"`
	TokensUsed        int     `json:"tokens_used"`
	RuleGenerated     string  `json:"rule_generated,omitempty"`
	ReviewedStatus    string  `json:"reviewed_status,omitempty"` // "false_positive", "confirmed", "dismissed", or ""
	ReviewedAt        string  `json:"reviewed_at,omitempty"`
}

// llmSelectFields is the canonical SELECT column list for LLMAnalysis queries.
// Keep in sync with scanLLMAnalysis.
const llmSelectFields = `id, message_id, timestamp, from_agent, to_agent,
	provider, model, risk_score, recommended_action, confidence,
	threats_json, intent_json, latency_ms, tokens_used,
	COALESCE(rule_generated, ''), COALESCE(reviewed_status, ''), COALESCE(reviewed_at, '')`

// scanLLMAnalysis scans a row into an LLMAnalysis struct.
// Column order must match llmSelectFields.
func scanLLMAnalysis(sc interface{ Scan(...any) error }) (LLMAnalysis, error) {
	var a LLMAnalysis
	err := sc.Scan(&a.ID, &a.MessageID, &a.Timestamp, &a.FromAgent, &a.ToAgent,
		&a.Provider, &a.Model, &a.RiskScore, &a.RecommendedAction, &a.Confidence,
		&a.ThreatsJSON, &a.IntentJSON, &a.LatencyMs, &a.TokensUsed,
		&a.RuleGenerated, &a.ReviewedStatus, &a.ReviewedAt)
	return a, err
}

// LogLLMAnalysis stores an LLM analysis result.
func (s *Store) LogLLMAnalysis(a LLMAnalysis) error {
	_, err := s.db.Exec(`INSERT INTO llm_analysis
		(id, message_id, timestamp, from_agent, to_agent, provider, model,
		 risk_score, recommended_action, confidence, threats_json, intent_json,
		 latency_ms, tokens_used, rule_generated)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.MessageID, a.Timestamp, a.FromAgent, a.ToAgent,
		a.Provider, a.Model, a.RiskScore, a.RecommendedAction,
		a.Confidence, a.ThreatsJSON, a.IntentJSON,
		a.LatencyMs, a.TokensUsed, a.RuleGenerated,
	)
	return err
}

// QueryLLMAnalyses returns recent LLM analyses.
func (s *Store) QueryLLMAnalyses(limit int) ([]LLMAnalysis, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT `+llmSelectFields+`
		FROM llm_analysis ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // rows.Close error is non-actionable

	var results []LLMAnalysis
	for rows.Next() {
		a, err := scanLLMAnalysis(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, a)
	}
	return results, rows.Err()
}

// QueryLLMAnalysisByID returns a single LLM analysis by its ID.
func (s *Store) QueryLLMAnalysisByID(id string) (*LLMAnalysis, error) {
	a, err := scanLLMAnalysis(s.db.QueryRow(`SELECT `+llmSelectFields+`
		FROM llm_analysis WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// QueryLLMAnalysisByMessage returns the LLM analysis for a specific message.
func (s *Store) QueryLLMAnalysisByMessage(messageID string) (*LLMAnalysis, error) {
	a, err := scanLLMAnalysis(s.db.QueryRow(`SELECT `+llmSelectFields+`
		FROM llm_analysis WHERE message_id = ?`, messageID))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// LLMStats holds aggregate LLM usage statistics.
type LLMStats struct {
	TotalAnalyses  int     `json:"total_analyses"`
	TotalTokens    int64   `json:"total_tokens"`
	AvgLatencyMs   float64 `json:"avg_latency_ms"`
	AvgRiskScore   float64 `json:"avg_risk_score"`
	TotalThreats   int     `json:"total_threats"`
	RulesGenerated int     `json:"rules_generated"`
}

// QueryLLMStats returns aggregate LLM usage stats.
func (s *Store) QueryLLMStats() (*LLMStats, error) {
	var stats LLMStats
	err := s.db.QueryRow(`SELECT
		COUNT(*),
		COALESCE(SUM(tokens_used), 0),
		COALESCE(AVG(latency_ms), 0),
		COALESCE(AVG(risk_score), 0),
		COUNT(CASE WHEN threats_json != '[]' AND threats_json != '' AND threats_json != 'null' THEN 1 END),
		COUNT(CASE WHEN rule_generated != '' THEN 1 END)
		FROM llm_analysis`).Scan(
		&stats.TotalAnalyses, &stats.TotalTokens, &stats.AvgLatencyMs,
		&stats.AvgRiskScore, &stats.TotalThreats, &stats.RulesGenerated,
	)
	if err != nil {
		return &LLMStats{}, nil // table might not exist yet
	}
	return &stats, nil
}

// LLMTriageCounts holds counts for the triage summary bar.
type LLMTriageCounts struct {
	NeedsReview    int
	HighSeverity   int // risk >= 76, unreviewed
	MediumSeverity int // risk 31-75, unreviewed
	Resolved       int
}

// QueryLLMTriageCounts returns triage-oriented counts.
func (s *Store) QueryLLMTriageCounts() LLMTriageCounts {
	var c LLMTriageCounts
	row := s.db.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN COALESCE(reviewed_status,'')='' AND risk_score >= 30 THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN COALESCE(reviewed_status,'')='' AND risk_score >= 76 THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN COALESCE(reviewed_status,'')='' AND risk_score >= 31 AND risk_score < 76 THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN COALESCE(reviewed_status,'') != '' THEN 1 ELSE 0 END), 0)
	FROM llm_analysis`)
	_ = row.Scan(&c.NeedsReview, &c.HighSeverity, &c.MediumSeverity, &c.Resolved)
	return c
}

// QueryLLMAgentHistory returns recent analyses for a specific agent (as sender).
func (s *Store) QueryLLMAgentHistory(agent string, excludeID string, limit int) ([]LLMAnalysis, error) {
	rows, err := s.db.Query(`SELECT `+llmSelectFields+`
		FROM llm_analysis WHERE from_agent = ? AND id != ? ORDER BY timestamp DESC LIMIT ?`,
		agent, excludeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // rows.Close error is non-actionable
	var results []LLMAnalysis
	for rows.Next() {
		a, err := scanLLMAnalysis(rows)
		if err != nil {
			continue
		}
		results = append(results, a)
	}
	return results, nil
}

// UpdateLLMReviewStatus sets the review status for an LLM analysis entry.
func (s *Store) UpdateLLMReviewStatus(id, status string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(
		`UPDATE llm_analysis SET reviewed_status=?, reviewed_at=? WHERE id=?`,
		status, now, id,
	)
	return err
}
