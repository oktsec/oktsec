package audit

import "database/sql"

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
	rows, err := s.db.Query(`SELECT id, message_id, timestamp, from_agent, to_agent,
		provider, model, risk_score, recommended_action, confidence,
		threats_json, intent_json, latency_ms, tokens_used, COALESCE(rule_generated, '')
		FROM llm_analysis ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // rows.Close error is non-actionable

	var results []LLMAnalysis
	for rows.Next() {
		var a LLMAnalysis
		if err := rows.Scan(&a.ID, &a.MessageID, &a.Timestamp, &a.FromAgent, &a.ToAgent,
			&a.Provider, &a.Model, &a.RiskScore, &a.RecommendedAction, &a.Confidence,
			&a.ThreatsJSON, &a.IntentJSON, &a.LatencyMs, &a.TokensUsed,
			&a.RuleGenerated); err != nil {
			return nil, err
		}
		results = append(results, a)
	}
	return results, rows.Err()
}

// QueryLLMAnalysisByID returns a single LLM analysis by its ID.
func (s *Store) QueryLLMAnalysisByID(id string) (*LLMAnalysis, error) {
	var a LLMAnalysis
	err := s.db.QueryRow(`SELECT id, message_id, timestamp, from_agent, to_agent,
		provider, model, risk_score, recommended_action, confidence,
		threats_json, intent_json, latency_ms, tokens_used, COALESCE(rule_generated, '')
		FROM llm_analysis WHERE id = ?`, id).Scan(
		&a.ID, &a.MessageID, &a.Timestamp, &a.FromAgent, &a.ToAgent,
		&a.Provider, &a.Model, &a.RiskScore, &a.RecommendedAction, &a.Confidence,
		&a.ThreatsJSON, &a.IntentJSON, &a.LatencyMs, &a.TokensUsed,
		&a.RuleGenerated)
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
	var a LLMAnalysis
	err := s.db.QueryRow(`SELECT id, message_id, timestamp, from_agent, to_agent,
		provider, model, risk_score, recommended_action, confidence,
		threats_json, intent_json, latency_ms, tokens_used, COALESCE(rule_generated, '')
		FROM llm_analysis WHERE message_id = ?`, messageID).Scan(
		&a.ID, &a.MessageID, &a.Timestamp, &a.FromAgent, &a.ToAgent,
		&a.Provider, &a.Model, &a.RiskScore, &a.RecommendedAction, &a.Confidence,
		&a.ThreatsJSON, &a.IntentJSON, &a.LatencyMs, &a.TokensUsed,
		&a.RuleGenerated)
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
