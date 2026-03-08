package llm

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// flexFloat64 handles JSON values that may be either a number or a string containing a number.
// Some LLMs (e.g., qwen3.5) return numeric fields as strings.
type flexFloat64 float64

func (f *flexFloat64) UnmarshalJSON(data []byte) error {
	// Try number first
	var n float64
	if err := json.Unmarshal(data, &n); err == nil {
		*f = flexFloat64(n)
		return nil
	}
	// Try string
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		n, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return fmt.Errorf("cannot parse %q as float64", s)
		}
		*f = flexFloat64(n)
		return nil
	}
	return fmt.Errorf("cannot unmarshal %s into float64", string(data))
}

// flexThreat is a flexible intermediate struct for parsing LLM threat findings.
// Handles confidence as string or number.
type flexThreat struct {
	Type        string          `json:"type"`
	Description string          `json:"description"`
	Severity    string          `json:"severity"`
	Evidence    string          `json:"evidence"`
	Confidence  flexFloat64     `json:"confidence"`
	Suggestion  *RuleSuggestion `json:"suggestion,omitempty"`
}

// flexResult is a flexible intermediate struct for parsing LLM responses.
type flexResult struct {
	Threats           []json.RawMessage `json:"threats,omitempty"`
	IntentAnalysis    *IntentResult     `json:"intent_analysis,omitempty"`
	RiskScore         flexFloat64       `json:"risk_score"`
	RecommendedAction string            `json:"recommended_action"`
	Confidence        flexFloat64       `json:"confidence"`
}

// parseAnalysisResponse parses the JSON response from any LLM provider.
func parseAnalysisResponse(raw string) (*AnalysisResult, error) {
	// Strip markdown code fences if present
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "```") {
		lines := strings.Split(raw, "\n")
		// Remove first and last lines (```json and ```)
		if len(lines) > 2 {
			lines = lines[1 : len(lines)-1]
			raw = strings.Join(lines, "\n")
		}
	}

	var flex flexResult
	if err := json.Unmarshal([]byte(raw), &flex); err != nil {
		return nil, fmt.Errorf("invalid JSON from LLM: %w (first 200 chars: %s)", err, truncateStr(raw, 200))
	}

	result := AnalysisResult{
		RiskScore:         float64(flex.RiskScore),
		RecommendedAction: flex.RecommendedAction,
		Confidence:        float64(flex.Confidence),
		IntentAnalysis:    flex.IntentAnalysis,
	}

	// Parse threats individually, skipping malformed entries
	for _, raw := range flex.Threats {
		var ft flexThreat
		if err := json.Unmarshal(raw, &ft); err != nil {
			// Skip malformed threat entries rather than failing the entire parse
			continue
		}
		result.Threats = append(result.Threats, ThreatFinding{
			Type:        ft.Type,
			Description: ft.Description,
			Severity:    ft.Severity,
			Evidence:    ft.Evidence,
			Confidence:  float64(ft.Confidence),
			Suggestion:  ft.Suggestion,
		})
	}

	// Validate recommended_action
	switch result.RecommendedAction {
	case "escalate", "confirm", "investigate", "block", "log", "none", "":
		// valid
	default:
		result.RecommendedAction = "investigate"
	}

	// Clamp values
	if result.RiskScore < 0 {
		result.RiskScore = 0
	}
	if result.RiskScore > 100 {
		result.RiskScore = 100
	}
	if result.Confidence < 0 {
		result.Confidence = 0
	}
	if result.Confidence > 1 {
		result.Confidence = 1
	}

	// Validate threat severities
	for i := range result.Threats {
		switch result.Threats[i].Severity {
		case "critical", "high", "medium", "low":
			// valid
		default:
			result.Threats[i].Severity = "medium"
		}
		if result.Threats[i].Confidence < 0 {
			result.Threats[i].Confidence = 0
		}
		if result.Threats[i].Confidence > 1 {
			result.Threats[i].Confidence = 1
		}
	}

	return &result, nil
}

// truncateStr truncates a string to maxLen characters.
func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
