package llm

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/oktsec/oktsec/internal/audit"
)

// StoreResult persists an LLM analysis result to the audit store.
// This is the shared logic used by both the proxy server and gateway command.
func StoreResult(store audit.LLMStore, result AnalysisResult) error {
	threatsJSON, _ := json.Marshal(result.Threats)
	intentJSON, _ := json.Marshal(result.IntentAnalysis)
	return store.LogLLMAnalysis(audit.LLMAnalysis{
		ID:                fmt.Sprintf("llm-%s", result.MessageID),
		MessageID:         result.MessageID,
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
		FromAgent:         result.FromAgent,
		ToAgent:           result.ToAgent,
		Provider:          result.ProviderName,
		Model:             result.Model,
		RiskScore:         result.RiskScore,
		RecommendedAction: result.RecommendedAction,
		Confidence:        result.Confidence,
		ThreatsJSON:       string(threatsJSON),
		IntentJSON:        string(intentJSON),
		LatencyMs:         result.LatencyMs,
		TokensUsed:        result.TokensUsed,
	})
}
