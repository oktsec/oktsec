package dashboard

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/llm"
)

const sessionAnalysisPrompt = `You are a security analyst reviewing an AI agent session.

Session ID: %s
Agents: %s
Duration: %s
Tool calls: %d
Threats: %d blocked, %d quarantined, %d flagged

Timeline (most recent first):
%s

Analyze this session in 3-5 sentences:
1. What was the agent trying to accomplish?
2. Were any security findings legitimate threats or false positives?
3. Was the behavior pattern normal or anomalous?
4. Any recommendations for policy changes?

Be concise. Focus on actionable insights, not descriptions of what happened.`

// analyzeSession sends a session trace to the LLM for analysis and returns
// a text summary. Returns empty string if LLM is not configured.
func (s *Server) analyzeSession(ctx context.Context, trace *audit.SessionTrace) (string, error) {
	if s.llmQueue == nil {
		return "", fmt.Errorf("LLM not configured")
	}

	analyzer := s.llmQueue.Analyzer()
	if analyzer == nil {
		return "", fmt.Errorf("LLM analyzer not available")
	}

	// Build timeline text from trace steps
	var sb strings.Builder
	for _, step := range trace.Steps {
		verdict := step.Verdict
		if verdict == "" {
			verdict = "clean"
		}
		fmt.Fprintf(&sb, "- [%s] %s tool=%s verdict=%s",
			step.Timestamp, step.FromAgent, step.ToolName, verdict)
		if step.ToolInput != "" {
			fmt.Fprintf(&sb, " input=%q", step.ToolInput)
		}
		sb.WriteString("\n")
	}

	prompt := fmt.Sprintf(sessionAnalysisPrompt,
		trace.SessionID,
		trace.Agent,
		trace.Duration,
		trace.ToolCount,
		trace.Threats, 0, 0, // blocked, quarantined, flagged - threats is total
		sb.String(),
	)

	analysisCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result, err := analyzer.Analyze(analysisCtx, llm.AnalysisRequest{
		MessageID: "session-" + trace.SessionID,
		FromAgent: trace.Agent,
		Content:   prompt,
		Timestamp: time.Now(),
	})
	if err != nil {
		return "", fmt.Errorf("LLM analysis: %w", err)
	}

	// Use the recommended action as a summary, or construct from findings
	if result.RecommendedAction != "" && result.RecommendedAction != "none" {
		parts := []string{result.RecommendedAction}
		for _, t := range result.Threats {
			parts = append(parts, t.Description)
		}
		return strings.Join(parts, ". "), nil
	}

	// If no threats, return a clean summary
	if len(result.Threats) == 0 {
		return "Session appears clean. No anomalous behavior detected.", nil
	}

	var parts []string
	for _, t := range result.Threats {
		parts = append(parts, fmt.Sprintf("[%s] %s", t.Severity, t.Description))
	}
	return strings.Join(parts, ". "), nil
}
