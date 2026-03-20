package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/oktsec/oktsec/internal/audit"
)

const sessionAnalysisPrompt = `You are a security analyst reviewing an AI agent session for an enterprise security team. Your analysis will be read by a manager who needs to decide what to do.

Write a structured analysis using these exact sections:

**Risk Level:** CRITICAL, HIGH, MEDIUM, LOW, or CLEAN. One sentence why.

**Summary:** 2-3 sentences max. What the user/agent was doing and whether the security findings are real threats or false positives.

**Recommended actions:**
Each action must be specific and tied to a configuration change. Use this format:
- [Suspend agent NAME](/dashboard/agents/NAME) - reason
- [Suspend user NAME](/dashboard/agents/NAME) - reason
- [Review quarantined messages](/dashboard/events?tab=quarantine) - reason
- [Add rule for PATTERN](/dashboard/rules) - reason
- No action needed - reason

Session data:
- Agents: %s
- Duration: %s
- Tool calls: %d
- Threats: %d (blocked/quarantined/flagged)

Timeline (most recent first):
%s

Rules:
- Start directly with **Risk Level:**
- Never use em dashes. Use hyphens instead
- Do not use jargon like "red-team", "SOC", "IOC". Write for a startup CTO
- If the user attempted something dangerous (reading system files, exfiltrating data, injecting prompts), recommend suspending the user/agent with a link
- If blocks were false positives from normal file editing or content scanning, say "No action needed" clearly
- Keep it short. The manager should be able to act in 30 seconds
- 3-4 bullet points max in recommendations
- Every recommendation should link to the relevant oktsec dashboard page where the action can be taken`

// analyzeSession sends a session trace to the configured LLM for analysis.
// Makes a direct API call using the LLM config, bypassing the security
// analysis prompt and structured JSON parsing used by Analyzer.Analyze().
func (s *Server) analyzeSession(ctx context.Context, trace *audit.SessionTrace) (string, error) {
	cfg := s.cfg.LLM
	if !cfg.Enabled {
		return "", fmt.Errorf("LLM not configured")
	}

	apiKey := cfg.APIKey
	if apiKey == "" && cfg.APIKeyEnv != "" {
		apiKey = os.Getenv(cfg.APIKeyEnv)
	}
	if apiKey == "" {
		return "", fmt.Errorf("LLM API key not set")
	}

	// Build timeline text from trace steps
	var sb strings.Builder
	for i, step := range trace.Steps {
		if i >= 30 {
			fmt.Fprintf(&sb, "... and %d more steps\n", len(trace.Steps)-30)
			break
		}
		verdict := step.Verdict
		if verdict == "" {
			verdict = "clean"
		}
		fmt.Fprintf(&sb, "- %s tool=%s verdict=%s", step.FromAgent, step.ToolName, verdict)
		if step.ToolInput != "" {
			fmt.Fprintf(&sb, " input=%q", step.ToolInput)
		}
		sb.WriteString("\n")
	}

	prompt := fmt.Sprintf(sessionAnalysisPrompt,
		trace.Agent,
		trace.Duration,
		trace.ToolCount,
		trace.Threats,
		sb.String(),
	)

	analysisCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	switch cfg.Provider {
	case "claude":
		return s.callClaude(analysisCtx, apiKey, cfg.Model, prompt)
	case "openai":
		baseURL := cfg.BaseURL
		if baseURL == "" {
			baseURL = "https://api.openai.com/v1"
		}
		return s.callOpenAI(analysisCtx, apiKey, baseURL, cfg.Model, prompt)
	default:
		return "", fmt.Errorf("unsupported LLM provider %q for session analysis", cfg.Provider)
	}
}

func (s *Server) callClaude(ctx context.Context, apiKey, model, prompt string) (string, error) {
	if model == "" {
		model = "claude-sonnet-4-6"
	}

	body, _ := json.Marshal(map[string]any{
		"model":      model,
		"max_tokens": 512,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("claude request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("claude %d: %s", resp.StatusCode, truncStr(string(respBody), 200))
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	if len(result.Content) == 0 {
		return "", fmt.Errorf("empty response")
	}
	return result.Content[0].Text, nil
}

func (s *Server) callOpenAI(ctx context.Context, apiKey, baseURL, model, prompt string) (string, error) {
	if model == "" {
		model = "gpt-4o-mini"
	}

	body, _ := json.Marshal(map[string]any{
		"model":      model,
		"max_tokens": 512,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("openai request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openai %d: %s", resp.StatusCode, truncStr(string(respBody), 200))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("empty response")
	}
	return result.Choices[0].Message.Content, nil
}

func truncStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
