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

const sessionAnalysisPrompt = `You are a security analyst reviewing an AI agent session. Your analysis will be read by a manager who needs to decide what to do.

Important context about roles:
- Entries marked [HUMAN] are messages sent BY a human user TO the agent. If a human sends dangerous content (prompt injection, data exfiltration requests), the HUMAN is the threat actor, not the agent.
- Entries marked [AGENT] are responses or tool calls from the AI agent. If an agent blocked or refused a dangerous request, the agent is PROTECTING the system. Do NOT recommend suspending an agent that correctly blocked an attack.
- The "from" field tells you WHO sent the message. Blame the sender of malicious content.

Write a structured analysis using these exact sections:

**Risk Level:** CRITICAL, HIGH, MEDIUM, LOW, or CLEAN. One sentence why.

**Summary:** 2-3 sentences max. Who did what and whether the security findings are real threats or false positives. Be clear about who the threat actor is (human or agent).

**Recommended actions:**
Each action must link to a specific oktsec dashboard page. Use this format:
- [Suspend user NAME](/dashboard/agents/NAME) - reason (use when a HUMAN sent dangerous content)
- [Suspend agent NAME](/dashboard/agents/NAME) - reason (use only when an AGENT behaved maliciously)
- [Review quarantined messages](/dashboard/events?tab=quarantine) - reason
- [Add rule for PATTERN](/dashboard/rules) - reason
- No action needed - reason

Session data:
- Agents: %s
- Duration: %s
- Tool calls: %d
- Threats: %d (blocked/quarantined/flagged)

Existing detection rules already loaded (do NOT suggest adding rules for patterns already covered):
%s

Timeline (most recent first):
%s

Rules:
- Start directly with **Risk Level:**
- Never use em dashes or single hyphens as separators in sentences. Use commas or periods instead
- Write for a startup CTO, not a security specialist
- If a HUMAN sent dangerous content, recommend suspending the HUMAN, not the agent that blocked it
- If blocks were false positives from normal content, say "No action needed"
- Do NOT suggest adding a rule if the pattern is already covered by an existing rule listed above
- Keep it short. 3-4 bullet points max in recommendations
- Every recommendation must link to a dashboard page`

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

	// Build timeline text with role tags
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
		role := "[AGENT]"
		if step.ToolName == "message" {
			role = "[HUMAN]"
		}
		fmt.Fprintf(&sb, "- %s %s tool=%s verdict=%s", role, step.FromAgent, step.ToolName, verdict)
		if step.ToolInput != "" {
			fmt.Fprintf(&sb, " input=%q", step.ToolInput)
		}
		sb.WriteString("\n")
	}

	// Build existing rules summary so LLM doesn't suggest duplicates
	var rulesSummary string
	if s.scanner != nil {
		rules := s.scanner.ListRules()
		var rb strings.Builder
		for i, r := range rules {
			if i >= 30 {
				fmt.Fprintf(&rb, "... and %d more rules\n", len(rules)-30)
				break
			}
			fmt.Fprintf(&rb, "- %s: %s (%s)\n", r.ID, r.Name, r.Severity)
		}
		rulesSummary = rb.String()
	}
	if rulesSummary == "" {
		rulesSummary = "(no rules loaded)\n"
	}

	prompt := fmt.Sprintf(sessionAnalysisPrompt,
		trace.Agent,
		trace.Duration,
		trace.ToolCount,
		trace.Threats,
		rulesSummary,
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
