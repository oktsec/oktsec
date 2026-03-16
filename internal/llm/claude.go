package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/oktsec/oktsec/internal/netutil"
)

// claudeProvider implements Analyzer for the Anthropic Messages API.
type claudeProvider struct {
	client    *http.Client
	apiKey    string
	model     string
	maxTokens int
}

func newClaudeProvider(cfg Config) (*claudeProvider, error) {
	apiKey := cfg.ResolveAPIKey()
	if apiKey == "" {
		return nil, fmt.Errorf("claude provider requires api_key_env (e.g. ANTHROPIC_API_KEY)")
	}

	model := cfg.Model
	if model == "" {
		model = "claude-sonnet-4-6"
	}

	maxTokens := cfg.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 2048
	}

	return &claudeProvider{
		client: &http.Client{
			Timeout: cfg.ParseTimeout(),
			Transport: &http.Transport{
				DialContext: netutil.SafeDialContext,
			},
		},
		apiKey:    apiKey,
		model:     model,
		maxTokens: maxTokens,
	}, nil
}

type claudeRequest struct {
	Model     string           `json:"model"`
	MaxTokens int              `json:"max_tokens"`
	System    string           `json:"system,omitempty"`
	Messages  []claudeMessage  `json:"messages"`
}

type claudeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type claudeResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

func (p *claudeProvider) Analyze(ctx context.Context, req AnalysisRequest) (*AnalysisResult, error) {
	start := time.Now()

	prompt := buildAnalysisPrompt(req)

	body := claudeRequest{
		Model:     p.model,
		MaxTokens: p.maxTokens,
		System:    securityAnalysisSystemPrompt,
		Messages: []claudeMessage{
			{Role: "user", Content: prompt},
		},
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.anthropic.com/v1/messages", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("claude request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // HTTP body close error is non-actionable

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("claude returned %d: %s", resp.StatusCode, truncateStr(string(respBody), 200))
	}

	var claudeResp claudeResponse
	if err := json.Unmarshal(respBody, &claudeResp); err != nil {
		return nil, fmt.Errorf("parse claude response: %w", err)
	}

	if len(claudeResp.Content) == 0 {
		return nil, fmt.Errorf("claude returned no content")
	}

	result, err := parseAnalysisResponse(claudeResp.Content[0].Text)
	if err != nil {
		return nil, fmt.Errorf("parse analysis: %w", err)
	}

	result.MessageID = req.MessageID
	result.LatencyMs = time.Since(start).Milliseconds()
	result.TokensUsed = claudeResp.Usage.InputTokens + claudeResp.Usage.OutputTokens
	result.ProviderName = string(ProviderClaude)
	result.Model = p.model

	return result, nil
}

func (p *claudeProvider) Name() string {
	return fmt.Sprintf("claude/%s", p.model)
}
