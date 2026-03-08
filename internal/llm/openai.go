package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// openaiProvider implements Analyzer for any OpenAI Chat Completions-compatible API.
// Covers: OpenAI, Ollama, vLLM, llama.cpp, LM Studio, Mistral, Groq, Together, Azure.
type openaiProvider struct {
	client     *http.Client
	baseURL    string
	apiKey     string
	model      string
	maxTokens  int
	temp       float64
	apiVersion string // for Azure OpenAI
}

func newOpenAIProvider(cfg Config) (*openaiProvider, error) {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}

	apiKey := cfg.ResolveAPIKey()
	// apiKey can be empty for local providers (Ollama, vLLM, llama.cpp)

	maxTokens := cfg.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 2048
	}

	temp := cfg.Temperature
	if temp <= 0 {
		temp = 0.1
	}

	return &openaiProvider{
		client:     &http.Client{Timeout: cfg.ParseTimeout()},
		baseURL:    baseURL,
		apiKey:     apiKey,
		model:      cfg.Model,
		maxTokens:  maxTokens,
		temp:       temp,
		apiVersion: cfg.APIVersion,
	}, nil
}

type chatRequest struct {
	Model          string          `json:"model"`
	Messages       []chatMessage   `json:"messages"`
	MaxTokens      int             `json:"max_tokens,omitempty"`
	Temperature    float64         `json:"temperature"`
	ResponseFormat *responseFormat `json:"response_format,omitempty"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type responseFormat struct {
	Type string `json:"type"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		TotalTokens int `json:"total_tokens"`
	} `json:"usage"`
}

func (p *openaiProvider) Analyze(ctx context.Context, req AnalysisRequest) (*AnalysisResult, error) {
	start := time.Now()

	prompt := buildAnalysisPrompt(req)

	body := chatRequest{
		Model: p.model,
		Messages: []chatMessage{
			{Role: "system", Content: securityAnalysisSystemPrompt},
			{Role: "user", Content: prompt},
		},
		MaxTokens:      p.maxTokens,
		Temperature:    p.temp,
		ResponseFormat: &responseFormat{Type: "json_object"},
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	endpoint := p.baseURL + "/chat/completions"

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if p.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	}
	// OpenRouter-specific headers
	if strings.Contains(p.baseURL, "openrouter") {
		httpReq.Header.Set("HTTP-Referer", "https://oktsec.com")
		httpReq.Header.Set("X-Title", "oktsec")
	}
	if p.apiVersion != "" {
		q := httpReq.URL.Query()
		q.Set("api-version", p.apiVersion)
		httpReq.URL.RawQuery = q.Encode()
	}

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("llm request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // HTTP body close error is non-actionable

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("llm returned %d: %s", resp.StatusCode, truncateStr(string(respBody), 200))
	}

	var chatResp chatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return nil, fmt.Errorf("llm returned no choices")
	}

	result, err := parseAnalysisResponse(chatResp.Choices[0].Message.Content)
	if err != nil {
		return nil, fmt.Errorf("parse analysis: %w", err)
	}

	result.MessageID = req.MessageID
	result.LatencyMs = time.Since(start).Milliseconds()
	result.TokensUsed = chatResp.Usage.TotalTokens
	result.ProviderName = string(ProviderOpenAICompat)
	result.Model = p.model

	return result, nil
}

func (p *openaiProvider) Name() string {
	return fmt.Sprintf("openai-compat/%s", p.model)
}
