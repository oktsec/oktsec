package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// FastChecker is an optional interface for providers that support a fast
// yes/no pre-classification. Stage 1 uses a single-token response to decide
// whether Stage 2 (full analysis) is needed. Providers that don't implement
// this interface skip Stage 1 and run full analysis directly.
type FastChecker interface {
	// FastCheck returns true if the message looks suspicious and needs
	// full analysis (Stage 2). Returns false if the message appears clean.
	FastCheck(ctx context.Context, req AnalysisRequest) (suspicious bool, err error)
}

// parseFastCheckResponse returns true (suspicious) if the response contains "yes".
func parseFastCheckResponse(response string) bool {
	return strings.Contains(strings.ToLower(strings.TrimSpace(response)), "yes")
}

// FastCheck implements FastChecker for the OpenAI-compatible provider.
func (p *openaiProvider) FastCheck(ctx context.Context, req AnalysisRequest) (bool, error) {
	prompt := buildFastCheckPrompt(req)

	body := chatRequest{
		Model: p.model,
		Messages: []chatMessage{
			{Role: "system", Content: fastCheckSystemPrompt},
			{Role: "user", Content: prompt},
		},
		MaxTokens:   5,
		Temperature: 0,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return false, fmt.Errorf("marshal fast check request: %w", err)
	}

	endpoint := p.baseURL + "/chat/completions"

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(jsonBody))
	if err != nil {
		return false, fmt.Errorf("create fast check request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if p.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	}
	if p.isOpenRouter {
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
		return false, fmt.Errorf("fast check request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // HTTP body close error is non-actionable

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return false, fmt.Errorf("read fast check response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("fast check returned %d: %s", resp.StatusCode, truncateStr(string(respBody), 200))
	}

	var chatResp chatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return false, fmt.Errorf("parse fast check response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return false, fmt.Errorf("fast check returned no choices")
	}

	return parseFastCheckResponse(chatResp.Choices[0].Message.Content), nil
}

// FastCheck implements FastChecker for the Claude provider.
func (p *claudeProvider) FastCheck(ctx context.Context, req AnalysisRequest) (bool, error) {
	prompt := buildFastCheckPrompt(req)

	body := claudeRequest{
		Model:     p.model,
		MaxTokens: 5,
		System:    fastCheckSystemPrompt,
		Messages: []claudeMessage{
			{Role: "user", Content: prompt},
		},
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return false, fmt.Errorf("marshal fast check request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.anthropic.com/v1/messages", bytes.NewReader(jsonBody))
	if err != nil {
		return false, fmt.Errorf("create fast check request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return false, fmt.Errorf("fast check request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // HTTP body close error is non-actionable

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return false, fmt.Errorf("read fast check response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("fast check returned %d: %s", resp.StatusCode, truncateStr(string(respBody), 200))
	}

	var claudeResp claudeResponse
	if err := json.Unmarshal(respBody, &claudeResp); err != nil {
		return false, fmt.Errorf("parse fast check response: %w", err)
	}

	if len(claudeResp.Content) == 0 {
		return false, fmt.Errorf("fast check returned no content")
	}

	return parseFastCheckResponse(claudeResp.Content[0].Text), nil
}

// FastCheck implements FastChecker for the FallbackAnalyzer.
// It tries the primary's fast check first, falling back to the secondary.
func (f *FallbackAnalyzer) FastCheck(ctx context.Context, req AnalysisRequest) (bool, error) {
	if fc, ok := f.primary.(FastChecker); ok {
		suspicious, err := fc.FastCheck(ctx, req)
		if err == nil {
			return suspicious, nil
		}
		f.logger.Warn("primary fast check failed, trying fallback",
			"primary", f.primary.Name(),
			"error", err,
		)
	}

	if fc, ok := f.secondary.(FastChecker); ok {
		return fc.FastCheck(ctx, req)
	}

	// Neither provider supports fast check — return true to ensure
	// the message goes through full analysis (fail-open to safety).
	return true, nil
}

// Compile-time interface checks
var (
	_ FastChecker = (*openaiProvider)(nil)
	_ FastChecker = (*claudeProvider)(nil)
	_ FastChecker = (*FallbackAnalyzer)(nil)
)
