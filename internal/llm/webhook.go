package llm

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

	"github.com/oktsec/oktsec/internal/netutil"
)

// webhookProvider sends analysis requests to a custom HTTP endpoint.
type webhookProvider struct {
	client  *http.Client
	url     string
	headers map[string]string
}

func newWebhookProvider(cfg Config) (*webhookProvider, error) {
	if cfg.Webhook.URL == "" {
		return nil, fmt.Errorf("webhook provider requires webhook.url")
	}

	// Resolve env vars in headers (e.g. ${WEBHOOK_TOKEN})
	headers := make(map[string]string, len(cfg.Webhook.Headers))
	for k, v := range cfg.Webhook.Headers {
		headers[k] = expandEnv(v)
	}

	return &webhookProvider{
		client: &http.Client{
			Timeout: cfg.ParseTimeout(),
			Transport: &http.Transport{
				DialContext: netutil.SafeDialContext,
			},
		},
		url:     cfg.Webhook.URL,
		headers: headers,
	}, nil
}

func (p *webhookProvider) Analyze(ctx context.Context, req AnalysisRequest) (*AnalysisResult, error) {
	start := time.Now()

	jsonBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	for k, v := range p.headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // HTTP body close error is non-actionable

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("webhook returned %d: %s", resp.StatusCode, truncateStr(string(respBody), 200))
	}

	var result AnalysisResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parse webhook response: %w", err)
	}

	result.MessageID = req.MessageID
	result.LatencyMs = time.Since(start).Milliseconds()
	result.ProviderName = string(ProviderWebhook)

	return &result, nil
}

func (p *webhookProvider) Name() string {
	return "webhook"
}

// expandEnv replaces ${VAR} patterns with environment variable values.
func expandEnv(s string) string {
	if !strings.Contains(s, "${") {
		return s
	}
	return os.Expand(s, os.Getenv)
}
