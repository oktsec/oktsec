package proxy

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/oktsec/oktsec/internal/config"
)

// WebhookEvent is the payload sent to webhook endpoints.
type WebhookEvent struct {
	Event     string `json:"event"`
	MessageID string `json:"message_id"`
	From      string `json:"from"`
	To        string `json:"to"`
	Severity  string `json:"severity,omitempty"`
	Rule      string `json:"rule,omitempty"`
	Timestamp string `json:"timestamp"`
}

// WebhookNotifier sends notifications to configured webhooks.
type WebhookNotifier struct {
	webhooks []config.Webhook
	client   *http.Client
	logger   *slog.Logger
}

// NewWebhookNotifier creates a notifier from config.
func NewWebhookNotifier(webhooks []config.Webhook, logger *slog.Logger) *WebhookNotifier {
	return &WebhookNotifier{
		webhooks: webhooks,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		logger: logger,
	}
}

// Notify sends the event to all matching webhooks (fire-and-forget).
func (n *WebhookNotifier) Notify(event WebhookEvent) {
	for _, wh := range n.webhooks {
		if !matchesEvent(wh.Events, event.Event) {
			continue
		}
		go n.send(wh.URL, event)
	}
}

func (n *WebhookNotifier) send(url string, event WebhookEvent) {
	body, err := json.Marshal(event)
	if err != nil {
		n.logger.Error("webhook marshal failed", "error", err)
		return
	}

	resp, err := n.client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		n.logger.Warn("webhook delivery failed", "url", url, "error", err)
		return
	}
	_ = resp.Body.Close()

	if resp.StatusCode >= 400 {
		n.logger.Warn("webhook returned error", "url", url, "status", resp.StatusCode)
	}
}

func matchesEvent(configured []string, event string) bool {
	if len(configured) == 0 {
		return true // no filter = all events
	}
	for _, e := range configured {
		if e == event || "message_"+e == event {
			return true
		}
	}
	return false
}
