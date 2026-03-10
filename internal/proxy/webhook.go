package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
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
	RuleName  string `json:"rule_name,omitempty"`
	Category  string `json:"category,omitempty"`
	Match     string `json:"match,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Timestamp string `json:"timestamp"`
}

// AlertLogFunc is called after each webhook delivery attempt for persistence.
type AlertLogFunc func(event WebhookEvent, channel string, status string)

// WebhookNotifier sends notifications to configured webhooks.
type WebhookNotifier struct {
	webhooks []config.Webhook
	client   *http.Client
	logger   *slog.Logger

	// Cooldown: per event+agent dedup
	cooldown   time.Duration
	cooldownMu sync.Mutex
	lastSent   map[string]time.Time

	// Alert log callback (optional)
	onAlert AlertLogFunc
}

// NewWebhookNotifier creates a notifier from config.
// Invalid URLs (private IPs, non-HTTPS) are logged and skipped.
func NewWebhookNotifier(webhooks []config.Webhook, logger *slog.Logger) *WebhookNotifier {
	var valid []config.Webhook
	for _, wh := range webhooks {
		if err := validateWebhookURL(wh.URL); err != nil {
			logger.Warn("skipping invalid webhook URL", "url", wh.URL, "error", err)
			continue
		}
		valid = append(valid, wh)
	}
	return &WebhookNotifier{
		webhooks: valid,
		client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				DialContext: safeDialContext,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 2 {
					return errors.New("too many redirects")
				}
				// Validate redirect destination URL (defense-in-depth;
				// safeDialContext also validates at connection time)
				if err := validateWebhookURL(req.URL.String()); err != nil {
					return fmt.Errorf("redirect to blocked URL: %w", err)
				}
				return nil
			},
		},
		logger:   logger,
		lastSent: make(map[string]time.Time),
	}
}

// SetCooldown sets the minimum interval between duplicate alerts (same event+agent).
func (n *WebhookNotifier) SetCooldown(d time.Duration) {
	n.cooldown = d
}

// OnAlert sets a callback that fires after each delivery attempt.
func (n *WebhookNotifier) OnAlert(fn AlertLogFunc) {
	n.onAlert = fn
}

// validateWebhookURL performs pre-DNS validation on webhook URLs.
// It rejects non-HTTP schemes, alternative IP encodings, and known
// blocked IP ranges. Post-DNS validation happens in safeDialContext.
func validateWebhookURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return errors.New("webhook URL must use http or https")
	}
	return ValidateHost(u.Hostname())
}

// Notify sends the event to all matching webhooks (fire-and-forget).
func (n *WebhookNotifier) Notify(event WebhookEvent) {
	for _, wh := range n.webhooks {
		if !matchesEvent(wh.Events, event.Event) {
			continue
		}
		channel := wh.Name
		if channel == "" {
			channel = wh.URL
		}
		if n.shouldCooldown(event.Event, event.From) {
			n.logger.Debug("alert cooldown active, skipping", "event", event.Event, "agent", event.From)
			continue
		}
		go n.send(wh.URL, channel, event)
	}
}

// NotifyURL sends an event to a specific URL (fire-and-forget).
// The URL is validated before sending to prevent SSRF.
func (n *WebhookNotifier) NotifyURL(rawURL string, event WebhookEvent) {
	if err := validateWebhookURL(rawURL); err != nil {
		n.logger.Warn("skipping invalid notify URL", "url", rawURL, "error", err)
		return
	}
	go n.send(rawURL, rawURL, event)
}

// NotifyTemplated sends a templated body to a URL. Tags like {{RULE}}, {{ACTION}},
// {{SEVERITY}}, {{FROM}}, {{TO}}, {{MESSAGE_ID}}, {{TIMESTAMP}} are replaced.
// If tmpl is empty, falls back to the default JSON payload.
func (n *WebhookNotifier) NotifyTemplated(rawURL, tmpl string, event WebhookEvent) {
	if err := validateWebhookURL(rawURL); err != nil {
		n.logger.Warn("skipping invalid notify URL", "url", rawURL, "error", err)
		return
	}
	if tmpl == "" {
		go n.send(rawURL, rawURL, event)
		return
	}
	go n.sendRaw(rawURL, rawURL, RenderTemplate(tmpl, event), event)
}

// RenderTemplate replaces {{TAG}} placeholders in a plain-text template,
// then wraps the result in Slack-compatible JSON: {"text":"..."}.
func RenderTemplate(tmpl string, event WebhookEvent) string {
	r := strings.NewReplacer(
		"{{RULE}}", event.Rule,
		"{{RULE_NAME}}", event.RuleName,
		"{{CATEGORY}}", event.Category,
		"{{MATCH}}", event.Match,
		"{{ACTION}}", event.Event,
		"{{SEVERITY}}", event.Severity,
		"{{FROM}}", event.From,
		"{{TO}}", event.To,
		"{{MESSAGE_ID}}", event.MessageID,
		"{{TIMESTAMP}}", event.Timestamp,
	)
	text := r.Replace(tmpl)
	payload, _ := json.Marshal(map[string]string{"text": text})
	return string(payload)
}

// DefaultWebhookTemplate is the plain-text default shown in the UI.
// RenderTemplate wraps it in Slack JSON automatically.
const DefaultWebhookTemplate = "\U0001f6a8 *{{RULE}}* \u2014 {{RULE_NAME}}\n\u2022 *Severity:* {{SEVERITY}} | *Category:* {{CATEGORY}}\n\u2022 *Agents:* {{FROM}} \u2192 {{TO}}\n\u2022 *Match:* `{{MATCH}}`\n\u2022 *Message:* {{MESSAGE_ID}}\n\u2022 *Time:* {{TIMESTAMP}}"

func (n *WebhookNotifier) shouldCooldown(event, agent string) bool {
	if n.cooldown <= 0 {
		return false
	}
	key := event + ":" + agent
	n.cooldownMu.Lock()
	defer n.cooldownMu.Unlock()

	// Evict stale entries to prevent unbounded growth
	if len(n.lastSent) > 1000 {
		cutoff := time.Now().Add(-n.cooldown)
		for k, v := range n.lastSent {
			if v.Before(cutoff) {
				delete(n.lastSent, k)
			}
		}
	}

	if last, ok := n.lastSent[key]; ok && time.Since(last) < n.cooldown {
		return true
	}
	n.lastSent[key] = time.Now()
	return false
}

func (n *WebhookNotifier) send(url, channel string, event WebhookEvent) {
	status := "sent"
	body, err := json.Marshal(event)
	if err != nil {
		n.logger.Error("webhook marshal failed", "error", err)
		n.logAlert(event, channel, "failed")
		return
	}

	resp, err := n.client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		n.logger.Warn("webhook delivery failed", "url", url, "error", err)
		n.logAlert(event, channel, "failed")
		return
	}
	_ = resp.Body.Close()

	if resp.StatusCode >= 400 {
		n.logger.Warn("webhook returned error", "url", url, "status", resp.StatusCode)
		status = "failed"
	}
	n.logAlert(event, channel, status)
}

func (n *WebhookNotifier) sendRaw(url, channel, body string, event WebhookEvent) {
	status := "sent"
	resp, err := n.client.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		n.logger.Warn("webhook delivery failed", "url", url, "error", err)
		n.logAlert(event, channel, "failed")
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 400 {
		n.logger.Warn("webhook returned error", "url", url, "status", resp.StatusCode)
		status = "failed"
	}
	n.logAlert(event, channel, status)
}

func (n *WebhookNotifier) logAlert(event WebhookEvent, channel, status string) {
	if n.onAlert != nil {
		n.onAlert(event, channel, status)
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
