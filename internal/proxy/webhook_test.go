package proxy

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
)

func TestRenderTemplate_PlainTextToSlackJSON(t *testing.T) {
	event := WebhookEvent{
		Event:     "rule_triggered",
		MessageID: "msg-123",
		From:      "agent-a",
		To:        "agent-b",
		Severity:  "critical",
		Rule:      "CRED_001",
		Timestamp: "2026-02-24T10:00:00Z",
	}

	tmpl := "Rule *{{RULE}}* triggered\n• Action: {{ACTION}}\n• Severity: {{SEVERITY}}\n• From: {{FROM}} → {{TO}}"
	result := RenderTemplate(tmpl, event)

	// Should be valid JSON
	var payload map[string]string
	if err := json.Unmarshal([]byte(result), &payload); err != nil {
		t.Fatalf("RenderTemplate output is not valid JSON: %v\nOutput: %s", err, result)
	}

	text, ok := payload["text"]
	if !ok {
		t.Fatal("JSON payload missing 'text' field")
	}

	// Verify tags were replaced
	if want := "Rule *CRED_001* triggered"; !contains(text, want) {
		t.Errorf("text missing rule: %s", text)
	}
	if want := "Action: rule_triggered"; !contains(text, want) {
		t.Errorf("text missing action: %s", text)
	}
	if want := "Severity: critical"; !contains(text, want) {
		t.Errorf("text missing severity: %s", text)
	}
	if want := "From: agent-a → agent-b"; !contains(text, want) {
		t.Errorf("text missing from/to: %s", text)
	}
}

func TestRenderTemplate_AllTags(t *testing.T) {
	event := WebhookEvent{
		Event:     "blocked",
		MessageID: "msg-456",
		From:      "sender",
		To:        "receiver",
		Severity:  "high",
		Rule:      "PI-002",
		Timestamp: "2026-02-24T12:00:00Z",
	}

	tmpl := "{{RULE}} {{ACTION}} {{SEVERITY}} {{FROM}} {{TO}} {{MESSAGE_ID}} {{TIMESTAMP}}"
	result := RenderTemplate(tmpl, event)

	var payload map[string]string
	if err := json.Unmarshal([]byte(result), &payload); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}

	text := payload["text"]
	expected := "PI-002 blocked high sender receiver msg-456 2026-02-24T12:00:00Z"
	if text != expected {
		t.Errorf("text = %q, want %q", text, expected)
	}
}

func TestRenderTemplate_EmptyTemplate(t *testing.T) {
	event := WebhookEvent{Rule: "X"}
	result := RenderTemplate("", event)

	var payload map[string]string
	if err := json.Unmarshal([]byte(result), &payload); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if payload["text"] != "" {
		t.Errorf("expected empty text, got %q", payload["text"])
	}
}

func TestNotifyTemplated_SendsSlackJSON(t *testing.T) {
	var receivedBody string
	var receivedContentType string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		receivedBody = string(b)
		w.WriteHeader(200)
	}))
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	notifier := NewWebhookNotifier(nil, logger)

	event := WebhookEvent{
		Event:    "rule_triggered",
		Rule:     "TEST-001",
		Severity: "high",
		From:     "a",
		To:       "b",
	}

	// Call synchronously for testing (bypass goroutine)
	rendered := RenderTemplate("Alert: {{RULE}} fired ({{SEVERITY}})", event)
	notifier.sendRaw(ts.URL, rendered)

	if receivedContentType != "application/json" {
		t.Errorf("content-type = %q, want application/json", receivedContentType)
	}

	var payload map[string]string
	if err := json.Unmarshal([]byte(receivedBody), &payload); err != nil {
		t.Fatalf("server received invalid JSON: %v\nBody: %s", err, receivedBody)
	}
	if want := "Alert: TEST-001 fired (high)"; payload["text"] != want {
		t.Errorf("payload text = %q, want %q", payload["text"], want)
	}
}

func TestNotifyTemplated_EmptyFallsBackToJSON(t *testing.T) {
	var receivedBody string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		receivedBody = string(b)
		w.WriteHeader(200)
	}))
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	notifier := NewWebhookNotifier(nil, logger)

	event := WebhookEvent{
		Event: "rule_triggered",
		Rule:  "X",
		From:  "a",
		To:    "b",
	}

	// Empty template — should send default JSON struct
	notifier.send(ts.URL, event)

	var payload WebhookEvent
	if err := json.Unmarshal([]byte(receivedBody), &payload); err != nil {
		t.Fatalf("server received invalid JSON: %v", err)
	}
	if payload.Rule != "X" {
		t.Errorf("rule = %q, want X", payload.Rule)
	}
}

func TestValidateWebhookURL(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
	}{
		{"https://hooks.slack.com/services/T00/B00/xxx", false},
		{"http://example.com/webhook", false},
		{"ftp://example.com/file", true},
		{"https://127.0.0.1/webhook", true},
		{"https://10.0.0.1/webhook", true},
		{"https://192.168.1.1/webhook", true},
		{"not-a-url", true},
	}

	for _, tc := range tests {
		err := validateWebhookURL(tc.url)
		if (err != nil) != tc.wantErr {
			t.Errorf("validateWebhookURL(%q) err=%v, wantErr=%v", tc.url, err, tc.wantErr)
		}
	}
}

func TestNewWebhookNotifier_SkipsInvalidURLs(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	webhooks := []config.Webhook{
		{URL: "https://valid.example.com/hook", Events: []string{"blocked"}},
		{URL: "https://127.0.0.1/bad", Events: []string{"blocked"}},
		{URL: "https://also-valid.example.com/hook", Events: []string{"quarantined"}},
	}

	n := NewWebhookNotifier(webhooks, logger)
	if len(n.webhooks) != 2 {
		t.Errorf("expected 2 valid webhooks, got %d", len(n.webhooks))
	}
}

func TestMatchesEvent(t *testing.T) {
	tests := []struct {
		configured []string
		event      string
		want       bool
	}{
		{nil, "message_blocked", true},          // no filter = all
		{[]string{"blocked"}, "blocked", true},  // exact match
		{[]string{"blocked"}, "message_blocked", true}, // prefix match
		{[]string{"quarantined"}, "blocked", false},
	}
	for _, tc := range tests {
		got := matchesEvent(tc.configured, tc.event)
		if got != tc.want {
			t.Errorf("matchesEvent(%v, %q) = %v, want %v", tc.configured, tc.event, got, tc.want)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
