package proxy

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
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
		RuleName:  "Prompt Injection",
		Category:  "injection",
		Match:     "ignore previous instructions",
		Timestamp: "2026-02-24T12:00:00Z",
	}

	tmpl := "{{RULE}} {{RULE_NAME}} {{CATEGORY}} {{MATCH}} {{ACTION}} {{SEVERITY}} {{FROM}} {{TO}} {{MESSAGE_ID}} {{TIMESTAMP}}"
	result := RenderTemplate(tmpl, event)

	var payload map[string]string
	if err := json.Unmarshal([]byte(result), &payload); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}

	text := payload["text"]
	expected := "PI-002 Prompt Injection injection ignore previous instructions blocked high sender receiver msg-456 2026-02-24T12:00:00Z"
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
	notifier.client = ts.Client() // use test server client (bypasses safeDialContext for localhost)

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
	notifier.client = ts.Client() // use test server client (bypasses safeDialContext for localhost)

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
		desc    string
	}{
		// Valid
		{"https://hooks.slack.com/services/T00/B00/xxx", false, "valid slack webhook"},
		{"http://example.com/webhook", false, "valid http webhook"},

		// Scheme
		{"ftp://example.com/file", true, "non-http scheme"},
		{"not-a-url", true, "invalid URL"},

		// Standard private/loopback
		{"https://127.0.0.1/webhook", true, "loopback IPv4"},
		{"https://10.0.0.1/webhook", true, "private 10.x"},
		{"https://192.168.1.1/webhook", true, "private 192.168.x"},
		{"https://172.16.0.1/webhook", true, "private 172.16.x"},

		// Extended special-use ranges (RFC 5737, 2544)
		{"https://192.0.2.1/webhook", true, "TEST-NET-1"},
		{"https://198.51.100.1/webhook", true, "TEST-NET-2"},
		{"https://203.0.113.1/webhook", true, "TEST-NET-3"},
		{"https://198.18.0.1/webhook", true, "benchmarking range"},
		{"https://100.64.0.1/webhook", true, "CGN shared address"},
		{"https://224.0.0.1/webhook", true, "multicast"},
		{"https://240.0.0.1/webhook", true, "reserved"},

		// IPv6 blocked ranges
		{"https://[::1]/webhook", true, "IPv6 loopback"},
		{"https://[fc00::1]/webhook", true, "IPv6 unique local"},
		{"https://[fe80::1]/webhook", true, "IPv6 link-local"},
		{"https://[2001:db8::1]/webhook", true, "IPv6 documentation"},

		// IPv6 transition addresses (embed private IPv4)
		{"https://[2002:0a00:0001::]/webhook", true, "6to4 embedding 10.0.0.1"},
		{"https://[64:ff9b::10.0.0.1]/webhook", true, "NAT64 embedding 10.0.0.1"},
		{"https://[2001::1]/webhook", true, "Teredo prefix"},

		// Alternative IP encodings
		{"https://0x7f000001/webhook", true, "hex packed IP"},
		{"https://0xA9FEA9FE/webhook", true, "hex cloud metadata"},
		{"https://0x7f.0x00.0x00.0x01/webhook", true, "hex dot-separated"},
		{"https://0177.0.0.1/webhook", true, "octal IP"},
		{"https://0177.0000.0000.0001/webhook", true, "full octal IP"},
		{"https://2130706433/webhook", true, "packed decimal IP"},
	}

	for _, tc := range tests {
		err := validateWebhookURL(tc.url)
		if (err != nil) != tc.wantErr {
			t.Errorf("validateWebhookURL(%q) [%s] err=%v, wantErr=%v", tc.url, tc.desc, err, tc.wantErr)
		}
	}
}

func TestIsBlockedIP(t *testing.T) {
	tests := []struct {
		ip      string
		blocked bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"192.168.1.1", true},
		{"172.16.0.1", true},
		{"169.254.169.254", true},      // cloud metadata
		{"192.0.2.1", true},            // TEST-NET-1
		{"198.18.0.1", true},           // benchmarking
		{"100.64.0.1", true},           // CGN
		{"8.8.8.8", false},             // Google DNS
		{"1.1.1.1", false},             // Cloudflare
		{"::1", true},                  // IPv6 loopback
		{"fc00::1", true},              // IPv6 ULA
		{"2001:db8::1", true},          // IPv6 documentation
		{"2607:f8b0:4004:800::200e", false}, // Google IPv6
		{"ff02::1", true},                   // IPv6 multicast all-nodes
		{"ff05::1", true},                   // IPv6 multicast site-local
	}
	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("failed to parse IP %q", tc.ip)
		}
		got := isBlockedIP(ip)
		if got != tc.blocked {
			t.Errorf("isBlockedIP(%s) = %v, want %v", tc.ip, got, tc.blocked)
		}
	}
}

func TestLooksLikeAlternativeIP(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"0x7f000001", true},           // hex packed
		{"0xA9FEA9FE", true},           // hex packed
		{"0x7f.0x00.0x00.0x01", true},  // hex octets
		{"0177.0.0.1", true},           // octal
		{"2130706433", true},           // packed decimal
		{"example.com", false},         // normal hostname
		{"hooks.slack.com", false},     // normal hostname
		{"192.168.1.1", false},         // standard dotted decimal (caught by ParseIP)
	}
	for _, tc := range tests {
		got := looksLikeAlternativeIP(tc.host)
		if got != tc.want {
			t.Errorf("looksLikeAlternativeIP(%q) = %v, want %v", tc.host, got, tc.want)
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
