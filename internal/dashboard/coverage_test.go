package dashboard

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
)

func authedGet(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	srv := newTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("GET", path, nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func authedPost(t *testing.T, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	srv := newTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func TestParseTriggeredRules_Empty(t *testing.T) {
	rules := parseTriggeredRules("")
	if rules != nil {
		t.Errorf("expected nil for empty input, got %v", rules)
	}
}

func TestParseTriggeredRules_JSONArray(t *testing.T) {
	input := `[{"rule_id":"IAP-001","name":"Relay Injection","severity":"high"}]`
	rules := parseTriggeredRules(input)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].RuleID != "IAP-001" {
		t.Errorf("rule_id = %q, want IAP-001", rules[0].RuleID)
	}
}

func TestParseTriggeredRules_CommaSeparated(t *testing.T) {
	rules := parseTriggeredRules("IAP-001,IAP-002")
	if len(rules) < 2 {
		t.Fatalf("expected at least 2 rules, got %d", len(rules))
	}
	if rules[0].RuleID != "IAP-001" {
		t.Errorf("first rule = %q, want IAP-001", rules[0].RuleID)
	}
}

func TestHumanReadableDecision(t *testing.T) {
	tests := map[string]string{
		"allow":               "Message delivered normally",
		"content_blocked":     "Blocked — dangerous content detected",
		"content_quarantined": "Held for review — suspicious content detected",
		"unknown_value":       "unknown_value",
	}
	for input, want := range tests {
		got := humanReadableDecision(input)
		if got != want {
			t.Errorf("humanReadableDecision(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNormalizeCustomRuleID(t *testing.T) {
	tests := []struct {
		ruleID string
		name   string
		want   string
	}{
		{"", "My Rule", "CUSTOM-MY-RULE"},
		{"", "test 123", "CUSTOM-TEST-123"},
		{"CUSTOM-EXISTING", "ignored", "CUSTOM-EXISTING"},
		{"raw-id", "ignored", "CUSTOM-RAW-ID"},
	}
	for _, tc := range tests {
		got := normalizeCustomRuleID(tc.ruleID, tc.name)
		if got != tc.want {
			t.Errorf("normalizeCustomRuleID(%q, %q) = %q, want %q", tc.ruleID, tc.name, got, tc.want)
		}
	}
}

func TestSplitNonEmpty(t *testing.T) {
	tests := []struct {
		s    string
		sep  string
		want int
	}{
		{"a\nb\nc", "\n", 3},
		{"\n\na\n\n", "\n", 1},
		{"", "\n", 0},
		{"  \n  \n  ", "\n", 0},
	}
	for _, tc := range tests {
		got := splitNonEmpty(tc.s, tc.sep)
		if len(got) != tc.want {
			t.Errorf("splitNonEmpty(%q) = %d items, want %d", tc.s, len(got), tc.want)
		}
	}
}

func TestBuildCustomRuleYAML(t *testing.T) {
	yaml := buildCustomRuleYAML("CUSTOM-TEST", "Test Rule", "high", "injection", []string{"pattern1", "pattern2"})
	if !strings.Contains(yaml, "CUSTOM-TEST") {
		t.Error("YAML should contain rule ID")
	}
	if !strings.Contains(yaml, "Test Rule") {
		t.Error("YAML should contain rule name")
	}
	if !strings.Contains(yaml, "pattern1") {
		t.Error("YAML should contain pattern")
	}
}

func TestDateOnly(t *testing.T) {
	tests := map[string]string{
		"2026-03-05T10:00:00Z": "2026-03-05",
		"2026-01-01":           "2026-01-01",
		"":                     "",
	}
	for input, want := range tests {
		got := dateOnly(input)
		if got != want {
			t.Errorf("dateOnly(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestParseSinceRange(t *testing.T) {
	ranges := []string{"1h", "6h", "24h", "7d", "30d", "invalid"}
	for _, r := range ranges {
		result := parseSinceRange(r)
		if result == "" {
			t.Errorf("parseSinceRange(%q) returned empty", r)
		}
		if !strings.Contains(result, "T") {
			t.Errorf("parseSinceRange(%q) = %q, not RFC3339", r, result)
		}
	}
}

func TestParseExportLimit(t *testing.T) {
	tests := []struct {
		query string
		want  int
	}{
		{"", 10000},
		{"limit=100", 100},
		{"limit=0", 10000},
		{"limit=-5", 10000},
		{"limit=abc", 10000},
		{"limit=999999", 50000},
	}
	for _, tc := range tests {
		req := httptest.NewRequest("GET", "/export?"+tc.query, nil)
		got := parseExportLimit(req)
		if got != tc.want {
			t.Errorf("parseExportLimit(%q) = %d, want %d", tc.query, got, tc.want)
		}
	}
}

func TestCountInSet(t *testing.T) {
	set := map[string]bool{"a": true, "b": true, "c": true}
	tests := []struct {
		ids  []string
		want int
	}{
		{[]string{"a", "b"}, 2},
		{[]string{"a", "d"}, 1},
		{[]string{"d", "e"}, 0},
		{nil, 0},
	}
	for _, tc := range tests {
		got := countInSet(tc.ids, set)
		if got != tc.want {
			t.Errorf("countInSet(%v) = %d, want %d", tc.ids, got, tc.want)
		}
	}
}

func TestServer_RulesPageLoads(t *testing.T) {
	rr := authedGet(t, "/dashboard/rules")
	if rr.Code != http.StatusOK {
		t.Errorf("rules page status = %d, want 200", rr.Code)
	}
}

func TestServer_AgentsPageLoads(t *testing.T) {
	rr := authedGet(t, "/dashboard/agents")
	if rr.Code != http.StatusOK {
		t.Errorf("agents page status = %d, want 200", rr.Code)
	}
}

func TestServer_GraphPageLoads(t *testing.T) {
	rr := authedGet(t, "/dashboard/graph")
	if rr.Code != http.StatusOK {
		t.Errorf("graph page status = %d, want 200", rr.Code)
	}
}

func TestServer_EventsPageLoads(t *testing.T) {
	rr := authedGet(t, "/dashboard/events")
	if rr.Code != http.StatusOK {
		t.Errorf("events page status = %d, want 200", rr.Code)
	}
}

func TestServer_ToolInventoryPageLoads(t *testing.T) {
	// Discovery now redirects to gateway tab
	rr := authedGet(t, "/dashboard/discovery")
	if rr.Code != http.StatusFound {
		t.Errorf("discovery redirect status = %d, want 302", rr.Code)
	}
	// Verify discovery content in gateway
	rr2 := authedGet(t, "/dashboard/gateway?tab=discovery")
	if rr2.Code != http.StatusOK {
		t.Errorf("gateway discovery tab status = %d, want 200", rr2.Code)
	}
}

func TestServer_GatewayPageLoads(t *testing.T) {
	rr := authedGet(t, "/dashboard/gateway")
	if rr.Code != http.StatusOK {
		t.Errorf("gateway page status = %d, want 200", rr.Code)
	}
}

func TestServer_EnforcementPageLoads(t *testing.T) {
	rr := authedGet(t, "/dashboard/rules/enforcement")
	if rr.Code != http.StatusOK {
		t.Errorf("enforcement page status = %d, want 200", rr.Code)
	}
}

func TestServer_CustomRulesPageLoads(t *testing.T) {
	rr := authedGet(t, "/dashboard/rules/custom")
	if rr.Code != http.StatusOK {
		t.Errorf("custom rules page status = %d, want 200", rr.Code)
	}
}

func TestServer_ExportCSV(t *testing.T) {
	rr := authedGet(t, "/dashboard/api/export/csv")
	if rr.Code != http.StatusOK {
		t.Errorf("export CSV status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/csv") {
		t.Errorf("Content-Type = %q, want text/csv", ct)
	}
}

func TestServer_ExportJSON(t *testing.T) {
	rr := authedGet(t, "/dashboard/api/export/json")
	if rr.Code != http.StatusOK {
		t.Errorf("export JSON status = %d, want 200", rr.Code)
	}
}

func TestServer_NotFoundPage(t *testing.T) {
	rr := authedGet(t, "/dashboard/nonexistent-path")
	if rr.Code != http.StatusNotFound {
		t.Errorf("non-existent page status = %d, want 404", rr.Code)
	}
}

func TestServer_RuleDetailEndpoint(t *testing.T) {
	rr := authedGet(t, "/dashboard/api/rule/IAP-001")
	if rr.Code != http.StatusOK {
		t.Errorf("rule detail status = %d, want 200", rr.Code)
	}
}

func TestServer_RuleDetailNotFound(t *testing.T) {
	rr := authedGet(t, "/dashboard/api/rule/NONEXISTENT-999")
	if rr.Code != http.StatusNotFound {
		t.Errorf("missing rule detail status = %d, want 404", rr.Code)
	}
}

func TestServer_AgentDetailPage(t *testing.T) {
	rr := authedGet(t, "/dashboard/agents/test-agent")
	if rr.Code != http.StatusOK {
		t.Errorf("agent detail status = %d, want 200", rr.Code)
	}
}

func TestServer_AgentDetailNotFound(t *testing.T) {
	rr := authedGet(t, "/dashboard/agents/nonexistent-agent")
	// Should still return 200 with empty data or 404
	if rr.Code != http.StatusOK && rr.Code != http.StatusNotFound {
		t.Errorf("agent detail for unknown agent status = %d", rr.Code)
	}
}

func TestServer_APIStatsEndpoint(t *testing.T) {
	rr := authedGet(t, "/dashboard/api/stats")
	if rr.Code != http.StatusOK {
		t.Errorf("api stats status = %d, want 200", rr.Code)
	}
}

func TestServer_APIRecentEndpoint(t *testing.T) {
	rr := authedGet(t, "/dashboard/api/recent")
	if rr.Code != http.StatusOK {
		t.Errorf("api recent status = %d, want 200", rr.Code)
	}
}

func TestServer_AuditSandboxPage(t *testing.T) {
	rr := authedGet(t, "/dashboard/audit/sandbox")
	if rr.Code != http.StatusOK {
		t.Errorf("audit sandbox status = %d, want 200", rr.Code)
	}
}

func TestServer_LogoutRedirects(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("POST", "/dashboard/logout", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound && rr.Code != http.StatusSeeOther {
		t.Errorf("logout status = %d, want redirect", rr.Code)
	}
}

func TestServer_SuspendToggle(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("POST", "/dashboard/agents/test-agent/suspend", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should either redirect or return success
	if rr.Code != http.StatusOK && rr.Code != http.StatusFound && rr.Code != http.StatusSeeOther {
		t.Errorf("suspend toggle status = %d", rr.Code)
	}
}

func TestServer_GraphRanges(t *testing.T) {
	for _, r := range []string{"1h", "6h", "24h", "7d", "30d"} {
		rr := authedGet(t, "/dashboard/graph?range="+r)
		if rr.Code != http.StatusOK {
			t.Errorf("graph range=%s status = %d, want 200", r, rr.Code)
		}
	}
}

func TestServer_ToggleRule(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("POST", "/dashboard/api/rule/IAP-001/toggle", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK && rr.Code != http.StatusFound {
		t.Errorf("toggle rule status = %d", rr.Code)
	}
}

func TestServer_ToggleCategory(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("POST", "/dashboard/api/category/inter-agent/toggle", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK && rr.Code != http.StatusFound {
		t.Errorf("toggle category status = %d", rr.Code)
	}
}

func TestServer_GatewayHealthCheck(t *testing.T) {
	rr := authedGet(t, "/dashboard/gateway/health")
	// Should return status (may fail if no gateway is running, but shouldn't panic)
	if rr.Code == 0 {
		t.Error("gateway health should return a status code")
	}
}

func TestServer_ExportCSVWithAgent(t *testing.T) {
	rr := authedGet(t, "/dashboard/api/export/csv?agent=test-agent&limit=10")
	if rr.Code != http.StatusOK {
		t.Errorf("export CSV with agent status = %d, want 200", rr.Code)
	}
}

func TestServer_ExportJSONWithLimit(t *testing.T) {
	rr := authedGet(t, "/dashboard/api/export/json?limit=5")
	if rr.Code != http.StatusOK {
		t.Errorf("export JSON with limit status = %d, want 200", rr.Code)
	}
}

// --- LLM page tests ---

func TestServer_LLMPageLoads(t *testing.T) {
	rr := authedGet(t, "/dashboard/llm")
	if rr.Code != http.StatusOK {
		t.Errorf("llm page status = %d, want 200", rr.Code)
	}
}

func TestServer_LLMPageShowsSetupWhenDisabled(t *testing.T) {
	// LLM is disabled by default in test config
	rr := authedGet(t, "/dashboard/llm")
	if rr.Code != http.StatusOK {
		t.Fatalf("llm page status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Enable AI") {
		t.Error("expected setup state with 'Enable AI Analysis' button")
	}
}

func TestServer_LLMPageShowsActiveWhenEnabled(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.LLM.Enabled = true
	srv.cfg.LLM.Provider = "openai"
	srv.cfg.LLM.Model = "test-model"

	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("GET", "/dashboard/llm", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("llm page status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Save Configuration") {
		t.Error("expected active state with 'Save Configuration' button")
	}
	if !strings.Contains(body, "test-model") {
		t.Error("expected model name in active state")
	}
}

func TestServer_LLMSaveConfig(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	form := url.Values{
		"enabled":        {"true"},
		"provider":       {"openai"},
		"model":          {"gpt-4o"},
		"base_url":       {"http://localhost:11434/v1"},
		"api_key_env":    {""},
		"max_tokens":     {"1024"},
		"temperature":    {"0.0"},
		"max_concurrent": {"3"},
		"queue_size":     {"100"},
		"max_daily":      {"0"},
	}
	req := httptest.NewRequest("POST", "/dashboard/settings/llm", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound && rr.Code != http.StatusSeeOther {
		t.Errorf("save llm status = %d, want redirect", rr.Code)
	}
	if srv.cfg.LLM.Provider != "openai" {
		t.Errorf("provider = %q, want openai", srv.cfg.LLM.Provider)
	}
	if srv.cfg.LLM.Model != "gpt-4o" {
		t.Errorf("model = %q, want gpt-4o", srv.cfg.LLM.Model)
	}
}

func TestServer_LLMSaveRejectsInvalidProvider(t *testing.T) {
	form := url.Values{
		"enabled":  {"true"},
		"provider": {"invalid"},
		"model":    {"test"},
	}
	rr := authedPost(t, "/dashboard/settings/llm", form)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid provider status = %d, want 400", rr.Code)
	}
}

func TestServer_LLMCaseNotFound(t *testing.T) {
	rr := authedGet(t, "/dashboard/llm/case/nonexistent-id")
	if rr.Code != http.StatusNotFound {
		t.Errorf("missing case status = %d, want 404", rr.Code)
	}
}

func TestServer_LLMDetailAPINotFound(t *testing.T) {
	rr := authedGet(t, "/dashboard/api/llm/nonexistent-id")
	if rr.Code != http.StatusNotFound {
		t.Errorf("missing detail status = %d, want 404", rr.Code)
	}
}

func TestServer_Alerts(t *testing.T) {
	rr := authedGet(t, "/dashboard/alerts")
	if rr.Code != http.StatusOK {
		t.Errorf("alerts status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Alert History") {
		t.Error("alerts page missing history section")
	}
	if !strings.Contains(body, "Alert Configuration") {
		t.Error("alerts page missing config section")
	}
	if !strings.Contains(body, "Total Alerts") {
		t.Error("alerts page missing stats")
	}
}

func TestServer_Report(t *testing.T) {
	rr := authedGet(t, "/dashboard/report")
	if rr.Code != http.StatusOK {
		t.Errorf("report status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Security Posture Report") {
		t.Error("report page missing title")
	}
	if !strings.Contains(body, "Traffic Summary") {
		t.Error("report page missing traffic summary section")
	}
	if !strings.Contains(body, "Pipeline Configuration") {
		t.Error("report page missing pipeline config section")
	}
}

func TestServer_ExportSARIF(t *testing.T) {
	rr := authedGet(t, "/dashboard/api/export/sarif")
	if rr.Code != http.StatusOK {
		t.Errorf("SARIF export status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "sarif-schema-2.1.0") {
		t.Error("SARIF output missing schema reference")
	}
	if !strings.Contains(body, `"version": "2.1.0"`) {
		t.Error("SARIF output missing version")
	}
	if !strings.Contains(body, `"name": "oktsec"`) {
		t.Error("SARIF output missing tool name")
	}
}

func TestMaskWebhookURL(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantHost  string
		forbidden []string
	}{
		{
			name:      "slack-like webhook",
			input:     "https://hooks.example.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
			wantHost:  "hooks.example.com",
			forbidden: []string{"/services/T00000000", "B00000000", "XXXXXXXXXXXXXXXXXXXX"},
		},
		{
			name:      "discord webhook",
			input:     "https://discord.com/api/webhooks/123456789/abcdefghijklmnop",
			wantHost:  "discord.com",
			forbidden: []string{"/api/webhooks/123456789/abcdefghijklmno"},
		},
		{
			name:      "no path returns unchanged",
			input:     "https://example.com",
			wantHost:  "example.com",
			forbidden: nil,
		},
		{
			name:      "no scheme long string",
			input:     "not-a-url-but-long-enough",
			wantHost:  "",
			forbidden: []string{"not-a-url-but-long-enough"},
		},
		{
			name:      "no scheme short string",
			input:     "short",
			wantHost:  "",
			forbidden: []string{"short"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := maskWebhookURL(tt.input)
			if tt.wantHost != "" && !strings.Contains(got, tt.wantHost) {
				t.Errorf("maskWebhookURL(%q) = %q, missing host %q", tt.input, got, tt.wantHost)
			}
			for _, f := range tt.forbidden {
				if strings.Contains(got, f) {
					t.Errorf("maskWebhookURL(%q) = %q, must not contain secret segment %q", tt.input, got, f)
				}
			}
			if got == tt.input && tt.forbidden != nil {
				t.Errorf("maskWebhookURL(%q) returned input unchanged, secret is exposed", tt.input)
			}
		})
	}
}

func TestServer_AlertsPageMasksWebhookURLs(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.Webhooks = []config.Webhook{
		{Name: "slack-sec", URL: "https://hooks.example.com/services/T1234/B5678/xyzSECRETtokenABCD"},
	}
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("GET", "/dashboard/alerts", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("alerts status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if strings.Contains(body, "/services/T1234/B5678/xyzSECRETtokenABCD") {
		t.Error("alerts page exposes full webhook URL in DOM")
	}
	if !strings.Contains(body, "hooks.example.com") {
		t.Error("alerts page should show webhook host")
	}
}

func TestServer_ModalClosedNotInteractive(t *testing.T) {
	rr := authedGet(t, "/dashboard")
	if rr.Code != http.StatusOK {
		t.Fatalf("overview status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `setAttribute('aria-hidden','true')`) {
		t.Error("modal JS missing aria-hidden initialization")
	}
	if !strings.Contains(body, `role="dialog"`) {
		t.Error("modal missing role=\"dialog\"")
	}
	if !strings.Contains(body, `aria-modal="true"`) {
		t.Error("modal missing aria-modal=\"true\"")
	}
	if !strings.Contains(body, "overlay.hidden=true") {
		t.Error("modal JS missing hidden initialization")
	}
	if !strings.Contains(body, "overlay.inert=true") {
		t.Error("modal JS missing inert initialization")
	}
}

func TestServer_ModalCSSHidesFromAccessibilityTree(t *testing.T) {
	rr := authedGet(t, "/dashboard/static/dashboard.css")
	if rr.Code != http.StatusOK {
		t.Fatalf("CSS status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "visibility:hidden") {
		t.Error("modal-overlay CSS missing visibility:hidden for closed state")
	}
	if !strings.Contains(body, "visibility:visible") {
		t.Error("modal-overlay.open CSS missing visibility:visible")
	}
}

func TestServer_GraphPageHasContainer(t *testing.T) {
	rr := authedGet(t, "/dashboard/graph")
	if rr.Code != http.StatusOK {
		t.Fatalf("graph status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `id="graph-container"`) {
		t.Error("graph page missing #graph-container element")
	}
	if !strings.Contains(body, "renderGraph") {
		t.Error("graph page missing renderGraph function")
	}
	if !strings.Contains(body, `cache:'no-store'`) {
		t.Error("graph fetch missing cache:'no-store' option")
	}
}

func TestServer_BuildInfoInSidebar(t *testing.T) {
	Version = "v0.8.1-test"
	Commit = "abc1234"
	defer func() { Version = "dev"; Commit = "" }()

	rr := authedGet(t, "/dashboard")
	if rr.Code != http.StatusOK {
		t.Fatalf("overview status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "v0.8.1-test") {
		t.Error("sidebar missing version string")
	}
	if !strings.Contains(body, "abc1234") {
		t.Error("sidebar missing commit hash")
	}
}

func TestServer_SessionsAvgDuration(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	now := time.Now().UTC()
	// Session 1: 2 events spanning 5 minutes
	srv.audit.Log(audit.Entry{
		ID: "s1-e1", Timestamp: now.Add(-10 * time.Minute).Format(time.RFC3339),
		FromAgent: "agent-a", ToAgent: "agent-b", SessionID: "sess-1",
		Status: "delivered", LatencyMs: 2,
	})
	srv.audit.Log(audit.Entry{
		ID: "s1-e2", Timestamp: now.Add(-5 * time.Minute).Format(time.RFC3339),
		FromAgent: "agent-a", ToAgent: "agent-b", SessionID: "sess-1",
		Status: "delivered", LatencyMs: 3,
	})
	// Session 2: 2 events spanning 3 minutes
	srv.audit.Log(audit.Entry{
		ID: "s2-e1", Timestamp: now.Add(-8 * time.Minute).Format(time.RFC3339),
		FromAgent: "agent-c", ToAgent: "agent-d", SessionID: "sess-2",
		Status: "delivered", LatencyMs: 1,
	})
	srv.audit.Log(audit.Entry{
		ID: "s2-e2", Timestamp: now.Add(-5 * time.Minute).Format(time.RFC3339),
		FromAgent: "agent-c", ToAgent: "agent-d", SessionID: "sess-2",
		Status: "delivered", LatencyMs: 1,
	})
	srv.audit.Flush()

	req := httptest.NewRequest("GET", "/dashboard/sessions?range=24h", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("sessions page returned %d", rr.Code)
	}
	body := rr.Body.String()

	// Avg of 5m and 3m = 4m. Should NOT be "0s".
	if strings.Contains(body, "Avg duration: 0s") || strings.Contains(body, "Avg duration: -") {
		t.Error("avg duration should not be 0s or - with real sessions")
	}
	if !strings.Contains(body, "4m") {
		t.Errorf("expected avg duration ~4m in body, got page without it")
	}
}

func TestServer_OverviewAgentsObserved(t *testing.T) {
	rr := authedGet(t, "/dashboard")
	if rr.Code != http.StatusOK {
		t.Fatalf("overview returned %d", rr.Code)
	}
	body := rr.Body.String()
	if strings.Contains(body, "Agents Secured") {
		t.Error("overview should use 'Agents Observed' not 'Agents Secured'")
	}
	if !strings.Contains(body, "Agents Observed") {
		t.Error("overview missing 'Agents Observed' label")
	}
	if !strings.Contains(body, "All time") {
		t.Error("overview missing 'All time' temporal label")
	}
}

func TestServer_SettingsTimingLabels(t *testing.T) {
	rr := authedGet(t, "/dashboard/settings")
	if rr.Code != http.StatusOK {
		t.Fatalf("settings returned %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Takes effect immediately") {
		t.Error("settings missing 'Takes effect immediately' label")
	}
	if !strings.Contains(body, "Requires restart") {
		t.Error("settings missing 'Requires restart' label")
	}
}

func TestServer_GatewayDisabledBanner(t *testing.T) {
	rr := authedGet(t, "/dashboard/gateway")
	if rr.Code != http.StatusOK {
		t.Fatalf("gateway returned %d", rr.Code)
	}
	body := rr.Body.String()
	if strings.Contains(body, "Listening on") {
		t.Error("gateway disabled should not show 'Listening on'")
	}
	if !strings.Contains(body, "Configured Port") {
		t.Error("gateway disabled should show 'Configured Port'")
	}
	if !strings.Contains(body, "configured but not routing") {
		t.Error("gateway disabled should explain it's not routing traffic")
	}
}

func TestServer_AgentsRiskLabels(t *testing.T) {
	rr := authedGet(t, "/dashboard/agents")
	if rr.Code != http.StatusOK {
		t.Fatalf("agents returned %d", rr.Code)
	}
	body := rr.Body.String()
	if strings.Contains(body, "blocked ") && strings.Contains(body, " · risk ") {
		t.Error("agents should not use ambiguous 'blocked X% · risk N' format")
	}
}

func TestServer_EventsPageHeaderCopy(t *testing.T) {
	rr := authedGet(t, "/dashboard/events")
	if rr.Code != http.StatusOK {
		t.Fatalf("events returned %d", rr.Code)
	}
	body := rr.Body.String()
	if strings.Contains(body, "All intercepted messages") {
		t.Error("events page should use updated header copy, not 'All intercepted messages'")
	}
	if !strings.Contains(body, "Security events from the pipeline") {
		t.Error("events page should contain 'Security events from the pipeline'")
	}
}

func TestServer_EventsInspectButton(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	srv.audit.Log(audit.Entry{
		ID:        "inspect-test-1",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		FromAgent: "agent-a",
		ToAgent:   "agent-b",
		Status:    "delivered",
	})
	time.Sleep(100 * time.Millisecond)

	req := httptest.NewRequest("GET", "/dashboard/events", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("events returned %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Inspect</a>") {
		t.Error("events page should have Inspect button per row")
	}
}

func TestServer_EventsRedactionHint(t *testing.T) {
	rr := authedGet(t, "/dashboard/events")
	if rr.Code != http.StatusOK {
		t.Fatalf("events returned %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "redaction-hint") {
		t.Error("events page should have redaction hint element")
	}
	if !strings.Contains(body, "Rule match snippets are replaced with [REDACTED]") {
		t.Error("events page should explain analyst redaction level")
	}
}

func TestServer_ExportCSVExternalRedaction(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	srv.audit.Log(audit.Entry{
		ID:             "redact-ext-1",
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		FromAgent:      "agent-secret",
		ToAgent:        "agent-target",
		Status:         "blocked",
		RulesTriggered: `[{"rule_id":"IAP-001","name":"Relay","severity":"high","match":"secret payload"}]`,
		PolicyDecision: "content_blocked",
		LatencyMs:      50,
		Intent:         "sensitive content here",
	})
	time.Sleep(100 * time.Millisecond)

	req := httptest.NewRequest("GET", "/dashboard/api/export/csv?redaction=external", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("export CSV external status = %d", rr.Code)
	}
	body := rr.Body.String()
	if strings.Contains(body, "secret payload") {
		t.Error("external redaction must not include rule match snippets")
	}
	if strings.Contains(body, "sensitive content here") {
		t.Error("external redaction must not include intent/content")
	}
	if strings.Contains(body, "latency") || strings.Contains(body, "rules_triggered") {
		t.Error("external redaction CSV header must not include latency or rules_triggered columns")
	}
	if !strings.Contains(body, "agent-secret") {
		t.Error("external redaction should still include agent names")
	}
}

func TestServer_ExportCSVAnalystRedaction(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	srv.audit.Log(audit.Entry{
		ID:             "redact-analyst-1",
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		FromAgent:      "agent-x",
		ToAgent:        "agent-y",
		Status:         "blocked",
		RulesTriggered: `[{"rule_id":"IAP-002","name":"Exfil","severity":"high","match":"credentials leaked"}]`,
		PolicyDecision: "content_blocked",
		LatencyMs:      30,
	})
	time.Sleep(100 * time.Millisecond)

	req := httptest.NewRequest("GET", "/dashboard/api/export/csv?redaction=analyst", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("export CSV analyst status = %d", rr.Code)
	}
	body := rr.Body.String()
	if strings.Contains(body, "credentials leaked") {
		t.Error("analyst redaction must redact match content from rules")
	}
	if !strings.Contains(body, "[REDACTED]") {
		t.Error("analyst redaction should contain [REDACTED] placeholder")
	}
	if !strings.Contains(body, "IAP-002") {
		t.Error("analyst redaction should preserve rule IDs")
	}
}

func TestServer_ExportJSONExternalRedaction(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	srv.audit.Log(audit.Entry{
		ID:             "redact-json-1",
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		FromAgent:      "agent-j",
		ToAgent:        "agent-k",
		Status:         "blocked",
		RulesTriggered: `[{"rule_id":"IAP-003","match":"secret data"}]`,
		PolicyDecision: "content_blocked",
		LatencyMs:      25,
		Intent:         "private content",
	})
	time.Sleep(100 * time.Millisecond)

	req := httptest.NewRequest("GET", "/dashboard/api/export/json?redaction=external", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("export JSON external status = %d", rr.Code)
	}
	body := rr.Body.String()
	if strings.Contains(body, "secret data") {
		t.Error("external JSON must not include rule match content")
	}
	if strings.Contains(body, "private content") {
		t.Error("external JSON must not include intent content")
	}
	if strings.Contains(body, "latency_ms") {
		t.Error("external JSON must not include latency_ms field")
	}
	if !strings.Contains(body, "content_blocked") {
		t.Error("external JSON should still include policy_decision")
	}
}
