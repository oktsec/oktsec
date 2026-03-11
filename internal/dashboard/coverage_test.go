package dashboard

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
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
