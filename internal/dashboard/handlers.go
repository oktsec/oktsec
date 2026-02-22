package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/identity"
)

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginTmpl.Execute(w, nil)
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)

	// Check rate limit before processing
	allowed, retryAfter := s.auth.CheckRateLimit(ip)
	if !allowed {
		s.logger.Warn("login rate-limited",
			"ip", ip,
			"retry_after", retryAfter.Round(time.Second).String(),
		)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		msg := fmt.Sprintf("Too many failed attempts. Try again in %d minutes.", int(retryAfter.Minutes())+1)
		_ = loginTmpl.Execute(w, map[string]any{"Error": msg})
		return
	}

	code := r.FormValue("code")
	if !s.auth.ValidateCode(code) {
		lockout := s.auth.RecordFailure(ip)
		if lockout > 0 {
			s.logger.Warn("login lockout triggered",
				"ip", ip,
				"lockout_duration", lockout.String(),
			)
		} else {
			s.logger.Info("login failed", "ip", ip)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = loginTmpl.Execute(w, map[string]any{"Error": "Invalid access code. Check your terminal."})
		return
	}

	// Success — clear rate limit and create session
	s.auth.RecordSuccess(ip)
	s.logger.Info("login success", "ip", ip)

	token := s.auth.CreateSession()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/dashboard",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   false, // localhost only
	})
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		s.auth.InvalidateSession(cookie.Value)
	}

	// Clear the cookie
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/dashboard",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1, // delete cookie
	})

	s.logger.Info("logout", "ip", clientIP(r))
	http.Redirect(w, r, "/dashboard/login", http.StatusFound)
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	stats := s.getStats()
	recent := s.getRecentEvents(5)
	chart := s.getHourlyChart()

	qStats, _ := s.audit.QuarantineStats()
	var pendingReview int
	if qStats != nil {
		pendingReview = qStats.Pending
	}

	data := map[string]any{
		"Active":        "overview",
		"Stats":         stats,
		"Recent":        recent,
		"Chart":         chart,
		"AgentCount":    len(s.cfg.Agents),
		"RequireSig":    s.cfg.Identity.RequireSignature,
		"PendingReview": pendingReview,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = overviewTmpl.Execute(w, data)
}

type hourlyBar struct {
	Hour    int
	Count   int
	Percent int // 0-100
	Label   string
}

func (s *Server) getHourlyChart() []hourlyBar {
	hourMap, err := s.audit.QueryHourlyStats()
	if err != nil {
		return nil
	}

	var maxCount int
	for _, c := range hourMap {
		if c > maxCount {
			maxCount = c
		}
	}

	bars := make([]hourlyBar, 24)
	for i := range 24 {
		count := hourMap[i]
		pct := 0
		if maxCount > 0 {
			pct = (count * 100) / maxCount
		}
		if pct < 2 && count > 0 {
			pct = 2 // minimum visible bar
		}
		bars[i] = hourlyBar{
			Hour:    i,
			Count:   count,
			Percent: pct,
			Label:   fmt.Sprintf("%02d:00", i),
		}
	}
	return bars
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{
		"Active":     "agents",
		"Agents":     s.cfg.Agents,
		"RequireSig": s.cfg.Identity.RequireSignature,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = agentsTmpl.Execute(w, data)
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	// Build set of disabled rule IDs (rules with action "ignore")
	disabledRules := make(map[string]bool)
	for _, ra := range s.cfg.Rules {
		if ra.Action == "ignore" {
			disabledRules[ra.ID] = true
		}
	}

	var allRules []ruleRow
	catMap := make(map[string]*ruleCategory)
	var catOrder []string

	if s.scanner != nil {
		for _, ri := range s.scanner.ListRules() {
			// Fetch description (cheap — in-memory lookup)
			var desc string
			if detail, err := s.scanner.ExplainRule(ri.ID); err == nil && detail != nil {
				desc = detail.Description
			}

			row := ruleRow{
				ID:          ri.ID,
				Name:        ri.Name,
				Severity:    ri.Severity,
				Category:    ri.Category,
				Description: desc,
				Disabled:    disabledRules[ri.ID],
			}
			allRules = append(allRules, row)

			cat, ok := catMap[ri.Category]
			if !ok {
				cat = &ruleCategory{
					Name:        ri.Category,
					Description: categoryDescriptions[ri.Category],
				}
				catMap[ri.Category] = cat
				catOrder = append(catOrder, ri.Category)
			}
			cat.Rules = append(cat.Rules, row)
			cat.Total++
			if row.Disabled {
				cat.Disabled++
			}
			switch ri.Severity {
			case "critical":
				cat.Critical++
			case "high":
				cat.High++
			case "medium":
				cat.Medium++
			case "low":
				cat.Low++
			}
		}
	}

	// Sort categories: highest severity weight first
	sort.Slice(catOrder, func(i, j int) bool {
		ci, cj := catMap[catOrder[i]], catMap[catOrder[j]]
		wi := ci.Critical*4 + ci.High*3 + ci.Medium*2 + ci.Low
		wj := cj.Critical*4 + cj.High*3 + cj.Medium*2 + cj.Low
		if wi != wj {
			return wi > wj
		}
		return catOrder[i] < catOrder[j]
	})

	var categories []ruleCategory
	for _, name := range catOrder {
		categories = append(categories, *catMap[name])
	}

	data := map[string]any{
		"Active":         "rules",
		"AllRules":       allRules,
		"Categories":     categories,
		"Overrides":      s.cfg.Rules,
		"RuleCount":      len(allRules),
		"CatCount":       len(categories),
		"CustomRulesDir": s.cfg.CustomRulesDir,
		"RequireSig":     s.cfg.Identity.RequireSignature,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = rulesTmpl.Execute(w, data)
}

type ruleRow struct {
	ID          string
	Name        string
	Severity    string
	Category    string
	Description string
	Disabled    bool
}

type ruleCategory struct {
	Name        string
	Description string
	Rules       []ruleRow
	Critical    int
	High        int
	Medium      int
	Low         int
	Disabled    int // count of disabled rules in this category
	Total       int
}

// categoryDescriptions maps Aguara category names to human-readable descriptions.
var categoryDescriptions = map[string]string{
	"command-execution":   "Detects attempts to execute system commands, shell scripts, or invoke interpreters through agent messages.",
	"credential-leak":     "Catches leaked passwords, API keys, tokens, and other secrets being passed between agents.",
	"exfiltration":        "Identifies patterns of data theft: sending files, databases, or sensitive content to external destinations.",
	"external-download":   "Flags attempts to download or fetch resources from external URLs, which could introduce malicious payloads.",
	"indirect-injection":  "Detects prompt injection attacks hidden in data that agents process, targeting downstream LLMs.",
	"inter-agent":         "Monitors trust boundaries between agents: privilege escalation, impersonation, and unauthorized delegation.",
	"mcp-attack":          "Catches attacks targeting MCP (Model Context Protocol) servers: tool abuse, parameter injection, SSRF.",
	"mcp-config":          "Detects manipulation of MCP server configuration: adding malicious servers, changing tool permissions.",
	"prompt-injection":    "Identifies direct prompt injection attempts designed to override agent instructions or system prompts.",
	"ssrf-cloud":          "Detects Server-Side Request Forgery targeting cloud metadata endpoints (AWS, GCP, Azure).",
	"supply-chain":        "Flags attempts to install malicious packages, modify dependencies, or compromise build pipelines.",
	"third-party-content": "Detects loading of untrusted third-party content that could contain injection payloads.",
	"unicode-attack":      "Catches unicode-based attacks: homoglyphs, invisible characters, and bidirectional text manipulation.",
}

func (s *Server) handleCategoryRules(w http.ResponseWriter, r *http.Request) {
	catName := r.PathValue("category")

	// Build disabled rules set
	disabledRules := make(map[string]bool)
	for _, ra := range s.cfg.Rules {
		if ra.Action == "ignore" {
			disabledRules[ra.ID] = true
		}
	}

	// Find category
	cat := &ruleCategory{
		Name:        catName,
		Description: categoryDescriptions[catName],
	}

	if s.scanner != nil {
		for _, ri := range s.scanner.ListRules() {
			if ri.Category != catName {
				continue
			}
			var desc string
			if detail, err := s.scanner.ExplainRule(ri.ID); err == nil && detail != nil {
				desc = detail.Description
			}
			row := ruleRow{
				ID:          ri.ID,
				Name:        ri.Name,
				Severity:    ri.Severity,
				Category:    ri.Category,
				Description: desc,
				Disabled:    disabledRules[ri.ID],
			}
			cat.Rules = append(cat.Rules, row)
			cat.Total++
			if row.Disabled {
				cat.Disabled++
			}
			switch ri.Severity {
			case "critical":
				cat.Critical++
			case "high":
				cat.High++
			case "medium":
				cat.Medium++
			case "low":
				cat.Low++
			}
		}
	}

	if cat.Total == 0 {
		http.NotFound(w, r)
		return
	}

	data := map[string]any{
		"Active":       "rules",
		"Category":     cat,
		"EnabledCount": cat.Total - cat.Disabled,
		"RequireSig":   s.cfg.Identity.RequireSignature,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = categoryDetailTmpl.Execute(w, data)
}

func (s *Server) handleAgentDetail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	agent, ok := s.cfg.Agents[name]
	if !ok {
		http.NotFound(w, r)
		return
	}

	// Get recent messages for this agent
	entries, _ := s.audit.Query(audit.QueryOpts{Agent: name, Limit: 20})

	// Count stats for this agent
	all, _ := s.audit.Query(audit.QueryOpts{Agent: name, Limit: 10000})
	var delivered, blocked, rejected int
	for _, e := range all {
		switch e.Status {
		case "delivered":
			delivered++
		case "blocked":
			blocked++
		case "rejected":
			rejected++
		}
	}

	// Check if key exists
	var keyFP string
	if s.keys != nil {
		if pub, ok := s.keys.Get(name); ok {
			keyFP = identity.Fingerprint(pub)
		}
	}

	// Count quarantined
	var quarantined int
	for _, e := range all {
		if e.Status == "quarantined" {
			quarantined++
		}
	}

	data := map[string]any{
		"Active":      "agents",
		"Name":        name,
		"Agent":       agent,
		"Entries":     entries,
		"TotalMsgs":   len(all),
		"Delivered":   delivered,
		"Blocked":     blocked,
		"Rejected":    rejected,
		"Quarantined": quarantined,
		"KeyFP":       keyFP,
		"RequireSig":  s.cfg.Identity.RequireSignature,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = agentDetailTmpl.Execute(w, data)
}

// HTMX partial: stats bar
func (s *Server) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	stats := s.getStats()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}

// HTMX partial: recent events
func (s *Server) handleAPIRecent(w http.ResponseWriter, r *http.Request) {
	recent := s.getRecentEvents(5)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = recentPartialTmpl.Execute(w, recent)
}

func (s *Server) handleIdentityRevoke(w http.ResponseWriter, r *http.Request) {
	agentName := r.FormValue("agent")
	if agentName == "" {
		http.Error(w, "agent required", http.StatusBadRequest)
		return
	}

	if s.keys == nil {
		http.Error(w, "no keystore", http.StatusBadRequest)
		return
	}

	pub, ok := s.keys.Get(agentName)
	if !ok {
		http.Error(w, "key not found", http.StatusNotFound)
		return
	}

	fp := identity.Fingerprint(pub)
	if err := s.audit.RevokeKey(fp, agentName, "revoked via dashboard"); err != nil {
		http.Error(w, "revoke failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/dashboard/identity", http.StatusFound)
}

func (s *Server) handleModeToggle(w http.ResponseWriter, r *http.Request) {
	s.cfg.Identity.RequireSignature = !s.cfg.Identity.RequireSignature

	if s.cfgPath != "" {
		if err := s.cfg.Save(s.cfgPath); err != nil {
			s.logger.Error("failed to save config after mode toggle", "error", err)
		}
	}

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// --- SSE handler ---

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Extend write deadline so the SSE connection stays open
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{}) // no deadline

	// Flush headers immediately so clients don't block waiting
	flusher.Flush()

	ch := s.audit.Hub.Subscribe()
	defer s.audit.Hub.Unsubscribe(ch)

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case entry, ok := <-ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(entry)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// --- Search handler ---

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	entries, _ := s.audit.Query(audit.QueryOpts{Search: q, Limit: 50})

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = searchResultsTmpl.Execute(w, entries)
}

// --- Event detail handler ---

type triggeredRule struct {
	RuleID   string `json:"rule_id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Match    string `json:"match"`
	Category string `json:"category"`
}

func (s *Server) handleEventDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	entry, err := s.audit.QueryByID(id)
	if err != nil || entry == nil {
		http.NotFound(w, r)
		return
	}

	rules := parseTriggeredRules(entry.RulesTriggered)
	s.resolveRuleCategories(rules)

	data := map[string]any{
		"Entry":    entry,
		"Rules":    rules,
		"Decision": humanReadableDecision(entry.PolicyDecision),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = eventDetailTmpl.Execute(w, data)
}

func parseTriggeredRules(raw string) []triggeredRule {
	if raw == "" {
		return nil
	}
	var rules []triggeredRule
	if err := json.Unmarshal([]byte(raw), &rules); err == nil {
		return rules
	}
	// Fall back: try as string array or comma-separated
	var ids []string
	if err := json.Unmarshal([]byte(raw), &ids); err != nil {
		ids = strings.Split(raw, ",")
	}
	for _, rid := range ids {
		if t := strings.TrimSpace(rid); t != "" {
			rules = append(rules, triggeredRule{RuleID: t, Name: t})
		}
	}
	return rules
}

func (s *Server) resolveRuleCategories(rules []triggeredRule) {
	if s.scanner == nil {
		return
	}
	ruleMap := make(map[string]string)
	for _, ri := range s.scanner.ListRules() {
		ruleMap[ri.ID] = ri.Category
	}
	for i := range rules {
		if cat, ok := ruleMap[rules[i].RuleID]; ok {
			rules[i].Category = cat
		}
	}
}

var decisionLabels = map[string]string{
	"allow":               "Message delivered normally",
	"content_blocked":     "Blocked — dangerous content detected",
	"content_quarantined": "Held for review — suspicious content detected",
	"quarantine_approved": "Reviewed and approved for delivery",
	"quarantine_rejected": "Reviewed and rejected",
	"signature_required":  "Rejected — message was not signed",
	"acl_denied":          "Rejected — agent not authorized for this destination",
}

func humanReadableDecision(decision string) string {
	if label, ok := decisionLabels[decision]; ok {
		return label
	}
	return decision
}

// --- Rule detail handler ---

func (s *Server) handleRuleDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.scanner == nil {
		http.NotFound(w, r)
		return
	}

	detail, err := s.scanner.ExplainRule(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = ruleDetailTmpl.Execute(w, detail)
}

// --- Enforcement overrides handlers ---

func (s *Server) handleEnforcementOverrides(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{
		"Active":     "rules",
		"Overrides":  s.cfg.Rules,
		"RequireSig": s.cfg.Identity.RequireSignature,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = enforcementTmpl.Execute(w, data)
}

func (s *Server) handleSaveEnforcement(w http.ResponseWriter, r *http.Request) {
	ruleID := strings.TrimSpace(r.FormValue("rule_id"))
	severity := r.FormValue("severity")
	action := r.FormValue("action")

	if ruleID == "" || action == "" {
		http.Error(w, "rule_id and action required", http.StatusBadRequest)
		return
	}

	// Update existing or append new
	found := false
	for i := range s.cfg.Rules {
		if s.cfg.Rules[i].ID == ruleID {
			s.cfg.Rules[i].Severity = severity
			s.cfg.Rules[i].Action = action
			found = true
			break
		}
	}
	if !found {
		s.cfg.Rules = append(s.cfg.Rules, config.RuleAction{
			ID:       ruleID,
			Severity: severity,
			Action:   action,
		})
	}

	if s.cfgPath != "" {
		if err := s.cfg.Save(s.cfgPath); err != nil {
			s.logger.Error("failed to save config after enforcement update", "error", err)
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}
	}

	http.Redirect(w, r, "/dashboard/rules", http.StatusFound)
}

func (s *Server) handleDeleteEnforcement(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	filtered := s.cfg.Rules[:0]
	for _, ra := range s.cfg.Rules {
		if ra.ID != id {
			filtered = append(filtered, ra)
		}
	}
	s.cfg.Rules = filtered

	if s.cfgPath != "" {
		if err := s.cfg.Save(s.cfgPath); err != nil {
			s.logger.Error("failed to save config after enforcement delete", "error", err)
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
}

// --- Custom rules handlers ---

func (s *Server) handleCustomRules(w http.ResponseWriter, r *http.Request) {
	var customFiles []customRuleFile
	if s.cfg.CustomRulesDir != "" {
		entries, _ := os.ReadDir(s.cfg.CustomRulesDir)
		for _, e := range entries {
			ext := filepath.Ext(e.Name())
			if ext == ".yaml" || ext == ".yml" {
				customFiles = append(customFiles, customRuleFile{
					Filename: e.Name(),
					ID:       strings.TrimSuffix(e.Name(), ext),
				})
			}
		}
	}

	data := map[string]any{
		"Active":         "rules",
		"CustomFiles":    customFiles,
		"CustomRulesDir": s.cfg.CustomRulesDir,
		"RequireSig":     s.cfg.Identity.RequireSignature,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = customRulesTmpl.Execute(w, data)
}

type customRuleFile struct {
	Filename string
	ID       string
}

func (s *Server) handleCreateCustomRule(w http.ResponseWriter, r *http.Request) {
	if s.cfg.CustomRulesDir == "" {
		http.Error(w, "custom_rules_dir not configured", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	ruleID := normalizeCustomRuleID(strings.TrimSpace(r.FormValue("rule_id")), name)
	patterns := splitNonEmpty(r.FormValue("patterns"), "\n")
	yamlContent := buildCustomRuleYAML(ruleID, name, r.FormValue("severity"), strings.TrimSpace(r.FormValue("category")), patterns)

	if err := os.MkdirAll(s.cfg.CustomRulesDir, 0o755); err != nil {
		http.Error(w, "cannot create custom rules dir", http.StatusInternalServerError)
		return
	}

	filename := filepath.Join(s.cfg.CustomRulesDir, ruleID+".yaml")
	if err := os.WriteFile(filename, []byte(yamlContent), 0o644); err != nil {
		http.Error(w, "write failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/dashboard/rules", http.StatusFound)
}

func normalizeCustomRuleID(ruleID, name string) string {
	if ruleID == "" {
		slug := strings.ToUpper(strings.ReplaceAll(name, " ", "-"))
		var clean []byte
		for _, b := range []byte(slug) {
			if (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '-' {
				clean = append(clean, b)
			}
		}
		ruleID = "CUSTOM-" + string(clean)
	}
	if !strings.HasPrefix(strings.ToUpper(ruleID), "CUSTOM-") {
		ruleID = "CUSTOM-" + ruleID
	}
	return strings.ToUpper(ruleID)
}

func splitNonEmpty(s, sep string) []string {
	var result []string
	for _, line := range strings.Split(s, sep) {
		if t := strings.TrimSpace(line); t != "" {
			result = append(result, t)
		}
	}
	return result
}

func buildCustomRuleYAML(ruleID, name, severity, category string, patterns []string) string {
	yaml := fmt.Sprintf(`rules:
  - id: %s
    name: "%s"
    severity: %s
    category: %s
    description: "Custom rule created via dashboard"
    target: "*.md"
    match_mode: any
    patterns:
`, ruleID, name, severity, category)

	for _, p := range patterns {
		yaml += fmt.Sprintf("      - type: contains\n        value: \"%s\"\n", strings.ReplaceAll(p, `"`, `\"`))
	}

	yaml += fmt.Sprintf(`    examples:
      true_positive:
        - "%s test content"
      false_positive:
        - "benign content"
`, name)
	return yaml
}

func (s *Server) handleDeleteCustomRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.cfg.CustomRulesDir == "" {
		http.Error(w, "custom_rules_dir not configured", http.StatusBadRequest)
		return
	}

	// Try both .yaml and .yml extensions
	for _, ext := range []string{".yaml", ".yml"} {
		path := filepath.Join(s.cfg.CustomRulesDir, id+ext)
		if _, err := os.Stat(path); err == nil {
			if err := os.Remove(path); err != nil {
				http.Error(w, "delete failed: "+err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	http.NotFound(w, r)
}

// --- Quarantine handlers ---

func (s *Server) handleQuarantineDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	item, err := s.audit.QuarantineByID(id)
	if err != nil || item == nil {
		http.NotFound(w, r)
		return
	}

	// Parse rules triggered into structured objects
	var rules []triggeredRule
	if item.RulesTriggered != "" {
		_ = json.Unmarshal([]byte(item.RulesTriggered), &rules)
	}

	// Resolve categories
	if s.scanner != nil {
		ruleMap := make(map[string]string)
		for _, ri := range s.scanner.ListRules() {
			ruleMap[ri.ID] = ri.Category
		}
		for i := range rules {
			if cat, ok := ruleMap[rules[i].RuleID]; ok {
				rules[i].Category = cat
			}
		}
	}

	data := map[string]any{
		"Item":  item,
		"Rules": rules,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = quarantineDetailTmpl.Execute(w, data)
}

func (s *Server) handleQuarantineApprove(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.audit.QuarantineApprove(id, "dashboard"); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	item, _ := s.audit.QuarantineByID(id)
	data := map[string]any{"Item": item}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = quarantineRowTmpl.Execute(w, data)
}

func (s *Server) handleQuarantineReject(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.audit.QuarantineReject(id, "dashboard"); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	item, _ := s.audit.QuarantineByID(id)
	data := map[string]any{"Item": item}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = quarantineRowTmpl.Execute(w, data)
}

// --- Agent CRUD handlers ---

var agentNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

func (s *Server) handleCreateAgent(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" || !agentNameRe.MatchString(name) {
		http.Error(w, "invalid agent name (alphanumeric, hyphens, underscores)", http.StatusBadRequest)
		return
	}
	if _, exists := s.cfg.Agents[name]; exists {
		http.Error(w, "agent already exists", http.StatusConflict)
		return
	}

	if s.cfg.Agents == nil {
		s.cfg.Agents = make(map[string]config.Agent)
	}

	canMessage := strings.Fields(strings.ReplaceAll(r.FormValue("can_message"), ",", " "))
	tags := strings.Fields(strings.ReplaceAll(r.FormValue("tags"), ",", " "))

	s.cfg.Agents[name] = config.Agent{
		CanMessage:  canMessage,
		Description: strings.TrimSpace(r.FormValue("description")),
		CreatedBy:   "dashboard",
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		Location:    strings.TrimSpace(r.FormValue("location")),
		Tags:        tags,
	}

	if s.cfgPath != "" {
		if err := s.cfg.Save(s.cfgPath); err != nil {
			s.logger.Error("failed to save config after agent create", "error", err)
		}
	}

	http.Redirect(w, r, "/dashboard/agents/"+name, http.StatusFound)
}

func (s *Server) handleEditAgent(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	agent, ok := s.cfg.Agents[name]
	if !ok {
		http.NotFound(w, r)
		return
	}

	agent.Description = strings.TrimSpace(r.FormValue("description"))
	agent.Location = strings.TrimSpace(r.FormValue("location"))
	agent.Tags = strings.Fields(strings.ReplaceAll(r.FormValue("tags"), ",", " "))
	canMessage := strings.Fields(strings.ReplaceAll(r.FormValue("can_message"), ",", " "))
	if len(canMessage) > 0 {
		agent.CanMessage = canMessage
	}

	s.cfg.Agents[name] = agent

	if s.cfgPath != "" {
		if err := s.cfg.Save(s.cfgPath); err != nil {
			s.logger.Error("failed to save config after agent edit", "error", err)
		}
	}

	http.Redirect(w, r, "/dashboard/agents/"+name, http.StatusFound)
}

func (s *Server) handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, ok := s.cfg.Agents[name]; !ok {
		http.NotFound(w, r)
		return
	}

	delete(s.cfg.Agents, name)

	if s.cfgPath != "" {
		if err := s.cfg.Save(s.cfgPath); err != nil {
			s.logger.Error("failed to save config after agent delete", "error", err)
		}
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleAgentKeygen(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, ok := s.cfg.Agents[name]; !ok {
		http.NotFound(w, r)
		return
	}

	if s.cfg.Identity.KeysDir == "" {
		http.Error(w, "keys_dir not configured", http.StatusBadRequest)
		return
	}

	kp, err := identity.GenerateKeypair(name)
	if err != nil {
		http.Error(w, "keygen failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := os.MkdirAll(s.cfg.Identity.KeysDir, 0o700); err != nil {
		http.Error(w, "cannot create keys dir: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := kp.Save(s.cfg.Identity.KeysDir); err != nil {
		http.Error(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Reload keystore
	if s.keys != nil {
		if err := s.keys.ReloadFromDir(s.cfg.Identity.KeysDir); err != nil {
			s.logger.Error("failed to reload keys after keygen", "error", err)
		}
	}

	http.Redirect(w, r, "/dashboard/agents/"+name, http.StatusFound)
}

// --- Rule toggle handlers ---

func (s *Server) handleToggleRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// Check if rule is currently disabled (has "ignore" override)
	isDisabled := false
	for _, ra := range s.cfg.Rules {
		if ra.ID == id && ra.Action == "ignore" {
			isDisabled = true
			break
		}
	}

	if isDisabled {
		// Enable: remove the "ignore" override
		filtered := s.cfg.Rules[:0]
		for _, ra := range s.cfg.Rules {
			if ra.ID != id || ra.Action != "ignore" {
				filtered = append(filtered, ra)
			}
		}
		s.cfg.Rules = filtered
	} else {
		// Disable: add "ignore" override
		s.cfg.Rules = append(s.cfg.Rules, config.RuleAction{
			ID:     id,
			Action: "ignore",
		})
	}

	if s.cfgPath != "" {
		if err := s.cfg.Save(s.cfgPath); err != nil {
			s.logger.Error("failed to save config after rule toggle", "error", err)
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}
	}

	// Return the updated toggle button
	enabled := isDisabled // flipped
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = ruleToggleTmpl.Execute(w, map[string]any{"ID": id, "Enabled": enabled})
}

func (s *Server) handleToggleCategory(w http.ResponseWriter, r *http.Request) {
	catName := r.PathValue("name")

	ruleIDs := s.categoryRuleIDs(catName)
	if len(ruleIDs) == 0 {
		http.NotFound(w, r)
		return
	}

	disabledSet := s.disabledRuleSet()
	disabledCount := countInSet(ruleIDs, disabledSet)

	// If most are enabled → disable all; if most disabled → enable all
	if disabledCount < len(ruleIDs)/2+1 {
		s.disableCategoryRules(ruleIDs, disabledSet)
	} else {
		s.enableCategoryRules(ruleIDs)
	}

	if s.cfgPath != "" {
		if err := s.cfg.Save(s.cfgPath); err != nil {
			s.logger.Error("failed to save config after category toggle", "error", err)
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("HX-Redirect", "/dashboard/rules")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) categoryRuleIDs(category string) []string {
	if s.scanner == nil {
		return nil
	}
	var ids []string
	for _, ri := range s.scanner.ListRules() {
		if ri.Category == category {
			ids = append(ids, ri.ID)
		}
	}
	return ids
}

func (s *Server) disabledRuleSet() map[string]bool {
	set := make(map[string]bool)
	for _, ra := range s.cfg.Rules {
		if ra.Action == "ignore" {
			set[ra.ID] = true
		}
	}
	return set
}

func countInSet(ids []string, set map[string]bool) int {
	n := 0
	for _, id := range ids {
		if set[id] {
			n++
		}
	}
	return n
}

func (s *Server) disableCategoryRules(ruleIDs []string, alreadyDisabled map[string]bool) {
	for _, id := range ruleIDs {
		if !alreadyDisabled[id] {
			s.cfg.Rules = append(s.cfg.Rules, config.RuleAction{ID: id, Action: "ignore"})
		}
	}
}

func (s *Server) enableCategoryRules(ruleIDs []string) {
	catRuleSet := make(map[string]bool)
	for _, id := range ruleIDs {
		catRuleSet[id] = true
	}
	filtered := s.cfg.Rules[:0]
	for _, ra := range s.cfg.Rules {
		if !catRuleSet[ra.ID] || ra.Action != "ignore" {
			filtered = append(filtered, ra)
		}
	}
	s.cfg.Rules = filtered
}

// --- Events handler (merged audit log + quarantine) ---

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	tab := r.URL.Query().Get("tab")
	if tab == "" {
		tab = "all"
	}

	// All events
	entries, _ := s.audit.Query(audit.QueryOpts{Limit: 50})

	// Quarantine
	qStatusFilter := r.URL.Query().Get("status")
	if tab == "quarantine" && qStatusFilter == "" {
		qStatusFilter = "pending"
	}
	qItems, _ := s.audit.QuarantineQuery(qStatusFilter, "", 50)
	qStats, _ := s.audit.QuarantineStats()
	if qStats == nil {
		qStats = &audit.QuarantineStats{}
	}

	// Blocked entries
	blockedEntries, _ := s.audit.Query(audit.QueryOpts{Status: "blocked", Limit: 50})
	rejectedEntries, _ := s.audit.Query(audit.QueryOpts{Status: "rejected", Limit: 50})
	allBlocked := append(blockedEntries, rejectedEntries...)

	data := map[string]any{
		"Active":         "events",
		"Tab":            tab,
		"Entries":        entries,
		"QItems":         qItems,
		"QStats":         qStats,
		"QStatusFilter":  qStatusFilter,
		"QPending":       qStats.Pending,
		"BlockedEntries": allBlocked,
		"RequireSig":     s.cfg.Identity.RequireSignature,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = eventsTmpl.Execute(w, data)
}

// --- Settings handler ---

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	type keyInfo struct {
		Name        string
		Fingerprint string
	}

	var keys []keyInfo
	if s.keys != nil {
		for _, name := range s.keys.Names() {
			pub, _ := s.keys.Get(name)
			keys = append(keys, keyInfo{
				Name:        name,
				Fingerprint: identity.Fingerprint(pub),
			})
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i].Name < keys[j].Name })
	}

	revoked, _ := s.audit.ListRevokedKeys()

	// Build revoked fingerprint set for template lookup
	revokedFPs := make(map[string]bool)
	for _, rk := range revoked {
		revokedFPs[rk.Fingerprint] = true
	}

	qStats, _ := s.audit.QuarantineStats()
	var qPending int
	if qStats != nil {
		qPending = qStats.Pending
	}

	serverBind := s.cfg.Server.Bind
	if serverBind == "" {
		serverBind = "127.0.0.1"
	}

	data := map[string]any{
		"Active":         "settings",
		"RequireSig":     s.cfg.Identity.RequireSignature,
		"Keys":           keys,
		"KeysDir":        s.cfg.Identity.KeysDir,
		"Revoked":        revoked,
		"RevokedFPs":     revokedFPs,
		"QEnabled":       s.cfg.Quarantine.Enabled,
		"QExpiryHours":   s.cfg.Quarantine.ExpiryHours,
		"QPending":       qPending,
		"ServerPort":     s.cfg.Server.Port,
		"ServerBind":     serverBind,
		"LogLevel":       s.cfg.Server.LogLevel,
		"CustomRulesDir": s.cfg.CustomRulesDir,
		"WebhookCount":   len(s.cfg.Webhooks),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = settingsTmpl.Execute(w, data)
}

// --- Stats helpers ---

type dashboardStats struct {
	TotalMessages int `json:"total_messages"`
	Delivered     int `json:"delivered"`
	Blocked       int `json:"blocked"`
	Rejected      int `json:"rejected"`
	Quarantined   int `json:"quarantined"`
}

func (s *Server) getStats() dashboardStats {
	sc, err := s.audit.QueryStats()
	if err != nil {
		return dashboardStats{}
	}
	return dashboardStats{
		TotalMessages: sc.Total,
		Delivered:     sc.Delivered,
		Blocked:       sc.Blocked,
		Rejected:      sc.Rejected,
		Quarantined:   sc.Quarantined,
	}
}

func (s *Server) getRecentEvents(n int) []audit.Entry {
	entries, _ := s.audit.Query(audit.QueryOpts{Limit: n})
	return entries
}
