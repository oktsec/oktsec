package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
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
	code := r.FormValue("code")
	if !s.auth.ValidateCode(code) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = loginTmpl.Execute(w, map[string]any{"Error": "Invalid access code. Check your terminal."})
		return
	}

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

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	stats := s.getStats()
	recent := s.getRecentEvents(5)
	chart := s.getHourlyChart()

	data := map[string]any{
		"Active":     "overview",
		"Stats":      stats,
		"Recent":     recent,
		"Chart":      chart,
		"AgentCount": len(s.cfg.Agents),
		"RequireSig": s.cfg.Identity.RequireSignature,
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

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	entries, _ := s.audit.Query(audit.QueryOpts{Limit: 50})

	data := map[string]any{
		"Active":     "logs",
		"Entries":    entries,
		"RequireSig": s.cfg.Identity.RequireSignature,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = logsTmpl.Execute(w, data)
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
	var allRules []ruleRow
	if s.scanner != nil {
		for _, ri := range s.scanner.ListRules() {
			allRules = append(allRules, ruleRow{
				ID:       ri.ID,
				Name:     ri.Name,
				Severity: ri.Severity,
				Category: ri.Category,
			})
		}
	}

	data := map[string]any{
		"Active":       "rules",
		"AllRules":     allRules,
		"Overrides":    s.cfg.Rules,
		"RuleCount":    len(allRules),
		"RequireSig":   s.cfg.Identity.RequireSignature,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = rulesTmpl.Execute(w, data)
}

type ruleRow struct {
	ID       string
	Name     string
	Severity string
	Category string
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

	data := map[string]any{
		"Active":     "agents",
		"Name":       name,
		"Agent":      agent,
		"Entries":    entries,
		"TotalMsgs":  len(all),
		"Delivered":  delivered,
		"Blocked":    blocked,
		"Rejected":   rejected,
		"KeyFP":      keyFP,
		"RequireSig": s.cfg.Identity.RequireSignature,
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

func (s *Server) handleIdentity(w http.ResponseWriter, r *http.Request) {
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

	data := map[string]any{
		"Active":     "identity",
		"Keys":       keys,
		"Revoked":    revoked,
		"RequireSig": s.cfg.Identity.RequireSignature,
		"KeysDir":    s.cfg.Identity.KeysDir,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = identityTmpl.Execute(w, data)
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
			fmt.Fprintf(w, "data: %s\n\n", data)
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

func (s *Server) handleEventDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	entry, err := s.audit.QueryByID(id)
	if err != nil || entry == nil {
		http.NotFound(w, r)
		return
	}

	// Parse rules triggered into a list
	var rulesList []string
	if entry.RulesTriggered != "" {
		// Try JSON array first
		if err := json.Unmarshal([]byte(entry.RulesTriggered), &rulesList); err != nil {
			// Fall back to comma-separated
			for _, r := range strings.Split(entry.RulesTriggered, ",") {
				if t := strings.TrimSpace(r); t != "" {
					rulesList = append(rulesList, t)
				}
			}
		}
	}

	data := map[string]any{
		"Entry": entry,
		"Rules": rulesList,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = eventDetailTmpl.Execute(w, data)
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
		"Active":        "rules",
		"CustomFiles":   customFiles,
		"CustomRulesDir": s.cfg.CustomRulesDir,
		"RequireSig":    s.cfg.Identity.RequireSignature,
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

	ruleID := strings.TrimSpace(r.FormValue("rule_id"))
	name := strings.TrimSpace(r.FormValue("name"))
	severity := r.FormValue("severity")
	category := strings.TrimSpace(r.FormValue("category"))
	patternsRaw := r.FormValue("patterns")

	if ruleID == "" || name == "" {
		http.Error(w, "rule_id and name required", http.StatusBadRequest)
		return
	}

	// Ensure ID starts with CUSTOM-
	if !strings.HasPrefix(strings.ToUpper(ruleID), "CUSTOM-") {
		ruleID = "CUSTOM-" + ruleID
	}
	ruleID = strings.ToUpper(ruleID)

	// Build patterns list
	var patterns []string
	for _, line := range strings.Split(patternsRaw, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			patterns = append(patterns, t)
		}
	}

	// Build YAML content
	yamlContent := fmt.Sprintf(`rules:
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
		yamlContent += fmt.Sprintf("      - type: contains\n        value: \"%s\"\n", strings.ReplaceAll(p, `"`, `\"`))
	}

	yamlContent += fmt.Sprintf(`    examples:
      true_positive:
        - "%s test content"
      false_positive:
        - "benign content"
`, name)

	// Ensure directory exists
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
