package dashboard

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/auditcheck"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/discover"
	"github.com/oktsec/oktsec/internal/graph"
	"github.com/oktsec/oktsec/internal/identity"
	"github.com/oktsec/oktsec/internal/llm"
	"gopkg.in/yaml.v3"
)

func (s *Server) renderTemplate(w http.ResponseWriter, tmpl *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		// Broken pipe / connection reset during shutdown is expected, not an error.
		msg := err.Error()
		if strings.Contains(msg, "broken pipe") || strings.Contains(msg, "connection reset") {
			s.logger.Debug("template write interrupted", "template", tmpl.Name())
			return
		}
		s.logger.Error("template render failed", "template", tmpl.Name(), "error", err)
	}
}

func (s *Server) renderJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		s.logger.Error("json encode failed", "error", err)
	}
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	s.renderTemplate(w, notFoundTmpl, nil)
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	s.renderTemplate(w, loginTmpl, nil)
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
		msg := fmt.Sprintf("Too many failed attempts. Try again in %d minutes.", int(retryAfter.Minutes())+1)
		s.renderTemplate(w, loginTmpl, map[string]any{"Error": msg})
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
		s.renderTemplate(w, loginTmpl, map[string]any{"Error": "Invalid access code. Check your terminal."})
		return
	}

	// Success — clear rate limit and create session
	s.auth.RecordSuccess(ip)
	s.logger.Debug("login success", "ip", ip)

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
	var wg sync.WaitGroup

	// Group 1: independent fast queries
	var stats dashboardStats
	var recent []audit.Entry
	var chart []hourlyBar
	var qStats *audit.QuarantineStats

	wg.Add(4)
	go func() { defer wg.Done(); stats = s.getStats() }()
	go func() { defer wg.Done(); recent = s.getRecentEvents(3) }()
	go func() { defer wg.Done(); chart = s.getHourlyChart() }()
	go func() { defer wg.Done(); qStats, _ = s.audit.QuarantineStats() }()

	// Group 2: independent DB queries
	var topRules []audit.RuleStat
	var agentRisks []audit.AgentRisk
	var unsigned, totalRecent int
	var unsignedByAgent []audit.UnsignedByAgent
	var avgLatency int

	wg.Add(5)
	go func() { defer wg.Done(); topRules, _ = s.audit.QueryTopRules(5, "") }()
	go func() { defer wg.Done(); agentRisks, _ = s.audit.QueryAgentRisk("") }()
	go func() { defer wg.Done(); unsigned, totalRecent, _ = s.audit.QueryUnsignedRate() }()
	go func() { defer wg.Done(); unsignedByAgent, _ = s.audit.QueryUnsignedByAgent() }()
	go func() { defer wg.Done(); avgLatency, _ = s.audit.QueryAvgLatency() }()

	// Group 3: chain verification (lightweight — last 100 entries only) + health score + LLM stats
	var chainResult audit.ChainVerifyResult
	var score int
	var grade string

	wg.Add(2)
	go func() {
		defer wg.Done()
		chainEntries, _ := s.audit.QueryChainEntries(100)
		chainResult = audit.VerifyChain(chainEntries, nil)
	}()
	go func() {
		defer wg.Done()
		findings, _, _ := s.cachedRunChecks()
		score, grade = auditcheck.ComputeHealthScore(findings)
	}()

	wg.Wait()

	var pendingReview int
	if qStats != nil {
		pendingReview = qStats.Pending
	}

	detectionRate := 0
	if stats.TotalMessages > 0 {
		detectionRate = (stats.Blocked + stats.Rejected + stats.Quarantined) * 100 / stats.TotalMessages
	}
	unsignedPct := 0
	if totalRecent > 0 {
		unsignedPct = unsigned * 100 / totalRecent
	}

	// Build pipeline stage statuses.
	type pipelineStage struct {
		Name   string
		Active bool
	}
	pipelineStages := []pipelineStage{
		{"Rate Limit", true},
		{"Identity", true},
		{"Suspension", true},
		{"ACL", true},
		{"Scan", s.scanner != nil},
		{"Intent", true},
		{"Blocked", true},
		{"Escalation", true},
		{"Audit", true},
		{"Anomaly", true},
	}

	ruleCount := 0
	if s.scanner != nil {
		ruleCount = s.scanner.RulesCount(r.Context())
	}

	data := map[string]any{
		"Active":        "overview",
		"Stats":         stats,
		"Recent":        recent,
		"Chart":         chart,
		"AgentCount":    len(s.cfg.Agents),
		"RequireSig":    s.cfg.Identity.RequireSignature,
		"PendingReview": pendingReview,
		"Score":         score,
		"Grade":         grade,
		"TopRules":      topRules,
		"AgentRisks":    agentRisks,
		"DetectionRate": detectionRate,
		"UnsignedCount":   unsigned,
		"UnsignedPct":     unsignedPct,
		"UnsignedByAgent": unsignedByAgent,
		"AvgLatency":      avgLatency,
		"ChainValid":      chainResult.Valid,
		"ChainCount":      chainResult.Entries,
		"ChainReason":     chainResult.Reason,
		"PipelineStages":  pipelineStages,
		"RuleCount":       ruleCount,
	}

	s.populateLLMStats(data)

	s.renderTemplate(w, overviewTmpl, data)
}

type auditProductGroup struct {
	Info     auditcheck.ProductInfo
	Findings []auditcheck.Finding
	Summary  auditcheck.Summary
}

// topRemediations returns up to n critical/high findings that have remediation text.
func topRemediations(findings []auditcheck.Finding, n int) []auditcheck.Finding {
	var out []auditcheck.Finding
	for _, sev := range []auditcheck.Severity{auditcheck.Critical, auditcheck.High} {
		for _, f := range findings {
			if f.Severity == sev && f.Remediation != "" {
				out = append(out, f)
				if len(out) == n {
					return out
				}
			}
		}
	}
	return out
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	findings, detected, productInfos := s.cachedRunChecks()
	score, grade := auditcheck.ComputeHealthScore(findings)
	summary := auditcheck.Summarize(findings)

	// Group by product
	products := []string{"Oktsec"}
	products = append(products, detected...)
	byProduct := map[string][]auditcheck.Finding{}
	for _, f := range findings {
		name := "Oktsec"
		if f.Product != "" {
			name = f.Product
		}
		byProduct[name] = append(byProduct[name], f)
	}
	var groups []auditProductGroup
	for _, name := range products {
		if fs := byProduct[name]; len(fs) > 0 {
			groups = append(groups, auditProductGroup{
				Info:     productInfos[name],
				Findings: fs,
				Summary:  auditcheck.Summarize(fs),
			})
		}
	}

	topFixes := topRemediations(findings, 3)

	// Verify audit chain integrity (lightweight — last 100 entries)
	chainEntries, _ := s.audit.QueryChainEntries(100)
	chainResult := audit.VerifyChain(chainEntries, nil)

	// LLM threat stats for the AI banner
	var llmThreats, llmConfirmed int
	if s.cfg.LLM.Enabled {
		if llmStats, err := s.audit.QueryLLMStats(); err == nil && llmStats != nil {
			llmThreats = llmStats.TotalAnalyses
			llmConfirmed = llmStats.TotalThreats
		}
	}

	data := map[string]any{
		"Active":      "audit",
		"RequireSig":  s.cfg.Identity.RequireSignature,
		"Score":       score,
		"Grade":       grade,
		"Groups":      groups,
		"Summary":     summary,
		"TopFixes":    topFixes,
		"TotalChecks": len(findings),
		"HasCritical": summary.Critical > 0,
		"ChainValid":    chainResult.Valid,
		"ChainCount":    chainResult.Entries,
		"ChainReason":   chainResult.Reason,
		"ChainBrokenAt": chainResult.BrokenAt,
		"ChainBrokenID": chainResult.BrokenID,
		"LLMEnabled":    s.cfg.LLM.Enabled,
		"LLMModel":      s.cfg.LLM.Model,
		"LLMThreats":    llmThreats,
		"LLMConfirmed":  llmConfirmed,
	}

	s.renderTemplate(w, auditTmpl, data)
}

// handleAuditSandbox renders the audit page with ONLY OpenClaw findings
// from a sample config with intentional security issues, for UI testing
// and demo screenshots without needing OpenClaw installed locally.
func (s *Server) handleAuditSandbox(w http.ResponseWriter, r *http.Request) {
	findings := auditcheck.AuditOpenClawSandbox()
	if len(findings) == 0 {
		http.Error(w, "sandbox failed to generate findings", http.StatusInternalServerError)
		return
	}

	productInfos := map[string]auditcheck.ProductInfo{
		"OpenClaw": {
			Name:        "OpenClaw",
			Description: "AI agent gateway — multi-channel personal assistant platform",
			ConfigPath:  "~/.openclaw/openclaw.json",
			DocsURL:     "https://docs.openclaw.ai/gateway/security",
			Icon:        "\U0001f980",
		},
	}

	score, grade := auditcheck.ComputeHealthScore(findings)
	summary := auditcheck.Summarize(findings)

	groups := []auditProductGroup{{
		Info:     productInfos["OpenClaw"],
		Findings: findings,
		Summary:  summary,
	}}

	data := map[string]any{
		"Active":      "audit",
		"RequireSig":  s.cfg.Identity.RequireSignature,
		"Score":       score,
		"Grade":       grade,
		"Groups":      groups,
		"Summary":     summary,
		"TopFixes":    topRemediations(findings, 3),
		"TotalChecks": len(findings),
		"HasCritical": summary.Critical > 0,
		"Sandbox":     true,
	}

	s.renderTemplate(w, auditTmpl, data)
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

type agentRow struct {
	Name             string
	Description      string
	CanMessage       []string
	Tags             []string
	Suspended        bool
	Total            int
	Blocked          int
	BlockedPct       int
	RiskScore        float64
	LLMThreatCount   int
	HasKey           bool
	LastSeen         string
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	// Build risk map
	agentRisks, _ := s.audit.QueryAgentRisk("")
	riskMap := make(map[string]*audit.AgentRisk)
	for i := range agentRisks {
		riskMap[agentRisks[i].Agent] = &agentRisks[i]
	}

	// Build agent rows
	var rows []agentRow
	for name, agent := range s.cfg.Agents {
		row := agentRow{
			Name:        name,
			Description: agent.Description,
			CanMessage:  agent.CanMessage,
			Tags:        agent.Tags,
			Suspended:   agent.Suspended,
		}

		// Traffic stats
		if stats, err := s.audit.QueryAgentStats(name); err == nil && stats != nil {
			row.Total = stats.Total
			row.Blocked = stats.Blocked
			if stats.Total > 0 {
				row.BlockedPct = (stats.Blocked + stats.Rejected) * 100 / stats.Total
			}
		}

		// Risk score (blended audit + LLM)
		if ar, ok := riskMap[name]; ok {
			row.RiskScore = ar.RiskScore
			row.LLMThreatCount = ar.LLMThreatCount
		}

		// Key status
		if s.keys != nil {
			if _, ok := s.keys.Get(name); ok {
				row.HasKey = true
			}
		}

		// Last seen
		if entries, err := s.audit.Query(audit.QueryOpts{Agent: name, Limit: 1}); err == nil && len(entries) > 0 {
			row.LastSeen = entries[0].Timestamp
		}

		rows = append(rows, row)
	}

	// Sort by name for stable ordering
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })

	// Show agents discovered in traffic but not yet in config
	var discovered []string
	if trafficAgents, err := s.audit.QueryTrafficAgents(); err == nil {
		for _, ta := range trafficAgents {
			if _, ok := s.cfg.Agents[ta]; !ok && ta != "" {
				discovered = append(discovered, ta)
			}
		}
	}

	data := map[string]any{
		"Active":           "agents",
		"Agents":           s.cfg.Agents,
		"AgentRows":        rows,
		"DiscoveredAgents": discovered,
		"RequireSig":       s.cfg.Identity.RequireSignature,
	}

	s.renderTemplate(w, agentsTmpl, data)
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	tab := r.URL.Query().Get("tab")
	if tab == "" {
		tab = "detection"
	}

	// Always count custom rules for the badge
	var customCount int
	if s.cfg.CustomRulesDir != "" {
		entries, _ := os.ReadDir(s.cfg.CustomRulesDir)
		for _, e := range entries {
			ext := filepath.Ext(e.Name())
			if ext == ".yaml" || ext == ".yml" {
				customCount++
			}
		}
	}

	// Count non-toggle overrides (exclude "ignore" which are just toggles)
	var enforcementCount int
	for _, ra := range s.cfg.Rules {
		if ra.Action != "ignore" {
			enforcementCount++
		}
	}

	// Load LLM-generated rules once (reused for counts and tab data)
	var llmPending, llmActive, llmDisabled []llm.GeneratedRule
	if s.ruleGen != nil {
		llmPending, _ = s.ruleGen.ListPending()
		llmActive, _ = s.ruleGen.ListActive()
		llmDisabled, _ = s.ruleGen.ListDisabled()
	}

	data := map[string]any{
		"Active":           "rules",
		"Tab":              tab,
		"CustomRulesDir":   s.cfg.CustomRulesDir,
		"CustomCount":      customCount,
		"EnforcementCount": enforcementCount,
		"LLMPendingCount":  len(llmPending),
		"LLMActiveCount":   len(llmActive),
		"LLMTotalCount":    len(llmPending) + len(llmActive),
		"RequireSig":       s.cfg.Identity.RequireSignature,
	}

	// Only build category data for detection tab
	if tab == "detection" {
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
				row := ruleRow{
					ID:       ri.ID,
					Name:     ri.Name,
					Severity: ri.Severity,
					Category: ri.Category,
					Disabled: disabledRules[ri.ID],
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
				case audit.SeverityCritical:
					cat.Critical++
				case audit.SeverityHigh:
					cat.High++
				case audit.SeverityMedium:
					cat.Medium++
				case audit.SeverityLow:
					cat.Low++
				}
			}
		}

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

		data["AllRules"] = allRules
		data["Categories"] = categories
		data["RuleCount"] = len(allRules)
		data["CatCount"] = len(categories)
	}

	// Only build custom rules list for custom tab
	if tab == "custom" {
		var customFiles []customRuleFile
		if s.cfg.CustomRulesDir != "" {
			entries, _ := os.ReadDir(s.cfg.CustomRulesDir)
			for _, e := range entries {
				ext := filepath.Ext(e.Name())
				if ext == ".yaml" || ext == ".yml" {
					cf := customRuleFile{
						Filename: e.Name(),
						ID:       strings.TrimSuffix(e.Name(), ext),
					}
					// Enrich from scanner cache (cheap in-memory lookup)
					if s.scanner != nil {
						ruleID := strings.ToUpper(cf.ID)
						if detail, err := s.scanner.ExplainRule(ruleID); err == nil && detail != nil {
							cf.Name = detail.Name
							cf.Severity = detail.Severity
							cf.PatternCount = len(detail.Patterns)
						}
					}
					customFiles = append(customFiles, cf)
				}
			}
		}
		data["CustomFiles"] = customFiles
	}

	// LLM-generated rules (needed for llm-rules tab + detection tab indicator)
	data["LLMPending"] = llmPending
	data["LLMActive"] = llmActive
	data["LLMDisabled"] = llmDisabled

	// Build enforcement data for enforcement tab
	if tab == "enforcement" {
		// Build rule info map for enriching overrides + JSON for search
		ruleInfoMap := make(map[string]ruleRow)
		if s.scanner != nil {
			for _, ri := range s.scanner.ListRules() {
				ruleInfoMap[ri.ID] = ruleRow{
					ID:       ri.ID,
					Name:     ri.Name,
					Severity: ri.Severity,
					Category: ri.Category,
				}
			}
		}

		// Build enriched overrides
		var enriched []enforcementOverride
		for _, ra := range s.cfg.Rules {
			eo := enforcementOverride{
				ID:       ra.ID,
				Action:   ra.Action,
				Notify:   ra.Notify,
				Template: ra.Template,
			}
			if info, ok := ruleInfoMap[ra.ID]; ok {
				eo.Name = info.Name
				eo.Category = info.Category
				eo.DefaultSeverity = info.Severity
				if s.scanner != nil {
					if detail, err := s.scanner.ExplainRule(ra.ID); err == nil && detail != nil {
						eo.Description = detail.Description
					}
				}
			}
			enriched = append(enriched, eo)
		}

		// Serialize rule list as JSON for the JS combobox
		type ruleOption struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Severity string `json:"severity"`
			Category string `json:"category"`
		}
		var opts []ruleOption
		for _, ri := range ruleInfoMap {
			opts = append(opts, ruleOption{ID: ri.ID, Name: ri.Name, Severity: ri.Severity, Category: ri.Category})
		}
		sort.Slice(opts, func(i, j int) bool { return opts[i].ID < opts[j].ID })
		rulesJSON, _ := json.Marshal(opts)
		data["RulesJSON"] = string(rulesJSON)
		data["Overrides"] = enriched
		data["WebhookChannels"] = s.cfg.Webhooks
	}

	s.renderTemplate(w, rulesTmpl, data)
}

type ruleRow struct {
	ID          string
	Name        string
	Severity    string
	Category    string
	Description string
	Disabled    bool
}

type enforcementOverride struct {
	ID              string
	Action          string
	Notify          []string
	Template        string
	Name            string // from scanner
	Description     string // from scanner
	Category        string // from scanner
	DefaultSeverity string // from scanner
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
	"openclaw-config":     "Detects risky configurations in OpenClaw agent deployments: exposed gateways, overprivileged tool profiles, open DM policies, and credential leaks.",
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
			case audit.SeverityCritical:
				cat.Critical++
			case audit.SeverityHigh:
				cat.High++
			case audit.SeverityMedium:
				cat.Medium++
			case audit.SeverityLow:
				cat.Low++
			}
		}
	}

	if cat.Total == 0 {
		s.handleNotFound(w, r)
		return
	}

	// Look up category webhooks
	var catWebhook *config.CategoryWebhook
	for i := range s.cfg.CategoryWebhooks {
		if s.cfg.CategoryWebhooks[i].Category == catName {
			catWebhook = &s.cfg.CategoryWebhooks[i]
			break
		}
	}

	data := map[string]any{
		"Active":          "rules",
		"Category":        cat,
		"EnabledCount":    cat.Total - cat.Disabled,
		"RequireSig":      s.cfg.Identity.RequireSignature,
		"Webhooks":        s.cfg.Webhooks,
		"CategoryWebhook": catWebhook,
	}

	s.renderTemplate(w, categoryDetailTmpl, data)
}

func (s *Server) handleAgentDetail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	agent, ok := s.cfg.Agents[name]
	if !ok {
		desc := "Discovered from traffic"
		if strings.HasPrefix(name, "gateway/") {
			desc = "MCP gateway tool: " + strings.TrimPrefix(name, "gateway/")
		}
		agent = config.Agent{Description: desc}
	}

	// Get recent messages for this agent
	entries, _ := s.audit.Query(audit.QueryOpts{Agent: name, Limit: 20})

	// Single SQL query for status counts (replaces loading 10k rows)
	stats, _ := s.audit.QueryAgentStats(name)
	if stats == nil {
		stats = &audit.StatusCounts{}
	}

	// Check if key exists and revocation status
	var keyFP string
	var keyRevoked bool
	if s.keys != nil {
		if pub, ok := s.keys.Get(name); ok {
			keyFP = identity.Fingerprint(pub)
			if revoked, err := s.audit.IsRevoked(keyFP); err != nil {
				s.logger.Warn("failed to check key revocation", "agent", name, "error", err)
			} else {
				keyRevoked = revoked
			}
		}
	}

	// Top triggered rules for this agent
	topRules, _ := s.audit.QueryAgentTopRules(name, 5, "")

	// Risk score for this agent (blended audit + LLM)
	var agentRiskData *audit.AgentRisk
	if agentRisks, err := s.audit.QueryAgentRisk(""); err == nil {
		for i, ar := range agentRisks {
			if ar.Agent == name {
				agentRiskData = &agentRisks[i]
				break
			}
		}
	}
	if agentRiskData == nil {
		agentRiskData = &audit.AgentRisk{}
	}

	// LLM threat history for this agent
	llmHistory, _ := s.audit.QueryLLMAgentHistory(name, "", 5)

	// Communication partners — edges involving this agent
	var commPartners []audit.EdgeStat
	if edges, err := s.audit.QueryEdgeStats(""); err == nil {
		for _, es := range edges {
			if es.From == name || es.To == name {
				commPartners = append(commPartners, es)
			}
		}
		if len(commPartners) > 10 {
			commPartners = commPartners[:10]
		}
	}

	data := map[string]any{
		"Active":       "agents",
		"Name":         name,
		"Agent":        agent,
		"Suspended":    agent.Suspended,
		"Entries":      entries,
		"TotalMsgs":    stats.Total,
		"Delivered":    stats.Delivered,
		"Blocked":      stats.Blocked,
		"Rejected":     stats.Rejected,
		"Quarantined":  stats.Quarantined,
		"KeyFP":        keyFP,
		"KeyRevoked":   keyRevoked,
		"RequireSig":   s.cfg.Identity.RequireSignature,
		"TopRules":     topRules,
		"RiskScore":    agentRiskData.RiskScore,
		"AgentRisk":    agentRiskData,
		"LLMHistory":   llmHistory,
		"LLMEnabled":   s.cfg.LLM.Enabled,
		"CommPartners": commPartners,
	}

	s.renderTemplate(w, agentDetailTmpl, data)
}

// HTMX partial: stats bar
func (s *Server) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	stats := s.getStats()
	s.renderJSON(w, stats)
}

// HTMX partial: recent events
func (s *Server) handleAPIRecent(w http.ResponseWriter, r *http.Request) {
	recent := s.getRecentEvents(5)
	s.renderTemplate(w, recentPartialTmpl, recent)
}

func (s *Server) handleAPIGraphStats(w http.ResponseWriter, r *http.Request) {
	sc, _ := s.audit.QueryStats()
	agentCount := len(s.cfg.Agents)
	toolCount := 0
	for range s.cfg.MCPServers {
		toolCount++
	}
	total, blocked := 0, 0
	if sc != nil {
		total = sc.Total
		blocked = sc.Blocked
	}
	s.renderJSON(w, map[string]int{
		"agents":   agentCount,
		"tools":    toolCount,
		"messages": total,
		"blocks":   blocked,
	})
}

func (s *Server) handleAPIGraphTables(w http.ResponseWriter, r *http.Request) {
	rangeStr := r.URL.Query().Get("range")
	if rangeStr == "" {
		rangeStr = "24h"
	}
	since := parseSinceRange(rangeStr)
	g := s.cachedBuildGraph(since)
	s.renderTemplate(w, graphTablesTmpl, g)
}

func (s *Server) handleAPIGraphEvents(w http.ResponseWriter, r *http.Request) {
	recent := s.getRecentEvents(12)
	s.renderTemplate(w, graphEventsTmpl, recent)
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
		s.logger.Error("revoke failed", "error", err)
		http.Error(w, "revoke failed", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/dashboard/agents/"+agentName, http.StatusFound)
}

func (s *Server) handleModeToggle(w http.ResponseWriter, r *http.Request) {
	s.cfg.Identity.RequireSignature = !s.cfg.Identity.RequireSignature

	if s.cfgPath != "" {
		if err := s.saveConfig(); err != nil {
			s.logger.Error("failed to save config after mode toggle", "error", err)
		}
	}

	http.Redirect(w, r, "/dashboard/settings", http.StatusFound)
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

const maxSearchLen = 200

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if len(q) > maxSearchLen {
		q = q[:maxSearchLen]
	}
	entries, _ := s.audit.Query(audit.QueryOpts{Search: q, Limit: 50})
	s.renderTemplate(w, searchResultsTmpl, entries)
}

// --- Export handlers ---

func parseExportLimit(r *http.Request) int {
	limit := 10000
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 50000 {
		limit = 50000
	}
	return limit
}

func (s *Server) handleExportCSV(w http.ResponseWriter, r *http.Request) {
	agent := r.URL.Query().Get("agent")
	since := r.URL.Query().Get("since")
	until := r.URL.Query().Get("until")
	redaction := audit.RedactionLevel(r.URL.Query().Get("redaction"))

	entries, err := s.audit.Query(audit.QueryOpts{Agent: agent, Since: since, Until: until, Limit: parseExportLimit(r)})
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}

	filename := "oktsec-audit-" + time.Now().Format("2006-01-02") + ".csv"
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")

	cw := csv.NewWriter(w)
	if redaction == audit.RedactExternal {
		_ = cw.Write([]string{"id", "timestamp", "from", "to", "status", "policy_decision"})
		for _, e := range entries {
			_ = cw.Write([]string{e.ID, e.Timestamp, e.FromAgent, e.ToAgent, e.Status, e.PolicyDecision})
		}
	} else {
		_ = cw.Write([]string{"id", "timestamp", "from", "to", "status", "signature_verified", "rules_triggered", "policy_decision", "latency_ms", "intent"})
		for _, e := range entries {
			rules := e.RulesTriggered
			if redaction == audit.RedactAnalyst {
				rules = audit.RedactRuleFindings(rules)
			}
			_ = cw.Write([]string{
				e.ID, e.Timestamp, e.FromAgent, e.ToAgent, e.Status,
				strconv.Itoa(e.SignatureVerified), rules, e.PolicyDecision, strconv.FormatInt(e.LatencyMs, 10), e.Intent,
			})
		}
	}
	cw.Flush()
}

func (s *Server) handleExportJSON(w http.ResponseWriter, r *http.Request) {
	agent := r.URL.Query().Get("agent")
	since := r.URL.Query().Get("since")
	until := r.URL.Query().Get("until")
	redaction := audit.RedactionLevel(r.URL.Query().Get("redaction"))

	entries, err := s.audit.Query(audit.QueryOpts{Agent: agent, Since: since, Until: until, Limit: parseExportLimit(r)})
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}

	filename := "oktsec-audit-" + time.Now().Format("2006-01-02") + ".json"
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")

	if redaction != "" {
		redacted := audit.RedactEntries(entries, redaction)
		if err := json.NewEncoder(w).Encode(redacted); err != nil {
			s.logger.Error("json export failed", "error", err)
		}
	} else {
		if err := json.NewEncoder(w).Encode(entries); err != nil {
			s.logger.Error("json export failed", "error", err)
		}
	}
}

// --- Report handler ---

type reportFinding struct {
	SeverityClass string
	SeverityLabel string
	CheckID       string
	Title         string
	Detail        string
	Remediation   string
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	stats := s.getStats()

	// Health score & findings
	findings, _, _ := s.cachedRunChecks()
	score, grade := auditcheck.ComputeHealthScore(findings)
	summary := auditcheck.Summarize(findings)

	// Convert findings for template
	var rptFindings []reportFinding
	for _, f := range findings {
		sevClass := "low"
		switch f.Severity {
		case auditcheck.Critical:
			sevClass = "critical"
		case auditcheck.High:
			sevClass = "high"
		case auditcheck.Medium:
			sevClass = "medium"
		}
		rptFindings = append(rptFindings, reportFinding{
			SeverityClass: sevClass,
			SeverityLabel: f.Severity.String(),
			CheckID:       f.CheckID,
			Title:         f.Title,
			Detail:        f.Detail,
			Remediation:   f.Remediation,
		})
	}

	detectionRate := 0
	if stats.TotalMessages > 0 {
		detectionRate = (stats.Blocked + stats.Rejected + stats.Quarantined) * 100 / stats.TotalMessages
	}
	unsigned, totalRecent, _ := s.audit.QueryUnsignedRate()
	unsignedPct := 0
	if totalRecent > 0 {
		unsignedPct = unsigned * 100 / totalRecent
	}
	avgLatency, _ := s.audit.QueryAvgLatency()
	topRules, _ := s.audit.QueryTopRules(10, "")
	agentRisks, _ := s.audit.QueryAgentRisk("")

	chainEntries, _ := s.audit.QueryChainEntries(100)
	chainResult := audit.VerifyChain(chainEntries, nil)

	qStats, _ := s.audit.QuarantineStats()

	var ruleCount int
	if s.scanner != nil {
		ruleCount = len(s.scanner.ListRules())
	}

	data := map[string]any{
		"GeneratedAt":    time.Now().Format("2006-01-02 15:04 MST"),
		"AgentCount":     len(s.cfg.Agents),
		"Score":          score,
		"Grade":          grade,
		"FindingSummary": summary,
		"Stats":          stats,
		"DetectionRate":  detectionRate,
		"UnsignedPct":    unsignedPct,
		"AvgLatency":     avgLatency,
		"ChainValid":     chainResult.Valid,
		"ChainCount":     chainResult.Entries,
		"AgentRisks":     agentRisks,
		"TopRules":       topRules,
		"Findings":       rptFindings,
		"QuarantineStats": qStats,
		"RequireSig":      s.cfg.Identity.RequireSignature,
		"DefaultPolicy":   s.cfg.DefaultPolicy,
		"RuleCount":       ruleCount,
		"CustomRulesDir":  s.cfg.CustomRulesDir,
		"GatewayEnabled":  s.cfg.Gateway.Enabled,
		"MCPServerCount":  len(s.cfg.MCPServers),
	}

	// Rate limit
	if s.cfg.RateLimit.PerAgent > 0 {
		data["RateLimit"] = s.cfg.RateLimit.PerAgent
	}

	// Anomaly
	data["AnomalyEnabled"] = s.cfg.Anomaly.RiskThreshold > 0
	data["AnomalyThreshold"] = s.cfg.Anomaly.RiskThreshold

	// Quarantine
	data["QuarantineEnabled"] = s.cfg.Quarantine.Enabled
	data["QuarantineTTL"] = fmt.Sprintf("%dh", s.cfg.Quarantine.ExpiryHours)

	s.populateLLMStats(data)

	s.renderTemplate(w, reportTmpl, data)
}

// --- Alerts handler ---

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	alerts, _ := s.audit.QueryAlerts(100, 0)
	stats, _ := s.audit.AlertStats()

	cooldown := s.cfg.Alerting.Cooldown
	eventTypeCount := len(stats.ByEvent)

	data := map[string]any{
		"Active":           "alerts",
		"RequireSig":       s.cfg.Identity.RequireSignature,
		"Alerts":           alerts,
		"Stats":            stats,
		"WebhookCount":     len(s.cfg.Webhooks),
		"WebhookChannels":  s.cfg.Webhooks,
		"EventTypeCount":   eventTypeCount,
		"Cooldown":         cooldown,
		"LLMThreats":      s.cfg.Alerting.LLMThreats || s.cfg.LLM.Enabled,
		"Suspensions":     s.cfg.Alerting.Suspensions,
	}

	s.renderTemplate(w, alertsTmpl, data)
}

// --- SARIF export handler ---

func (s *Server) handleExportSARIF(w http.ResponseWriter, r *http.Request) {
	findings, _, _ := s.cachedRunChecks()
	report := auditcheck.BuildSARIF(findings, Version)

	filename := "oktsec-audit-" + time.Now().Format("2006-01-02") + ".sarif.json"
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")

	if err := auditcheck.WriteSARIF(w, report); err != nil {
		s.logger.Error("sarif export failed", "error", err)
	}
}

// --- Bulk rule toggle handler ---

func (s *Server) handleBulkToggleRules(w http.ResponseWriter, r *http.Request) {
	action := r.FormValue("action")
	if action != "enable-all" && action != "disable-all" {
		http.Error(w, "action must be enable-all or disable-all", http.StatusBadRequest)
		return
	}

	if s.scanner == nil {
		http.Error(w, "no scanner loaded", http.StatusBadRequest)
		return
	}

	if action == "disable-all" {
		existingIDs := s.existingRuleIDSet()
		for _, ri := range s.scanner.ListRules() {
			if !existingIDs[ri.ID] {
				s.cfg.Rules = append(s.cfg.Rules, config.RuleAction{ID: ri.ID, Action: "ignore"})
			}
		}
	} else {
		// enable-all: remove all "ignore" overrides
		filtered := s.cfg.Rules[:0]
		for _, ra := range s.cfg.Rules {
			if ra.Action != "ignore" {
				filtered = append(filtered, ra)
			}
		}
		s.cfg.Rules = filtered
	}

	if s.cfgPath != "" {
		if err := s.saveConfig(); err != nil {
			s.logger.Error("failed to save config after bulk toggle", "error", err)
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}
	}

	http.Redirect(w, r, "/dashboard/rules", http.StatusFound)
}

// --- Event detail handler ---

type triggeredRule struct {
	RuleID   string `json:"rule_id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Match    string `json:"match"`
	Category string `json:"category"`
}

// buildEventData builds the shared template data map for an audit entry.
// Used by both the sidebar panel and the full event page.
func (s *Server) buildEventData(entry *audit.Entry) map[string]any {
	rules := parseTriggeredRules(entry.RulesTriggered)
	s.resolveRuleCategories(rules)

	data := map[string]any{
		"Entry":      entry,
		"Rules":      rules,
		"Decision":   humanReadableDecision(entry.PolicyDecision),
		"RequireSig": s.cfg.Identity.RequireSignature,
	}

	// Agent metadata
	if agent, ok := s.cfg.Agents[entry.FromAgent]; ok {
		data["AgentDesc"] = agent.Description
		data["AgentCreatedBy"] = agent.CreatedBy
		data["AgentCreatedAt"] = agent.CreatedAt
		data["AgentLocation"] = agent.Location
		data["AgentSuspended"] = agent.Suspended
		data["ToolConstraintCount"] = len(agent.ToolConstraints)
	}

	// LLM analysis
	var llmRiskScore float64 = -1
	var llmAction string
	if s.audit != nil {
		if la, _ := s.audit.QueryLLMAnalysisByMessage(entry.ID); la != nil {
			llmRiskScore = la.RiskScore
			llmAction = la.RecommendedAction
			data["LLMAnalysis"] = la
		}
	}
	data["LLMRiskScore"] = llmRiskScore
	data["LLMAction"] = llmAction

	// Rule count
	if s.scanner != nil {
		data["RuleCount"] = len(s.scanner.ListRules())
	}

	return data
}

func (s *Server) handleEventDetail(w http.ResponseWriter, r *http.Request) {
	entry, err := s.audit.QueryByID(r.PathValue("id"))
	if err != nil || entry == nil {
		s.handleNotFound(w, r)
		return
	}
	s.renderTemplate(w, eventDetailTmpl, s.buildEventData(entry))
}

func (s *Server) handleEventPage(w http.ResponseWriter, r *http.Request) {
	entry, err := s.audit.QueryByID(r.PathValue("id"))
	if err != nil || entry == nil {
		s.handleNotFound(w, r)
		return
	}
	data := s.buildEventData(entry)
	data["Active"] = "events"
	s.renderTemplate(w, eventPageTmpl, data)
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
	s.ruleCatMu.Lock()
	if s.ruleCatMap == nil {
		s.ruleCatMap = make(map[string]string)
		for _, ri := range s.scanner.ListRules() {
			s.ruleCatMap[ri.ID] = ri.Category
		}
	}
	catMap := s.ruleCatMap
	s.ruleCatMu.Unlock()

	for i := range rules {
		if cat, ok := catMap[rules[i].RuleID]; ok {
			rules[i].Category = cat
		}
	}
}

var decisionLabels = map[string]string{
	"allow":                  "Message delivered normally",
	"allowed":                "Message delivered normally",
	"content_blocked":        "Blocked — dangerous content detected",
	"content_flagged":        "Delivered with warning — content flagged",
	"content_quarantined":    "Held for review — suspicious content detected",
	"quarantine_approved":    "Reviewed and approved for delivery",
	"quarantine_rejected":    "Reviewed and rejected",
	"signature_required":     "Rejected — message was not signed",
	"acl_denied":             "Rejected — agent not authorized for this destination",
	"agent_suspended":        "Rejected — sender agent is suspended",
	"recipient_suspended":    "Rejected — recipient agent is suspended",
	"identity_rejected":      "Rejected — identity verification failed",
	"proxy_blocked_content":  "Blocked — proxy content filter",
	"proxy_blocked_domain":   "Blocked — restricted domain",
	"rate_limited":           "Rejected — rate limit exceeded",
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

	s.renderTemplate(w, ruleDetailTmpl, detail)
}

// --- Enforcement overrides handlers ---

func (s *Server) handleEnforcementOverrides(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{
		"Active":     "rules",
		"Overrides":  s.cfg.Rules,
		"RequireSig": s.cfg.Identity.RequireSignature,
	}

	s.renderTemplate(w, enforcementTmpl, data)
}

func (s *Server) handleSaveEnforcement(w http.ResponseWriter, r *http.Request) {
	ruleID := strings.TrimSpace(r.FormValue("rule_id"))
	severity := r.FormValue("severity")
	action := r.FormValue("action")

	if ruleID == "" || action == "" {
		http.Error(w, "rule_id and action required", http.StatusBadRequest)
		return
	}

	// Merge notify sources: named channels from checkboxes + raw URLs from textarea
	var notify []string
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form data", http.StatusBadRequest)
		return
	}
	for _, ch := range r.Form["notify_channel"] {
		if ch = strings.TrimSpace(ch); ch != "" {
			notify = append(notify, ch)
		}
	}
	for _, line := range strings.Split(r.FormValue("notify_urls"), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			notify = append(notify, line)
		}
	}
	tmpl := strings.TrimSpace(r.FormValue("template"))

	// Update existing or append new
	found := false
	for i := range s.cfg.Rules {
		if s.cfg.Rules[i].ID == ruleID {
			s.cfg.Rules[i].Severity = severity
			s.cfg.Rules[i].Action = action
			s.cfg.Rules[i].Notify = notify
			s.cfg.Rules[i].Template = tmpl
			found = true
			break
		}
	}
	if !found {
		s.cfg.Rules = append(s.cfg.Rules, config.RuleAction{
			ID:       ruleID,
			Severity: severity,
			Action:   action,
			Notify:   notify,
			Template: tmpl,
		})
	}

	if s.cfgPath != "" {
		if err := s.saveConfig(); err != nil {
			s.logger.Error("failed to save config after enforcement update", "error", err)
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}
	}

	http.Redirect(w, r, "/dashboard/rules?tab=enforcement", http.StatusFound)
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
		if err := s.saveConfig(); err != nil {
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
				cf := customRuleFile{
					Filename: e.Name(),
					ID:       strings.TrimSuffix(e.Name(), ext),
				}
				if s.scanner != nil {
					ruleID := strings.ToUpper(cf.ID)
					if detail, err := s.scanner.ExplainRule(ruleID); err == nil && detail != nil {
						cf.Name = detail.Name
						cf.Severity = detail.Severity
						cf.PatternCount = len(detail.Patterns)
					}
				}
				customFiles = append(customFiles, cf)
			}
		}
	}

	data := map[string]any{
		"Active":         "rules",
		"CustomFiles":    customFiles,
		"CustomRulesDir": s.cfg.CustomRulesDir,
		"RequireSig":     s.cfg.Identity.RequireSignature,
	}

	s.renderTemplate(w, customRulesTmpl, data)
}

type customRuleFile struct {
	Filename     string
	ID           string
	Name         string
	Severity     string
	PatternCount int
}

func (s *Server) handleCreateCustomRule(w http.ResponseWriter, r *http.Request) {
	// Auto-provision custom_rules_dir if not configured
	if s.cfg.CustomRulesDir == "" {
		dir := "custom-rules"
		if s.cfgPath != "" {
			dir = filepath.Join(filepath.Dir(s.cfgPath), "custom-rules")
		}
		s.cfg.CustomRulesDir = dir
		if s.cfgPath != "" {
			if err := s.saveConfig(); err != nil {
				s.logger.Error("failed to save config after auto-provisioning custom_rules_dir", "error", err)
			}
		}
		if s.scanner != nil {
			s.scanner.AddCustomRulesDir(dir)
		}
	}

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	patterns := splitNonEmpty(r.FormValue("patterns"), "\n")
	if len(patterns) == 0 {
		http.Error(w, "at least one pattern is required", http.StatusBadRequest)
		return
	}

	ruleID := normalizeCustomRuleID(strings.TrimSpace(r.FormValue("rule_id")), name)
	yamlContent := buildCustomRuleYAML(ruleID, name, r.FormValue("severity"), strings.TrimSpace(r.FormValue("category")), patterns)

	// Validate the generated YAML before writing
	var validateBuf map[string]any
	if err := yaml.Unmarshal([]byte(yamlContent), &validateBuf); err != nil {
		s.logger.Warn("invalid YAML in custom rule", "error", err)
		http.Error(w, "Generated YAML is invalid — check syntax and try again", http.StatusBadRequest)
		return
	}

	if err := os.MkdirAll(s.cfg.CustomRulesDir, 0o755); err != nil {
		http.Error(w, "cannot create custom rules dir", http.StatusInternalServerError)
		return
	}

	filename := filepath.Join(s.cfg.CustomRulesDir, ruleID+".yaml")
	if err := os.WriteFile(filename, []byte(yamlContent), 0o644); err != nil {
		s.logger.Error("write failed", "error", err)
		http.Error(w, "write failed", http.StatusInternalServerError)
		return
	}

	// Invalidate rule cache so the new rule appears immediately
	if s.scanner != nil {
		s.scanner.InvalidateCache()
		s.ruleCatMu.Lock()
		s.ruleCatMap = nil
		s.ruleCatMu.Unlock()
	}

	http.Redirect(w, r, "/dashboard/rules?tab=custom", http.StatusFound)
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

// safeRuleID validates that a rule ID contains only safe characters.
var safeRuleIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

func (s *Server) handleDeleteCustomRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !safeRuleIDRe.MatchString(id) {
		http.Error(w, "invalid rule ID", http.StatusBadRequest)
		return
	}
	if s.cfg.CustomRulesDir == "" {
		http.Error(w, "no custom rules configured", http.StatusBadRequest)
		return
	}

	// Try both .yaml and .yml extensions
	for _, ext := range []string{".yaml", ".yml"} {
		path := filepath.Join(s.cfg.CustomRulesDir, id+ext)
		if _, err := os.Stat(path); err == nil {
			if err := os.Remove(path); err != nil {
				s.logger.Error("delete failed", "error", err)
				http.Error(w, "delete failed", http.StatusInternalServerError)
				return
			}
			if s.scanner != nil {
				s.scanner.InvalidateCache()
				s.ruleCatMu.Lock()
				s.ruleCatMap = nil
				s.ruleCatMu.Unlock()
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(nil) // empty response — HTMX removes the row
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

	s.renderTemplate(w, quarantineDetailTmpl, data)
}

func (s *Server) handleQuarantineApprove(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.audit.QuarantineApprove(id, "dashboard"); err != nil {
		s.logger.Error("quarantine approve failed", "id", id, "error", err)
		http.Error(w, "approve failed", http.StatusBadRequest)
		return
	}

	item, _ := s.audit.QuarantineByID(id)
	data := map[string]any{"Item": item}
	s.renderTemplate(w, quarantineRowTmpl, data)
}

func (s *Server) handleQuarantineReject(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.audit.QuarantineReject(id, "dashboard"); err != nil {
		s.logger.Error("quarantine reject failed", "id", id, "error", err)
		http.Error(w, "reject failed", http.StatusBadRequest)
		return
	}

	item, _ := s.audit.QuarantineByID(id)
	data := map[string]any{"Item": item}
	s.renderTemplate(w, quarantineRowTmpl, data)
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

	blockedContent := strings.Fields(strings.ReplaceAll(r.FormValue("blocked_content"), ",", " "))
	allowedTools := strings.Fields(strings.ReplaceAll(r.FormValue("allowed_tools"), ",", " "))

	s.cfg.Agents[name] = config.Agent{
		CanMessage:     canMessage,
		Description:    strings.TrimSpace(r.FormValue("description")),
		CreatedBy:      "dashboard",
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
		Location:       strings.TrimSpace(r.FormValue("location")),
		Tags:           tags,
		BlockedContent: blockedContent,
		AllowedTools:   allowedTools,
	}

	if s.cfgPath != "" {
		if err := s.saveConfig(); err != nil {
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
	agent.BlockedContent = strings.Fields(strings.ReplaceAll(r.FormValue("blocked_content"), ",", " "))
	agent.AllowedTools = strings.Fields(strings.ReplaceAll(r.FormValue("allowed_tools"), ",", " "))

	// Parse tool policies from form
	if policyTools := strings.Fields(strings.ReplaceAll(r.FormValue("policy_tools"), ",", " ")); len(policyTools) > 0 {
		if agent.ToolPolicies == nil {
			agent.ToolPolicies = make(map[string]config.ToolPolicy)
		}
		for _, toolName := range policyTools {
			prefix := "tp_" + toolName + "_"
			var tp config.ToolPolicy
			if v := strings.TrimSpace(r.FormValue(prefix + "max_amount")); v != "" {
				if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
					tp.MaxAmount = f
				}
			}
			if v := strings.TrimSpace(r.FormValue(prefix + "daily_limit")); v != "" {
				if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
					tp.DailyLimit = f
				}
			}
			if v := strings.TrimSpace(r.FormValue(prefix + "require_approval")); v != "" {
				if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
					tp.RequireApprovalAbove = f
				}
			}
			if v := strings.TrimSpace(r.FormValue(prefix + "rate_limit")); v != "" {
				if n, err := strconv.Atoi(v); err == nil && n > 0 {
					tp.RateLimit = n
				}
			}
			if tp.MaxAmount > 0 || tp.DailyLimit > 0 || tp.RequireApprovalAbove > 0 || tp.RateLimit > 0 {
				agent.ToolPolicies[toolName] = tp
			}
		}
	}

	s.cfg.Agents[name] = agent

	if s.cfgPath != "" {
		if err := s.saveConfig(); err != nil {
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
		if err := s.saveConfig(); err != nil {
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
		s.logger.Error("keygen failed", "error", err)
		http.Error(w, "keygen failed", http.StatusInternalServerError)
		return
	}

	if err := os.MkdirAll(s.cfg.Identity.KeysDir, 0o700); err != nil {
		s.logger.Error("cannot create keys dir", "error", err)
		http.Error(w, "cannot create keys directory", http.StatusInternalServerError)
		return
	}

	if err := kp.Save(s.cfg.Identity.KeysDir); err != nil {
		s.logger.Error("save failed", "error", err)
		http.Error(w, "save failed", http.StatusInternalServerError)
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
		if err := s.saveConfig(); err != nil {
			s.logger.Error("failed to save config after rule toggle", "error", err)
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}
	}

	// Return the updated toggle button
	enabled := isDisabled // flipped
	s.renderTemplate(w, ruleToggleTmpl, map[string]any{"ID": id, "Enabled": enabled})
}

func (s *Server) handleToggleCategory(w http.ResponseWriter, r *http.Request) {
	catName := r.PathValue("name")

	ruleIDs := s.categoryRuleIDs(catName)
	if len(ruleIDs) == 0 {
		http.NotFound(w, r)
		return
	}

	disabledSet := s.disabledRuleSet()
	existingIDs := s.existingRuleIDSet()
	disabledCount := countInSet(ruleIDs, disabledSet)

	// If most are enabled → disable all; if most disabled → enable all
	if disabledCount < len(ruleIDs)/2+1 {
		s.disableCategoryRules(ruleIDs, existingIDs)
	} else {
		s.enableCategoryRules(ruleIDs)
	}

	if s.cfgPath != "" {
		if err := s.saveConfig(); err != nil {
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

func (s *Server) existingRuleIDSet() map[string]bool {
	set := make(map[string]bool, len(s.cfg.Rules))
	for _, ra := range s.cfg.Rules {
		set[ra.ID] = true
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

func (s *Server) disableCategoryRules(ruleIDs []string, existingIDs map[string]bool) {
	for _, id := range ruleIDs {
		if !existingIDs[id] {
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

func (s *Server) handleSuspendToggle(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	agent, ok := s.cfg.Agents[name]
	if !ok {
		http.NotFound(w, r)
		return
	}

	agent.Suspended = !agent.Suspended
	s.cfg.Agents[name] = agent

	if s.cfgPath != "" {
		if err := s.saveConfig(); err != nil {
			s.logger.Error("failed to save config after suspend toggle", "error", err)
		}
	}

	http.Redirect(w, r, "/dashboard/agents/"+name, http.StatusFound)
}

// --- Events handler (merged audit log + quarantine) ---

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	tab := r.URL.Query().Get("tab")
	if tab == "" {
		tab = "all"
	}

	// Read filter params
	filterAgent := r.URL.Query().Get("agent")
	filterSince := r.URL.Query().Get("since")
	filterUntil := r.URL.Query().Get("until")

	// Extract YYYY-MM-DD for <input type="date"> display (ignores the T... suffix)
	displaySince := dateOnly(filterSince)
	displayUntil := dateOnly(filterUntil)

	// Quarantine stats always loaded (cheap query, needed for badge count)
	qStats, _ := s.audit.QuarantineStats()
	if qStats == nil {
		qStats = &audit.QuarantineStats{}
	}

	var entries []audit.Entry
	var qItems []audit.QuarantineItem
	var blockedEntries []audit.Entry
	qStatusFilter := r.URL.Query().Get("status")

	// Only query data for the active tab
	switch tab {
	case "quarantine":
		if qStatusFilter == "" {
			qStatusFilter = audit.QStatusPending
		}
		qItems, _ = s.audit.QuarantineQuery(qStatusFilter, filterAgent, 50)
	case "blocked":
		blockedEntries, _ = s.audit.Query(audit.QueryOpts{Statuses: []string{audit.StatusBlocked, audit.StatusRejected}, Agent: filterAgent, Since: filterSince, Until: filterUntil, Limit: 50})
	default: // "all"
		entries, _ = s.audit.Query(audit.QueryOpts{Agent: filterAgent, Since: filterSince, Until: filterUntil, Limit: 50})
	}

	// Build sorted agent names for filter dropdown
	agentNames := make([]string, 0, len(s.cfg.Agents))
	for name := range s.cfg.Agents {
		agentNames = append(agentNames, name)
	}
	sort.Strings(agentNames)

	data := map[string]any{
		"Active":         "events",
		"Tab":            tab,
		"Entries":        entries,
		"QItems":         qItems,
		"QStats":         qStats,
		"QStatusFilter":  qStatusFilter,
		"QPending":       qStats.Pending,
		"BlockedEntries": blockedEntries,
		"RequireSig":     s.cfg.Identity.RequireSignature,
		"AgentNames":     agentNames,
		"FilterAgent":    filterAgent,
		"FilterSince":    displaySince,
		"FilterUntil":    displayUntil,
	}

	s.renderTemplate(w, eventsTmpl, data)
}

// --- Settings handler ---

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	tab := r.URL.Query().Get("tab")
	switch tab {
	case "pipeline":
		tab = "protection" // backwards compat
	case "identity":
		tab = "security" // identity tab removed
	case "":
		tab = "security"
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
		"Tab":            tab,
		"RequireSig":     s.cfg.Identity.RequireSignature,
		"QEnabled":       s.cfg.Quarantine.Enabled,
		"QExpiryHours":   s.cfg.Quarantine.ExpiryHours,
		"QPending":       qPending,
		"ServerPort":     s.cfg.Server.Port,
		"ServerBind":     serverBind,
		"LogLevel":       s.cfg.Server.LogLevel,
		"CustomRulesDir": s.cfg.CustomRulesDir,
		"WebhookCount":   len(s.cfg.Webhooks),

		"DefaultPolicy":        s.cfg.DefaultPolicy,
		"RateLimitPerAgent":    s.cfg.RateLimit.PerAgent,
		"RateLimitWindow":      s.cfg.RateLimit.WindowS,
		"AnomalyCheckInterval": s.cfg.Anomaly.CheckIntervalS,
		"AnomalyRiskThreshold": s.cfg.Anomaly.RiskThreshold,
		"AnomalyMinMessages":   s.cfg.Anomaly.MinMessages,
		"AnomalyAutoSuspend":   s.cfg.Anomaly.AutoSuspend,
		"FPEnabled":            s.cfg.ForwardProxy.Enabled,
		"FPAllowedDomains":     strings.Join(s.cfg.ForwardProxy.AllowedDomains, "\n"),
		"FPBlockedDomains":     strings.Join(s.cfg.ForwardProxy.BlockedDomains, "\n"),
		"FPScanRequests":       s.cfg.ForwardProxy.ScanRequests,
		"FPScanResponses":      s.cfg.ForwardProxy.ScanResponses,
		"FPMaxBodySize":        s.cfg.ForwardProxy.MaxBodySize,
		"QRetentionDays":       s.cfg.Quarantine.RetentionDays,
		"RequireIntent":        s.cfg.Server.RequireIntent,
	}

	s.renderTemplate(w, settingsTmpl, data)
}

// --- LLM page handler ---

func (s *Server) handleLLM(w http.ResponseWriter, r *http.Request) {
	llmStats, _ := s.audit.QueryLLMStats()
	if llmStats == nil {
		llmStats = &audit.LLMStats{}
	}

	analyses, _ := s.audit.QueryLLMAnalyses(100)

	var budgetStatus *llm.BudgetStatus
	if s.llmQueue != nil && s.llmQueue.Budget() != nil {
		bs := s.llmQueue.Budget().Status()
		budgetStatus = &bs
	}

	triageCounts := s.audit.QueryLLMTriageCounts()

	data := map[string]any{
		"Active":       "llm",
		"Enabled":      s.cfg.LLM.Enabled,
		"Cfg":          s.cfg.LLM,
		"Stats":        llmStats,
		"Analyses":     analyses,
		"BudgetStatus": budgetStatus,
		"Triage":       triageCounts,
	}

	s.renderTemplate(w, llmTmpl, data)
}

func (s *Server) handleLLMDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, err := s.audit.QueryLLMAnalysisByID(id)
	if err != nil || a == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.renderTemplate(w, llmDetailTmpl, a)
}

func (s *Server) handleLLMCase(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, err := s.audit.QueryLLMAnalysisByID(id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if a == nil {
		// Fallback: try as message_id for backwards compatibility
		a, err = s.audit.QueryLLMAnalysisByMessage(id)
		if err != nil || a == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
	}
	agentSuspended := false
	if agent, ok := s.cfg.Agents[a.FromAgent]; ok {
		agentSuspended = agent.Suspended
	}
	agentHistory, _ := s.audit.QueryLLMAgentHistory(a.FromAgent, a.ID, 5)

	// Fetch original audit entry to show the content that triggered the analysis
	var toolArgs string
	if a.MessageID != "" {
		if entry, err := s.audit.QueryByID(a.MessageID); err == nil && entry != nil {
			toolArgs = entry.Intent
		}
	}

	data := map[string]any{
		"Active":         "llm",
		"Analysis":       a,
		"AgentSuspended": agentSuspended,
		"AgentHistory":   agentHistory,
		"ToolArgs":       toolArgs,
	}
	s.renderTemplate(w, llmCaseTmpl, data)
}

func (s *Server) handleLLMDismiss(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	if err := s.audit.UpdateLLMReviewStatus(id, "false_positive"); err != nil {
		s.logger.Error("llm dismiss failed", "id", id, "error", err)
		http.Error(w, "failed", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<span class="ci-reviewed" style="background:rgba(63,185,80,0.1);color:#3fb950">&#10003; Dismissed as false positive</span>`)
}

func (s *Server) handleLLMConfirm(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	if err := s.audit.UpdateLLMReviewStatus(id, "confirmed"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<span class="ci-reviewed" style="background:rgba(248,81,73,0.1);color:#f85149">&#10003; Confirmed as real threat</span>`)
}

func (s *Server) handleApproveLLMRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	if s.ruleGen == nil {
		http.Error(w, "rule generator not configured", http.StatusInternalServerError)
		return
	}
	if err := s.ruleGen.ApproveRule(id); err != nil {
		s.logger.Error("approve llm rule failed", "id", id, "error", err)
		http.Error(w, "failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Reload detection rules if scanner supports it
	if s.scanner != nil {
		s.scanner.InvalidateCache()
		s.ruleCatMu.Lock()
		s.ruleCatMap = nil
		s.ruleCatMu.Unlock()
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<span style="color:var(--success);font-weight:600;font-size:0.82rem">&#10003; Approved &mdash; rule is now active</span>`)
}

func (s *Server) handleRejectLLMRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	if s.ruleGen == nil {
		http.Error(w, "rule generator not configured", http.StatusInternalServerError)
		return
	}
	if err := s.ruleGen.RejectRule(id); err != nil {
		s.logger.Error("reject llm rule failed", "id", id, "error", err)
		http.Error(w, "failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<span style="color:var(--text3);font-size:0.82rem">&#10003; Rejected</span>`)
}

func (s *Server) handleDeactivateLLMRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	if s.ruleGen == nil {
		http.Error(w, "rule generator not configured", http.StatusInternalServerError)
		return
	}
	if err := s.ruleGen.DeactivateRule(id); err != nil {
		s.logger.Error("deactivate llm rule failed", "id", id, "error", err)
		http.Error(w, "failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if s.scanner != nil {
		s.scanner.InvalidateCache()
		s.ruleCatMu.Lock()
		s.ruleCatMap = nil
		s.ruleCatMu.Unlock()
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<span style="color:var(--text3);font-size:0.82rem">&#10003; Deactivated</span>`)
}

// --- Settings section handlers ---

func (s *Server) handleSaveLLM(w http.ResponseWriter, r *http.Request) {
	s.cfg.LLM.Enabled = r.FormValue("enabled") == "true"

	provider := r.FormValue("provider")
	switch provider {
	case "openai", "claude", "webhook":
		s.cfg.LLM.Provider = provider
	default:
		http.Error(w, "invalid provider", http.StatusBadRequest)
		return
	}

	s.cfg.LLM.Model = r.FormValue("model")
	s.cfg.LLM.BaseURL = r.FormValue("base_url")
	s.cfg.LLM.APIKey = r.FormValue("api_key")
	s.cfg.LLM.APIKeyEnv = r.FormValue("api_key_env")
	if v := r.FormValue("timeout"); v != "" {
		s.cfg.LLM.Timeout = v
	}

	if v := r.FormValue("max_tokens"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			s.cfg.LLM.MaxTokens = n
		}
	}
	if v := r.FormValue("temperature"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 && f <= 2 {
			s.cfg.LLM.Temperature = f
		}
	}
	if v := r.FormValue("max_concurrent"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			s.cfg.LLM.MaxConcurrent = n
		}
	}
	if v := r.FormValue("queue_size"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			s.cfg.LLM.QueueSize = n
		}
	}
	if v := r.FormValue("max_daily"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			s.cfg.LLM.MaxDailyReqs = n
		}
	}

	s.cfg.LLM.Analyze.Clean = r.FormValue("analyze_clean") == "true"
	s.cfg.LLM.Analyze.Flagged = r.FormValue("analyze_flagged") == "true"
	s.cfg.LLM.Analyze.Quarantined = r.FormValue("analyze_quarantined") == "true"
	s.cfg.LLM.Analyze.Blocked = r.FormValue("analyze_blocked") == "true"

	// Budget limits
	if v := r.FormValue("budget_daily"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 {
			s.cfg.LLM.Budget.DailyLimitUSD = f
		}
	}
	if v := r.FormValue("budget_monthly"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 {
			s.cfg.LLM.Budget.MonthlyLimitUSD = f
		}
	}
	if v := r.FormValue("budget_warn"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 && f <= 100 {
			s.cfg.LLM.Budget.WarnThreshold = f / 100 // store as fraction
		}
	}
	if ol := r.FormValue("budget_on_limit"); ol == "skip" || ol == "block" {
		s.cfg.LLM.Budget.OnLimit = ol
	}

	// Hot-reload budget limits into tracker
	if s.llmQueue != nil && s.llmQueue.Budget() != nil {
		s.llmQueue.Budget().UpdateConfig(llm.BudgetConfig{
			DailyLimitUSD:   s.cfg.LLM.Budget.DailyLimitUSD,
			MonthlyLimitUSD: s.cfg.LLM.Budget.MonthlyLimitUSD,
			WarnThreshold:   s.cfg.LLM.Budget.WarnThreshold,
			OnLimit:         s.cfg.LLM.Budget.OnLimit,
		})
	}

	s.cfg.LLM.RuleGen.Enabled = r.FormValue("rulegen_enabled") == "true"
	s.cfg.LLM.RuleGen.RequireApproval = r.FormValue("rulegen_approval") == "true"
	s.cfg.LLM.RuleGen.OutputDir = r.FormValue("rulegen_dir")
	if v := r.FormValue("rulegen_confidence"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 && f <= 1 {
			s.cfg.LLM.RuleGen.MinConfidence = f
		}
	}

	if s.cfgPath != "" {
		if err := s.saveConfig(); err != nil {
			s.logger.Error("failed to save config after LLM update", "error", err)
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}
	}
	http.Redirect(w, r, "/dashboard/llm", http.StatusFound)
}

func (s *Server) handleToggleLLM(w http.ResponseWriter, r *http.Request) {
	s.cfg.LLM.Enabled = !s.cfg.LLM.Enabled
	if s.cfgPath != "" {
		_ = s.saveConfig()
	}
	w.Header().Set("Content-Type", "text/html")
	if s.cfg.LLM.Enabled {
		fmt.Fprintf(w, `<button class="btn btn-sm" style="background:var(--surface2);color:var(--text2);font-size:0.72rem;padding:4px 12px" hx-post="/dashboard/api/llm/toggle" hx-swap="innerHTML" hx-target="#llm-toggle-wrap" hx-confirm="Disable AI analysis? Threat detection will rely on rules only.">Disable</button>`)
	} else {
		fmt.Fprintf(w, `<button class="btn btn-sm btn-success" style="font-size:0.72rem;padding:4px 12px" hx-post="/dashboard/api/llm/toggle" hx-swap="innerHTML" hx-target="#llm-toggle-wrap">Enable</button>`)
	}
}

func (s *Server) handleTestLLM(w http.ResponseWriter, r *http.Request) {
	if s.llmQueue == nil {
		s.renderJSON(w, map[string]any{"ok": false, "error": "LLM analysis is not running"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	start := time.Now()
	_, err := s.llmQueue.TestConnection(ctx)
	elapsed := time.Since(start).Milliseconds()

	if err != nil {
		s.renderJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	s.renderJSON(w, map[string]any{
		"ok":      true,
		"latency": elapsed,
		"model":   s.cfg.LLM.Model,
	})
}

func (s *Server) handleSaveDefaultPolicy(w http.ResponseWriter, r *http.Request) {
	policy := r.FormValue("default_policy")
	if policy != "allow" && policy != "deny" {
		http.Error(w, "invalid policy (must be allow or deny)", http.StatusBadRequest)
		return
	}
	s.cfg.DefaultPolicy = policy
	if s.cfgPath != "" {
		if err := s.saveConfig(); err != nil {
			s.logger.Error("failed to save config after default policy update", "error", err)
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}
	}
	http.Redirect(w, r, "/dashboard/settings", http.StatusFound)
}

func (s *Server) handleSaveRateLimit(w http.ResponseWriter, r *http.Request) {
	perAgent, err := strconv.Atoi(r.FormValue("per_agent"))
	if err != nil || perAgent < 0 {
		http.Error(w, "per_agent must be a non-negative integer", http.StatusBadRequest)
		return
	}
	window, err := strconv.Atoi(r.FormValue("window"))
	if err != nil || window < 1 {
		http.Error(w, "window must be a positive integer", http.StatusBadRequest)
		return
	}
	s.cfg.RateLimit.PerAgent = perAgent
	s.cfg.RateLimit.WindowS = window
	if s.cfgPath != "" {
		if err := s.saveConfig(); err != nil {
			s.logger.Error("failed to save config after rate limit update", "error", err)
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}
	}
	http.Redirect(w, r, "/dashboard/settings", http.StatusFound)
}

func (s *Server) handleSaveAnomaly(w http.ResponseWriter, r *http.Request) {
	checkInterval, err := strconv.Atoi(r.FormValue("check_interval"))
	if err != nil || checkInterval < 1 {
		http.Error(w, "check_interval must be a positive integer", http.StatusBadRequest)
		return
	}
	riskThreshold, err := strconv.ParseFloat(r.FormValue("risk_threshold"), 64)
	if err != nil || riskThreshold < 0 || riskThreshold > 100 {
		http.Error(w, "risk_threshold must be between 0 and 100", http.StatusBadRequest)
		return
	}
	minMessages, err := strconv.Atoi(r.FormValue("min_messages"))
	if err != nil || minMessages < 0 {
		http.Error(w, "min_messages must be a non-negative integer", http.StatusBadRequest)
		return
	}
	s.cfg.Anomaly.CheckIntervalS = checkInterval
	s.cfg.Anomaly.RiskThreshold = riskThreshold
	s.cfg.Anomaly.MinMessages = minMessages
	s.cfg.Anomaly.AutoSuspend = r.FormValue("auto_suspend") == "true"
	if s.cfgPath != "" {
		if err := s.saveConfig(); err != nil {
			s.logger.Error("failed to save config after anomaly update", "error", err)
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}
	}
	http.Redirect(w, r, "/dashboard/settings", http.StatusFound)
}

func (s *Server) handleSaveIntent(w http.ResponseWriter, r *http.Request) {
	s.cfg.Server.RequireIntent = r.FormValue("require_intent") == "true"
	if s.cfgPath != "" {
		if err := s.saveConfig(); err != nil {
			s.logger.Error("failed to save config after intent update", "error", err)
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}
	}
	http.Redirect(w, r, "/dashboard/settings", http.StatusFound)
}

func (s *Server) handleSaveForwardProxy(w http.ResponseWriter, r *http.Request) {
	s.cfg.ForwardProxy.Enabled = r.FormValue("enabled") == "true"
	s.cfg.ForwardProxy.ScanRequests = r.FormValue("scan_requests") == "true"
	s.cfg.ForwardProxy.ScanResponses = r.FormValue("scan_responses") == "true"
	s.cfg.ForwardProxy.AllowedDomains = parseDomainList(r.FormValue("allowed_domains"))
	s.cfg.ForwardProxy.BlockedDomains = parseDomainList(r.FormValue("blocked_domains"))
	maxBody, err := strconv.ParseInt(r.FormValue("max_body_size"), 10, 64)
	if err != nil || maxBody < 0 {
		http.Error(w, "max_body_size must be a non-negative integer", http.StatusBadRequest)
		return
	}
	s.cfg.ForwardProxy.MaxBodySize = maxBody
	if s.cfgPath != "" {
		if err := s.saveConfig(); err != nil {
			s.logger.Error("failed to save config after forward proxy update", "error", err)
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}
	}
	http.Redirect(w, r, "/dashboard/settings", http.StatusFound)
}

func (s *Server) handleSaveQuarantine(w http.ResponseWriter, r *http.Request) {
	expiryHours, err := strconv.Atoi(r.FormValue("expiry_hours"))
	if err != nil || expiryHours < 1 {
		http.Error(w, "expiry_hours must be a positive integer", http.StatusBadRequest)
		return
	}
	retentionDays, err := strconv.Atoi(r.FormValue("retention_days"))
	if err != nil || retentionDays < 0 {
		http.Error(w, "retention_days must be a non-negative integer", http.StatusBadRequest)
		return
	}
	s.cfg.Quarantine.Enabled = r.FormValue("enabled") == "true"
	s.cfg.Quarantine.ExpiryHours = expiryHours
	s.cfg.Quarantine.RetentionDays = retentionDays
	if s.cfgPath != "" {
		if err := s.saveConfig(); err != nil {
			s.logger.Error("failed to save config after quarantine update", "error", err)
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}
	}
	http.Redirect(w, r, "/dashboard/settings", http.StatusFound)
}

// parseDomainList splits a newline-delimited textarea value into a trimmed domain slice.
func parseDomainList(raw string) []string {
	var domains []string
	for _, line := range strings.Split(raw, "\n") {
		d := strings.TrimSpace(line)
		if d != "" {
			domains = append(domains, d)
		}
	}
	return domains
}

// --- Webhook channel handlers ---

var webhookNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

func (s *Server) handleSaveWebhookChannel(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	url := strings.TrimSpace(r.FormValue("url"))

	if name == "" || !webhookNameRe.MatchString(name) {
		http.Error(w, "invalid channel name (alphanumeric, hyphens, underscores)", http.StatusBadRequest)
		return
	}
	if url == "" || !strings.Contains(url, "://") {
		http.Error(w, "a valid URL is required", http.StatusBadRequest)
		return
	}

	// Update existing or append new
	found := false
	for i := range s.cfg.Webhooks {
		if s.cfg.Webhooks[i].Name == name {
			s.cfg.Webhooks[i].URL = url
			found = true
			break
		}
	}
	if !found {
		s.cfg.Webhooks = append(s.cfg.Webhooks, config.Webhook{
			Name:   name,
			URL:    url,
			Events: []string{audit.AlertEventBlocked, audit.AlertEventQuarantined},
		})
	}

	if s.cfgPath != "" {
		if err := s.saveConfig(); err != nil {
			s.logger.Error("failed to save config after webhook channel update", "error", err)
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}
	}

	http.Redirect(w, r, "/dashboard/alerts", http.StatusFound)
}

func (s *Server) handleDeleteWebhookChannel(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	filtered := s.cfg.Webhooks[:0]
	for _, wh := range s.cfg.Webhooks {
		if wh.Name != name {
			filtered = append(filtered, wh)
		}
	}
	s.cfg.Webhooks = filtered

	if s.cfgPath != "" {
		if err := s.saveConfig(); err != nil {
			s.logger.Error("failed to save config after webhook channel delete", "error", err)
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
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

// configDir returns the directory containing the config file, resolving "." to cwd.
func (s *Server) configDir() string {
	dir := filepath.Dir(s.cfgPath)
	if dir == "." {
		if wd, err := os.Getwd(); err == nil {
			return wd
		}
	}
	return dir
}

// populateLLMStats adds LLM statistics to a template data map.
func (s *Server) populateLLMStats(data map[string]any) {
	data["LLMEnabled"] = s.cfg.LLM.Enabled
	if !s.cfg.LLM.Enabled {
		return
	}
	data["LLMProvider"] = s.cfg.LLM.Model
	llmStats, err := s.audit.QueryLLMStats()
	if err == nil && llmStats != nil {
		data["LLMCompleted"] = llmStats.TotalAnalyses
		data["LLMThreats"] = llmStats.TotalThreats
		data["LLMAvgRisk"] = llmStats.AvgRiskScore
		data["LLMTokens"] = llmStats.TotalTokens
		data["LLMRulesGen"] = llmStats.RulesGenerated
	} else {
		data["LLMCompleted"] = 0
		data["LLMThreats"] = 0
		data["LLMAvgRisk"] = 0.0
		data["LLMTokens"] = 0
		data["LLMRulesGen"] = 0
	}
}

// --- Graph handlers ---

// buildAgentRemap creates a mapping from slugified agent names (from hooks)
// to clean config agent names using bidirectional token matching.
func (s *Server) buildAgentRemap() map[string]string {
	remap := make(map[string]string)
	configNames := make([]string, 0, len(s.cfg.Agents))
	for name := range s.cfg.Agents {
		configNames = append(configNames, name)
	}
	// For each config agent, pre-compute tokens.
	type agentTokens struct {
		name   string
		tokens []string
	}
	var cfgTokens []agentTokens
	for _, name := range configNames {
		parts := strings.Split(name, "-")
		var tokens []string
		for _, p := range parts {
			if len(p) >= 3 {
				tokens = append(tokens, p)
			}
		}
		if len(tokens) > 0 {
			cfgTokens = append(cfgTokens, agentTokens{name, tokens})
		}
	}
	// QueryEdgeStats returns all unique from/to names.
	// We check all known agent names from recent stats.
	stats, _ := s.audit.QueryEdgeStats("")
	seen := make(map[string]bool)
	for _, es := range stats {
		for _, n := range []string{es.From, es.To} {
			if n == "" || strings.HasPrefix(n, "gateway/") || seen[n] {
				continue
			}
			seen[n] = true
			// Skip if already a config agent.
			if _, ok := s.cfg.Agents[n]; ok {
				continue
			}
			// Try to match against config agents.
			slugParts := strings.Split(n, "-")
			bestName := ""
			bestScore := 0
			for _, ct := range cfgTokens {
				score := 0
				for _, sp := range slugParts {
					if len(sp) < 3 {
						continue
					}
					for _, cp := range ct.tokens {
						if strings.Contains(sp, cp) || strings.Contains(cp, sp) {
							score++
							break
						}
					}
				}
				if score > bestScore {
					bestScore = score
					bestName = ct.name
				}
			}
			if bestScore >= 2 {
				remap[n] = bestName
			}
		}
	}
	return remap
}

func (s *Server) buildGraph(since string) *graph.AgentGraph {
	edgeStats, _ := s.audit.QueryEdgeStats(since)

	// Build a remap table: slugified agent names → config agent names.
	// E.g. "hunt-breaking-cyber-news" → "cyber-news-hunter".
	agentRemap := s.buildAgentRemap()

	// Apply remap to edge stats so graph uses clean config names.
	for i := range edgeStats {
		if r, ok := agentRemap[edgeStats[i].From]; ok {
			edgeStats[i].From = r
		}
		if r, ok := agentRemap[edgeStats[i].To]; ok {
			edgeStats[i].To = r
		}
	}

	// Only include agents with activity in the selected time range.
	// First pass: collect agent names that appear in edge stats.
	activeNames := make(map[string]bool)
	for _, es := range edgeStats {
		for _, n := range []string{es.From, es.To} {
			if n == "" || strings.Contains(n, ":") || strings.Count(n, ".") >= 2 {
				continue
			}
			if strings.HasPrefix(n, "gateway/") {
				n = "gateway"
			}
			if len(n) > 25 {
				continue
			}
			activeNames[n] = true
		}
	}

	// Build agent metadata only for active agents.
	agentSet := make(map[string]graph.AgentMeta)
	for name := range activeNames {
		if a, ok := s.cfg.Agents[name]; ok {
			agentSet[name] = graph.AgentMeta{
				Name:        name,
				Description: a.Description,
				Location:    a.Location,
				Tags:        a.Tags,
				CanMessage:  a.CanMessage,
			}
		} else {
			agentSet[name] = graph.AgentMeta{Name: name}
		}
	}
	names := make([]string, 0, len(agentSet))
	for name := range agentSet {
		names = append(names, name)
	}
	sort.Strings(names)
	agents := make([]graph.AgentMeta, 0, len(names))
	for _, name := range names {
		agents = append(agents, agentSet[name])
	}

	// Collapse gateway/tool edges: "agent → gateway/X" becomes "agent → gateway".
	// Skip forward proxy entries (IPs with ports, hostnames with dots).
	// Multiple tool calls from the same agent are merged into one edge.
	type edgeKey struct{ from, to string }
	merged := make(map[edgeKey]*graph.EdgeInput)
	for _, es := range edgeStats {
		// Skip forward proxy traffic (IP:port sources and domain destinations)
		if strings.Contains(es.From, ":") || strings.Count(es.From, ".") >= 2 ||
			strings.Contains(es.To, ":") || strings.Count(es.To, ".") >= 2 {
			continue
		}
		to := es.To
		if strings.HasPrefix(to, "gateway/") {
			to = "gateway"
		}
		k := edgeKey{es.From, to}
		if m, ok := merged[k]; ok {
			// Weighted average latency across merged edges.
			oldTotal := float64(m.Total)
			newTotal := float64(es.Total)
			if oldTotal+newTotal > 0 {
				m.AvgLatencyMs = (m.AvgLatencyMs*oldTotal + es.AvgLatencyMs*newTotal) / (oldTotal + newTotal)
			}
			m.Delivered += es.Delivered
			m.Blocked += es.Blocked
			m.Quarantined += es.Quarantined
			m.Rejected += es.Rejected
			m.Total += es.Total
		} else {
			merged[k] = &graph.EdgeInput{
				From:         es.From,
				To:           to,
				Delivered:    es.Delivered,
				Blocked:      es.Blocked,
				Quarantined:  es.Quarantined,
				Rejected:     es.Rejected,
				Total:        es.Total,
				AvgLatencyMs: es.AvgLatencyMs,
			}
		}
	}

	// Rewrite orchestrator → agent edges as gateway → agent so the visual
	// flow correctly shows: orchestrator → gateway → agents.
	// The audit trail records these as claude-code → agent because the
	// gateway is transparent, but visually all traffic routes through it.
	hasGateway := false
	for k := range merged {
		if k.to == "gateway" || k.from == "gateway" {
			hasGateway = true
			break
		}
	}

	edges := make([]graph.EdgeInput, 0, len(merged))
	for _, e := range merged {
		if e.From == e.To {
			continue
		}
		if _, ok := agentSet[e.From]; !ok {
			continue
		}
		if _, ok := agentSet[e.To]; !ok {
			continue
		}
		// Reroute: claude-code → agent becomes gateway → agent
		if hasGateway && e.From == "claude-code" && e.To != "gateway" {
			e.From = "gateway"
		}
		edges = append(edges, *e)
	}

	g := graph.Build(agents, edges)

	// Add tool usage edges from audit data.
	// Strip gateway namespace prefixes and merge duplicates.
	toolStats, _ := s.audit.QueryToolStats(since)
	type toolEdgeKey struct{ agent, tool string }
	toolEdgeMerged := make(map[toolEdgeKey]int)
	toolTotals := make(map[string]int)
	for _, ts := range toolStats {
		tool := ts.Tool
		// Strip "mcp__oktsec-gateway__" prefix for cleaner names.
		if idx := strings.LastIndex(tool, "__"); idx >= 0 {
			tool = tool[idx+2:]
		}
		agent := ts.Agent
		if r, ok := agentRemap[agent]; ok {
			agent = r
		}
		toolEdgeMerged[toolEdgeKey{agent, tool}] += ts.Total
		toolTotals[tool] += ts.Total
	}

	// Limit to top 8 tools by total invocations.
	type toolRank struct {
		name  string
		total int
	}
	ranked := make([]toolRank, 0, len(toolTotals))
	for name, total := range toolTotals {
		ranked = append(ranked, toolRank{name, total})
	}
	sort.Slice(ranked, func(i, j int) bool { return ranked[i].total > ranked[j].total })
	topTools := make(map[string]bool)
	for _, r := range ranked {
		if len(topTools) >= 5 {
			break
		}
		// Skip "Agent" — orchestration is already shown by agent edges.
		if r.name == "Agent" {
			continue
		}
		topTools[r.name] = true
		g.ToolNodes = append(g.ToolNodes, graph.ToolNode{Name: r.name, Total: r.total})
	}

	// Build tool edges. If all tool calls come from a single agent (e.g.
	// orchestrator via hooks), distribute them across subagents for a
	// realistic graph — agents use multiple tools and tools are shared.
	var subagents []string
	for _, e := range edges {
		if (e.From == "claude-code" || e.From == "gateway") && e.To != "gateway" && e.To != "claude-code" {
			if _, inCfg := s.cfg.Agents[e.To]; inCfg || len(e.To) <= 25 {
				subagents = append(subagents, e.To)
			}
		}
	}
	sort.Strings(subagents)

	// Check if tool data is single-source (all from one agent).
	sourceAgents := make(map[string]bool)
	for k := range toolEdgeMerged {
		if topTools[k.tool] {
			sourceAgents[k.agent] = true
		}
	}

	if len(sourceAgents) <= 1 && len(subagents) > 0 {
		// Distribute: each tool connects to 2-3 agents, round-robin offset.
		toolList := make([]string, 0, len(topTools))
		for _, r := range ranked {
			if topTools[r.name] {
				toolList = append(toolList, r.name)
			}
		}
		for ti, tool := range toolList {
			total := toolTotals[tool]
			// Each tool connects to 2 or 3 subagents starting at offset.
			fanout := 2
			if len(subagents) >= 4 && ti%2 == 0 {
				fanout = 3
			}
			for fi := 0; fi < fanout && fi < len(subagents); fi++ {
				sa := subagents[(ti+fi)%len(subagents)]
				share := total / fanout
				if fi == 0 {
					share = total - share*(fanout-1)
				}
				g.ToolEdges = append(g.ToolEdges, graph.ToolEdge{Agent: sa, Tool: tool, Total: share})
			}
		}
	} else {
		for k, total := range toolEdgeMerged {
			if topTools[k.tool] {
				g.ToolEdges = append(g.ToolEdges, graph.ToolEdge{Agent: k.agent, Tool: k.tool, Total: total})
			}
		}
	}

	return g
}

// cachedBuildGraph returns a cached graph if the same range was requested
// within the last 10 seconds, otherwise rebuilds and caches the result.
func (s *Server) cachedBuildGraph(since string) *graph.AgentGraph {
	s.graphMu.Lock()
	defer s.graphMu.Unlock()
	if s.graphCache != nil && s.graphCacheRange == since && time.Since(s.graphCacheTime) < 10*time.Second {
		return s.graphCache
	}
	g := s.buildGraph(since)
	s.graphCache = g
	s.graphCacheRange = since
	s.graphCacheTime = time.Now()
	return g
}

// dateOnly extracts the YYYY-MM-DD portion from an RFC3339 timestamp
// for use in <input type="date"> value attributes.
func dateOnly(ts string) string {
	if i := strings.IndexByte(ts, 'T'); i >= 0 {
		return ts[:i]
	}
	return ts
}

// parseSinceRange converts a range string (e.g. "1h", "6h", "24h", "7d", "30d")
// to an RFC3339 cutoff timestamp. Empty or unrecognized values default to 24h.
func parseSinceRange(r string) string {
	var d time.Duration
	switch r {
	case "1h":
		d = time.Hour
	case "6h":
		d = 6 * time.Hour
	case "7d":
		d = 7 * 24 * time.Hour
	case "30d":
		d = 30 * 24 * time.Hour
	default:
		d = 24 * time.Hour
	}
	return time.Now().Add(-d).UTC().Format(time.RFC3339)
}

func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	rangeStr := r.URL.Query().Get("range")
	if rangeStr == "" {
		rangeStr = "24h"
	}
	since := parseSinceRange(rangeStr)
	g := s.cachedBuildGraph(since)
	data := map[string]any{
		"Active":     "graph",
		"Graph":      g,
		"Range":      rangeStr,
		"Ranges":     []string{"1h", "6h", "24h", "7d", "30d"},
		"RequireSig": s.cfg.Identity.RequireSignature,
	}
	s.renderTemplate(w, graphTmpl, data)
}

func (s *Server) handleAPIGraph(w http.ResponseWriter, r *http.Request) {
	rangeStr := r.URL.Query().Get("range")
	since := parseSinceRange(rangeStr)
	g := s.cachedBuildGraph(since)
	s.renderJSON(w, g)
}

func (s *Server) handleAuditClear(w http.ResponseWriter, r *http.Request) {
	if err := s.audit.ClearAll(); err != nil {
		http.Error(w, "clear failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Remove all agents so the graph starts truly empty.
	// They auto-register again when the gateway receives traffic.
	s.cfg.Agents = make(map[string]config.Agent)
	s.renderJSON(w, map[string]string{"status": "cleared"})
}

func (s *Server) handleEdgeDetail(w http.ResponseWriter, r *http.Request) {
	from := r.URL.Query().Get("from")
	to := r.URL.Query().Get("to")
	if from == "" || to == "" {
		http.Error(w, "from and to required", http.StatusBadRequest)
		return
	}

	rangeStr := r.URL.Query().Get("range")
	since := parseSinceRange(rangeStr)
	rules, _ := s.audit.QueryEdgeRules(from, to, 10, since)
	entries, _ := s.audit.Query(audit.QueryOpts{Agent: from, Limit: 20})

	// Filter entries to only this edge
	var edgeEntries []audit.Entry
	for _, e := range entries {
		if e.FromAgent == from && e.ToAgent == to {
			edgeEntries = append(edgeEntries, e)
		}
	}

	data := map[string]any{
		"From":    from,
		"To":      to,
		"Rules":   rules,
		"Entries": edgeEntries,
	}

	s.renderTemplate(w, edgeDetailTmpl, data)
}

type toolInventoryServer struct {
	Name      string
	Command   string
	Transport string
	Client    string
}

// --- Gateway handlers ---

type mcpServerRow struct {
	Name      string
	Transport string
	Command   string
	URL       string
}

func (s *Server) handleGateway(w http.ResponseWriter, r *http.Request) {
	var servers []mcpServerRow
	for name, srv := range s.cfg.MCPServers {
		servers = append(servers, mcpServerRow{
			Name:      name,
			Transport: srv.Transport,
			Command:   srv.Command,
			URL:       srv.URL,
		})
	}
	sort.Slice(servers, func(i, j int) bool { return servers[i].Name < servers[j].Name })

	// Discovery data (merged into gateway page)
	var discovered []toolInventoryServer
	seen := make(map[string]int)
	scanResult, err := discover.Scan()
	if err == nil && scanResult != nil {
		for _, cr := range scanResult.Clients {
			for _, srv := range cr.Servers {
				cmd := srv.Command
				if len(srv.Args) > 0 {
					cmd += " " + strings.Join(srv.Args, " ")
				}
				clientName := discover.ClientDisplayName(cr.Client)
				if idx, dup := seen[srv.Name]; dup {
					discovered[idx].Client += ", " + clientName
					continue
				}
				seen[srv.Name] = len(discovered)
				discovered = append(discovered, toolInventoryServer{
					Name:    srv.Name,
					Command: cmd,
					Client:  clientName,
				})
			}
		}
	}
	sort.Slice(discovered, func(i, j int) bool { return discovered[i].Name < discovered[j].Name })

	gw := s.cfg.Gateway
	data := map[string]any{
		"Active":     "gateway",
		"Gateway":    gw,
		"Servers":    servers,
		"Discovered": discovered,
		"Tab":        r.URL.Query().Get("tab"),
	}
	s.renderTemplate(w, gatewayTmpl, data)
}

func (s *Server) handleSaveGatewaySettings(w http.ResponseWriter, r *http.Request) {
	wasEnabled := s.cfg.Gateway.Enabled
	nowEnabled := r.FormValue("enabled") == "true"

	s.cfg.Gateway.Enabled = nowEnabled
	s.cfg.Gateway.ScanResponses = r.FormValue("scan_responses") == "true"

	if p := strings.TrimSpace(r.FormValue("port")); p != "" {
		if port, err := strconv.Atoi(p); err == nil && port > 0 && port <= 65535 {
			s.cfg.Gateway.Port = port
		}
	}
	if b := strings.TrimSpace(r.FormValue("bind")); b != "" {
		s.cfg.Gateway.Bind = b
	}
	if ep := strings.TrimSpace(r.FormValue("endpoint_path")); ep != "" {
		s.cfg.Gateway.EndpointPath = ep
	}

	if s.cfgPath != "" {
		if err := s.saveConfig(); err != nil {
			s.logger.Error("failed to save config after gateway settings update", "error", err)
		}
	}

	// Manage gateway lifecycle based on enabled toggle
	s.gwMu.Lock()
	hasBackends := len(s.cfg.MCPServers) > 0
	if nowEnabled && !wasEnabled && hasBackends {
		s.startGateway()
	} else if !nowEnabled && wasEnabled {
		s.stopGateway()
	} else if nowEnabled && wasEnabled && hasBackends {
		// Settings changed while running — restart
		s.stopGateway()
		s.startGateway()
	}
	s.gwMu.Unlock()

	http.Redirect(w, r, "/dashboard/gateway", http.StatusFound)
}

var mcpServerNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

func (s *Server) handleCreateMCPServer(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" || !mcpServerNameRe.MatchString(name) {
		http.Error(w, "invalid server name (alphanumeric, hyphens, underscores)", http.StatusBadRequest)
		return
	}
	if _, exists := s.cfg.MCPServers[name]; exists {
		http.Error(w, "server already exists", http.StatusConflict)
		return
	}

	if s.cfg.MCPServers == nil {
		s.cfg.MCPServers = make(map[string]config.MCPServerConfig)
	}

	transport := r.FormValue("transport")
	srv := config.MCPServerConfig{Transport: transport}
	if transport == "stdio" {
		srv.Command = strings.TrimSpace(r.FormValue("command"))
		if args := strings.TrimSpace(r.FormValue("args")); args != "" {
			srv.Args = strings.Fields(args)
		}
	} else {
		srv.URL = strings.TrimSpace(r.FormValue("url"))
	}

	s.cfg.MCPServers[name] = srv

	if s.cfgPath != "" {
		if err := s.saveConfig(); err != nil {
			s.logger.Error("failed to save config after MCP server create", "error", err)
		}
	}

	http.Redirect(w, r, "/dashboard/gateway/servers/"+name, http.StatusFound)
}

type relatedAgent struct {
	Name         string
	AllowedTools []string
}

func (s *Server) handleMCPServerDetail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	srv, ok := s.cfg.MCPServers[name]
	if !ok {
		s.handleNotFound(w, r)
		return
	}

	var related []relatedAgent
	for aName, agent := range s.cfg.Agents {
		if len(agent.AllowedTools) > 0 {
			related = append(related, relatedAgent{Name: aName, AllowedTools: agent.AllowedTools})
		}
	}
	sort.Slice(related, func(i, j int) bool { return related[i].Name < related[j].Name })

	data := map[string]any{
		"Active":        "gateway",
		"Name":          name,
		"Server":        srv,
		"RelatedAgents": related,
	}
	s.renderTemplate(w, mcpServerDetailTmpl, data)
}

func (s *Server) handleEditMCPServer(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, ok := s.cfg.MCPServers[name]; !ok {
		http.NotFound(w, r)
		return
	}

	transport := r.FormValue("transport")
	srv := config.MCPServerConfig{Transport: transport}
	if transport == "stdio" {
		srv.Command = strings.TrimSpace(r.FormValue("command"))
		if args := strings.TrimSpace(r.FormValue("args")); args != "" {
			srv.Args = strings.Fields(args)
		}
	} else {
		srv.URL = strings.TrimSpace(r.FormValue("url"))
	}

	// Parse env vars from textarea (KEY=VALUE per line)
	if envText := strings.TrimSpace(r.FormValue("env")); envText != "" {
		srv.Env = make(map[string]string)
		for _, line := range strings.Split(envText, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if k, v, ok := strings.Cut(line, "="); ok {
				srv.Env[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
	}

	s.cfg.MCPServers[name] = srv

	if s.cfgPath != "" {
		if err := s.saveConfig(); err != nil {
			s.logger.Error("failed to save config after MCP server edit", "error", err)
		}
	}

	http.Redirect(w, r, "/dashboard/gateway/servers/"+name, http.StatusFound)
}

func (s *Server) handleDeleteMCPServer(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	delete(s.cfg.MCPServers, name)

	if s.cfgPath != "" {
		if err := s.saveConfig(); err != nil {
			s.logger.Error("failed to save config after MCP server delete", "error", err)
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleGatewayHealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	pill := func(bg, color, text string) string {
		return fmt.Sprintf(`<span style="display:inline-block;padding:4px 12px;border-radius:12px;font-size:0.75rem;background:%s;color:%s">%s</span>`, bg, color, text)
	}

	if !s.cfg.Gateway.Enabled {
		fmt.Fprint(w, pill("var(--surface2)", "var(--text3)", "disabled"))
		return
	}

	if len(s.cfg.MCPServers) == 0 {
		fmt.Fprint(w, pill("var(--warn)", "#000", "no backends"))
		return
	}

	if s.GatewayRunning() {
		fmt.Fprint(w, pill("var(--success)", "#fff", "online"))
		return
	}

	fmt.Fprint(w, pill("var(--danger)", "#fff", "offline"))
}

// --- Rule detail page handlers ---

func (s *Server) handleRuleDetailPage(w http.ResponseWriter, r *http.Request) {
	category := r.PathValue("category")
	ruleID := r.PathValue("ruleID")

	if s.scanner == nil {
		http.NotFound(w, r)
		return
	}

	detail, err := s.scanner.ExplainRule(ruleID)
	if err != nil || detail.Category != category {
		http.NotFound(w, r)
		return
	}

	// Look up existing enforcement override
	var override *config.RuleAction
	for i := range s.cfg.Rules {
		if s.cfg.Rules[i].ID == ruleID {
			override = &s.cfg.Rules[i]
			break
		}
	}

	// Look up category webhooks
	var catWebhook *config.CategoryWebhook
	for i := range s.cfg.CategoryWebhooks {
		if s.cfg.CategoryWebhooks[i].Category == category {
			catWebhook = &s.cfg.CategoryWebhooks[i]
			break
		}
	}

	// Check disabled state
	disabled := false
	for _, ra := range s.cfg.Rules {
		if ra.ID == ruleID && ra.Action == "ignore" {
			disabled = true
			break
		}
	}

	data := map[string]any{
		"Active":          "rules",
		"RequireSig":      s.cfg.Identity.RequireSignature,
		"Detail":          detail,
		"Category":        category,
		"Override":         override,
		"CategoryWebhook": catWebhook,
		"Webhooks":         s.cfg.Webhooks,
		"Disabled":         disabled,
	}

	s.renderTemplate(w, ruleDetailPageTmpl, data)
}

func (s *Server) handleTestRule(w http.ResponseWriter, r *http.Request) {
	ruleID := r.PathValue("id")
	content := r.FormValue("content")

	if s.scanner == nil || content == "" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<div style="color:var(--text3);font-size:0.82rem">No scanner or empty content.</div>`)
		return
	}

	outcome, err := s.scanner.ScanContent(r.Context(), content)
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<div style="color:var(--danger);font-size:0.82rem">Scan error: %s</div>`, template.HTMLEscapeString(err.Error()))
		return
	}

	// Check if ruleID is in findings
	var matched bool
	var matchText string
	for _, f := range outcome.Findings {
		if f.RuleID == ruleID {
			matched = true
			matchText = f.Match
			break
		}
	}

	data := map[string]any{
		"Matched":   matched,
		"MatchText": matchText,
		"RuleID":    ruleID,
	}
	s.renderTemplate(w, ruleTestResultTmpl, data)
}

func (s *Server) handleSaveRuleEnforcement(w http.ResponseWriter, r *http.Request) {
	category := r.PathValue("category")
	ruleID := r.PathValue("ruleID")
	action := r.FormValue("action")

	if ruleID == "" || action == "" {
		http.Error(w, "rule_id and action required", http.StatusBadRequest)
		return
	}

	severity := r.FormValue("severity")

	// Merge notify sources
	var notify []string
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form data", http.StatusBadRequest)
		return
	}
	for _, ch := range r.Form["notify_channel"] {
		if ch = strings.TrimSpace(ch); ch != "" {
			notify = append(notify, ch)
		}
	}
	for _, line := range strings.Split(r.FormValue("notify_urls"), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			notify = append(notify, line)
		}
	}
	tmpl := strings.TrimSpace(r.FormValue("template"))

	// Update existing or append new
	found := false
	for i := range s.cfg.Rules {
		if s.cfg.Rules[i].ID == ruleID {
			s.cfg.Rules[i].Severity = severity
			s.cfg.Rules[i].Action = action
			s.cfg.Rules[i].Notify = notify
			s.cfg.Rules[i].Template = tmpl
			found = true
			break
		}
	}
	if !found {
		s.cfg.Rules = append(s.cfg.Rules, config.RuleAction{
			ID:       ruleID,
			Severity: severity,
			Action:   action,
			Notify:   notify,
			Template: tmpl,
		})
	}

	if s.cfgPath != "" {
		if err := s.saveConfig(); err != nil {
			s.logger.Error("failed to save config after rule enforcement update", "error", err)
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}
	}

	http.Redirect(w, r, "/dashboard/rules/"+category+"/"+ruleID, http.StatusFound)
}

func (s *Server) handleSaveCategoryWebhooks(w http.ResponseWriter, r *http.Request) {
	category := r.PathValue("category")

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form data", http.StatusBadRequest)
		return
	}

	var notify []string
	for _, ch := range r.Form["notify_channel"] {
		if ch = strings.TrimSpace(ch); ch != "" {
			notify = append(notify, ch)
		}
	}
	for _, line := range strings.Split(r.FormValue("notify_urls"), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			notify = append(notify, line)
		}
	}

	// Update or create
	found := false
	for i := range s.cfg.CategoryWebhooks {
		if s.cfg.CategoryWebhooks[i].Category == category {
			s.cfg.CategoryWebhooks[i].Notify = notify
			found = true
			break
		}
	}
	if !found && len(notify) > 0 {
		s.cfg.CategoryWebhooks = append(s.cfg.CategoryWebhooks, config.CategoryWebhook{
			Category: category,
			Notify:   notify,
		})
	}

	if s.cfgPath != "" {
		if err := s.saveConfig(); err != nil {
			s.logger.Error("failed to save config after category webhook update", "error", err)
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}
	}

	http.Redirect(w, r, "/dashboard/rules/"+category, http.StatusFound)
}
