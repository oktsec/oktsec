package dashboard

import (
	"encoding/json"
	"net/http"

	"github.com/oktsec/oktsec/internal/audit"
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

	data := map[string]any{
		"Active":    "overview",
		"Stats":     stats,
		"Recent":    recent,
		"AgentCount": len(s.cfg.Agents),
		"RequireSig": s.cfg.Identity.RequireSignature,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = overviewTmpl.Execute(w, data)
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	entries, _ := s.audit.Query(audit.QueryOpts{Limit: 50})

	data := map[string]any{
		"Active":  "logs",
		"Entries": entries,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = logsTmpl.Execute(w, data)
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{
		"Active": "agents",
		"Agents": s.cfg.Agents,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = agentsTmpl.Execute(w, data)
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{
		"Active": "rules",
		"Rules":  s.cfg.Rules,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = rulesTmpl.Execute(w, data)
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

type dashboardStats struct {
	TotalMessages int `json:"total_messages"`
	Delivered     int `json:"delivered"`
	Blocked       int `json:"blocked"`
	Rejected      int `json:"rejected"`
	Quarantined   int `json:"quarantined"`
}

func (s *Server) getStats() dashboardStats {
	var stats dashboardStats

	all, _ := s.audit.Query(audit.QueryOpts{Limit: 10000})
	stats.TotalMessages = len(all)
	for _, e := range all {
		switch e.Status {
		case "delivered":
			stats.Delivered++
		case "blocked":
			stats.Blocked++
		case "rejected":
			stats.Rejected++
		case "quarantined":
			stats.Quarantined++
		}
	}
	return stats
}

func (s *Server) getRecentEvents(n int) []audit.Entry {
	entries, _ := s.audit.Query(audit.QueryOpts{Limit: n})
	return entries
}
