package tui

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
)

// Config holds initialization parameters for the TUI.
type Config struct {
	Version    string
	Mode       string           // "observe" or "enforce" (initial value)
	DashURL    string
	DashCode   string
	AgentCount int
	Hub        audit.EventHub
	LiveCfg    *config.Config   // live config pointer — TUI reads current mode on each render
}

// EventRow is a displayable event in the live feed.
type EventRow struct {
	Time      string
	Agent     string
	Tool      string
	Status    string
	Latency   string
	Rule      string
	RawRules  string
	Decision  string
	EventID     string
	SessionID   string
	ToAgent     string
	Content     string
	ContentHash string
}

// Model is the Bubbletea model for the oktsec TUI.
type Model struct {
	cfg Config

	// Live stats
	totalScanned  int
	threatsFound  int
	blockedCount  int
	agentsSeen    map[string]bool
	agentList     []string
	sessionAgents map[string]string

	// Event feed
	events    []EventRow
	maxEvents int

	// Interactive state
	scrollPos   int
	cursorPos   int  // position within visible events (0 = bottom)
	autoScroll  bool
	paused      bool
	selectedIdx int
	filterAgent int

	// Sub
	sub chan audit.Entry
	hub audit.EventHub

	// UI
	spinner       spinner.Model
	width         int
	height        int
	started       time.Time
	lastEventTime time.Time
}

type auditEntryMsg audit.Entry
type tickMsg time.Time

// New creates a new TUI model.
func New(cfg Config) Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color(colorSuccess))

	m := Model{
		cfg:           cfg,
		agentsSeen:    make(map[string]bool),
		sessionAgents: make(map[string]string),
		maxEvents:     500,
		spinner:       s,
		started:       time.Now(),
		hub:           cfg.Hub,
		autoScroll:    true,
		selectedIdx:   -1,
		filterAgent:   -1,
	}

	if cfg.Hub != nil {
		m.sub = cfg.Hub.Subscribe()
	}

	return m
}

func (m Model) Init() tea.Cmd {
	cmds := []tea.Cmd{m.spinner.Tick}
	if m.sub != nil {
		cmds = append(cmds, waitForEvent(m.sub))
	}
	cmds = append(cmds, tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	}))
	return tea.Batch(cmds...)
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.selectedIdx >= 0 {
			switch msg.String() {
			case "esc", "enter", "q":
				m.selectedIdx = -1
				return m, nil
			}
			return m, nil
		}

		switch msg.String() {
		case "ctrl+c":
			if m.hub != nil && m.sub != nil {
				m.hub.Unsubscribe(m.sub)
			}
			return m, tea.Quit
		case "up", "k":
			m.autoScroll = false
			filtered := m.filteredEvents()
			maxScroll := len(filtered) - m.feedHeight()
			if maxScroll < 0 {
				maxScroll = 0
			}
			vis := m.visibleRange(filtered)
			if m.cursorPos < len(vis)-1 {
				m.cursorPos++
			} else if m.scrollPos < maxScroll {
				m.scrollPos++
			}
		case "down", "j":
			if m.cursorPos > 0 {
				m.cursorPos--
			} else if m.scrollPos > 0 {
				m.scrollPos--
			} else {
				m.autoScroll = true
			}
		case " ":
			m.paused = !m.paused
		case "tab":
			if len(m.agentList) > 0 {
				m.filterAgent++
				if m.filterAgent >= len(m.agentList) {
					m.filterAgent = -1
				}
				m.scrollPos = 0
				m.cursorPos = 0
				m.autoScroll = true
			}
		case "shift+tab":
			if len(m.agentList) > 0 {
				m.filterAgent--
				if m.filterAgent < -1 {
					m.filterAgent = len(m.agentList) - 1
				}
				m.scrollPos = 0
				m.cursorPos = 0
				m.autoScroll = true
			}
		case "enter":
			filtered := m.filteredEvents()
			if len(filtered) > 0 {
				vis := m.visibleRange(filtered)
				idx := len(vis) - 1 - m.cursorPos
				if idx >= 0 && idx < len(vis) {
					m.selectedIdx = vis[idx].origIdx
				}
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case tickMsg:
		return m, tea.Tick(time.Second, func(t time.Time) tea.Msg {
			return tickMsg(t)
		})

	case auditEntryMsg:
		entry := audit.Entry(msg)
		if !m.paused {
			m.totalScanned++
			m.lastEventTime = time.Now()

			if entry.ToAgent != "" && !strings.HasPrefix(entry.ToAgent, "gateway/") {
				if entry.SessionID != "" {
					m.sessionAgents[entry.SessionID] = entry.ToAgent
				}
				if !m.agentsSeen[entry.ToAgent] {
					m.agentsSeen[entry.ToAgent] = true
					m.agentList = append(m.agentList, entry.ToAgent)
				}
			}
			if entry.FromAgent != "" && !m.agentsSeen[entry.FromAgent] {
				m.agentsSeen[entry.FromAgent] = true
				m.agentList = append(m.agentList, entry.FromAgent)
			}

			status := classifyStatus(entry)
			switch status {
			case "blocked", "rejected":
				m.blockedCount++
				m.threatsFound++
			case "quarantined", "flagged":
				m.threatsFound++
			}

			agent := entry.FromAgent
			if entry.ToAgent != "" && !strings.HasPrefix(entry.ToAgent, "gateway/") {
				agent = entry.ToAgent
			} else if entry.SessionID != "" {
				if resolved, ok := m.sessionAgents[entry.SessionID]; ok {
					agent = resolved
				}
			}

			row := EventRow{
				Time:      parseTime(entry.Timestamp),
				Agent:     agent,
				Tool:      entry.ToolName,
				Status:    status,
				Latency:   fmt.Sprintf("%dms", entry.LatencyMs),
				Rule:      formatRules(entry.RulesTriggered),
				RawRules:  entry.RulesTriggered,
				Decision:  entry.PolicyDecision,
				EventID:   entry.ID,
				SessionID: entry.SessionID,
				ToAgent:   entry.ToAgent,
				Content:     truncate(entry.Intent, 300),
				ContentHash: entry.ContentHash,
			}
			m.events = append(m.events, row)
			if len(m.events) > m.maxEvents {
				m.events = m.events[1:]
				if m.scrollPos > 0 {
					m.scrollPos--
				}
			}
		}
		return m, waitForEvent(m.sub)
	}

	return m, nil
}

type indexedEvent struct {
	EventRow
	origIdx int
}

func (m Model) filteredEvents() []indexedEvent {
	var result []indexedEvent
	for i, ev := range m.events {
		if m.filterAgent >= 0 && m.filterAgent < len(m.agentList) {
			if ev.Agent != m.agentList[m.filterAgent] {
				continue
			}
		}
		result = append(result, indexedEvent{ev, i})
	}
	return result
}

func (m Model) visibleRange(filtered []indexedEvent) []indexedEvent {
	h := m.feedHeight()
	total := len(filtered)
	if total == 0 {
		return nil
	}
	end := total - m.scrollPos
	if end < 0 {
		end = 0
	}
	start := end - h
	if start < 0 {
		start = 0
	}
	return filtered[start:end]
}

func (m Model) feedHeight() int {
	h := m.height - 20
	if h < 5 {
		h = 5
	}
	return h
}

func (m Model) View() string {
	if m.selectedIdx >= 0 && m.selectedIdx < len(m.events) {
		return m.renderDetail()
	}

	w := m.width
	if w < 60 {
		w = 80
	}
	contentWidth := min(w-4, 90)

	// Animated hexagons — light up when agents are active
	lit := lipgloss.NewStyle().Foreground(lipgloss.Color(colorPrimary))
	dm := lipgloss.NewStyle().Foreground(lipgloss.Color(colorDim))
	active := !m.lastEventTime.IsZero() && time.Since(m.lastEventTime) < 3*time.Second
	hx := [4]string{dm.Render("⏣"), dm.Render("⏣"), dm.Render("⏣"), dm.Render("⏣")}
	if active {
		// Original animation: all dim, one lit violet cycling
		a := (int(time.Since(m.started).Milliseconds()) / 400) % 4
		hx[a] = lit.Render("⏣")
	}

	header := lipgloss.JoinVertical(lipgloss.Left,
		hx[0]+" "+hx[1]+"  "+headerStyle.Render("oktsec")+" "+dimStyle.Render(m.cfg.Version),
		hx[2]+" "+hx[3]+"  "+taglineStyle.Render("See everything your AI agents execute"),
	)

	currentMode := m.cfg.Mode
	if m.cfg.LiveCfg != nil {
		if m.cfg.LiveCfg.Identity.RequireSignature {
			currentMode = "enforce"
		} else {
			currentMode = "observe"
		}
	}
	mode := observeStyle.Render("observe")
	if currentMode == "enforce" {
		mode = enforceStyle.Render("enforce")
	}
	agentCount := len(m.agentsSeen)
	if agentCount == 0 {
		agentCount = m.cfg.AgentCount
	}

	statusContent := lipgloss.JoinVertical(lipgloss.Left,
		labelStyle.Render("Mode")+mode,
		labelStyle.Render("Agents")+valueStyle.Render(fmt.Sprintf("%d", agentCount)),
		labelStyle.Render("Dashboard")+urlStyle.Render(m.cfg.DashURL),
		labelStyle.Render("Access code")+codeStyle.Render(m.cfg.DashCode),
	)

	metricsContent := fmt.Sprintf("%s %s    %s %s    %s %s",
		mutedStyle.Render("Scanned"), valueStyle.Render(fmt.Sprintf("%d", m.totalScanned)),
		mutedStyle.Render("Threats"), threatStyle(m.threatsFound),
		mutedStyle.Render("Blocked"), blockedStyle(m.blockedCount),
	)

	topBox := boxStyle.Width(contentWidth).Render(
		lipgloss.JoinVertical(lipgloss.Left,
			header, "", statusContent, "", metricsContent,
		),
	)

	// Feed header
	filterStr := mutedStyle.Render("All agents")
	if m.filterAgent >= 0 && m.filterAgent < len(m.agentList) {
		filterStr = lipgloss.NewStyle().Foreground(lipgloss.Color(colorPrimary)).Render(m.agentList[m.filterAgent])
	}
	feedTitle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(colorText)).Render("LIVE FEED")
	if m.paused {
		feedTitle += " " + lipgloss.NewStyle().Foreground(lipgloss.Color(colorWarning)).Bold(true).Render("PAUSED")
	}
	feedTitle += "  " + dimStyle.Render("Filter:") + " " + filterStr

	// Feed content
	var feedContent string
	filtered := m.filteredEvents()
	if len(filtered) == 0 && len(m.events) == 0 {
		feedContent = m.spinner.View() + " " + mutedStyle.Render("Waiting for agent activity...")
	} else if len(filtered) == 0 {
		feedContent = mutedStyle.Render("No events for this agent")
	} else {
		visible := m.visibleRange(filtered)
		cursorIdx := len(visible) - 1 - m.cursorPos
		var lines []string
		for i, ev := range visible {
			isCursor := !m.autoScroll && i == cursorIdx
			prefix := " "
			if isCursor {
				prefix = ">"
			}
			line := fmt.Sprintf("%s%s %s %s %s %s",
				prefix,
				dimStyle.Render(ev.Time),
				agentStyle.Width(16).Render(truncate(ev.Agent, 16)),
				renderStatus(ev.Status),
				toolStyle.Width(10).Render(truncate(ev.Tool, 10)),
				dimStyle.Render(ev.Latency),
			)
			if isCursor {
				line = lipgloss.NewStyle().Background(lipgloss.Color("#21262d")).Render(line)
			}
			lines = append(lines, line)
		}
		feedContent = strings.Join(lines, "\n")
	}

	scrollInfo := ""
	if !m.autoScroll && m.scrollPos > 0 {
		scrollInfo = dimStyle.Render(fmt.Sprintf("  ↑ %d more", m.scrollPos))
	}

	feedBox := boxStyle.Width(contentWidth).Render(
		lipgloss.JoinVertical(lipgloss.Left,
			feedTitle, "", feedContent, scrollInfo,
		),
	)

	uptime := time.Since(m.started).Truncate(time.Second)
	var controls string
	if w > 75 {
		controls = "↑↓ scroll · Space pause · Tab filter · Enter detail · Ctrl+C quit"
	} else if w > 55 {
		controls = "↑↓ · Space · Tab · Enter · Ctrl+C"
	} else {
		controls = "↑↓ · Space · Ctrl+C"
	}
	footer := dimStyle.Render(fmt.Sprintf(" %s | %s", uptime, controls))

	return lipgloss.JoinVertical(lipgloss.Left, "", topBox, feedBox, footer, "")
}

func (m Model) renderDetail() string {
	w := m.width
	if w < 40 {
		w = 40
	}
	contentWidth := min(w-4, 90)

	ev := m.events[m.selectedIdx]
	detailBox := boxStyle.Width(contentWidth).BorderForeground(lipgloss.Color(colorDim))
	sepW := contentWidth - 8
	if sepW < 10 {
		sepW = 10
	}
	sep := dimStyle.Render(strings.Repeat("─", sepW))

	rulesContent := mutedStyle.Render("No rules triggered")
	if ev.RawRules != "" && ev.RawRules != "[]" {
		rulesContent = formatRulesDetail(ev.RawRules)
	}

	contentPreview := mutedStyle.Render("Not stored")
	if ev.Content != "" {
		contentPreview = dimStyle.Render(ev.Content)
	}

	target := mutedStyle.Render("n/a")
	if ev.ToAgent != "" {
		target = toolStyle.Render(ev.ToAgent)
	}
	eventID := mutedStyle.Render("n/a")
	if ev.EventID != "" {
		eventID = dimStyle.Render(truncate(ev.EventID, 36))
	}
	sessionID := mutedStyle.Render("n/a")
	if ev.SessionID != "" {
		sessionID = dimStyle.Render(truncate(ev.SessionID, 36))
	}

	return "\n" + detailBox.Render(
		lipgloss.JoinVertical(lipgloss.Left,
			headerStyle.Render("EVENT DETAIL"),
			"",
			labelStyle.Render("Agent")+agentStyle.Render(ev.Agent),
			labelStyle.Render("Target")+target,
			labelStyle.Render("Tool")+toolStyle.Render(ev.Tool),
			labelStyle.Render("Time")+mutedStyle.Render(ev.Time),
			labelStyle.Render("Latency")+mutedStyle.Render(ev.Latency),
			labelStyle.Render("Status")+renderStatus(ev.Status),
			labelStyle.Render("Decision")+mutedStyle.Render(ev.Decision),
			sep,
			mutedStyle.Render("RULES"),
			rulesContent,
			sep,
			mutedStyle.Render("CONTENT"),
			contentPreview,
			sep,
			labelStyle.Render("Event ID")+eventID,
			labelStyle.Render("Session")+sessionID,
			labelStyle.Render("Hash")+dimStyle.Render(truncate(ev.ContentHash, 36)),
			"",
			dimStyle.Render("Esc or Enter to go back"),
		),
	) + "\n"
}

// Helpers

func waitForEvent(sub chan audit.Entry) tea.Cmd {
	return func() tea.Msg {
		entry, ok := <-sub
		if !ok {
			return tea.Quit()
		}
		return auditEntryMsg(entry)
	}
}

func classifyStatus(e audit.Entry) string {
	switch e.Status {
	case "blocked":
		return "blocked"
	case "quarantined":
		return "quarantined"
	case "rejected":
		return "rejected"
	default:
		if e.PolicyDecision == audit.DecisionContentFlagged {
			return "flagged"
		}
		return "clean"
	}
}

func parseTime(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		t, err = time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return ts
		}
	}
	return t.Local().Format("15:04:05")
}

func renderStatus(s string) string {
	switch s {
	case "clean":
		return cleanStatusStyle.Render("clean")
	case "flagged":
		return flaggedStatusStyle.Render("flagged")
	case "blocked":
		return blockedStatusStyle.Render("blocked")
	case "quarantined":
		return quarantinedStatusStyle.Render("quar")
	case "rejected":
		return blockedStatusStyle.Render("rejected")
	default:
		return dimStyle.Render(s)
	}
}

func formatRules(raw string) string {
	if raw == "" || raw == "[]" {
		return ""
	}
	var rules []struct {
		RuleID string `json:"rule_id"`
	}
	if json.Unmarshal([]byte(raw), &rules) != nil {
		return truncate(raw, 40)
	}
	var ids []string
	for _, r := range rules {
		ids = append(ids, r.RuleID)
	}
	return strings.Join(ids, ", ")
}

func formatRulesDetail(raw string) string {
	var rules []struct {
		RuleID   string `json:"rule_id"`
		Name     string `json:"name"`
		Severity string `json:"severity"`
	}
	if json.Unmarshal([]byte(raw), &rules) != nil {
		return mutedStyle.Render(raw)
	}
	var lines []string
	for _, r := range rules {
		sev := dimStyle
		switch r.Severity {
		case "critical":
			sev = lipgloss.NewStyle().Foreground(lipgloss.Color(colorDanger))
		case "high":
			sev = lipgloss.NewStyle().Foreground(lipgloss.Color(colorOrange))
		case "medium":
			sev = lipgloss.NewStyle().Foreground(lipgloss.Color(colorWarning))
		}
		lines = append(lines, fmt.Sprintf("%s %s  %s",
			sev.Render(fmt.Sprintf("%-9s", strings.ToUpper(r.Severity))),
			valueStyle.Render(r.RuleID),
			mutedStyle.Render(r.Name),
		))
	}
	return strings.Join(lines, "\n")
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "\u2026"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
