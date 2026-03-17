package tui

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
)

// Color constants matching the oktsec dashboard design system.
const (
	colorPrimary = "#8b7cf7" // oktsec violet
	colorText    = "#e6edf3" // primary text
	colorText2   = "#c9d1d9" // secondary text
	colorMuted   = "#8b949e" // labels, descriptions
	colorDim     = "#484f58" // separators, subtle
	colorBorder  = "#2d333b" // box borders
	colorLink    = "#58a6ff" // URLs, clickable
	colorSuccess = "#3fb950" // positive states
	colorDanger  = "#f85149" // threats, blocked
	colorWarning = "#d29922" // warnings, flagged
	colorOrange  = "#db6d28" // quarantined
)

var (
	// Layout
	boxBorder = lipgloss.RoundedBorder()
	boxStyle  = lipgloss.NewStyle().
			Border(boxBorder).
			BorderForeground(lipgloss.Color(colorBorder)).
			Padding(1, 2)

	// Text
	headerStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(colorText))
	taglineStyle = lipgloss.NewStyle().Foreground(lipgloss.Color(colorMuted))
	dimStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color(colorDim))
	mutedStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color(colorMuted))
	valueStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(colorText))
	labelStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color(colorMuted)).Width(14)

	// Highlights
	urlStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color(colorLink))
	codeStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(colorPrimary))

	// Mode
	observeStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(colorLink))
	enforceStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(colorDanger))

	// Agent/tool in feed
	agentStyle = lipgloss.NewStyle().Foreground(lipgloss.Color(colorText2))
	toolStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color(colorMuted))

	// Status badges in feed
	cleanStatusStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color(colorSuccess)).Width(8)
	flaggedStatusStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color(colorWarning)).Width(8)
	blockedStatusStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color(colorDanger)).Width(8)
	quarantinedStatusStyle = lipgloss.NewStyle().Foreground(lipgloss.Color(colorOrange)).Width(8)
)

func threatStyle(n int) string {
	if n == 0 {
		return valueStyle.Render("0")
	}
	return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(colorWarning)).Render(fmt.Sprintf("%d", n))
}

func blockedStyle(n int) string {
	if n == 0 {
		return valueStyle.Render("0")
	}
	return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(colorDanger)).Render(fmt.Sprintf("%d", n))
}
