package claudecode

import (
	"time"
)

// PrincipalID is the canonical principal id oktsec uses for Claude
// Code activity in the audit store. Centralised here so callers can
// look up last-seen events without sprinkling the literal across the
// dashboard or doctor code (see dashboard regression test that bans
// hard-coded client names in graph code).
const PrincipalID = "claude-code"

// SurfaceHooks / SurfaceMCPHTTP are the audit-store surface names
// the connector has historically been observed on. Phase 2 will add
// dedicated hooks once the manifest lands; until then both fall back
// to whichever surface saw activity.
const (
	SurfaceHooks   = "hooks"
	SurfaceMCPHTTP = "mcp_http"
)

// LastSeenLookup is the narrow projection of audit.Store the
// connector needs to derive freshness. Defined locally so the
// dashboard handler does not have to thread the whole AuditStore
// interface through this package and so tests can stub the lookup
// without spinning up a real store.
type LastSeenLookup interface {
	LastSeenByPrincipalSurface(principalID, surface string) (string, error)
}

// LookupLastEvent returns the most recent timestamp the audit store
// can attribute to Claude Code on the hooks surface, falling back to
// the gateway HTTP surface for installs that route there. Returns ""
// (and no error) when nothing has been observed; callers treat that
// as the partial state.
func LookupLastEvent(store LastSeenLookup) string {
	if store == nil {
		return ""
	}
	if ts, _ := store.LastSeenByPrincipalSurface(PrincipalID, SurfaceHooks); ts != "" {
		return ts
	}
	ts, _ := store.LastSeenByPrincipalSurface(PrincipalID, SurfaceMCPHTTP)
	return ts
}

// ConnectorHealth is the dashboard- and CLI-facing summary of one
// Claude Code install. The fields are derived from an Inventory plus
// (optionally) the audit store's last-seen signal for the principal.
//
// Status decision is intentionally simple and ordered from worst to
// best so the UI can color-code without re-deriving a score:
//
//	not_installed    -- no Claude binary, no settings, no state file
//	disconnected     -- Claude is here but no oktsec hook is installed
//	partial          -- hook(s) installed but no recent event observed
//	stale            -- last event older than the staleness threshold
//	ready            -- recent event observed
//
// The derivation lives in DeriveHealth so callers (doctor, dashboard)
// share one canonical mapping.
type ConnectorHealth struct {
	ConnectorID string `json:"connector_id"`
	Status      string `json:"status"`

	// Surface flags reported verbatim from the inventory so the UI
	// does not have to re-read it.
	Installed        bool `json:"installed"`
	HookInstalled    bool `json:"hook_installed"`
	GatewayConfigured bool `json:"gateway_configured"`

	// Counts let the UI render "X subagent files, Y MCP servers"
	// without exposing the full inventory.
	SubagentsFound int `json:"subagents_found"`
	MCPServersFound int `json:"mcp_servers_found"`

	// LastEvent is the most recent activity timestamp the audit store
	// could attribute to claude-code. Empty when no event has ever
	// been observed.
	LastEvent string `json:"last_event,omitempty"`

	// MissingExpectedEvents is the Phase 2 hook events the operator
	// should install to lift the connector to "ready" coverage. Empty
	// when every expected event already has an oktsec hook.
	MissingExpectedEvents []string `json:"missing_expected_events,omitempty"`

	// Reason is the one-line explanation that the dashboard renders
	// next to the status pill. Composed from inventory + last-seen so
	// the UI never has to guess at "why partial?".
	Reason string `json:"reason"`
}

// HealthOptions controls staleness thresholds and lets callers inject
// the last-seen signal without depending on the audit store directly.
// Phase 1 keeps both fields optional so the doctor can compute a
// useful health snapshot even when no audit store is reachable.
type HealthOptions struct {
	// LastEvent is the most recent timestamp (RFC3339) attributable
	// to claude-code, or "" when none. Callers typically derive this
	// from audit.Store.LastSeenByPrincipalSurface(principalID, surface).
	LastEvent string

	// StaleAfter is the cutoff between "ready" and "stale". Defaults
	// to 24h when zero, matching the spec's section 5 thresholds.
	StaleAfter time.Duration

	// Now is the clock seam for tests. Defaults to time.Now().
	Now func() time.Time
}

// DeriveHealth maps an Inventory + observed signal to a ConnectorHealth.
// Pure function: no I/O, no side effects, deterministic given inputs.
func DeriveHealth(inv Inventory, opts HealthOptions) ConnectorHealth {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.StaleAfter <= 0 {
		opts.StaleAfter = 24 * time.Hour
	}

	h := ConnectorHealth{
		ConnectorID:           "claude-code",
		Installed:             inv.Detected,
		HookInstalled:         hasOktsecHook(inv.Hooks),
		GatewayConfigured:     hasOktsecGatewayMCP(inv.MCPServers),
		SubagentsFound:        len(inv.Subagents),
		MCPServersFound:       len(inv.MCPServers),
		LastEvent:             opts.LastEvent,
		MissingExpectedEvents: MissingExpectedEvents(inv.Hooks),
	}

	switch {
	case !inv.Detected:
		h.Status = "not_installed"
		h.Reason = "Claude Code is not installed on this machine."
	case !h.HookInstalled && !h.GatewayConfigured:
		h.Status = "disconnected"
		h.Reason = "Claude Code is installed, but no oktsec hook or gateway MCP entry was found in user/project settings."
	case opts.LastEvent == "":
		h.Status = "partial"
		h.Reason = reasonPartial(h)
	default:
		ts, err := time.Parse(time.RFC3339, opts.LastEvent)
		if err != nil {
			// Unparseable timestamp is a data bug, not the operator's
			// fault — surface it as partial so the dashboard does not
			// claim "ready" on garbled input.
			h.Status = "partial"
			h.Reason = "An event was reported but its timestamp could not be parsed; treating as partial."
			break
		}
		age := opts.Now().Sub(ts)
		if age > opts.StaleAfter {
			h.Status = "stale"
			h.Reason = "Last Claude Code event observed " + humanizeAge(age) + " ago; coverage may be out of date."
		} else {
			h.Status = "ready"
			h.Reason = "Claude Code connected. Last event observed " + humanizeAge(age) + " ago."
		}
	}
	return h
}

func reasonPartial(h ConnectorHealth) string {
	switch {
	case h.HookInstalled && !h.GatewayConfigured:
		return "Claude Code hooks are installed but no event has reached oktsec from this project yet."
	case !h.HookInstalled && h.GatewayConfigured:
		return "Claude Code's MCP gateway entry exists, but no oktsec hook is installed for pre-action coverage."
	default:
		return "Claude Code is wired to oktsec, but no event has been observed yet."
	}
}

// hasOktsecGatewayMCP returns true when the inventory lists at least
// one MCP server entry that points at the oktsec gateway. Helper
// shared with DeriveHealth so the dashboard and doctor agree on what
// counts as "gateway configured".
func hasOktsecGatewayMCP(servers []MCPServerRef) bool {
	for _, s := range servers {
		if s.IsOktsec {
			return true
		}
	}
	return false
}

// humanizeAge returns a short ("2m", "3h", "5d") description suitable
// for the dashboard. Local helper because importing a humanize
// library for one string is overkill.
func humanizeAge(d time.Duration) string {
	if d < time.Minute {
		return "less than a minute"
	}
	if d < time.Hour {
		return formatUnit(int(d.Minutes()), "minute")
	}
	if d < 24*time.Hour {
		return formatUnit(int(d.Hours()), "hour")
	}
	return formatUnit(int(d.Hours()/24), "day")
}

func formatUnit(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	// Hand-rolled to avoid pulling in fmt for an expected hot path.
	return itoa(n) + " " + unit + "s"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
