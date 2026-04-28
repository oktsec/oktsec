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

	// Runtime is the Phase 3C-0 evidence projection that turns
	// "hooks installed" into "hooks observed". When the runtime
	// store has no rows yet the block is empty; when there are
	// rows the dashboard reads RuntimeReady to decide whether the
	// Overview tile says "observed" vs "installed, not yet observed".
	Runtime RuntimeEvidence `json:"runtime"`
}

// RuntimeEvidence is the durable runtime signal the Connection
// Health tile and the doctor consume to tell "we have evidence
// the hooks are firing" apart from "we believe they are
// installed". Empty timestamps mean "never observed"; the UI
// renders the explicit empty state instead of inventing a value.
//
// Computed once in DeriveHealth from a HealthOptions.Runtime
// snapshot the caller fills from runtime.Store. Pure
// projection — no I/O here.
type RuntimeEvidence struct {
	LastHeartbeatAt          string   `json:"last_heartbeat_at,omitempty"`
	LastEventAt              string   `json:"last_event_at,omitempty"`
	LastEventFamily          string   `json:"last_event_family,omitempty"`
	ObservedFamilies         []string `json:"observed_families,omitempty"`
	MissingInstalledFamilies []string `json:"missing_installed_families,omitempty"`
	SubagentsObserved        int      `json:"subagents_observed"`
	SessionsObserved         int      `json:"sessions_observed"`

	// HasEvidence is true when runtime tables have at least one
	// row attributable to Claude Code (heartbeat or real event).
	// The Overview tile uses it to switch between "no evidence
	// yet" copy and the observed view, and the dashboard's
	// posture handler uses it to decide whether to suppress the
	// hard grade.
	HasEvidence bool `json:"has_evidence"`

	// CoverageStage is the strongest stage the runtime has
	// observed in the rollup window. One of "protected",
	// "observed", "blind", or "" (no evidence). Lets the tile
	// render Protected/Observed without joining back to the
	// activity row for every render.
	CoverageStage string `json:"coverage_stage,omitempty"`
}

// HealthOptions controls staleness thresholds and lets callers inject
// the last-seen signal without depending on the audit store directly.
// Phase 1 keeps the audit-derived fields optional so the doctor can
// compute a useful health snapshot even when no store is reachable;
// Phase 3C-0 adds Runtime so the dashboard can lift the status to
// "ready" only when there is real runtime evidence.
type HealthOptions struct {
	// LastEvent is the most recent audit-store timestamp
	// (RFC3339) attributable to claude-code, or "" when none.
	// Kept for backwards compatibility with the doctor command;
	// the new Runtime block carries the same signal but with
	// finer detail when available.
	LastEvent string

	// Runtime is the optional projection from the Phase 3
	// runtime store. When provided it takes precedence over
	// LastEvent for the freshness check because the runtime row
	// is the durable evidence Phase 3B writes per hook event.
	Runtime *RuntimeEvidenceInput

	// StaleAfter is the cutoff between "ready" and "stale". Defaults
	// to 24h when zero, matching the spec's section 5 thresholds.
	StaleAfter time.Duration

	// FreshHeartbeat is the cutoff for "heartbeat is recent enough
	// to count toward ready". Defaults to 10 minutes per spec
	// section "Health rules" — a heartbeat older than this stops
	// promoting the status by itself.
	FreshHeartbeat time.Duration

	// FreshEvent is the cutoff for "real event is recent enough
	// to count toward ready". Defaults to 30 minutes per spec
	// section "Health rules".
	FreshEvent time.Duration

	// Now is the clock seam for tests. Defaults to time.Now().
	Now func() time.Time
}

// RuntimeEvidenceInput is the dashboard-supplied snapshot of the
// runtime store. Defined as a separate input type from
// RuntimeEvidence (the JSON projection) so the package boundary
// stays one-way: callers feed in raw signals, DeriveHealth
// computes the derived view.
//
// Empty fields mean "no evidence on this dimension". The
// derivation tolerates partial inputs — e.g. a heartbeat without
// real events still moves the status off "partial" because it
// proves the hook command can reach the gateway.
type RuntimeEvidenceInput struct {
	LastHeartbeatAt          string
	LastEventAt              string
	LastEventFamily          string
	ObservedFamilies         []string
	MissingInstalledFamilies []string
	SubagentsObserved        int
	SessionsObserved         int

	// CoverageStage is the strongest stage observed in the
	// recent window: "protected" (PreToolUse with token auth),
	// "observed" (any non-blocking auth or post-action), "blind"
	// (no evidence). Empty means no evidence yet.
	CoverageStage string
}

// DeriveHealth maps an Inventory + observed signals to a
// ConnectorHealth. Pure function: no I/O, no side effects,
// deterministic given inputs.
//
// Phase 3C-0 rules (per spec section "Health rules"):
//
//   - inventory says not installed → not_installed
//   - installed but no oktsec hook AND no gateway → disconnected
//   - hook installed + heartbeat in last FreshHeartbeat → ready (heartbeat)
//   - hook installed + real event in last FreshEvent → ready (event)
//   - hook installed + last event older than StaleAfter → stale
//   - hook installed + nothing observed → partial ("installed,
//     not yet observed")
//
// The runtime block on HealthOptions takes precedence over the
// legacy LastEvent string; LastEvent is still honored when the
// caller has no runtime store (the doctor command).
func DeriveHealth(inv Inventory, opts HealthOptions) ConnectorHealth {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.StaleAfter <= 0 {
		opts.StaleAfter = 24 * time.Hour
	}
	if opts.FreshHeartbeat <= 0 {
		opts.FreshHeartbeat = 10 * time.Minute
	}
	if opts.FreshEvent <= 0 {
		opts.FreshEvent = 30 * time.Minute
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
	h.Runtime = projectRuntimeEvidence(opts.Runtime)

	// Pick the most recent timestamp the caller can offer. The
	// presence of opts.Runtime — not its content — switches the
	// signal source: when the dashboard wires a runtime store it
	// is the authoritative source, and an empty runtime means
	// "installed but not yet observed". Falling back to the
	// audit-store LastEvent in that case would let a legacy
	// audit row from before runtime was wired flip the tile to
	// ready, masking the real setup state. opts.LastEvent is
	// only honored when the caller (the doctor command) has no
	// runtime store at all.
	bestEvent := ""
	if opts.Runtime != nil {
		bestEvent = h.Runtime.LastEventAt
	} else {
		bestEvent = opts.LastEvent
	}

	switch {
	case !inv.Detected:
		h.Status = "not_installed"
		h.Reason = "Claude Code is not installed on this machine."
	case !h.HookInstalled && !h.GatewayConfigured:
		h.Status = "disconnected"
		h.Reason = "Claude Code is installed, but no oktsec hook or gateway MCP entry was found in user/project settings."
	default:
		// Heartbeat-driven promotion. A heartbeat alone is not
		// "real activity" but it does prove the hook command can
		// reach the gateway, which is the connection-truth signal.
		if hb, ok := freshTimestamp(h.Runtime.LastHeartbeatAt, opts.Now(), opts.FreshHeartbeat); ok {
			h.Status = "ready"
			h.Reason = "Claude Code connected. Heartbeat received " + humanizeAge(opts.Now().Sub(hb)) + " ago."
			break
		}
		// Real-event promotion. Wins when the event is fresh
		// enough by FreshEvent. Anything older drops to stale
		// below — the connection-truth contract requires
		// evidence fresh enough to trust, so a 2-hour-old event
		// must NOT keep the tile reading "Connected and
		// observed" or the posture grade visible.
		if ev, ok := freshTimestamp(bestEvent, opts.Now(), opts.FreshEvent); ok {
			h.Status = "ready"
			h.Reason = "Claude Code connected. Last event observed " + humanizeAge(opts.Now().Sub(ev)) + " ago."
			break
		}
		// Past FreshEvent but parseable: stale. Stale never
		// promotes back to ready in this branch — the only path
		// to ready is the FreshEvent gate above. StaleAfter
		// still distinguishes "we have recent-ish history" from
		// "evidence so old it might as well not exist": past
		// StaleAfter we drop to partial so the dashboard does not
		// claim coverage from a row that may predate the current
		// installation.
		if ev, ok := parseTimestamp(bestEvent); ok {
			age := opts.Now().Sub(ev)
			if age <= opts.StaleAfter {
				h.Status = "stale"
				h.Reason = "Last Claude Code event observed " + humanizeAge(age) + " ago; connection is no longer fresh."
				break
			}
		}
		// No usable timestamp, or so old we discard it —
		// installed but not yet observed.
		h.Status = "partial"
		h.Reason = reasonPartial(h)
	}
	return h
}

// projectRuntimeEvidence converts the dashboard-supplied input
// into the JSON projection. Centralised so the input shape and
// the wire shape can evolve independently without callers having
// to know which fields drive the UI.
func projectRuntimeEvidence(in *RuntimeEvidenceInput) RuntimeEvidence {
	if in == nil {
		return RuntimeEvidence{}
	}
	out := RuntimeEvidence{
		LastHeartbeatAt:          in.LastHeartbeatAt,
		LastEventAt:              in.LastEventAt,
		LastEventFamily:          in.LastEventFamily,
		ObservedFamilies:         append([]string(nil), in.ObservedFamilies...),
		MissingInstalledFamilies: append([]string(nil), in.MissingInstalledFamilies...),
		SubagentsObserved:        in.SubagentsObserved,
		SessionsObserved:         in.SessionsObserved,
		CoverageStage:            in.CoverageStage,
	}
	out.HasEvidence = in.LastHeartbeatAt != "" || in.LastEventAt != "" ||
		in.SessionsObserved > 0 || in.SubagentsObserved > 0 ||
		len(in.ObservedFamilies) > 0
	return out
}

// freshTimestamp parses ts and returns (time, true) when it is
// at most fresh ago. Empty / unparseable timestamps return
// (zero, false) so callers fall through to the next rule.
func freshTimestamp(ts string, now time.Time, fresh time.Duration) (time.Time, bool) {
	t, ok := parseTimestamp(ts)
	if !ok {
		return time.Time{}, false
	}
	if now.Sub(t) > fresh {
		return time.Time{}, false
	}
	return t, true
}

// parseTimestamp tolerates both RFC3339 and the nanosecond-
// resolution form runtime tables use. Returns (zero, false) on
// any parse failure so the caller can downgrade to partial /
// stale instead of claiming a false "ready".
func parseTimestamp(ts string) (time.Time, bool) {
	if ts == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		return t, true
	}
	return time.Time{}, false
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
