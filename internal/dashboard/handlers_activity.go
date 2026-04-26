package dashboard

import (
	"context"
	"html/template"
	"net/http"
	"strconv"
	"time"

	"github.com/oktsec/oktsec/internal/activity"
	"github.com/oktsec/oktsec/internal/coverage"
)

// activityQueryTimeout bounds the activity Store.Query call the
// drill-down handler issues so a stalled or locked activity DB cannot
// pin a dashboard request. Larger than the per-cell LastSeen budget
// because Query returns a result set (up to MaxQueryLimit rows) and
// is paged on the surface index, but still tight enough that a real
// stall fails fast and the operator sees an empty drawer instead of
// a hung tab.
const activityQueryTimeout = 2 * time.Second

// drillDownEventLimit is how many activity events the cell drawer
// shows per render. The spec calls for "the last 20 activity events"
// so the drawer stays scannable. The /dashboard/api/activity JSON
// endpoint accepts a higher limit (capped at MaxQueryLimit) for
// scripting use.
const drillDownEventLimit = 20

// activityEventDTO is the JSON shape /dashboard/api/activity returns.
// Field names are the Phase 2B.1 spec's canonical contract — distinct
// from activity.Event's struct tags so the API stays stable even if
// internal field names move (for example principal_trust_level vs
// trust_level here is a deliberate rename to match the spec).
//
// EvidenceJSON is intentionally NOT exposed: surface adapters write
// it as a bounded redacted blob, but the operator-facing drill-down
// has no need for it today and excluding it keeps the response small.
// Future diagnostics can opt into a separate endpoint.
type activityEventDTO struct {
	ID             string `json:"id"`
	Timestamp      string `json:"timestamp"`
	PrincipalID    string `json:"principal_id"`
	ReportedActor  string `json:"reported_actor,omitempty"`
	ConnectorID    string `json:"connector_id,omitempty"`
	Surface        string `json:"surface"`
	EventType      string `json:"event_type"`
	CoverageMode   string `json:"coverage_mode"`
	AuthMethod     string `json:"auth_method,omitempty"`
	TrustLevel     string `json:"trust_level,omitempty"`
	ResourceType   string `json:"resource_type,omitempty"`
	ResourceLabel  string `json:"resource_label,omitempty"`
	Status         string `json:"status,omitempty"`
	PolicyDecision string `json:"policy_decision,omitempty"`
	Confidence     int    `json:"confidence"`
	AuditEntryID   string `json:"audit_entry_id,omitempty"`
	SessionID      string `json:"session_id,omitempty"`
}

// handleAPIActivity returns activity events as JSON for scripting
// callers and the in-dashboard drill-down. Filters mirror the spec:
//
//	GET /dashboard/api/activity?principal_id=&surface=&connector_id=
//	    &workspace_id=&coverage=&limit=
//
// Auth is handled by the dashboard's existing session middleware.
// Limit is bounded at MaxQueryLimit (500) regardless of input.
//
// ConnectorID is a DERIVED filter: surface adapters do not persist
// activity.Event.ConnectorID (it would denormalize a value already
// in config that changes when tokens are revoked). When the caller
// passes connector_id, the handler resolves it to the set of
// principals currently in that connector and pushes the filter into
// SQL via PrincipalIDs (an IN clause), so the LIMIT applies AFTER
// the connector filter. Without this, asking for limit=100 of an
// uncommon connector could return [] just because the last 100
// global rows happened to belong to other connectors.
func (s *Server) handleAPIActivity(w http.ResponseWriter, r *http.Request) {
	store := s.coverageActivityStore()
	if store == nil {
		// No activity store wired (test mocks, future stores). Empty
		// result is the correct response — callers should treat this
		// as "no activity data available" rather than an error.
		s.renderJSON(w, []activityEventDTO{})
		return
	}

	requestedConnector := r.URL.Query().Get("connector_id")
	requestedPrincipal := r.URL.Query().Get("principal_id")
	connByPrincipal := s.connectorIDsByPrincipal()

	if requestedConnector != "" {
		// If the caller pinned a single principal, just verify its
		// connector matches and short-circuit if it does not. Saves a
		// round-trip and avoids a redundant IN clause of size 1.
		if requestedPrincipal != "" {
			if connByPrincipal[requestedPrincipal] != requestedConnector {
				s.renderJSON(w, []activityEventDTO{})
				return
			}
		}
	}

	q := activity.Query{
		PrincipalID: requestedPrincipal,
		Surface:     r.URL.Query().Get("surface"),
		WorkspaceID: r.URL.Query().Get("workspace_id"),
		Coverage:    r.URL.Query().Get("coverage"),
		// Intentional: ConnectorID is NOT passed to the store; the
		// PrincipalIDs filter below pushes the connector membership
		// into SQL instead.
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			q.Limit = n
		}
	}

	if requestedConnector != "" && requestedPrincipal == "" {
		// Resolve the connector to its principal set and push the
		// filter into SQL so the bounded LIMIT applies AFTER the
		// connector filter. Empty match set means no principal
		// belongs to this connector — short-circuit with [] instead
		// of issuing an IN () (which is invalid SQL on most engines).
		matching := principalsForConnector(connByPrincipal, requestedConnector)
		if len(matching) == 0 {
			s.renderJSON(w, []activityEventDTO{})
			return
		}
		q.PrincipalIDs = matching
	}

	ctx, cancel := context.WithTimeout(r.Context(), activityQueryTimeout)
	defer cancel()
	events, err := store.Query(ctx, q)
	if err != nil {
		s.logger.Warn("activity query failed", "error", err,
			"principal_id", q.PrincipalID, "surface", q.Surface)
		http.Error(w, "activity query failed", http.StatusInternalServerError)
		return
	}

	out := make([]activityEventDTO, 0, len(events))
	for _, e := range events {
		out = append(out, eventDTO(e, connByPrincipal[e.PrincipalID]))
	}
	s.renderJSON(w, out)
}

// principalsForConnector returns every principal ID currently mapped
// to the requested connector. Order is not guaranteed; callers feed
// this straight into an IN clause where order does not matter.
func principalsForConnector(connByPrincipal map[string]string, connector string) []string {
	out := make([]string, 0)
	for principal, id := range connByPrincipal {
		if id == connector {
			out = append(out, principal)
		}
	}
	return out
}

// eventDTO converts an activity.Event to its API-facing shape. The
// connectorID is computed by the caller (handleAPIActivity does it
// once per principal so we do not re-resolve for every row).
func eventDTO(e activity.Event, connectorID string) activityEventDTO {
	return activityEventDTO{
		ID:             e.ID,
		Timestamp:      e.Timestamp.UTC().Format(time.RFC3339Nano),
		PrincipalID:    e.PrincipalID,
		ReportedActor:  e.ReportedActor,
		ConnectorID:    connectorID,
		Surface:        string(e.Surface),
		EventType:      string(e.EventType),
		CoverageMode:   string(e.CoverageMode),
		AuthMethod:     e.AuthMethod,
		TrustLevel:     e.PrincipalTrustLevel,
		ResourceType:   e.ResourceType,
		ResourceLabel:  e.ResourceLabel,
		Status:         e.Status,
		PolicyDecision: e.PolicyDecision,
		Confidence:     e.Confidence,
		AuditEntryID:   e.AuditEntryID,
		SessionID:      e.SessionID,
	}
}

// connectorIDsByPrincipal computes the connector ID for each
// configured principal. We pass nil for the AuditReader because the
// connector label is derived purely from config (active token mix +
// loopback posture); LastSeen would just trigger N×3 hybrid reader
// calls per /api/activity request for a value the JSON does not use.
// This keeps the JSON endpoint cheap regardless of activity-store
// health.
func (s *Server) connectorIDsByPrincipal() map[string]string {
	out := map[string]string{}
	for _, c := range coverage.Compute(s.cfg, nil) {
		// All cells for the same principal share the same connector.
		// First write wins; later cells just overwrite with the same
		// value, which is harmless.
		out[c.PrincipalID] = c.ConnectorID
	}
	return out
}

// handleCoverageCellDrawer renders the per-cell HTMX fragment the
// Overview matrix opens when a cell is clicked. It returns HTML, not
// JSON, because the rest of the dashboard's drill-down infrastructure
// (the slide-in panel, panel-overlay, openPanel JS) is HTMX-driven.
//
// The fragment shows: principal, surface, coverage label, connector;
// a short "Why this state" explanation that translates the wire-level
// label into operator language; an optional next-action link when
// coverage is not Protected; then the last drillDownEventLimit
// activity events newest-first. Empty state is explicit so the
// operator sees "No activity recorded for this surface yet." instead
// of a blank pane.
func (s *Server) handleCoverageCellDrawer(w http.ResponseWriter, r *http.Request) {
	principalID := r.URL.Query().Get("principal_id")
	surface := r.URL.Query().Get("surface")
	if principalID == "" || surface == "" {
		http.Error(w, "principal_id and surface are required", http.StatusBadRequest)
		return
	}

	// Coverage label and connector ID are config-derived; LastSeen is
	// the only column on a CoverageCell that depends on the audit /
	// activity readers. The drawer body shows the events list itself
	// (queried separately below) so LastSeen is redundant here. Pass
	// nil to keep this handler independent of activity-store health.
	cells := coverage.Compute(s.cfg, nil)
	cellCoverage, cellConnector := lookupCell(cells, principalID, surface)

	data := struct {
		PrincipalID   string
		Surface       string
		SurfaceLabel  string
		Coverage      string
		CoverageLabel string
		ConnectorID   string
		Connector     string
		Explanation   string
		NextAction    coverageAction
		Events        []activityEventDTO
		Limit         int
	}{
		PrincipalID:   principalID,
		Surface:       surface,
		SurfaceLabel:  surfaceDisplayName(surface),
		Coverage:      cellCoverage,
		CoverageLabel: coverageBadgeLabel(cellCoverage),
		ConnectorID:   cellConnector,
		Connector:     coverage.ConnectorDisplayName(cellConnector),
		Explanation:   coverageExplanation(cellCoverage),
		NextAction:    coverageNextAction(cellCoverage, surface, principalID),
		Limit:         drillDownEventLimit,
	}

	store := s.coverageActivityStore()
	if store != nil {
		ctx, cancel := context.WithTimeout(r.Context(), activityQueryTimeout)
		defer cancel()
		events, err := store.ListByCoverageCell(ctx, principalID, surface, drillDownEventLimit)
		if err != nil {
			s.logger.Warn("coverage cell drawer: activity list failed", "error", err,
				"principal_id", principalID, "surface", surface)
		} else {
			for _, e := range events {
				data.Events = append(data.Events, eventDTO(e, cellConnector))
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := coverageCellDrawerTmpl.Execute(w, data); err != nil {
		s.logger.Error("coverage cell drawer template failed", "error", err)
	}
}

// lookupCell finds the (coverage, connector) for one (principal,
// surface) pair from the live coverage matrix. Returns ("", "") when
// the pair is not in the matrix — the template renders an empty
// header row in that case rather than failing the request.
func lookupCell(cells []coverage.CoverageCell, principalID, surface string) (coverageStr, connector string) {
	for _, c := range cells {
		if c.PrincipalID == principalID && c.Surface == surface {
			return string(c.Coverage), c.ConnectorID
		}
	}
	return "", ""
}

// surfaceDisplayName humanizes a surface wire value for the drawer
// header. Mirrors the column names in tmpl_overview.go so the drawer
// title matches the cell the operator clicked.
func surfaceDisplayName(s string) string {
	switch s {
	case "mcp_http":
		return "MCP Gateway"
	case "http_egress_proxy":
		return "Egress Proxy"
	case "hooks":
		return "Hooks"
	}
	return s
}

// coverageBadgeLabel returns the badge text for a coverage wire
// value. Kept local to the drawer to avoid pulling the coverage
// package's display helper into this file's surface area.
func coverageBadgeLabel(c string) string {
	switch c {
	case "protected":
		return "Protected"
	case "observed":
		return "Observed only"
	case "blind":
		return "Blind"
	}
	return ""
}

// coverageExplanation returns the operator-facing one-sentence
// answer to "why is this cell in this state?". Wording is the
// canonical contract from the Phase 2B.1 dashboard UX spec — change
// it here, not in the template, so all three coverage states stay in
// lock-step. Deliberately neutral (no "fully", "complete", "blind
// failure"): Protected does not imply global coverage and Observed
// does not imply blocking.
func coverageExplanation(coverage string) string {
	switch coverage {
	case "protected":
		return "Oktsec is in the pre-action path with authenticated identity for this surface."
	case "observed":
		return "Oktsec has telemetry for this surface, but cannot claim pre-action blocking."
	case "blind":
		return "Oktsec has no active protection or usable telemetry for this surface."
	}
	return "No coverage state is available for this surface."
}

// coverageAction is the optional next step the drawer surfaces when
// coverage is not Protected. It carries a one-sentence Hint plus the
// CLI Command an operator can copy-paste — token issuance is a CLI
// workflow today, not a dashboard one, so the drawer must not link
// to an in-app screen that cannot perform the action. Empty Hint
// means "render nothing" and the template skips the block.
type coverageAction struct {
	Hint    string
	Command string
}

// coverageNextAction returns the truthful next step a non-Protected
// cell can take. Token issuance lives in `oktsec tokens create`, so
// the action shows that CLI command pre-filled with the principal
// id rather than a link to /dashboard/settings (which exists, but
// does not currently issue gateway_bearer / proxy_basic / hook_bearer
// tokens — that would violate the community-repo truth constraint).
//
// Protected cells return the zero value and the template renders
// nothing — Protected is the goal state and a "fix this" affordance
// would be misleading.
func coverageNextAction(coverage, surface, principalID string) coverageAction {
	if coverage == "protected" {
		return coverageAction{}
	}
	pid := principalID
	if pid == "" {
		pid = "<principal>"
	}
	switch surface {
	case "mcp_http":
		return coverageAction{
			Hint:    "Issue a gateway bearer token from the CLI:",
			Command: "oktsec tokens create --principal " + pid + " --type gateway_bearer",
		}
	case "http_egress_proxy":
		return coverageAction{
			Hint:    "Issue a forward-proxy token from the CLI:",
			Command: "oktsec tokens create --principal " + pid + " --type proxy_basic",
		}
	case "hooks":
		return coverageAction{
			Hint:    "Issue a hook bearer token from the CLI:",
			Command: "oktsec tokens create --principal " + pid + " --type hook_bearer",
		}
	}
	return coverageAction{}
}

// coverageCellDrawerTmpl renders the slide-in drawer body for one
// (principal, surface) cell. Inline CSS is scoped to .cd-* so it
// cannot collide with the rest of the dashboard.
var coverageCellDrawerTmpl = template.Must(template.New("coverage-cell-drawer").Parse(`
<style>
.cd-hdr{padding:var(--sp-3) var(--sp-4);border-bottom:1px solid var(--border-subtle)}
.cd-title{font-size:var(--text-base);font-weight:600;color:var(--text);margin:0 0 4px 0}
.cd-meta{display:flex;flex-wrap:wrap;gap:var(--sp-2);font-size:var(--text-xs);color:var(--text2);align-items:center}
.cd-meta span{color:var(--text2)}
.cd-meta b{color:var(--text);font-weight:500}
.cd-badge{display:inline-block;padding:2px 8px;border-radius:var(--radius-sm);font-size:var(--text-xs);font-weight:600;letter-spacing:0.02em}
.cd-badge.protected{background:rgba(63,185,80,0.12);color:var(--success);border:1px solid rgba(63,185,80,0.30)}
.cd-badge.observed{background:rgba(88,166,255,0.10);color:var(--accent);border:1px solid rgba(88,166,255,0.25)}
.cd-badge.blind{background:transparent;color:var(--text3);border:1px solid var(--border)}
.cd-explain{padding:var(--sp-3) var(--sp-4);border-bottom:1px solid var(--border-subtle)}
.cd-explain-title{margin:0 0 var(--sp-2) 0;font-size:var(--text-xs);text-transform:uppercase;letter-spacing:var(--ls-wide);color:var(--text3);font-weight:600}
.cd-explain-body{margin:0;font-size:var(--text-sm);color:var(--text);line-height:1.5}
.cd-next-hint{margin:var(--sp-2) 0 4px 0;font-size:var(--text-sm);color:var(--text2)}
.cd-next-cmd{margin:0;padding:8px 10px;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-sm);font-family:var(--mono);font-size:var(--text-xs);color:var(--accent-light);white-space:pre-wrap;word-break:break-all;overflow-x:auto}
.cd-events{padding:var(--sp-3) var(--sp-4)}
.cd-events h4{margin:0 0 var(--sp-2) 0;font-size:var(--text-xs);text-transform:uppercase;letter-spacing:var(--ls-wide);color:var(--text3)}
.cd-event{padding:var(--sp-2) 0;border-bottom:1px solid var(--border-subtle);font-size:var(--text-sm)}
.cd-event:last-child{border-bottom:none}
.cd-event-row{display:flex;justify-content:space-between;gap:var(--sp-2);align-items:baseline}
.cd-event-resource{font-family:var(--mono);color:var(--text);font-size:var(--text-sm)}
.cd-event-time{font-family:var(--mono);font-size:var(--text-xs);color:var(--text3);white-space:nowrap}
.cd-event-meta{font-size:var(--text-xs);color:var(--text2);margin-top:2px}
.cd-empty{padding:var(--sp-4);text-align:center;color:var(--text3);font-size:var(--text-sm)}
</style>
<div class="cd-hdr">
  <h3 class="cd-title">{{.PrincipalID}} on {{.SurfaceLabel}}</h3>
  <div class="cd-meta">
    {{if .CoverageLabel}}<span><b>Coverage:</b> <span class="cd-badge {{.Coverage}}">{{.CoverageLabel}}</span></span>{{end}}
    {{if .Connector}}<span><b>Connector:</b> {{.Connector}}</span>{{end}}
    <span><b>Surface:</b> {{.Surface}}</span>
  </div>
</div>
<div class="cd-explain">
  <h4 class="cd-explain-title">Why this state</h4>
  <p class="cd-explain-body">{{.Explanation}}</p>
  {{if .NextAction.Hint}}
  <p class="cd-next-hint">{{.NextAction.Hint}}</p>
  <pre class="cd-next-cmd"><code>{{.NextAction.Command}}</code></pre>
  {{end}}
</div>
<div class="cd-events">
  <h4>Last {{.Limit}} activity events</h4>
  {{if .Events}}
    {{range .Events}}
    <div class="cd-event">
      <div class="cd-event-row">
        <span class="cd-event-resource">{{if .ResourceLabel}}{{.ResourceLabel}}{{else}}—{{end}}</span>
        <span class="cd-event-time" data-ts="{{.Timestamp}}">{{.Timestamp}}</span>
      </div>
      <div class="cd-event-meta">
        {{.EventType}} &middot;
        status: {{if .Status}}{{.Status}}{{else}}—{{end}} &middot;
        auth: {{if .AuthMethod}}{{.AuthMethod}}{{else}}—{{end}} &middot;
        coverage: {{.CoverageMode}}
      </div>
    </div>
    {{end}}
  {{else}}
    <div class="cd-empty">No activity recorded for this surface yet.</div>
  {{end}}
</div>
`))
