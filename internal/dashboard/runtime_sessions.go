package dashboard

import (
	"context"
	"strings"
	"time"

	"github.com/oktsec/oktsec/internal/runtime"
)

// runtime_sessions.go is the only file that knows how to project
// runtime.Store rows into the Sessions list and detail views the
// dashboard renders. Keeping the projection here means
// internal/runtime stays consumable as a generic event substrate
// (no client-specific or dashboard-specific knowledge bleeds into
// types.go / store.go) and the Sessions handlers only need to
// branch "runtime first, audit fallback" without re-implementing
// status and heartbeat semantics each call site.

// sessionsRowLimit caps both the runtime and the legacy queries so
// the Sessions list has a single, predictable upper bound. Larger
// than the per-page render budget on purpose: filtering happens
// client-side in tmpl_sessions.go and the operator can scroll.
const sessionsRowLimit = 200

// sessionListRow is the row shape both the runtime list template
// and the (planned) audit-bridged template render. The "Source"
// field exists so a single template can be parameterised by the
// origin store; today the runtime path is the only writer of this
// shape. Audit fallback keeps using the legacy SessionSummary type
// directly so we do not pay a translation cost for the fallback
// path.
type sessionListRow struct {
	SessionID       string
	PrincipalID     string
	ClientID        string
	ConnectorID     string
	Status          string // active | ended | heartbeat
	StatusLabel     string
	StatusClass     string
	StartedAt       string
	LastSeenAt      string
	Duration        string
	EventCount      int64
	ToolEventCount  int64
	SubagentCount   int64
	TaskCount       int64
	BlockCount      int64
	CoverageStage   string
	Threat          bool
	IsHeartbeatOnly bool
	Source          string // runtime | audit
	SearchData      string // joined free-text the client filter matches against
}

// runtimeActorView is one node in the actor tree the runtime
// session detail page renders. Kind drives the icon/label choice
// in the template; Parent/Root are wire data the template uses to
// nest children under their parents.
type runtimeActorView struct {
	ID            string
	ParentActorID string
	Label         string
	Kind          string
	Source        string
	ToolCount     int64
	EventCount    int64
	BlockCount    int64
	FirstSeenAt   string
	LastSeenAt    string
}

// runtimeEventView is one row in the runtime timeline. All
// payload-shaped fields are explicitly hashes or tails — never raw
// input/output. AuditEntryID is rendered as a link to the
// /dashboard/events/ detail when present.
type runtimeEventView struct {
	ID              string
	Timestamp       string
	HookEventName   string
	Lifecycle       string
	Stage           string
	ActorLabel      string
	ActorKind       string
	ToolName        string
	ToolUseID       string
	ToolInputHash   string
	ToolOutputHash  string
	TaskID          string
	TaskSubject     string
	FilePathTail    string
	Status          string
	PolicyDecision  string
	CoverageMode    string
	Confidence      int
	AuditEntryID    string
	ActivityEventID string
	LatencyMs       int64
	IsHeartbeat     bool
}

// runtimeSessionDetailView is the full payload the runtime detail
// template consumes. JSONExportURL / CSVExportURL are pre-built so
// the template can render the action buttons without knowing
// route shapes.
type runtimeSessionDetailView struct {
	Session       sessionListRow
	Actors        []runtimeActorView
	Events        []runtimeEventView
	IsRuntime     bool
	JSONExportURL string
	CSVExportURL  string
}

// parseSessionsRange normalises the ?range= query string into one
// of the supported windows and returns the canonical token.
// Anything unknown collapses to 24h so the URL bar always reflects
// a valid state.
func parseSessionsRange(rangeParam string) string {
	switch rangeParam {
	case "7d", "30d":
		return rangeParam
	default:
		return "24h"
	}
}

// sessionsRangeSince converts the canonical range token into an
// absolute RFC3339 timestamp the audit and runtime stores both
// accept as their "since" filter.
func sessionsRangeSince(rangeParam string) time.Time {
	switch rangeParam {
	case "7d":
		return time.Now().Add(-7 * 24 * time.Hour).UTC()
	case "30d":
		return time.Now().Add(-30 * 24 * time.Hour).UTC()
	default:
		return time.Now().Add(-24 * time.Hour).UTC()
	}
}

// runtimeSessionRows is the runtime-first projection the Sessions
// list handler calls. ok signals "runtime store reachable AND
// query succeeded" — an empty rows slice with ok=true is a valid
// "runtime is wired but the window is quiet" state and the caller
// can choose to fall through to legacy. Returning ok=false means
// the runtime store is not available or the query errored.
func (s *Server) runtimeSessionRows(ctx context.Context, since time.Time, limit int) ([]sessionListRow, bool) {
	store := s.runtimeStore()
	if store == nil {
		return nil, false
	}
	if limit <= 0 {
		limit = sessionsRowLimit
	}
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	sessions, err := store.QuerySessions(queryCtx, runtime.SessionQuery{
		Since: since,
		Limit: limit,
	})
	if err != nil {
		s.logger.Warn("runtime sessions: QuerySessions failed", "error", err)
		return nil, false
	}
	rows := make([]sessionListRow, 0, len(sessions))
	for _, sess := range sessions {
		rows = append(rows, projectSessionListRow(sess))
	}
	return rows, true
}

// runtimeSessionDetail returns the runtime detail view for one
// session id. ok=true when the runtime store has a session row
// for the id (regardless of whether actors/events exist); the
// caller renders the runtime template. ok=false routes to the
// legacy audit trace.
func (s *Server) runtimeSessionDetail(ctx context.Context, sessionID string) (*runtimeSessionDetailView, bool) {
	store := s.runtimeStore()
	if store == nil || sessionID == "" {
		return nil, false
	}
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	detail, err := store.QuerySession(queryCtx, sessionID)
	if err != nil {
		s.logger.Warn("runtime sessions: QuerySession failed", "error", err, "session_id", sessionID)
		return nil, false
	}
	if detail == nil || detail.SessionID == "" {
		return nil, false
	}

	actors := make([]runtimeActorView, 0, len(detail.Actors))
	for _, a := range detail.Actors {
		actors = append(actors, runtimeActorView{
			ID:            a.ID,
			ParentActorID: a.ParentActorID,
			Label:         actorDisplayLabel(a),
			Kind:          a.Kind,
			Source:        a.Source,
			ToolCount:     a.ToolCount,
			EventCount:    a.EventCount,
			BlockCount:    a.BlockCount,
			FirstSeenAt:   formatRuntimeTimestamp(a.FirstSeenAt),
			LastSeenAt:    formatRuntimeTimestamp(a.LastSeenAt),
		})
	}

	actorByID := make(map[string]runtime.Actor, len(detail.Actors))
	for _, a := range detail.Actors {
		actorByID[a.ID] = a
	}

	events := make([]runtimeEventView, 0, len(detail.Events))
	for _, ev := range detail.Events {
		events = append(events, projectEventView(ev, actorByID))
	}

	row := projectSessionListRow(detail.Session)
	return &runtimeSessionDetailView{
		Session:       row,
		Actors:        actors,
		Events:        events,
		IsRuntime:     true,
		JSONExportURL: "/dashboard/api/session/" + detail.SessionID + "/export",
		CSVExportURL:  "/dashboard/api/session/" + detail.SessionID + "/csv",
	}, true
}

// projectSessionListRow turns one runtime.Session into the
// sessionListRow the templates consume. Heartbeat detection,
// status mapping, threat counting, and search-data formatting
// all live here so handlers and tests share one shape.
func projectSessionListRow(sess runtime.Session) sessionListRow {
	heartbeat := runtime.IsHeartbeatSession(sess.SessionID) || strings.EqualFold(sess.Status, runtime.SessionStatusHeartbeat)
	status, label, class := sessionStatusFields(sess, heartbeat)
	threat := !heartbeat && sess.BlockCount > 0
	row := sessionListRow{
		SessionID:       sess.SessionID,
		PrincipalID:     sess.PrincipalID,
		ClientID:        sess.ClientID,
		ConnectorID:     sess.ConnectorID,
		Status:          status,
		StatusLabel:     label,
		StatusClass:     class,
		StartedAt:       formatRuntimeTimestamp(sess.StartedAt),
		LastSeenAt:      formatRuntimeTimestamp(sess.LastSeenAt),
		Duration:        sessionDurationString(sess, heartbeat),
		EventCount:      sess.EventCount,
		ToolEventCount:  sess.ToolEventCount,
		SubagentCount:   sess.SubagentCount,
		TaskCount:       sess.TaskCount,
		BlockCount:      sess.BlockCount,
		Threat:          threat,
		IsHeartbeatOnly: heartbeat,
		Source:          "runtime",
	}
	if heartbeat {
		// Heartbeat rows are diagnostic only: zero out tool counts
		// and skip threat/coverage badges so the row never reads
		// as observed activity in the UI.
		row.ToolEventCount = 0
		row.SubagentCount = 0
		row.TaskCount = 0
		row.BlockCount = 0
		row.Threat = false
		row.CoverageStage = ""
	} else if row.ToolEventCount > 0 {
		row.CoverageStage = "tools"
	}
	row.SearchData = strings.ToLower(strings.Join([]string{
		sess.SessionID, sess.PrincipalID, sess.ClientID, sess.ConnectorID, status, label,
	}, " "))
	return row
}

// sessionStatusFields maps a runtime.Session into the (status,
// label, css class) triple the template needs. Heartbeat takes
// precedence; an unended row is "active"; otherwise "ended".
func sessionStatusFields(sess runtime.Session, heartbeat bool) (status, label, class string) {
	switch {
	case heartbeat:
		return "heartbeat", "Diagnostic heartbeat", "heartbeat"
	case sess.EndedAt.IsZero():
		return "active", "Active", "active"
	default:
		return "ended", "Ended", "ended"
	}
}

// sessionDurationString formats the elapsed time the row should
// display. Active sessions read the open window from
// StartedAt → LastSeenAt; ended sessions read the closed window
// from StartedAt → EndedAt; heartbeat-only rows always read 0s
// because their "duration" is an artefact of the upsert keepalive.
func sessionDurationString(sess runtime.Session, heartbeat bool) string {
	if heartbeat {
		return "0s"
	}
	end := sess.EndedAt
	if end.IsZero() {
		end = sess.LastSeenAt
	}
	if end.IsZero() || sess.StartedAt.IsZero() {
		return "—"
	}
	d := end.Sub(sess.StartedAt)
	if d <= 0 {
		return "—"
	}
	if d >= time.Second {
		return d.Round(time.Second).String()
	}
	return d.Round(time.Millisecond).String()
}

// projectEventView translates one runtime.HookEvent into the
// row the timeline template renders. The actor label is
// resolved against the session's actor set so a
// SubagentStart event renders as "subagent/research" instead of
// the opaque actor id; if the actor is unknown (event references
// an actor row outside the limit), we fall back to the parent id
// tail.
func projectEventView(ev runtime.HookEvent, actorByID map[string]runtime.Actor) runtimeEventView {
	actorLabel, actorKind := "", ""
	if a, ok := actorByID[ev.ActorID]; ok {
		actorLabel = actorDisplayLabel(a)
		actorKind = a.Kind
	} else if ev.ActorID != "" {
		actorLabel = actorIDTail(ev.ActorID)
	}
	return runtimeEventView{
		ID:              ev.ID,
		Timestamp:       formatRuntimeTimestamp(ev.Timestamp),
		HookEventName:   ev.HookEventName,
		Lifecycle:       ev.Lifecycle,
		Stage:           ev.Stage,
		ActorLabel:      actorLabel,
		ActorKind:       actorKind,
		ToolName:        ev.ToolName,
		ToolUseID:       ev.ToolUseID,
		ToolInputHash:   ev.ToolInputHash,
		ToolOutputHash:  ev.ToolOutputHash,
		TaskID:          ev.TaskID,
		TaskSubject:     ev.TaskSubject,
		FilePathTail:    ev.FilePathTail,
		Status:          ev.Status,
		PolicyDecision:  ev.PolicyDecision,
		CoverageMode:    ev.CoverageMode,
		Confidence:      ev.Confidence,
		AuditEntryID:    ev.AuditEntryID,
		ActivityEventID: ev.ActivityEventID,
		LatencyMs:       ev.LatencyMs,
		IsHeartbeat:     runtime.IsHeartbeatSession(ev.SessionID),
	}
}

// actorDisplayLabel mirrors the runtime graph's label rules so
// the Sessions detail page and the Graph page name the same actor
// the same way. Root prefers PrincipalID (the policy identity),
// subagents and tasks prefer their runtime label or the trailing
// id segment.
func actorDisplayLabel(a runtime.Actor) string {
	switch a.Kind {
	case runtime.ActorKindRoot:
		if a.PrincipalID != "" {
			return a.PrincipalID
		}
		if a.Label != "" {
			return a.Label
		}
		return "root"
	case runtime.ActorKindSubagent:
		if a.Label != "" {
			return "subagent/" + a.Label
		}
		return "subagent/" + actorIDTail(a.ID)
	case runtime.ActorKindTask:
		if a.Label != "" {
			return "task/" + a.Label
		}
		return "task/" + actorIDTail(a.ID)
	default:
		if a.Label != "" {
			return a.Label
		}
		return "actor/" + actorIDTail(a.ID)
	}
}

// formatRuntimeTimestamp produces the RFC3339 string the templates
// expect. Empty / zero times become an empty string so the
// template renders an em-dash placeholder rather than the Go zero
// value.
func formatRuntimeTimestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
