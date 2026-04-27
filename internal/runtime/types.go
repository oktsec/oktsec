package runtime

import "time"

// Session is the row shape Sessions list/detail APIs return. It is
// the projection of runtime_sessions every dashboard caller works
// with; the storage layout in migrate.go can evolve as long as
// this type stays stable.
type Session struct {
	SessionID          string
	PrincipalID        string
	ClientID           string
	ConnectorID        string
	RootActorID        string
	CWDTail            string
	CWDHash            string
	TranscriptPathTail string
	TranscriptPathHash string
	StartedAt          time.Time
	LastSeenAt         time.Time
	EndedAt            time.Time // zero when active
	EndReason          string
	StartSource        string
	Model              string
	Status             string
	EventCount         int64
	ToolEventCount     int64
	SubagentCount      int64
	TaskCount          int64
	BlockCount         int64
	LastHeartbeatAt    time.Time
	LastHeartbeatID    string
}

// SessionDetail extends Session with the actor and event slices
// the Sessions detail page needs. Phase 3A returns the type but
// the dashboard does not consume it until 3C.
type SessionDetail struct {
	Session
	Actors []Actor
	Events []HookEvent
}

// Actor is the projection of runtime_actors. ClaudeAgentID/Type
// are display + correlation only and must never be used as a
// policy identity.
type Actor struct {
	ID              string
	SessionID       string
	PrincipalID     string
	ParentActorID   string
	RootActorID     string
	Kind            string
	Label           string
	Source          string
	ClaudeAgentID   string
	ClaudeAgentType string
	FirstSeenAt     time.Time
	LastSeenAt      time.Time
	ToolCount       int64
	EventCount      int64
	BlockCount      int64
}

// HookEvent is the projection of runtime_hook_events. The Audit
// and Activity links let the dashboard render a joined timeline
// without re-querying the source rows.
type HookEvent struct {
	ID              string
	Timestamp       time.Time
	SessionID       string
	PrincipalID     string
	ActorID         string
	ParentActorID   string
	RootActorID     string
	ClientID        string
	ConnectorID     string
	HookEventName   string
	Lifecycle       string
	Stage           string
	BlockCapable    bool
	ToolName        string
	ToolUseID       string
	TaskID          string
	TaskSubject     string
	ConfigSource    string
	FilePathTail    string
	FilePathHash    string
	Status          string
	PolicyDecision  string
	CoverageMode    string
	Confidence      int
	AuditEntryID    string
	ActivityEventID string
	LatencyMs       int64
}

// Heartbeat is the LastHeartbeat projection. The dashboard's
// Connection Health card reads it to label "events observed in
// the last X" without reaching into runtime_sessions itself.
type Heartbeat struct {
	SessionID  string
	ReceivedAt time.Time
	ClientID   string
}

// ActorEdge is one (parent_actor, child_actor) pair derived from
// the runtime tables. The Graph package consumes a generic
// projection of these rows so it stays client-agnostic per the
// Phase 3 invariants.
type ActorEdge struct {
	ParentActorID    string
	ParentLabel      string
	ParentKind       string
	ChildActorID     string
	ChildLabel       string
	ChildKind        string
	SessionID        string
	PrincipalID      string
	EventCount       int64
	LastSeenAt       time.Time
}

// SessionQuery filters the Sessions list. Empty fields mean "no
// filter on this dimension"; defaults are applied in the store.
type SessionQuery struct {
	PrincipalID string
	ClientID    string
	Status      string
	Since       time.Time
	Until       time.Time
	Limit       int
}

// ActorQuery filters runtime_actors. Used by the Sessions detail
// page and by the graph builder.
type ActorQuery struct {
	SessionID   string
	PrincipalID string
	Kind        string
	Limit       int
}

// EventQuery filters runtime_hook_events. The dashboard's
// timeline view passes (SessionID, Since) most often; the audit
// drill-down passes AuditEntryID alone.
type EventQuery struct {
	SessionID    string
	ActorID      string
	PrincipalID  string
	HookEventName string
	AuditEntryID string
	Since        time.Time
	Until        time.Time
	Limit        int
}

// EdgeQuery filters runtime_actors-derived edges. Empty PrincipalID
// means "all principals"; Limit caps the row count for graph
// rendering performance.
type EdgeQuery struct {
	PrincipalID string
	Since       time.Time
	Until       time.Time
	Limit       int
}
