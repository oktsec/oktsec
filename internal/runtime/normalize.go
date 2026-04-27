package runtime

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// IdentityResolution is the contract the hook handler hands to
// Normalize. It carries the resolver result (PrincipalID + auth
// trust + auth method) plus the request-side hints the handler
// can supply cheaply (X-Oktsec-Client, Mcp-Session-Id). Defined
// locally so the runtime package does not import
// internal/identity/resolve directly — the hook handler does the
// resolver call and feeds us a flat struct.
type IdentityResolution struct {
	PrincipalID         string
	PrincipalTrustLevel string
	AuthMethod          string
	ClientID            string // X-Oktsec-Client
	SessionID           string // X-Oktsec-Session header (may differ from payload)
}

// rawClaudePayload is the slice of the inbound JSON the
// normalizer needs. Anything not modeled is left untouched in the
// raw evidence blob (which is then redacted before persistence).
type rawClaudePayload struct {
	HookEventName  string          `json:"hook_event_name"`
	SessionID      string          `json:"session_id"`
	TranscriptPath string          `json:"transcript_path"`
	AgentTranscriptPath string     `json:"agent_transcript_path"`
	CWD            string          `json:"cwd"`
	Source         string          `json:"source"`
	Model          string          `json:"model"`
	AgentID        string          `json:"agent_id"`
	AgentType      string          `json:"agent_type"`
	ToolName       string          `json:"tool_name"`
	ToolUseID      string          `json:"tool_use_id"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ToolResponse   json.RawMessage `json:"tool_response"`
	TaskID         string          `json:"task_id"`
	TaskSubject    string          `json:"task_subject"`
	TaskDescription string         `json:"task_description"`
	Teammate       string          `json:"teammate_name"`
	Team           string          `json:"team_name"`
	ConfigSource   string          `json:"config_source"`
	ConfigPath     string          `json:"config_path"`
	FilePath       string          `json:"file_path"`
	FileEvent      string          `json:"file_event"`
}

// Normalize converts a raw Claude Code hook payload + the
// already-resolved identity into a HookEnvelope. The function is
// pure: no DB calls, no I/O. The hook handler runs Normalize and
// then hands the envelope to Store.RecordHook.
//
// Errors only signal "the payload is structurally unparseable".
// Missing optional fields are tolerated; the envelope simply
// carries empty defaults so a partially-filled event still ends
// up on disk for the dashboard to surface.
func Normalize(rawBody []byte, identity IdentityResolution, receivedAt time.Time) (HookEnvelope, error) {
	if receivedAt.IsZero() {
		receivedAt = time.Now().UTC()
	}
	var payload rawClaudePayload
	if len(rawBody) > 0 {
		if err := json.Unmarshal(rawBody, &payload); err != nil {
			return HookEnvelope{}, fmt.Errorf("runtime: parse hook payload: %w", err)
		}
	}

	env := HookEnvelope{
		ID:                  newEventID(),
		ReceivedAt:          receivedAt.UTC(),
		ClientID:            identity.ClientID,
		ConnectorID:         ConnectorGenericHooks,
		Surface:             SurfaceHooks,
		PrincipalID:         identity.PrincipalID,
		PrincipalTrustLevel: identity.PrincipalTrustLevel,
		AuthMethod:          identity.AuthMethod,
		HookEventName:       payload.HookEventName,
		CWD:                 PathTail(payload.CWD),
		CWDHash:             HashPath(payload.CWD),
	}

	// Session id resolution: prefer header, fall back to payload.
	// Either is enough; both empty produces an envelope without a
	// session, which the store skips on the upsert path so the
	// event still lands in runtime_hook_events.
	env.SessionID = identity.SessionID
	if env.SessionID == "" {
		env.SessionID = payload.SessionID
	}

	// Transcript fingerprints (tail + hash). Spec section "Field
	// rules" forbids storing the full path, so we only keep the
	// tail and the hash.
	env.TranscriptRef = TranscriptRef{
		PathTail:      PathTail(payload.TranscriptPath),
		PathHash:      HashPath(payload.TranscriptPath),
		AgentPathTail: PathTail(payload.AgentTranscriptPath),
		AgentPathHash: HashPath(payload.AgentTranscriptPath),
	}

	// Lifecycle, stage, and block-capability come from one table
	// so a future Claude addition is one entry to update.
	mapping := lookupEventMapping(payload.HookEventName)
	env.Lifecycle = mapping.lifecycle
	env.Stage = mapping.stage
	env.BlockCapable = mapping.blockCapable

	// Resource refs.
	env.Tool = ToolRef{
		Name:       payload.ToolName,
		UseID:      payload.ToolUseID,
		InputHash:  hashJSON(payload.ToolInput),
		OutputHash: hashJSON(payload.ToolResponse),
	}
	env.Task = TaskRef{
		ID:          payload.TaskID,
		Subject:     payload.TaskSubject,
		Description: truncate(payload.TaskDescription, 200),
		Teammate:    payload.Teammate,
		Team:        payload.Team,
	}
	env.Config = ConfigRef{
		Source:   payload.ConfigSource,
		PathTail: PathTail(payload.ConfigPath),
		PathHash: HashPath(payload.ConfigPath),
	}
	env.File = FileRef{
		PathTail: PathTail(payload.FilePath),
		PathHash: HashPath(payload.FilePath),
		Event:    payload.FileEvent,
	}

	// Actor + parent + root. The spec's actor-id construction lives
	// in actor.go; the normalizer just picks which constructor to
	// call based on the lifecycle.
	env.RootActorID = ActorIDForRoot(env.SessionID)
	env.Actor = pickActor(env, payload, mapping)
	env.ParentActorID = pickParent(env, mapping)

	// Bounded raw evidence. The full body might contain secrets or
	// long prose; we keep an opaque marker plus a hashed path
	// fingerprint so the dashboard can correlate without exposing
	// the data.
	env.RawEvidenceJSON = boundEvidence(payload, env)

	return env, nil
}

// eventMapping captures one row of the spec's "Event Mapping"
// table. Centralised here so the hook handler, the dashboard, and
// the tests share one source of truth.
type eventMapping struct {
	lifecycle    string
	stage        string
	blockCapable bool
	actorKind    string // root | subagent | task | "" (no implicit actor)
}

var eventMappings = map[string]eventMapping{
	"SessionStart":       {LifecycleSession, StageObserved, false, ActorKindRoot},
	"SessionEnd":         {LifecycleSession, StageObserved, false, ActorKindRoot},
	"PreToolUse":         {LifecycleTool, StagePreAction, true, ""},
	"PostToolUse":        {LifecycleTool, StagePostAction, true, ""},
	"PostToolUseFailure": {LifecycleTool, StagePostAction, true, ""},
	"PostToolBatch":      {LifecycleTool, StagePostAction, true, ""},
	"PermissionRequest":  {LifecyclePermission, StagePreAction, true, ""},
	"PermissionDenied":   {LifecyclePermission, StageObserved, false, ""},
	"SubagentStart":      {LifecycleSubagent, StageObserved, false, ActorKindSubagent},
	"SubagentStop":       {LifecycleSubagent, StagePostAction, true, ActorKindSubagent},
	"TaskCreated":        {LifecycleTask, StageObserved, true, ActorKindTask},
	"TaskCompleted":      {LifecycleTask, StagePostAction, true, ActorKindTask},
	"ConfigChange":       {LifecycleConfig, StagePostAction, true, ActorKindRoot},
	"InstructionsLoaded": {LifecycleConfig, StageObserved, false, ActorKindRoot},
	"CwdChanged":         {LifecycleCwd, StageObserved, false, ActorKindRoot},
	"FileChanged":        {LifecycleFile, StageObserved, false, ActorKindRoot},
	"Notification":       {LifecycleNotification, StageObserved, false, ActorKindRoot},
	"Stop":               {LifecycleStop, StagePostAction, true, ActorKindRoot},
	"StopFailure":        {LifecycleStop, StageObserved, false, ActorKindRoot},
}

func lookupEventMapping(event string) eventMapping {
	if m, ok := eventMappings[event]; ok {
		return m
	}
	// Unknown / future events still produce a usable envelope so
	// the dashboard can render them. They are observed-only by
	// default until their lifecycle is explicitly added to the
	// table above.
	return eventMapping{
		lifecycle:    LifecycleNotification,
		stage:        StageObserved,
		blockCapable: false,
		actorKind:    ActorKindRoot,
	}
}

// pickActor builds the ActorRef for one event. The selection
// follows the spec:
//
//   - SubagentStart / Stop with agent_id => subagent actor
//   - PreToolUse / PostToolUse with agent_id => same subagent
//     (lazily-created with source=inferred_from_tool_event when
//     SubagentStart has not landed yet)
//   - TaskCreated / Completed with task_id => task actor
//   - everything else => root actor
func pickActor(env HookEnvelope, payload rawClaudePayload, m eventMapping) ActorRef {
	if env.SessionID == "" {
		return ActorRef{}
	}
	rootLabel := formatRoot(env.ClientID)
	root := ActorRef{
		ID:     ActorIDForRoot(env.SessionID),
		Kind:   ActorKindRoot,
		Label:  rootLabel,
		Source: ActorSourcePayload,
	}

	switch m.lifecycle {
	case LifecycleSubagent:
		fingerprint := stablePayloadFingerprint(payload.AgentID, payload.AgentType, payload.SessionID)
		id := ActorIDForSubagent(env.SessionID, payload.AgentID, payload.AgentType, fingerprint)
		return ActorRef{
			ID:              id,
			Kind:            ActorKindSubagent,
			Label:           subagentLabel(payload),
			Source:          ActorSourcePayload,
			ClaudeAgentID:   payload.AgentID,
			ClaudeAgentType: payload.AgentType,
		}
	case LifecycleTask:
		fingerprint := stablePayloadFingerprint(payload.TaskID, payload.TaskSubject, payload.SessionID)
		id := ActorIDForTask(env.SessionID, payload.TaskID, fingerprint)
		return ActorRef{
			ID:     id,
			Kind:   ActorKindTask,
			Label:  taskLabel(payload),
			Source: ActorSourcePayload,
		}
	case LifecycleTool, LifecyclePermission:
		// Tool / permission events that carry agent_id belong to a
		// subagent actor that may not have been declared yet.
		// Lazy-create with the inferred source so the dashboard
		// can show "we saw this subagent's tool calls before its
		// SubagentStart".
		if payload.AgentID != "" || payload.AgentType != "" {
			fingerprint := stablePayloadFingerprint(payload.AgentID, payload.AgentType, payload.SessionID)
			id := ActorIDForSubagent(env.SessionID, payload.AgentID, payload.AgentType, fingerprint)
			return ActorRef{
				ID:              id,
				Kind:            ActorKindSubagent,
				Label:           subagentLabel(payload),
				Source:          ActorSourceInferred,
				ClaudeAgentID:   payload.AgentID,
				ClaudeAgentType: payload.AgentType,
			}
		}
		return root
	}
	// Session / config / cwd / file / notification / stop / etc.
	// belong to the root actor by default.
	if m.actorKind == ActorKindRoot {
		// SessionStart with an agent_type means the session was
		// started via `claude --agent <name>`; surface the agent
		// name in the label but keep the actor as root because the
		// principal is still the root client.
		if payload.HookEventName == "SessionStart" && payload.AgentType != "" {
			root.Label = subagentLabel(payload)
			root.Source = ActorSourceCLIRuntime
			root.ClaudeAgentType = payload.AgentType
		}
		return root
	}
	return root
}

// pickParent applies the spec's parent rules:
//
//   - root has no parent
//   - subagent parent defaults to root
//   - task parent defaults to root
func pickParent(env HookEnvelope, m eventMapping) string {
	if env.SessionID == "" || env.Actor.ID == "" {
		return ""
	}
	if env.Actor.Kind == ActorKindRoot {
		return ""
	}
	switch m.lifecycle {
	case LifecycleSubagent, LifecycleTask, LifecycleTool, LifecyclePermission:
		return ActorIDForRoot(env.SessionID)
	}
	return ""
}

// subagentLabel picks the most specific human-readable name for a
// subagent. agent_type is preferred (it is the declared name);
// agent_id falls back when only the runtime id is present.
func subagentLabel(payload rawClaudePayload) string {
	switch {
	case payload.AgentType != "":
		return payload.AgentType
	case payload.AgentID != "":
		return payload.AgentID
	default:
		return ActorKindSubagent
	}
}

// taskLabel picks the human-readable label for a task actor.
// Subject wins when present; task id is the fallback.
func taskLabel(payload rawClaudePayload) string {
	if s := strings.TrimSpace(payload.TaskSubject); s != "" {
		return truncate(s, 80)
	}
	if payload.TaskID != "" {
		return "task " + payload.TaskID
	}
	return ActorKindTask
}

// boundEvidence produces a short JSON blob the runtime tables can
// store as evidence_json. The full payload may contain secrets or
// long prose; this projection keeps only the redacted
// fingerprints + the lifecycle metadata so the dashboard can
// correlate without exposing the original data.
func boundEvidence(payload rawClaudePayload, env HookEnvelope) string {
	evidence := map[string]any{
		"hook_event_name":      env.HookEventName,
		"lifecycle":            env.Lifecycle,
		"stage":                env.Stage,
		"actor_id":             env.Actor.ID,
		"actor_kind":           env.Actor.Kind,
		"actor_source":         env.Actor.Source,
		"parent_actor_id":      env.ParentActorID,
		"tool_use_id":          env.Tool.UseID,
		"tool_input_hash":      env.Tool.InputHash,
		"tool_output_hash":     env.Tool.OutputHash,
		"task_id":              env.Task.ID,
		"cwd_hash":             env.CWDHash,
		"transcript_path_hash": env.TranscriptRef.PathHash,
	}
	if payload.Source != "" {
		evidence["source"] = payload.Source
	}
	body, err := json.Marshal(evidence)
	if err != nil {
		// Fallback to an empty object so the column constraint
		// (DEFAULT '{}') is honored even if marshaling somehow fails.
		return "{}"
	}
	return string(body)
}

// hashJSON returns a short hex digest of a JSON value, or "" when
// the value is empty / null. Used for tool_input / tool_response
// fingerprints so callers can join events without storing the
// payload itself.
func hashJSON(raw json.RawMessage) string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return ""
	}
	return shortHash(trimmed)
}

// newEventID generates a 16-byte random id for a runtime hook
// event. We do NOT use the payload's session_id or tool_use_id
// because those are operator-supplied; per the spec the row id
// must be Oktsec-generated.
func newEventID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// crypto/rand only fails on a broken kernel entropy source;
		// fall back to a coarser id rather than panicking inside a
		// hook hot path.
		return fmt.Sprintf("evt-%d", time.Now().UnixNano())
	}
	return "evt-" + hex.EncodeToString(buf[:])
}
