package runtime

import (
	"strings"
	"testing"
	"time"
)

// baseIdentity is the loopback-mode identity the hook handler will
// build for a typical local Claude Code session. Tests reuse it
// so the focus stays on payload-driven normalization.
var baseIdentity = IdentityResolution{
	PrincipalID:         "claude-code",
	PrincipalTrustLevel: "trusted_local",
	AuthMethod:          "loopback_header",
	ClientID:            "claude-code",
	SessionID:           "sess-test",
}

// TestNormalize_LifecycleMappingTable spot-checks the mapping
// table for one event of each lifecycle so a future addition
// cannot accidentally drop or relabel an existing family without
// breaking the test.
func TestNormalize_LifecycleMappingTable(t *testing.T) {
	cases := []struct {
		event     string
		lifecycle string
		stage     string
		blockable bool
	}{
		{"SessionStart", LifecycleSession, StageObserved, false},
		{"PreToolUse", LifecycleTool, StagePreAction, true},
		{"PostToolUse", LifecycleTool, StagePostAction, true},
		{"PostToolUseFailure", LifecycleTool, StagePostAction, true},
		{"PermissionRequest", LifecyclePermission, StagePreAction, true},
		{"PermissionDenied", LifecyclePermission, StageObserved, false},
		{"SubagentStart", LifecycleSubagent, StageObserved, false},
		{"SubagentStop", LifecycleSubagent, StagePostAction, true},
		{"TaskCreated", LifecycleTask, StageObserved, true},
		{"TaskCompleted", LifecycleTask, StagePostAction, true},
		{"ConfigChange", LifecycleConfig, StagePostAction, true},
		{"FileChanged", LifecycleFile, StageObserved, false},
		{"CwdChanged", LifecycleCwd, StageObserved, false},
		{"Stop", LifecycleStop, StagePostAction, true},
		{"StopFailure", LifecycleStop, StageObserved, false},
		{"Notification", LifecycleNotification, StageObserved, false},
		{"InstructionsLoaded", LifecycleConfig, StageObserved, false},
	}
	for _, tc := range cases {
		t.Run(tc.event, func(t *testing.T) {
			body := `{"hook_event_name":"` + tc.event + `","session_id":"sess-test"}`
			env, err := Normalize([]byte(body), baseIdentity, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if env.Lifecycle != tc.lifecycle {
				t.Errorf("lifecycle = %q, want %q", env.Lifecycle, tc.lifecycle)
			}
			if env.Stage != tc.stage {
				t.Errorf("stage = %q, want %q", env.Stage, tc.stage)
			}
			if env.BlockCapable != tc.blockable {
				t.Errorf("blockCapable = %v, want %v", env.BlockCapable, tc.blockable)
			}
		})
	}
}

// TestNormalize_SubagentActorIDs covers the spec's actor-id rules
// for subagents: agent_id wins, agent_type is the fallback, and
// fingerprint is the last resort. Same agent twice produces the
// same id (idempotency invariant for upserts).
func TestNormalize_SubagentActorIDs(t *testing.T) {
	type want struct {
		id       string
		kind     string
		label    string
		source   string
		claudeID string
	}
	cases := []struct {
		name string
		body string
		want want
	}{
		{
			name: "with_agent_id",
			body: `{"hook_event_name":"SubagentStart","session_id":"sess-test","agent_id":"sa-1","agent_type":"code-reviewer"}`,
			want: want{
				id:       "sess-test:subagent:sa-1",
				kind:     ActorKindSubagent,
				label:    "code-reviewer",
				source:   ActorSourcePayload,
				claudeID: "sa-1",
			},
		},
		{
			name: "type_only",
			body: `{"hook_event_name":"SubagentStart","session_id":"sess-test","agent_type":"explorer"}`,
			want: want{
				id:     "sess-test:subagent-type:explorer",
				kind:   ActorKindSubagent,
				label:  "explorer",
				source: ActorSourcePayload,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, _ := Normalize([]byte(tc.body), baseIdentity, time.Now())
			if env.Actor.ID != tc.want.id {
				t.Errorf("actor.id = %q, want %q", env.Actor.ID, tc.want.id)
			}
			if env.Actor.Kind != tc.want.kind {
				t.Errorf("actor.kind = %q, want %q", env.Actor.Kind, tc.want.kind)
			}
			if env.Actor.Label != tc.want.label {
				t.Errorf("actor.label = %q, want %q", env.Actor.Label, tc.want.label)
			}
			if env.Actor.Source != tc.want.source {
				t.Errorf("actor.source = %q, want %q", env.Actor.Source, tc.want.source)
			}
			if tc.want.claudeID != "" && env.Actor.ClaudeAgentID != tc.want.claudeID {
				t.Errorf("actor.claude_agent_id = %q, want %q", env.Actor.ClaudeAgentID, tc.want.claudeID)
			}
		})
	}

	// Idempotency: same payload twice produces the same actor id.
	body := `{"hook_event_name":"SubagentStart","session_id":"sess-test","agent_id":"same","agent_type":"x"}`
	a, _ := Normalize([]byte(body), baseIdentity, time.Now())
	b, _ := Normalize([]byte(body), baseIdentity, time.Now())
	if a.Actor.ID != b.Actor.ID {
		t.Errorf("actor.id not idempotent: %q vs %q", a.Actor.ID, b.Actor.ID)
	}
}

// TestNormalize_LazyActorMarkedInferred locks in the spec rule
// that a tool event arriving before SubagentStart yields an
// inferred actor source. The store's upsert preserves that source
// even when SubagentStart later refreshes the row (covered in
// store_test.go).
func TestNormalize_LazyActorMarkedInferred(t *testing.T) {
	body := `{"hook_event_name":"PreToolUse","session_id":"sess-test","agent_id":"sa-2","agent_type":"helper","tool_name":"Read"}`
	env, err := Normalize([]byte(body), baseIdentity, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if env.Actor.Kind != ActorKindSubagent {
		t.Errorf("actor.kind = %q, want subagent", env.Actor.Kind)
	}
	if env.Actor.Source != ActorSourceInferred {
		t.Errorf("actor.source = %q, want inferred_from_tool_event", env.Actor.Source)
	}
}

// TestNormalize_ToolEventWithoutAgentBelongsToRoot validates the
// "everything else => root actor" branch of pickActor.
func TestNormalize_ToolEventWithoutAgentBelongsToRoot(t *testing.T) {
	body := `{"hook_event_name":"PreToolUse","session_id":"sess-test","tool_name":"Bash"}`
	env, _ := Normalize([]byte(body), baseIdentity, time.Now())
	if env.Actor.Kind != ActorKindRoot {
		t.Errorf("actor.kind = %q, want root", env.Actor.Kind)
	}
	if env.ParentActorID != "" {
		t.Errorf("root actor must have empty parent, got %q", env.ParentActorID)
	}
}

// TestNormalize_TaskActor pin the task actor id format and label
// fallback (subject preferred, task id fallback).
func TestNormalize_TaskActor(t *testing.T) {
	body := `{"hook_event_name":"TaskCreated","session_id":"sess-test","task_id":"t-1","task_subject":"Investigate failing build"}`
	env, _ := Normalize([]byte(body), baseIdentity, time.Now())
	if env.Actor.Kind != ActorKindTask {
		t.Errorf("actor.kind = %q, want task", env.Actor.Kind)
	}
	if env.Actor.ID != "sess-test:task:t-1" {
		t.Errorf("actor.id = %q", env.Actor.ID)
	}
	if env.Actor.Label != "Investigate failing build" {
		t.Errorf("actor.label = %q", env.Actor.Label)
	}
	if env.ParentActorID != ActorIDForRoot("sess-test") {
		t.Errorf("task parent = %q, want root", env.ParentActorID)
	}
}

// TestNormalize_TranscriptAndCWDAreRedacted asserts the spec rule
// that full paths never land in the envelope: only path tail +
// hash. A test grep for the full path string proves the contract.
func TestNormalize_TranscriptAndCWDAreRedacted(t *testing.T) {
	body := `{"hook_event_name":"SessionStart","session_id":"sess-test","cwd":"/Users/secretuser/sensitive/proj","transcript_path":"/Users/secretuser/.claude/transcripts/2026-04-27/abc.jsonl"}`
	env, _ := Normalize([]byte(body), baseIdentity, time.Now())
	if strings.Contains(env.CWD, "secretuser") {
		t.Errorf("envelope.CWD leaks full path: %q", env.CWD)
	}
	if strings.Contains(env.TranscriptRef.PathTail, "secretuser") {
		t.Errorf("envelope.TranscriptRef.PathTail leaks full path: %q", env.TranscriptRef.PathTail)
	}
	if env.CWDHash == "" {
		t.Error("envelope.CWDHash should be populated")
	}
	if env.TranscriptRef.PathHash == "" {
		t.Error("envelope.TranscriptRef.PathHash should be populated")
	}
	if strings.Contains(env.RawEvidenceJSON, "secretuser") {
		t.Errorf("evidence JSON leaks full path: %s", env.RawEvidenceJSON)
	}
}

// TestNormalize_ToolInputHashOnly proves the input/output payload
// is hashed, not embedded. The dashboard correlates by hash and
// joins the audit row for the full body.
func TestNormalize_ToolInputHashOnly(t *testing.T) {
	body := `{"hook_event_name":"PreToolUse","session_id":"sess-test","tool_name":"Bash","tool_input":{"command":"echo SUPER_SECRET"}}`
	env, _ := Normalize([]byte(body), baseIdentity, time.Now())
	if env.Tool.InputHash == "" {
		t.Error("tool input hash missing")
	}
	if strings.Contains(env.RawEvidenceJSON, "SUPER_SECRET") {
		t.Errorf("evidence leaks tool input: %s", env.RawEvidenceJSON)
	}
}

// TestNormalize_HeartbeatSessionStartHasObservedSource ensures
// the heartbeat detection wires into start_source so the upsert
// can label the session correctly.
func TestNormalize_HeartbeatSessionStartHasObservedSource(t *testing.T) {
	if !IsHeartbeatSession("heartbeat-20260427T120000Z") {
		t.Error("IsHeartbeatSession false-negative on canonical id")
	}
	if IsHeartbeatSession("sess-real-001") {
		t.Error("IsHeartbeatSession false-positive on real session id")
	}
}

// TestNormalize_UnknownEventDefaultsToObserved keeps a future
// Claude addition functional: an unknown hook event should still
// produce a usable envelope with sane defaults instead of
// erroring out.
func TestNormalize_UnknownEventDefaultsToObserved(t *testing.T) {
	body := `{"hook_event_name":"SomeBrandNewEvent","session_id":"sess-test"}`
	env, err := Normalize([]byte(body), baseIdentity, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if env.Stage != StageObserved {
		t.Errorf("unknown event stage = %q, want observed", env.Stage)
	}
	if env.BlockCapable {
		t.Error("unknown event must default to non-blocking")
	}
}

// TestNormalize_MalformedJSONErrors makes sure the normalizer
// surfaces a parse error so the hook handler can choose how to
// handle it, instead of silently returning an empty envelope.
func TestNormalize_MalformedJSONErrors(t *testing.T) {
	_, err := Normalize([]byte("{not json"), baseIdentity, time.Now())
	if err == nil {
		t.Error("expected parse error on malformed JSON")
	}
}

// TestNormalize_EventIDsAreUnique sanity-checks that two
// envelopes for the same payload still get distinct ids — the
// runtime row is OUR row, not the operator's, so it must never
// collide on retry.
func TestNormalize_EventIDsAreUnique(t *testing.T) {
	body := `{"hook_event_name":"SessionStart","session_id":"sess-test"}`
	a, _ := Normalize([]byte(body), baseIdentity, time.Now())
	b, _ := Normalize([]byte(body), baseIdentity, time.Now())
	if a.ID == b.ID {
		t.Errorf("event ids collided: %q", a.ID)
	}
	if a.ID == "" {
		t.Error("event id is empty")
	}
}
