package dashboard

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/oktsec/oktsec/internal/runtime"
)

// runtime_session_analysis.go is the runtime-evidence path for
// "Analyze with AI" on /dashboard/sessions/{id}. The legacy
// audit path in session_analysis.go converts a SessionTrace into
// the prompt and saves the result keyed on the bare sessionID;
// the runtime path needs a separate envelope, a separate prompt,
// and a separate persistence key so the two surfaces never mix.
//
// Why a separate file: tmpl_session.go and the legacy analyzer
// already speak the SessionTrace shape (humans/agents, raw tool
// inputs, [HUMAN]/[AGENT] role tags). Runtime evidence is hash-
// based and actor-tree-based; forcing it into the legacy shape
// would either require lying about roles or leaking raw payload.
// Keep them apart.

// runtimeSessionAnalysisKey is the persistence key for runtime
// analyses. Using a "runtime:" namespace prevents collisions
// with the legacy audit path that saves under the bare session
// id, so a session that exists in both stores never displays the
// audit analysis next to runtime evidence.
func runtimeSessionAnalysisKey(sessionID string) string {
	return "runtime:" + sessionID
}

// runtimeSessionAnalysisEnvelope is the read-only payload the
// runtime analyzer consumes. Every field is either metadata
// already on the runtime session row (counts, timestamps, ids)
// or a redacted projection (hash, tail). The struct exists so
// the prompt builder cannot accidentally reach into raw hook
// envelope fields.
type runtimeSessionAnalysisEnvelope struct {
	Source          string
	SessionID       string
	PrincipalID     string
	ClientID        string
	ConnectorID     string
	Status          string
	StartedAt       string
	LastSeenAt      string
	Duration        string
	EventCount      int64
	ToolEventCount  int64
	SubagentCount   int64
	TaskCount       int64
	BlockCount      int64
	IsHeartbeatOnly bool
	Actors          []runtimeSessionAnalysisActor
	Events          []runtimeSessionAnalysisEvent
}

type runtimeSessionAnalysisActor struct {
	Label       string
	Kind        string
	ToolCount   int64
	EventCount  int64
	BlockCount  int64
	FirstSeenAt string
	LastSeenAt  string
}

// runtimeSessionAnalysisEvent — fields are deliberately a
// subset of runtime.HookEvent. The omissions are intentional
// and listed in runtime_session_analysis.go's package doc:
//   - tool_input / tool_output (raw bytes)
//   - cwd / cwd_hash (filesystem fingerprint)
//   - transcript path
//   - file path full (we keep the tail only)
//   - task subject (can carry prompt-like content)
//   - raw hook envelope JSON
type runtimeSessionAnalysisEvent struct {
	Timestamp      string
	HookEventName  string
	ActorLabel     string
	ActorKind      string
	ToolName       string
	ToolUseID      string
	ToolInputHash  string
	ToolOutputHash string
	FilePathTail   string
	Status         string
	PolicyDecision string
	CoverageMode   string
	Confidence     int
	AuditEntryID   string
	LatencyMs      int64
}

// buildRuntimeSessionAnalysisEnvelope fetches the session +
// actors + events from the runtime store and projects them into
// the analysis envelope. Returns (nil, false) when the session
// does not exist in runtime — the caller falls back to legacy
// audit analysis. Heartbeat-only sessions return a non-nil
// envelope with IsHeartbeatOnly=true; the handler refuses
// analysis on that shape but still distinguishes "not in
// runtime" from "in runtime but diagnostic-only".
func (s *Server) buildRuntimeSessionAnalysisEnvelope(ctx context.Context, sessionID string) (*runtimeSessionAnalysisEnvelope, bool) {
	store := s.runtimeStore()
	if store == nil || sessionID == "" {
		return nil, false
	}
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	detail, err := store.QuerySession(queryCtx, sessionID)
	if err != nil {
		s.logger.Warn("runtime session analysis: QuerySession failed", "error", err, "session_id", sessionID)
		return nil, false
	}
	if detail == nil || detail.SessionID == "" {
		return nil, false
	}

	row := projectSessionListRow(detail.Session)

	env := &runtimeSessionAnalysisEnvelope{
		Source:          "runtime",
		SessionID:       detail.SessionID,
		PrincipalID:     detail.PrincipalID,
		ClientID:        detail.ClientID,
		ConnectorID:     detail.ConnectorID,
		Status:          row.Status,
		StartedAt:       row.StartedAt,
		LastSeenAt:      row.LastSeenAt,
		Duration:        row.Duration,
		EventCount:      detail.EventCount,
		ToolEventCount:  detail.ToolEventCount,
		SubagentCount:   detail.SubagentCount,
		TaskCount:       detail.TaskCount,
		BlockCount:      detail.BlockCount,
		IsHeartbeatOnly: row.IsHeartbeatOnly,
	}

	actorByID := make(map[string]runtime.Actor, len(detail.Actors))
	for _, a := range detail.Actors {
		actorByID[a.ID] = a
		env.Actors = append(env.Actors, runtimeSessionAnalysisActor{
			Label:       actorDisplayLabel(a),
			Kind:        a.Kind,
			ToolCount:   a.ToolCount,
			EventCount:  a.EventCount,
			BlockCount:  a.BlockCount,
			FirstSeenAt: formatRuntimeTimestamp(a.FirstSeenAt),
			LastSeenAt:  formatRuntimeTimestamp(a.LastSeenAt),
		})
	}

	for _, ev := range detail.Events {
		// Drop heartbeat events from the analysis stream — they
		// are diagnostic and never represent agent activity.
		if runtime.IsHeartbeatSession(ev.SessionID) {
			continue
		}
		actorLabel, actorKind := "", ""
		if a, ok := actorByID[ev.ActorID]; ok {
			actorLabel = actorDisplayLabel(a)
			actorKind = a.Kind
		}
		env.Events = append(env.Events, runtimeSessionAnalysisEvent{
			Timestamp:      formatRuntimeTimestamp(ev.Timestamp),
			HookEventName:  ev.HookEventName,
			ActorLabel:     actorLabel,
			ActorKind:      actorKind,
			ToolName:       ev.ToolName,
			ToolUseID:      ev.ToolUseID,
			ToolInputHash:  ev.ToolInputHash,
			ToolOutputHash: ev.ToolOutputHash,
			FilePathTail:   ev.FilePathTail,
			Status:         ev.Status,
			PolicyDecision: ev.PolicyDecision,
			CoverageMode:   ev.CoverageMode,
			Confidence:     ev.Confidence,
			AuditEntryID:   ev.AuditEntryID,
			LatencyMs:      ev.LatencyMs,
		})
	}
	return env, true
}

// runtimeSessionAnalysisPrompt is the system prompt for runtime
// analyses. Distinct from sessionAnalysisPrompt because the
// inputs are structurally different and the recommendations
// vocabulary is narrower:
//
//   - The model never sees raw tool input/output, only sha256
//     prefixes and file path tails. The prompt says so up front
//     so it does not fabricate content claims off a hash.
//   - "Blocked" / "quarantined" events are evidence of an
//     Oktsec control firing, NOT a verdict on the agent. The
//     prompt repeats this so a single block does not produce
//     "Suspend agent X".
//   - The recommended-actions vocabulary is restricted to a
//     short whitelist that maps onto runtime drill-downs that
//     actually exist (sessions, events, rules) so the model
//     cannot point the operator at an unimplemented page.
//   - Heartbeat is diagnostic only. The prompt repeats this so
//     a heartbeat-only session that somehow reaches analysis
//     does not produce a risk claim.
const runtimeSessionAnalysisPrompt = `You are a security analyst reviewing runtime hook evidence captured by Oktsec for one agent session.

What you are looking at:
- This is RUNTIME hook evidence, not raw conversation content. Every event was emitted by a Claude Code hook and recorded by Oktsec at the moment it fired.
- Tool input and tool output are presented as sha256 prefixes only. Never infer the content of a tool call from a hash.
- File paths are presented as the trailing component only.
- "Blocked" and "quarantined" status mean Oktsec's runtime controls fired. They are evidence the system is defending the agent, not automatic proof the agent is malicious.
- "Heartbeat" rows are diagnostic and have already been filtered out of this prompt.

Roles:
- The session has one root actor (the principal) and zero or more subagents and tasks. Each event is attributed to one actor. Recommend suspending an actor only if its runtime behaviour shows repeated unsafe action attempts that were NOT already blocked by Oktsec.

Write a structured analysis using these exact sections:

**Risk Level:** CRITICAL, HIGH, MEDIUM, LOW, or CLEAN. One sentence why, grounded in observed runtime behaviour, not in tool names.

**What happened:** 2-3 sentences. Describe the actor chain and the highest-impact events.

**Runtime control assessment:** Explain which coverage mode applied (protected, observed, or blind), what was blocked or quarantined, and whether Oktsec's controls were sufficient. If coverage was blind for any tool surface, call that out as a configuration gap.

**Recommended actions:**
Each action must link to a specific Oktsec dashboard page. Allowed shapes:
- [Review session](/dashboard/sessions/<sessionID>) - reason
- [Review event](/dashboard/events/<auditEntryID>) - reason. Use only when an audit entry id was attached to the event.
- [Review rules](/dashboard/rules) - reason. Use only when a rule gap is the root cause.
- No action needed - reason. Use when blocks were Oktsec controls firing correctly.

Rules:
- Start directly with **Risk Level:**.
- Never use em dashes.
- Do not invent tool inputs from a hash.
- Do not recommend suspending an actor that was already protected by a block.
- Keep it short. Maximum 4 bullets in recommended actions.

Session metadata:
%s

Actor tree:
%s

Timeline (oldest first, heartbeats already filtered):
%s
`

// analyzeRuntimeSession is the runtime equivalent of
// analyzeSession. Same provider switch, same callClaude /
// callOpenAI helpers, but a runtime-aware prompt assembled from
// the analysis envelope.
func (s *Server) analyzeRuntimeSession(ctx context.Context, env *runtimeSessionAnalysisEnvelope) (string, error) {
	cfg := s.cfg.LLM
	if !cfg.Enabled {
		return "", fmt.Errorf("LLM not configured")
	}
	apiKey := cfg.APIKey
	if apiKey == "" && cfg.APIKeyEnv != "" {
		apiKey = os.Getenv(cfg.APIKeyEnv)
	}
	if apiKey == "" {
		return "", fmt.Errorf("LLM API key not set")
	}

	prompt := buildRuntimeSessionAnalysisPrompt(env)

	analysisCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	switch cfg.Provider {
	case "claude":
		return s.callClaude(analysisCtx, apiKey, cfg.Model, prompt)
	case "openai":
		baseURL := cfg.BaseURL
		if baseURL == "" {
			baseURL = "https://api.openai.com/v1"
		}
		return s.callOpenAI(analysisCtx, apiKey, baseURL, cfg.Model, prompt)
	default:
		return "", fmt.Errorf("unsupported LLM provider %q for runtime session analysis", cfg.Provider)
	}
}

// buildRuntimeSessionAnalysisPrompt assembles the prompt body.
// Pulled out so the test suite can assert on the prompt shape
// without round-tripping through the LLM client.
func buildRuntimeSessionAnalysisPrompt(env *runtimeSessionAnalysisEnvelope) string {
	if env == nil {
		return ""
	}
	var meta strings.Builder
	fmt.Fprintf(&meta, "- source: %s\n", env.Source)
	fmt.Fprintf(&meta, "- session_id: %s\n", env.SessionID)
	if env.PrincipalID != "" {
		fmt.Fprintf(&meta, "- principal_id: %s\n", env.PrincipalID)
	}
	if env.ClientID != "" {
		fmt.Fprintf(&meta, "- client_id: %s\n", env.ClientID)
	}
	if env.ConnectorID != "" {
		fmt.Fprintf(&meta, "- connector_id: %s\n", env.ConnectorID)
	}
	fmt.Fprintf(&meta, "- status: %s\n", env.Status)
	if env.StartedAt != "" {
		fmt.Fprintf(&meta, "- started_at: %s\n", env.StartedAt)
	}
	if env.LastSeenAt != "" {
		fmt.Fprintf(&meta, "- last_seen_at: %s\n", env.LastSeenAt)
	}
	if env.Duration != "" {
		fmt.Fprintf(&meta, "- duration: %s\n", env.Duration)
	}
	fmt.Fprintf(&meta, "- events: %d (tool: %d, subagent: %d, task: %d, blocked: %d)\n",
		env.EventCount, env.ToolEventCount, env.SubagentCount, env.TaskCount, env.BlockCount)

	var tree strings.Builder
	for _, a := range env.Actors {
		fmt.Fprintf(&tree, "- %s [%s] events=%d tool_calls=%d blocked=%d\n",
			a.Label, a.Kind, a.EventCount, a.ToolCount, a.BlockCount)
	}
	if tree.Len() == 0 {
		tree.WriteString("(no actors recorded)\n")
	}

	var events strings.Builder
	for i, ev := range env.Events {
		if i >= 30 {
			fmt.Fprintf(&events, "... and %d more events\n", len(env.Events)-30)
			break
		}
		fmt.Fprintf(&events, "- %s actor=%s event=%s",
			ev.Timestamp, ev.ActorLabel, ev.HookEventName)
		if ev.ToolName != "" {
			fmt.Fprintf(&events, " tool=%s", ev.ToolName)
		}
		if ev.ToolUseID != "" {
			fmt.Fprintf(&events, " use_id=%s", ev.ToolUseID)
		}
		if ev.ToolInputHash != "" {
			fmt.Fprintf(&events, " input=sha256:%s", truncStr(ev.ToolInputHash, 16))
		}
		if ev.ToolOutputHash != "" {
			fmt.Fprintf(&events, " output=sha256:%s", truncStr(ev.ToolOutputHash, 16))
		}
		if ev.FilePathTail != "" {
			fmt.Fprintf(&events, " path=%s", ev.FilePathTail)
		}
		if ev.Status != "" {
			fmt.Fprintf(&events, " status=%s", ev.Status)
		}
		if ev.PolicyDecision != "" && ev.PolicyDecision != ev.Status {
			fmt.Fprintf(&events, " policy=%s", ev.PolicyDecision)
		}
		if ev.CoverageMode != "" {
			fmt.Fprintf(&events, " coverage=%s", ev.CoverageMode)
		}
		if ev.AuditEntryID != "" {
			fmt.Fprintf(&events, " audit_entry_id=%s", ev.AuditEntryID)
		}
		events.WriteString("\n")
	}
	if events.Len() == 0 {
		events.WriteString("(no non-heartbeat events recorded)\n")
	}

	return fmt.Sprintf(runtimeSessionAnalysisPrompt, meta.String(), tree.String(), events.String())
}

// runtimeAnalysisRejectionReason returns the operator-facing
// reason string when an envelope is not eligible for AI
// analysis. Keeping it here so the handler error and the
// template's "AI disabled" copy stay in sync.
func runtimeAnalysisRejectionReason(env *runtimeSessionAnalysisEnvelope) string {
	switch {
	case env == nil:
		return "runtime session not found"
	case env.IsHeartbeatOnly:
		return "runtime session is heartbeat-only and has no analysable activity"
	case len(env.Events) == 0:
		return "runtime session has no recorded events to analyse"
	default:
		return ""
	}
}
