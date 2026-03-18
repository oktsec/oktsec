// Package hooks provides a client-agnostic HTTP endpoint for receiving
// tool-call telemetry from MCP clients. Any client that supports hook-style
// callbacks (pre/post tool execution) can POST events here. oktsec runs them
// through the security pipeline and logs to the audit trail.
package hooks

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/engine"
	"github.com/oktsec/oktsec/internal/verdict"
	"github.com/oktsec/oktsec/internal/config"
)

// ToolEvent is the client-agnostic payload for a tool call event.
// Clients normalize their native format into these fields, or send them
// directly if they already match (e.g., Claude Code's hook JSON is close).
type ToolEvent struct {
	// Core fields (required)
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input,omitempty"`

	// Lifecycle
	Event      string `json:"event,omitempty"`           // "pre_tool_use" or "post_tool_use"
	ToolOutput string `json:"tool_output,omitempty"`     // post_tool_use only
	ExitCode   *int   `json:"exit_code,omitempty"`       // post_tool_use only (Bash)

	// Identity
	Agent     string `json:"agent,omitempty"`           // agent name (from header or payload)
	Client    string `json:"client,omitempty"`          // source client: "claude-code", "cursor", etc.
	SessionID string `json:"session_id,omitempty"`
	ToolUseID string `json:"tool_use_id,omitempty"`

	// Subagent identity (Claude Code sends these when running inside a subagent)
	AgentID   string `json:"agent_id,omitempty"`        // unique subagent instance ID
	AgentType string `json:"agent_type,omitempty"`      // subagent type: "Explore", "Plan", or custom name

	// Context
	CWD string `json:"cwd,omitempty"`

	// Claude Code specific (auto-normalized)
	HookEventName string `json:"hook_event_name,omitempty"` // "PreToolUse" / "PostToolUse"

	// Delegation chain (optional) — cryptographic proof of authorization lineage
	DelegationChain json.RawMessage `json:"delegation_chain,omitempty"`

	// Reasoning capture (optional) — chain-of-thought for audit/compliance
	Reasoning     string `json:"reasoning,omitempty"`      // model's reasoning for this tool call
	ReasoningHash string `json:"reasoning_hash,omitempty"` // SHA-256 of reasoning (if client sends hash-only)
	PlanStep      int    `json:"plan_step,omitempty"`      // position in a multi-step plan
	PlanTotal     int    `json:"plan_total,omitempty"`     // total steps in plan
}

// normalize fills generic fields from client-specific ones.
func (e *ToolEvent) normalize(r *http.Request) {
	// Claude Code: hook_event_name -> event
	if e.Event == "" && e.HookEventName != "" {
		switch e.HookEventName {
		case "PreToolUse":
			e.Event = "pre_tool_use"
		case "PostToolUse":
			e.Event = "post_tool_use"
		default:
			e.Event = strings.ToLower(e.HookEventName)
		}
	}
	if e.Event == "" {
		e.Event = "pre_tool_use" // default
	}

	// Agent from header (fallback for non-subagent tool calls)
	if hdr := r.Header.Get("X-Oktsec-Agent"); hdr != "" {
		e.Agent = hdr
	}
	if e.Agent == "" {
		e.Agent = "unknown"
	}

	// Client from header
	if hdr := r.Header.Get("X-Oktsec-Client"); hdr != "" {
		e.Client = hdr
	}
}

// scanContent builds a string representation for the scanner.
func (e *ToolEvent) scanContent() string {
	var sb strings.Builder
	sb.WriteString(e.ToolName)
	if len(e.ToolInput) > 0 && string(e.ToolInput) != "null" {
		sb.WriteString(" ")
		sb.Write(e.ToolInput)
	}
	if e.ToolOutput != "" {
		sb.WriteString("\n---\n")
		sb.WriteString(e.ToolOutput)
	}
	return sb.String()
}

// contentHash returns a SHA-256 hash of the scannable content.
func (e *ToolEvent) contentHash() string {
	h := sha256.Sum256([]byte(e.scanContent()))
	return fmt.Sprintf("%x", h[:16])
}

// Handler processes tool-call events from any MCP client.
type Handler struct {
	scanner *engine.Scanner
	store   *audit.Store
	cfg     *config.Config
	logger  *slog.Logger
}

// NewHandler creates a hooks handler wired to the security pipeline.
func NewHandler(scanner *engine.Scanner, store *audit.Store, cfg *config.Config, logger *slog.Logger) *Handler {
	return &Handler{
		scanner: scanner,
		store:   store,
		cfg:     cfg,
		logger:  logger,
	}
}

// maxBody limits hook payloads to 1 MB.
const maxBody = 1 << 20

// ServeHTTP handles POST requests with tool-call events.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	var ev ToolEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	ev.normalize(r)

	start := time.Now()

	// Scan content through the security pipeline.
	content := ev.scanContent()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	outcome, scanErr := h.scanner.ScanContent(ctx, content)

	// Determine verdict.
	status := audit.StatusDelivered
	decision := audit.DecisionAllow
	findingsJSON := "[]"

	if scanErr != nil {
		h.logger.Warn("hook scan error", "error", scanErr, "tool", ev.ToolName)
		decision = audit.DecisionScanError
	} else if outcome != nil && len(outcome.Findings) > 0 {
		// Apply tool-scoped rule overrides from config.
		verdict.ApplyToolScopedOverrides(h.cfg.Rules, outcome, ev.ToolName)

		// Apply scan profile only for content tools (Write, Edit, etc.)
		// where file content naturally contains patterns that match rules.
		// Execution tools (Bash, Agent, WebFetch) keep strict scanning
		// so real threats are detected.
		if config.ContentTools[ev.ToolName] {
			profile := config.ScanProfileContentAware
			if agent, ok := h.cfg.Agents[ev.Agent]; ok && agent.ScanProfile != "" {
				profile = agent.ScanProfile
			}
			verdict.ApplyScanProfile(profile, outcome, ev.ToolName)
		}

		// If all findings were removed by tool scoping, reset to clean.
		if len(outcome.Findings) == 0 {
			outcome.Verdict = engine.VerdictClean
		}

		findingsJSON = verdict.EncodeFindings(outcome.Findings)

		status, decision = verdict.ToAuditStatus(outcome.Verdict)
	}

	// Log to audit trail.
	msgID := uuid.New().String()
	toolArgs := truncateStr(string(ev.ToolInput), 2000)

	// Resolve the acting agent when running inside a subagent.
	// Claude Code sends agent_type for tool calls within subagents.
	if ev.AgentType != "" {
		resolved := h.resolveAgent(ev.AgentType)
		if resolved != "" {
			ev.Agent = resolved
		}
	}

	// For Agent tool calls, extract the subagent name from description
	// so the graph shows claude-code → subagent instead of claude-code → gateway/Agent.
	toAgent := "gateway/" + ev.ToolName
	if ev.ToolName == "Agent" {
		toAgent = h.extractSubagentName(ev.ToolInput)
	}

	// Compute delegation chain hash if provided.
	var delegationHash string
	if len(ev.DelegationChain) > 0 && string(ev.DelegationChain) != "null" {
		dh := sha256.Sum256(ev.DelegationChain)
		delegationHash = fmt.Sprintf("%x", dh)
	}

	h.store.Log(audit.Entry{
		ID:                  msgID,
		Timestamp:           time.Now().UTC().Format(time.RFC3339),
		FromAgent:           ev.Agent,
		ToAgent:             toAgent,
		ToolName:            ev.ToolName,
		ContentHash:         ev.contentHash(),
		Status:              status,
		RulesTriggered:      findingsJSON,
		PolicyDecision:      decision,
		LatencyMs:           time.Since(start).Milliseconds(),
		Intent:              toolArgs,
		SessionID:           ev.SessionID,
		DelegationChainHash: delegationHash,
	})

	// Log reasoning if provided (separate table for large data).
	if ev.Reasoning != "" {
		rHash := ev.ReasoningHash
		if rHash == "" {
			rh := sha256.Sum256([]byte(ev.Reasoning))
			rHash = fmt.Sprintf("%x", rh)
		}
		_ = h.store.LogReasoning(audit.ReasoningEntry{
			ID:            uuid.New().String(),
			AuditEntryID:  msgID,
			SessionID:     ev.SessionID,
			ToolUseID:     ev.ToolUseID,
			Reasoning:     ev.Reasoning,
			ReasoningHash: rHash,
			PlanStep:      ev.PlanStep,
			PlanTotal:     ev.PlanTotal,
			Timestamp:     time.Now().UTC().Format(time.RFC3339),
		})
	}

	h.logger.Debug("hook event",
		"event", ev.Event,
		"agent", ev.Agent,
		"tool", ev.ToolName,
		"decision", decision,
		"latency_ms", time.Since(start).Milliseconds(),
	)

	// Return decision.
	w.Header().Set("Content-Type", "application/json")
	if status == audit.StatusBlocked {
		// Signal the client to block execution.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"decision": "block",
			"reason":   formatBlockReason(outcome),
		})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"decision": "allow",
	})
}

func formatBlockReason(outcome *engine.ScanOutcome) string {
	if outcome == nil || len(outcome.Findings) == 0 {
		return "blocked by security policy"
	}
	return fmt.Sprintf("rule %s: %s", outcome.Findings[0].RuleID, outcome.Findings[0].Name)
}

// resolveAgent maps a Claude Code agent_type to a known agent name from config.
// Returns the matched agent name, or the slugified agent_type if no match.
// Built-in types like "Explore", "Plan", "general-purpose" are kept as-is.
func (h *Handler) resolveAgent(agentType string) string {
	lower := strings.ToLower(agentType)

	// Exact match against configured agents.
	if _, ok := h.cfg.Agents[lower]; ok {
		return lower
	}

	// Keyword match: split agent_type into words and match against agent names.
	words := strings.FieldsFunc(lower, func(r rune) bool {
		return r == '-' || r == '_' || r == ' '
	})
	bestName := ""
	bestScore := 0
	for name := range h.cfg.Agents {
		if name == "claude-code" {
			continue
		}
		parts := strings.Split(name, "-")
		score := 0
		for _, p := range parts {
			if len(p) < 3 {
				continue
			}
			for _, w := range words {
				if strings.Contains(w, p) || strings.Contains(p, w) {
					score++
					break
				}
			}
		}
		if score > bestScore {
			bestScore = score
			bestName = name
		}
	}
	if bestScore >= 2 {
		return bestName
	}

	return lower
}

// extractSubagentName parses Agent tool_input to get a slug from the description field,
// then tries to match it against a known agent from config.
func (h *Handler) extractSubagentName(input json.RawMessage) string {
	var payload struct {
		Description string `json:"description"`
	}
	if json.Unmarshal(input, &payload) != nil || payload.Description == "" {
		return "subagent"
	}
	slug := slugify(payload.Description)

	// Match against configured agents using bidirectional keyword overlap.
	// "vuln" matches "vulnerability" and vice versa via prefix containment.
	descWords := strings.Fields(strings.ToLower(payload.Description))
	bestName := ""
	bestScore := 0
	for name := range h.cfg.Agents {
		if name == "claude-code" {
			continue
		}
		parts := strings.Split(name, "-")
		score := 0
		for _, p := range parts {
			if len(p) < 3 {
				continue
			}
			for _, w := range descWords {
				// Either the name part is in the word or the word is in the name part.
				if strings.Contains(w, p) || strings.Contains(p, w) {
					score++
					break
				}
			}
		}
		if score > bestScore {
			bestScore = score
			bestName = name
		}
	}
	if bestScore >= 2 {
		return bestName
	}
	return slug
}

// slugify converts a description like "Breaking cybersecurity news hunt" to "breaking-cybersecurity-news-hunt".
func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	prevDash := false
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			prevDash = false
		} else if !prevDash && b.Len() > 0 {
			b.WriteByte('-')
			prevDash = true
		}
	}
	out := strings.TrimRight(b.String(), "-")
	if out == "" {
		return "subagent"
	}
	return out
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
