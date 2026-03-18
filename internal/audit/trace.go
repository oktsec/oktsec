package audit

import (
	"time"
)

// SessionTrace reconstructs the reasoning timeline for a session.
// Even without explicit reasoning text, the sequence of tool calls,
// their inputs/outputs, timing, and verdicts tells the story of
// what the agent did and why.
type SessionTrace struct {
	SessionID string      `json:"session_id"`
	Agent     string      `json:"agent"`
	Steps     []TraceStep `json:"steps"`
	Duration  string      `json:"duration"`
	StartedAt string      `json:"started_at"`
	EndedAt   string      `json:"ended_at"`
	ToolCount int         `json:"tool_count"`
	Threats   int         `json:"threats"`
}

// TraceStep is a single tool call in a session trace.
type TraceStep struct {
	ToolName   string `json:"tool_name"`
	ToolInput  string `json:"tool_input"`
	Reasoning  string `json:"reasoning,omitempty"`
	Verdict    string `json:"verdict"`
	Decision   string `json:"decision"`
	Timestamp  string `json:"timestamp"`
	GapMs      int64  `json:"gap_ms"`
	LatencyMs  int64  `json:"latency_ms"`
	EventID    string `json:"event_id"`
	PlanStep   int    `json:"plan_step,omitempty"`
	PlanTotal  int    `json:"plan_total,omitempty"`
}

// BuildSessionTrace constructs a timeline of tool calls for a session.
func (s *Store) BuildSessionTrace(sessionID string) (*SessionTrace, error) {
	// Get all audit entries for this session
	entries, err := s.Query(QueryOpts{
		SessionID: sessionID,
		Limit:     500,
	})
	if err != nil {
		return nil, err
	}

	if len(entries) == 0 {
		return nil, nil
	}

	// Get reasoning entries for this session
	reasoningEntries, err := s.QueryReasoningBySession(sessionID)
	if err != nil {
		reasoningEntries = nil // non-fatal
	}
	reasoningMap := make(map[string]*ReasoningEntry, len(reasoningEntries))
	for i := range reasoningEntries {
		reasoningMap[reasoningEntries[i].AuditEntryID] = &reasoningEntries[i]
	}

	// Entries come back DESC from query, reverse for chronological order
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}

	trace := &SessionTrace{
		SessionID: sessionID,
		Agent:     entries[0].FromAgent,
		ToolCount: len(entries),
		StartedAt: entries[0].Timestamp,
		EndedAt:   entries[len(entries)-1].Timestamp,
	}

	// Calculate duration (try RFC3339Nano then RFC3339)
	parseTS := func(ts string) (time.Time, bool) {
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			return t, true
		}
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			return t, true
		}
		return time.Time{}, false
	}
	if start, ok := parseTS(trace.StartedAt); ok {
		if end, ok := parseTS(trace.EndedAt); ok {
			d := end.Sub(start).Round(time.Second)
			if d < time.Second {
				d = end.Sub(start).Round(time.Millisecond)
			}
			trace.Duration = d.String()
		}
	}

	var prevTime time.Time
	for _, e := range entries {
		step := TraceStep{
			ToolName:  e.ToolName,
			ToolInput: truncateStr(e.Intent, 200),
			Verdict:   e.Status,
			Decision:  e.PolicyDecision,
			Timestamp: e.Timestamp,
			LatencyMs: e.LatencyMs,
			EventID:   e.ID,
		}

		// Calculate gap from previous step
		if t, ok := parseTS(e.Timestamp); ok {
			if !prevTime.IsZero() {
				step.GapMs = t.Sub(prevTime).Milliseconds()
			}
			prevTime = t
		}

		// Attach reasoning if available
		if r, ok := reasoningMap[e.ID]; ok {
			step.Reasoning = truncateStr(r.Reasoning, 500)
			step.PlanStep = r.PlanStep
			step.PlanTotal = r.PlanTotal
		}

		// Count threats
		if e.Status == StatusBlocked || e.Status == StatusQuarantined {
			trace.Threats++
		}

		trace.Steps = append(trace.Steps, step)
	}

	return trace, nil
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
