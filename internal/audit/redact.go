package audit

import (
	"strings"
)

// RedactionLevel controls how much detail is visible in exported audit data.
type RedactionLevel string

const (
	// RedactNone exposes all fields (admin-only).
	RedactNone RedactionLevel = "full"
	// RedactAnalyst hides PII from rule findings but keeps structure.
	RedactAnalyst RedactionLevel = "analyst"
	// RedactExternal shows only status, timestamp, agents, and policy decision.
	RedactExternal RedactionLevel = "external"
)

// RedactedEntry is an audit entry with fields redacted per the chosen level.
type RedactedEntry struct {
	ID                string `json:"id"`
	Timestamp         string `json:"timestamp"`
	FromAgent         string `json:"from_agent"`
	ToAgent           string `json:"to_agent"`
	ContentHash       string `json:"content_hash,omitempty"`
	SignatureVerified *int   `json:"signature_verified,omitempty"`
	Status            string `json:"status"`
	RulesTriggered    string `json:"rules_triggered,omitempty"`
	PolicyDecision    string `json:"policy_decision"`
	LatencyMs         *int64 `json:"latency_ms,omitempty"`
}

// Redact applies the given redaction level to an audit entry.
func Redact(e Entry, level RedactionLevel) RedactedEntry {
	switch level {
	case RedactExternal:
		return RedactedEntry{
			ID:             e.ID,
			Timestamp:      e.Timestamp,
			FromAgent:      e.FromAgent,
			ToAgent:        e.ToAgent,
			Status:         e.Status,
			PolicyDecision: e.PolicyDecision,
		}
	case RedactAnalyst:
		rules := redactRuleFindings(e.RulesTriggered)
		return RedactedEntry{
			ID:                e.ID,
			Timestamp:         e.Timestamp,
			FromAgent:         e.FromAgent,
			ToAgent:           e.ToAgent,
			ContentHash:       e.ContentHash,
			SignatureVerified: &e.SignatureVerified,
			Status:            e.Status,
			RulesTriggered:    rules,
			PolicyDecision:    e.PolicyDecision,
			LatencyMs:         &e.LatencyMs,
		}
	default: // RedactNone / "full"
		return RedactedEntry{
			ID:                e.ID,
			Timestamp:         e.Timestamp,
			FromAgent:         e.FromAgent,
			ToAgent:           e.ToAgent,
			ContentHash:       e.ContentHash,
			SignatureVerified: &e.SignatureVerified,
			Status:            e.Status,
			RulesTriggered:    e.RulesTriggered,
			PolicyDecision:    e.PolicyDecision,
			LatencyMs:         &e.LatencyMs,
		}
	}
}

// RedactEntries applies redaction to a slice of entries.
func RedactEntries(entries []Entry, level RedactionLevel) []RedactedEntry {
	result := make([]RedactedEntry, len(entries))
	for i, e := range entries {
		result[i] = Redact(e, level)
	}
	return result
}

// redactRuleFindings strips matched content from rule findings JSON while
// preserving rule IDs, names, and severities. This is a simple string-level
// redaction that removes "matched" fields.
func redactRuleFindings(rulesJSON string) string {
	if rulesJSON == "" || rulesJSON == "[]" {
		return rulesJSON
	}

	const needle = `"matched":"`
	const placeholder = `"matched":"[REDACTED]"`
	var b strings.Builder
	b.Grow(len(rulesJSON))

	remaining := rulesJSON
	for {
		idx := strings.Index(remaining, needle)
		if idx == -1 {
			b.WriteString(remaining)
			break
		}
		// Write everything before the match key + the placeholder
		b.WriteString(remaining[:idx])
		b.WriteString(placeholder)

		// Skip past the original value: find closing quote after the key
		valStart := idx + len(needle)
		end := valStart
		for end < len(remaining) {
			if remaining[end] == '\\' && end+1 < len(remaining) {
				end += 2
				continue
			}
			if remaining[end] == '"' {
				end++ // consume closing quote
				break
			}
			end++
		}
		remaining = remaining[end:]
	}
	return b.String()
}
