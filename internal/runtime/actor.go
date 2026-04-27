package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
)

// ActorIDForRoot is the deterministic root-actor id for a session.
// One per session id; the upsert collapses repeats. Centralised so
// every caller (normalizer, hook handler, dashboard tests) builds
// the same id from the same session id.
func ActorIDForRoot(sessionID string) string {
	if sessionID == "" {
		return ""
	}
	return sessionID + ":root"
}

// ActorIDForSubagent prefers the Claude-assigned agent_id when
// available because it is unique within a session. Falls back to a
// type-slug when only agent_type is present (CLI-defined or
// frontmatter-defined subagents that did not surface an id) and to
// a stable hash when neither is present.
func ActorIDForSubagent(sessionID, agentID, agentType string, payloadStable string) string {
	if sessionID == "" {
		return ""
	}
	switch {
	case agentID != "":
		return sessionID + ":subagent:" + agentID
	case agentType != "":
		return sessionID + ":subagent-type:" + slug(agentType)
	default:
		return sessionID + ":unknown:" + shortHash(payloadStable)
	}
}

// ActorIDForTask is the deterministic id for a task actor. Tasks
// are addressed by their Claude task id; if the payload omits one
// we fall back to a hash so the dashboard still has something to
// pivot on.
func ActorIDForTask(sessionID, taskID, payloadStable string) string {
	if sessionID == "" {
		return ""
	}
	if taskID != "" {
		return sessionID + ":task:" + taskID
	}
	return sessionID + ":task:" + shortHash(payloadStable)
}

// HashPath produces a stable SHA-256 hex digest for an absolute
// path. The dashboard uses it to correlate file events across
// sessions without leaking the full path. Always returns 16-byte
// hex (32 chars) so the column has a predictable width.
func HashPath(path string) string {
	if path == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(path))
	return hex.EncodeToString(sum[:16])
}

// PathTail keeps the trailing one or two path components for
// display. Drops the rest so the dashboard never accidentally
// shows the operator's home directory or a project root prefix.
func PathTail(path string) string {
	if path == "" {
		return ""
	}
	clean := filepath.Clean(path)
	parts := strings.Split(clean, string(filepath.Separator))
	if len(parts) <= 2 {
		return clean
	}
	return parts[len(parts)-2] + string(filepath.Separator) + parts[len(parts)-1]
}

// IsHeartbeatSession returns true when the session id matches the
// pattern `oktsec doctor claude-code --emit-heartbeat` produces.
// Used by the session upsert to set status=heartbeat and by the
// dashboard to label heartbeat rows as diagnostic.
func IsHeartbeatSession(sessionID string) bool {
	return strings.HasPrefix(sessionID, "heartbeat-")
}

// isHeartbeatSession is the unexported alias used inside this
// package; kept distinct so the public API surface stays IsXxx.
func isHeartbeatSession(sessionID string) bool {
	return IsHeartbeatSession(sessionID)
}

// slug converts an arbitrary string into a stable, filename-safe
// identifier. Used for actor ids derived from agent_type so a
// space or dash in the agent name does not break URL routing or
// SQL parameter binding (defensive — neither would today, but the
// invariant is cheap to keep).
func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	var b strings.Builder
	prevDash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		case r == '-' || r == '_':
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return shortHash(s)
	}
	return out
}

// shortHash returns the first 16 hex chars of SHA-256(s). Stable
// across runs so a fallback actor id reused in two events maps to
// the same row.
func shortHash(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

// stablePayloadFingerprint builds a deterministic fingerprint of
// the fields the normalizer reaches for when no agent_id /
// agent_type / task_id is present. Keeps fallback actor ids
// stable across retries of the same event without depending on
// timestamps.
func stablePayloadFingerprint(parts ...string) string {
	return shortHash(strings.Join(parts, "|"))
}

// formatRoot is a tiny helper for the dashboard's label fallback
// when no other actor name is available.
func formatRoot(clientID string) string {
	if clientID == "" {
		return "root"
	}
	return fmt.Sprintf("root (%s)", clientID)
}
