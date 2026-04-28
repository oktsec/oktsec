package claudecode

import (
	"testing"
	"time"
)

// TestDeriveHealth_HeartbeatPromotesToReady locks in the
// Phase 3C-0 acceptance: a fresh heartbeat (under FreshHeartbeat,
// 10m default) is enough to lift the connection to "ready" even
// before any real event lands. This is the path
// `oktsec doctor claude-code --emit-heartbeat` exercises.
func TestDeriveHealth_HeartbeatPromotesToReady(t *testing.T) {
	now := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	inv := Inventory{
		Detected: true,
		Hooks:    []HookRef{{IsOktsec: true, Event: "PreToolUse"}},
	}
	h := DeriveHealth(inv, HealthOptions{
		Runtime: &RuntimeEvidenceInput{
			LastHeartbeatAt: now.Add(-2 * time.Minute).Format(time.RFC3339Nano),
		},
		Now: clock,
	})
	if h.Status != "ready" {
		t.Errorf("status = %q, want ready (heartbeat 2m ago should promote)", h.Status)
	}
	if !h.Runtime.HasEvidence {
		t.Errorf("runtime.HasEvidence = false, want true")
	}
}

// TestDeriveHealth_StaleHeartbeatDoesNotPromote covers the other
// half of the heartbeat rule: an old heartbeat should not falsely
// claim "ready". 11 minutes is just past the default 10m window.
func TestDeriveHealth_StaleHeartbeatDoesNotPromote(t *testing.T) {
	now := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	inv := Inventory{
		Detected: true,
		Hooks:    []HookRef{{IsOktsec: true, Event: "PreToolUse"}},
	}
	h := DeriveHealth(inv, HealthOptions{
		Runtime: &RuntimeEvidenceInput{
			LastHeartbeatAt: now.Add(-11 * time.Minute).Format(time.RFC3339Nano),
		},
		Now: clock,
	})
	if h.Status == "ready" {
		t.Errorf("status = ready, want partial/stale (heartbeat 11m ago is past FreshHeartbeat)")
	}
}

// TestDeriveHealth_RealEventPromotesToReady covers the second
// path to ready: a real hook event under FreshEvent (30m
// default) wins regardless of heartbeat presence.
func TestDeriveHealth_RealEventPromotesToReady(t *testing.T) {
	now := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	inv := Inventory{
		Detected: true,
		Hooks:    []HookRef{{IsOktsec: true, Event: "PreToolUse"}},
	}
	h := DeriveHealth(inv, HealthOptions{
		Runtime: &RuntimeEvidenceInput{
			LastEventAt:     now.Add(-5 * time.Minute).Format(time.RFC3339Nano),
			LastEventFamily: "PreToolUse",
			CoverageStage:   "observed",
		},
		Now: clock,
	})
	if h.Status != "ready" {
		t.Errorf("status = %q, want ready", h.Status)
	}
	if h.Runtime.CoverageStage != "observed" {
		t.Errorf("runtime.CoverageStage = %q, want observed", h.Runtime.CoverageStage)
	}
}

// TestDeriveHealth_InstalledNoEvidenceStaysPartial pins the
// Overview tile's "installed, waiting for first observed event"
// state. The user emphasised that this must not look like a
// security gap, so the test asserts the status string the tile
// renders off.
func TestDeriveHealth_InstalledNoEvidenceStaysPartial(t *testing.T) {
	inv := Inventory{
		Detected: true,
		Hooks:    []HookRef{{IsOktsec: true, Event: "PreToolUse"}},
	}
	h := DeriveHealth(inv, HealthOptions{
		Runtime: &RuntimeEvidenceInput{}, // empty: no heartbeat, no event
	})
	if h.Status != "partial" {
		t.Errorf("status = %q, want partial", h.Status)
	}
	if h.Runtime.HasEvidence {
		t.Errorf("runtime.HasEvidence = true, want false (empty input)")
	}
}

// TestDeriveHealth_RuntimeEvidenceTrumpsAuditLastEvent confirms
// the precedence rule: when both are present, the runtime
// timestamp wins because runtime is the durable per-event row.
func TestDeriveHealth_RuntimeEvidenceTrumpsAuditLastEvent(t *testing.T) {
	now := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	inv := Inventory{
		Detected: true,
		Hooks:    []HookRef{{IsOktsec: true, Event: "PreToolUse"}},
	}
	// Audit says it's old; runtime says it's fresh. Runtime wins.
	h := DeriveHealth(inv, HealthOptions{
		LastEvent: now.Add(-2 * time.Hour).Format(time.RFC3339),
		Runtime: &RuntimeEvidenceInput{
			LastEventAt: now.Add(-3 * time.Minute).Format(time.RFC3339Nano),
		},
		Now: clock,
	})
	if h.Status != "ready" {
		t.Errorf("status = %q, want ready (runtime fresh trumps audit stale)", h.Status)
	}
}

// TestDeriveHealth_AuditLastEventStillWorksForLegacyCallers
// verifies the doctor command path: when no Runtime block is
// passed (the doctor opens audit read-only and has no runtime
// store), DeriveHealth still uses the audit-supplied LastEvent.
func TestDeriveHealth_AuditLastEventStillWorksForLegacyCallers(t *testing.T) {
	now := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	inv := Inventory{
		Detected: true,
		Hooks:    []HookRef{{IsOktsec: true, Event: "PreToolUse"}},
	}
	h := DeriveHealth(inv, HealthOptions{
		LastEvent: now.Add(-2 * time.Minute).Format(time.RFC3339),
		Now:       clock,
	})
	if h.Status != "ready" {
		t.Errorf("status = %q, want ready (legacy LastEvent path)", h.Status)
	}
}
