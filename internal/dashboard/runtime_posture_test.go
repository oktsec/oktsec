package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/oktsec/oktsec/internal/auditcheck"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/connectors/claudecode"
	"github.com/oktsec/oktsec/internal/runtime"
)

// runtime_posture_test.go covers the Phase 4A spec acceptance:
// the Agent Runtime Posture page must surface runtime evidence
// first and never headline a hardening grade for a runtime state
// nobody has finished setting up. The pure builder is exercised
// with PostureInputs fixtures so the rules stay reproducible
// without a live runtime.Store, plus a couple of end-to-end
// cases hit /dashboard/audit through the real handler so the
// template renders the right copy.

// fixtureProtectedConnection returns a ConnectorHealth value
// representing a fully wired Claude Code with fresh real tool
// activity under protected coverage. Used by the protected /
// hardening-secondary cases.
func fixtureProtectedConnection() claudecode.ConnectorHealth {
	return claudecode.ConnectorHealth{
		ConnectorID:       "claude-code",
		Status:            "ready",
		Installed:         true,
		HookInstalled:     true,
		GatewayConfigured: true,
		Runtime: claudecode.RuntimeEvidence{
			HasEvidence:       true,
			HasFreshHeartbeat: true,
			HasFreshRealEvent: true,
			CoverageStage:     PostureCellProtected,
		},
	}
}

// fixtureHeartbeatOnlyConnection returns a ConnectorHealth value
// representing a connector that has emitted heartbeats but no
// real tool activity yet. Used by the observing / heartbeat-only
// cases.
func fixtureHeartbeatOnlyConnection() claudecode.ConnectorHealth {
	return claudecode.ConnectorHealth{
		ConnectorID:   "claude-code",
		Status:        "ready",
		Installed:     true,
		HookInstalled: true,
		Runtime: claudecode.RuntimeEvidence{
			HasEvidence:       true,
			HasFreshHeartbeat: true,
			HasFreshRealEvent: false,
			CoverageStage:     "",
		},
	}
}

// baseInputsWithConnection bundles a connection into a
// PostureInputs with neutral defaults (audit grade = A, runtime
// store ready, signature required). Tests override only what
// they care about.
func baseInputsWithConnection(conn claudecode.ConnectorHealth) PostureInputs {
	return PostureInputs{
		Connection:         conn,
		Identity:           config.IdentityConfig{RequireSignature: true},
		Cfg:                &config.Config{},
		HookInstalled:      conn.HookInstalled,
		Auditcheck:         nil,
		AuditcheckSummary:  auditcheck.Summary{},
		AuditcheckScore:    100,
		AuditcheckGrade:    "A",
		FixableCount:       0,
		RuntimeStoreReady:  true,
		AuditChainValid:    true,
		AuditChainEntries:  10,
		HasRuntimeEvidence: conn.Runtime.HasEvidence,
	}
}

// TestRuntimePosture_NoRuntimeEvidenceSuppressesScore — when
// runtime cannot prove the agent is being protected, the page
// must NOT render a hardening grade as the headline. Status
// collapses to setup_pending and SuppressScore=true.
func TestRuntimePosture_NoRuntimeEvidenceSuppressesScore(t *testing.T) {
	in := baseInputsWithConnection(claudecode.ConnectorHealth{
		Status: "not_installed",
	})
	in.HasRuntimeEvidence = false
	snap := buildRuntimePostureSnapshot(in)

	if snap.Status != PostureStatusSetupPending {
		t.Errorf("Status = %q, want %q", snap.Status, PostureStatusSetupPending)
	}
	if !snap.SuppressScore {
		t.Errorf("SuppressScore = false, want true on no-runtime-evidence state")
	}
	if !snap.Hardening.Suppressed {
		t.Errorf("Hardening.Suppressed = false, want true (mirror of SuppressScore)")
	}
	if snap.Hardening.Reason == "" {
		t.Errorf("Hardening.Reason should explain why the grade is hidden")
	}
}

// TestRuntimePosture_HeartbeatOnlyShowsDiagnosticNotProtected —
// a fresh heartbeat lifts status to observing, NOT protected.
// Coverage dimension stays observed-only and the explanation
// must say the heartbeat is diagnostic, not protection.
func TestRuntimePosture_HeartbeatOnlyShowsDiagnosticNotProtected(t *testing.T) {
	in := baseInputsWithConnection(fixtureHeartbeatOnlyConnection())
	snap := buildRuntimePostureSnapshot(in)

	if snap.Status != PostureStatusObserving {
		t.Errorf("Status = %q, want %q (heartbeat-only must not be protected)", snap.Status, PostureStatusObserving)
	}
	if strings.Contains(strings.ToLower(snap.Title), "protected") {
		t.Errorf("Heartbeat-only Title contains 'protected': %q", snap.Title)
	}
	if strings.Contains(strings.ToLower(snap.Summary), "protected coverage") {
		t.Errorf("Heartbeat-only Summary claims protected coverage: %q", snap.Summary)
	}
	cov := findDimension(t, snap, PostureDimCoverage)
	if cov.Status == PostureCellProtected {
		t.Errorf("Coverage dimension reads protected on a heartbeat-only state")
	}
}

// TestRuntimePosture_FreshProtectedHookShowsProtected — the
// happy path: fresh real event + protected coverage = protected
// posture. Hardening can show its grade as secondary because
// runtime has actually proven it is being defended.
func TestRuntimePosture_FreshProtectedHookShowsProtected(t *testing.T) {
	in := baseInputsWithConnection(fixtureProtectedConnection())
	snap := buildRuntimePostureSnapshot(in)

	if snap.Status != PostureStatusProtected {
		t.Errorf("Status = %q, want %q", snap.Status, PostureStatusProtected)
	}
	if snap.SuppressScore {
		t.Errorf("SuppressScore = true on protected state; expected false so hardening grade can appear secondary")
	}
	if snap.Hardening.Suppressed {
		t.Errorf("Hardening.Suppressed = true on protected state")
	}
}

// TestRuntimePosture_ExpiredProtectedHookDoesNotShowProtected —
// a connector that USED to have evidence but no longer has fresh
// rows must not surface as protected. Stale runtime is
// degraded — the operator needs to see the freshness gap, not a
// false-positive protected pill.
func TestRuntimePosture_ExpiredProtectedHookDoesNotShowProtected(t *testing.T) {
	conn := claudecode.ConnectorHealth{
		Status:        "stale",
		Installed:     true,
		HookInstalled: true,
		Runtime: claudecode.RuntimeEvidence{
			HasEvidence:       true,
			HasFreshHeartbeat: false,
			HasFreshRealEvent: false,
			// Coverage stage from the last observed event — value
			// is irrelevant once HasFreshRealEvent is false.
			CoverageStage: PostureCellProtected,
		},
	}
	in := baseInputsWithConnection(conn)
	snap := buildRuntimePostureSnapshot(in)

	if snap.Status == PostureStatusProtected {
		t.Errorf("Status = %q, want anything but protected on expired evidence", snap.Status)
	}
	if snap.EvidenceFreshness == PostureFreshnessFresh {
		t.Errorf("EvidenceFreshness = fresh on a stale connection")
	}
}

// TestRuntimePosture_RequireSignatureFalseIsIdentityFinding —
// dev-mode signature is a finding on the identity_context
// dimension, but it does NOT mention Okta/Auth0/Entra (those
// are out of scope per the Phase 4A guardrails).
func TestRuntimePosture_RequireSignatureFalseIsIdentityFinding(t *testing.T) {
	in := baseInputsWithConnection(fixtureProtectedConnection())
	in.Identity.RequireSignature = false
	snap := buildRuntimePostureSnapshot(in)

	id := findDimension(t, snap, PostureDimIdentityContext)
	if id.Status == PostureCellOK {
		t.Errorf("identity_context Status = ok with RequireSignature=false")
	}
	if !strings.Contains(strings.ToLower(id.Summary), "signature") {
		t.Errorf("identity_context summary missing signature reference: %q", id.Summary)
	}
	for _, vendor := range []string{"okta", "auth0", "entra"} {
		if strings.Contains(strings.ToLower(id.Summary+id.Evidence), vendor) {
			t.Errorf("identity_context dimension mentions vendor %q (must stay vendor-neutral): summary=%q evidence=%q", vendor, id.Summary, id.Evidence)
		}
	}
}

// TestRuntimePosture_LocalSignedIdentityIsEnough — RequireSignature=true
// alone is sufficient for a positive identity_context state.
// Missing IdP integration is not a finding.
func TestRuntimePosture_LocalSignedIdentityIsEnough(t *testing.T) {
	in := baseInputsWithConnection(fixtureProtectedConnection())
	snap := buildRuntimePostureSnapshot(in)
	id := findDimension(t, snap, PostureDimIdentityContext)
	if id.Status != PostureCellOK {
		t.Errorf("identity_context Status = %q, want ok", id.Status)
	}
}

// TestRuntimePosture_AuditFallbackDoesNotOverrideRuntimePartial —
// a runtime-partial state must stay setup_pending even when the
// audit chain is valid and the auditcheck score is high. The
// fix in Phase 3 was that audit fallback never resurrects a
// runtime-empty page; the same rule applies to posture.
func TestRuntimePosture_AuditFallbackDoesNotOverrideRuntimePartial(t *testing.T) {
	conn := claudecode.ConnectorHealth{
		Status:        "partial",
		Installed:     true,
		HookInstalled: true,
		Runtime:       claudecode.RuntimeEvidence{},
	}
	in := baseInputsWithConnection(conn)
	in.HasRuntimeEvidence = false
	in.AuditcheckScore = 95
	in.AuditcheckGrade = "A"
	in.AuditChainValid = true

	snap := buildRuntimePostureSnapshot(in)
	if snap.Status != PostureStatusSetupPending {
		t.Errorf("Status = %q, want setup_pending; audit fallback overrode runtime-partial", snap.Status)
	}
	if !snap.SuppressScore {
		t.Errorf("SuppressScore = false on runtime-partial state; audit chain validity should not unlock the score")
	}
}

// TestRuntimePosture_EvidenceStoreShowsRuntimeAndAuditChain — the
// evidence dimension is "ok" only when BOTH the runtime store is
// reachable AND the audit chain verifies. Either failure flips
// the dimension to a warn / not_configured shape.
func TestRuntimePosture_EvidenceStoreShowsRuntimeAndAuditChain(t *testing.T) {
	in := baseInputsWithConnection(fixtureProtectedConnection())
	snap := buildRuntimePostureSnapshot(in)
	ev := findDimension(t, snap, PostureDimEvidence)
	if ev.Status != PostureCellOK {
		t.Errorf("evidence Status = %q, want ok with both runtime store + chain healthy", ev.Status)
	}

	// Runtime store unavailable -> not_configured.
	in.RuntimeStoreReady = false
	snap = buildRuntimePostureSnapshot(in)
	ev = findDimension(t, snap, PostureDimEvidence)
	if ev.Status != PostureCellNotConfigured {
		t.Errorf("evidence Status = %q, want not_configured when runtime store missing", ev.Status)
	}

	// Audit chain invalid -> warn.
	in.RuntimeStoreReady = true
	in.AuditChainValid = false
	snap = buildRuntimePostureSnapshot(in)
	ev = findDimension(t, snap, PostureDimEvidence)
	if ev.Status != PostureCellWarn {
		t.Errorf("evidence Status = %q, want warn when audit chain invalid", ev.Status)
	}
}

// TestRuntimePosture_HardeningChecksAreSecondary — even on the
// happy path the hardening summary must not become the headline.
// The hero's Title is the runtime status, not the auditcheck
// grade word.
func TestRuntimePosture_HardeningChecksAreSecondary(t *testing.T) {
	in := baseInputsWithConnection(fixtureProtectedConnection())
	in.AuditcheckGrade = "A"
	snap := buildRuntimePostureSnapshot(in)

	for _, banned := range []string{"Deployment needs attention", "Critical security gaps detected", "Deployment secured"} {
		if strings.Contains(snap.Title, banned) || strings.Contains(snap.Summary, banned) {
			t.Errorf("hero copy carries legacy hardening headline %q: title=%q summary=%q", banned, snap.Title, snap.Summary)
		}
	}
	if snap.Hardening.Grade == "" {
		t.Errorf("Hardening.Grade should be available for the secondary section")
	}
}

// TestRuntimePosture_SuppressedHardeningHidesGradeAndScore is the
// explicit guardrail gus called out: when SuppressScore=true the
// rendered audit page must NOT show the score ring, the Grade
// label, or any alarmist headline copy. The neutral check count
// must remain visible so the operator can still navigate to
// remediation.
func TestRuntimePosture_SuppressedHardeningHidesGradeAndScore(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.Identity.RequireSignature = false
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	body := fetchAuditHTML(t, cookie, handler)

	for _, banned := range []string{
		"ps-ring",                         // legacy score ring CSS class
		"ps-grade-label",                  // legacy grade chip
		"Deployment needs attention",      // legacy hero copy
		"Critical security gaps detected", // legacy hero copy
	} {
		if strings.Contains(body, banned) {
			t.Errorf("audit page leaked legacy score artefact %q (suppress contract broken)", banned)
		}
	}

	if !strings.Contains(body, "Hardening checks") {
		t.Errorf("audit page must keep the Hardening checks section header even when suppressed")
	}
	if !strings.Contains(body, "Runtime evidence required") {
		t.Errorf("audit page must show the suppressed reason copy")
	}
}

// TestRuntimePosture_FreshHeartbeatIsDiagnosticNotProtected pairs
// with the heartbeat-only snapshot test above but exercises the
// full handler + template path, asserting the rendered HTML
// never tells the operator the agent is protected on the back of
// a heartbeat.
func TestRuntimePosture_FreshHeartbeatIsDiagnosticNotProtected(t *testing.T) {
	srv, rs, _ := newRuntimeGraphTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	// Seed a fresh heartbeat session — no real tool activity.
	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"SessionStart","session_id":"heartbeat-2026-04-30-rp"}`,
		"heartbeat-2026-04-30-rp", "local-codex", now.Add(-1*time.Minute), runtime.OutcomeRefs{})

	body := fetchAuditHTML(t, cookie, handler)

	if !strings.Contains(body, "Agent Runtime Posture") {
		t.Errorf("audit page missing the runtime hero")
	}
	for _, banned := range []string{
		"Protected — fresh runtime evidence",
		"Hooks installed and receiving fresh real activity",
	} {
		if strings.Contains(body, banned) {
			t.Errorf("audit page claimed protection on a heartbeat-only state via copy %q", banned)
		}
	}
}

// fetchAuditHTML hits /dashboard/audit with a logged-in cookie
// and returns the rendered body.
func fetchAuditHTML(t *testing.T, cookie *http.Cookie, handler http.Handler) string {
	t.Helper()
	req := httptest.NewRequest("GET", "/dashboard/audit", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("audit page status = %d, body=%s", w.Code, w.Body.String())
	}
	return w.Body.String()
}

// findDimension returns the dimension row with the given id or
// fails the test if it is absent.
func findDimension(t *testing.T, snap RuntimePostureSnapshot, id string) RuntimePostureDimension {
	t.Helper()
	for _, d := range snap.Dimensions {
		if d.ID == id {
			return d
		}
	}
	t.Fatalf("dimension %q not found in snapshot; have %d dimensions", id, len(snap.Dimensions))
	return RuntimePostureDimension{}
}
