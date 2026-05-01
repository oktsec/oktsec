package dashboard

import (
	"strings"

	"github.com/oktsec/oktsec/internal/auditcheck"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/connectors/claudecode"
)

// runtime_posture.go projects the dashboard's runtime evidence
// into the Agent Runtime Posture view-model the /dashboard/audit
// page renders. The Phase 4A spec is explicit: this page is a
// runtime-evidence summary first, NOT a hardening-score headline.
// The legacy auditcheck output stays present but lands as a
// secondary "Hardening checks" section, and its grade/score is
// suppressed entirely whenever runtime cannot prove the agent is
// being protected right now.
//
// Why a separate file: handleAudit was already large and mixed
// auditcheck rendering with chain verification with LLM stats.
// The Phase 4A spec calls for a pure builder so handleAudit can
// stay an orchestrator (gather inputs, call builder, pass view
// model) and the freshness/coverage/identity rules live in one
// testable place.

// Status values for the hero band. The page never shows raw
// timestamps as status — fresh / stale / expired / none are
// separate states (per the Phase 4A guardrails) and they map onto
// these five enum values.
const (
	PostureStatusSetupPending = "setup_pending"
	PostureStatusObserving    = "observing"
	PostureStatusProtected    = "protected"
	PostureStatusDegraded     = "degraded"
	PostureStatusBlind        = "blind"
)

// Evidence freshness buckets. Computed once and reused across
// dimensions so the template never re-derives freshness from
// timestamps.
const (
	PostureFreshnessFresh   = "fresh"
	PostureFreshnessStale   = "stale"
	PostureFreshnessExpired = "expired"
	PostureFreshnessNone    = "none"
)

// Dimension ids — the spec lists exactly five.
const (
	PostureDimConnection      = "connection"
	PostureDimCoverage        = "coverage"
	PostureDimEnforcement     = "enforcement"
	PostureDimIdentityContext = "identity_context"
	PostureDimEvidence        = "evidence"
)

// Per-dimension status enum. Distinct from the top-level posture
// status: a dimension can be "blind" even when the overall page
// is "observing" (e.g. hooks observed, egress blind).
const (
	PostureCellProtected     = "protected"
	PostureCellObserved      = "observed"
	PostureCellPartial       = "partial"
	PostureCellBlind         = "blind"
	PostureCellNotConfigured = "not_configured"
	PostureCellStale         = "stale"
	PostureCellOK            = "ok" // identity / evidence dimensions when everything is in order
	PostureCellWarn          = "warn"
)

// RuntimePostureSnapshot is the value handleAudit hands to the
// template. Fields are intentionally template-friendly: every
// status is a string the template can match against, every
// boolean has an explicit name, and the hardening summary is a
// substruct rather than a flat field set so the template can
// branch on .Hardening.Suppressed without spelunking the parent.
type RuntimePostureSnapshot struct {
	Status            string                    // setup_pending | observing | protected | degraded | blind
	Title             string                    // hero headline derived from Status
	Summary           string                    // one-line explanation under the title
	EvidenceFreshness string                    // fresh | stale | expired | none — informational, not status
	SuppressScore     bool                      // when true, hide score ring + grade + alarmist copy
	Dimensions        []RuntimePostureDimension // ordered: connection, coverage, enforcement, identity_context, evidence
	Signals           []RuntimePostureSignal    // gaps and next actions surfaced under the dimensions block
	Hardening         RuntimeHardeningSummary   // legacy auditcheck rollup — secondary section
}

// RuntimePostureDimension is one row in the Runtime dimensions
// block. The template renders Label + Status pill + Summary
// line + Evidence detail; clicking opens (in a later slice) the
// drill-down for that dimension.
type RuntimePostureDimension struct {
	ID       string
	Label    string
	Status   string
	Summary  string
	Evidence string
}

// RuntimePostureSignal is one gap/next-action row. Severity
// drives the badge colour; ActionLabel + ActionHref render an
// inline link the operator can click. Source records where the
// signal came from (runtime/activity/auditcheck/config) so the
// template can render a small attribution chip.
type RuntimePostureSignal struct {
	ID          string
	Dimension   string
	Status      string // ok | warn | fail | info
	Severity    string // info | low | medium | high | critical
	Title       string
	Detail      string
	Evidence    string
	Source      string
	ActionLabel string
	ActionHref  string
}

// RuntimeHardeningSummary wraps the existing auditcheck output
// for the secondary "Hardening checks" section. When Suppressed
// is true the template must hide the grade, the score, and any
// alarmist headline copy; the neutral counts and the
// auto-fixable count remain visible so the operator still has a
// clear path to remediation.
type RuntimeHardeningSummary struct {
	Score        int
	Grade        string
	TotalChecks  int
	Critical     int
	High         int
	Medium       int
	Info         int
	FixableCount int
	Suppressed   bool
	Reason       string // displayed when Suppressed is true ("Runtime evidence required before showing a hardening grade.")
}

// PostureInputs is the read-only bundle the orchestrator passes
// into the builder. Keeping the builder pure (no DB/store calls)
// lets the test suite construct snapshots from fixtures without
// spinning up a runtime.Store, and makes every status decision
// reproducible from a single struct value.
type PostureInputs struct {
	Connection         claudecode.ConnectorHealth
	Identity           config.IdentityConfig
	Cfg                *config.Config
	HookInstalled      bool
	Auditcheck         []auditcheck.Finding
	AuditcheckSummary  auditcheck.Summary
	AuditcheckScore    int
	AuditcheckGrade    string
	FixableCount       int
	RuntimeStoreReady  bool
	AuditChainValid    bool
	AuditChainEntries  int
	HasRuntimeEvidence bool // mirrors Connection.Runtime.HasEvidence; broken out so tests can flip it independently of a full ConnectorHealth fixture
}

// buildRuntimePostureSnapshot is the pure projection from
// PostureInputs to view-model. No I/O, no global state — every
// rule lives here.
func buildRuntimePostureSnapshot(in PostureInputs) RuntimePostureSnapshot {
	freshness := evidenceFreshness(in)
	status, suppress, title, summary := postureStatusAndTitle(in, freshness)

	snap := RuntimePostureSnapshot{
		Status:            status,
		Title:             title,
		Summary:           summary,
		EvidenceFreshness: freshness,
		SuppressScore:     suppress,
		Dimensions:        buildDimensions(in, status, freshness),
		Hardening:         buildHardeningSummary(in, suppress),
	}
	snap.Signals = buildSignals(in, snap.Dimensions)
	return snap
}

// evidenceFreshness collapses the runtime-evidence flags into one
// of four buckets. The page shows the bucket as informational
// metadata; status decisions consume the underlying booleans
// directly so a "stale" bucket cannot be promoted to "protected".
func evidenceFreshness(in PostureInputs) string {
	rt := in.Connection.Runtime
	switch {
	case rt.HasFreshRealEvent || rt.HasFreshHeartbeat:
		return PostureFreshnessFresh
	case rt.HasEvidence:
		return PostureFreshnessStale
	case in.Connection.LastEvent != "":
		// Audit-side last event existed once but no runtime row.
		// Treat as expired because runtime is the contract going
		// forward and the audit timestamp is no longer the
		// authoritative signal.
		return PostureFreshnessExpired
	default:
		return PostureFreshnessNone
	}
}

// postureStatusAndTitle is the spec's status decision tree
// inlined. The order is deliberate and the two axes — freshness
// and coverage — are kept independent so the page never reads
// "stale" off a fresh blind event or "protected" off an
// observed-only one. Setup_pending wins outright; otherwise we
// branch first on "is there fresh real activity?", then by
// coverage; heartbeat-only and stale-evidence cases follow
// after.
func postureStatusAndTitle(in PostureInputs, freshness string) (status string, suppress bool, title, summary string) {
	rt := in.Connection.Runtime

	// setup_pending — runtime is not in a state where evidence
	// can be evaluated. Suppress hard score so we never headline
	// a hardening grade for a setup nobody finished.
	switch in.Connection.Status {
	case "not_installed", "disconnected", "partial":
		return PostureStatusSetupPending, true,
			"Setup pending",
			"Runtime evidence is not available yet. Finish the connector setup before hardening claims apply."
	}
	if !in.RuntimeStoreReady {
		return PostureStatusSetupPending, true,
			"Setup pending",
			"Runtime store is not reachable. Finish the connector setup before hardening claims apply."
	}
	if !in.HasRuntimeEvidence && !rt.HasFreshHeartbeat {
		return PostureStatusSetupPending, true,
			"Setup pending",
			"Hooks are present but Oktsec has not received runtime evidence yet."
	}

	// Fresh real event branch — freshness alone never decides
	// status; we still split by coverage stage so an observed
	// or blind event does not get promoted to protected, and a
	// fresh-but-blind event does not collapse into the stale
	// "degraded" branch below.
	if rt.HasFreshRealEvent {
		switch rt.CoverageStage {
		case PostureCellProtected:
			return PostureStatusProtected, false,
				"Protected — fresh runtime evidence",
				"Real hook activity is reaching Oktsec under protected coverage."
		case PostureCellObserved:
			return PostureStatusObserving, false,
				"Observing — fresh activity, coverage not yet at full enforcement",
				"Real hook activity is reaching Oktsec but coverage is observed-only. Configure tool policies or block-capable hooks to enable full enforcement."
		case PostureCellBlind:
			return PostureStatusBlind, false,
				"Blind — agent activity observed but not covered",
				"Real hook activity is reaching Oktsec but no coverage layer is protecting the surface. Configure block-capable hooks or tool policies so coverage can lift to observed or protected."
		default:
			// CoverageStage is empty: we have a real event but
			// the runtime did not yet attach a coverage stage.
			// Observing is the safe label — never protected.
			return PostureStatusObserving, false,
				"Observing — fresh activity, coverage not yet evaluated",
				"Real hook activity is reaching Oktsec. Coverage stage will appear once the next event tags one."
		}
	}

	// Fresh heartbeat only — diagnostic. Heartbeat must never
	// read as protected; the 3C invariant is reused verbatim.
	if rt.HasFreshHeartbeat {
		return PostureStatusObserving, false,
			"Observing — heartbeat received, no tool activity yet",
			"Hook path is reachable. Run a real agent action so Oktsec can lift coverage from observed to protected."
	}

	// degraded — there IS evidence but neither a fresh real
	// event nor a fresh heartbeat. Stale by definition.
	if rt.HasEvidence {
		return PostureStatusDegraded, false,
			"Degraded — runtime evidence is stale",
			"The last runtime event is outside the freshness window. Run a fresh agent action to refresh posture."
	}

	// blind — connector is healthy enough to evaluate, but
	// nothing has been observed at all.
	return PostureStatusBlind, false,
		"Blind — connector ready but no runtime activity observed",
		"Agents and tools are configured but Oktsec has not observed any runtime activity for them."
}

// buildDimensions walks the five spec dimensions in order and
// builds a row per dimension. Each row's Status is independent:
// the connection dimension can be "ok" while coverage is
// "blind", and the template renders both side-by-side without
// re-deriving any rule.
func buildDimensions(in PostureInputs, postureStatus, freshness string) []RuntimePostureDimension {
	return []RuntimePostureDimension{
		buildConnectionDimension(in, freshness),
		buildCoverageDimension(in),
		buildEnforcementDimension(in),
		buildIdentityContextDimension(in),
		buildEvidenceDimension(in),
	}
}

func buildConnectionDimension(in PostureInputs, freshness string) RuntimePostureDimension {
	rt := in.Connection.Runtime
	dim := RuntimePostureDimension{
		ID:    PostureDimConnection,
		Label: "Connection",
	}
	switch in.Connection.Status {
	case "not_installed":
		dim.Status = PostureCellNotConfigured
		dim.Summary = "Claude Code is not installed."
		dim.Evidence = in.Connection.Reason
	case "disconnected":
		dim.Status = PostureCellNotConfigured
		dim.Summary = "Claude Code is installed but no Oktsec hook is wired."
		dim.Evidence = in.Connection.Reason
	case "partial":
		dim.Status = PostureCellPartial
		dim.Summary = "Hooks are installed but Oktsec has not received a real event yet."
		dim.Evidence = in.Connection.Reason
	case "stale":
		dim.Status = PostureCellStale
		dim.Summary = "Hooks installed; last event is older than the freshness window."
		dim.Evidence = "Last event: " + safeDash(in.Connection.LastEvent)
	case "ready":
		// Connection is about reachability. Protection is the
		// coverage dimension's job — promoting connection to
		// "protected" off a fresh real event painted a green
		// pill that disagreed with an observed-only or blind
		// coverage row in the same view.
		switch {
		case rt.HasFreshRealEvent:
			dim.Status = PostureCellOK
			dim.Summary = "Hook path reachable; receiving fresh real activity."
		case rt.HasFreshHeartbeat:
			dim.Status = PostureCellOK
			dim.Summary = "Hook path is reachable (heartbeat). Waiting for real tool activity."
		default:
			dim.Status = PostureCellObserved
			dim.Summary = "Hooks ready. Waiting for runtime evidence."
		}
		dim.Evidence = "Freshness: " + freshness
	default:
		dim.Status = PostureCellNotConfigured
		dim.Summary = "Connector status is unknown."
	}
	return dim
}

func buildCoverageDimension(in PostureInputs) RuntimePostureDimension {
	rt := in.Connection.Runtime
	dim := RuntimePostureDimension{
		ID:    PostureDimCoverage,
		Label: "Coverage",
	}
	switch rt.CoverageStage {
	case PostureCellProtected:
		dim.Status = PostureCellProtected
		dim.Summary = "Hook surface is protected by block-capable handlers."
	case PostureCellObserved:
		dim.Status = PostureCellObserved
		dim.Summary = "Hook surface is observed-only. Real events are reaching Oktsec but cannot be blocked."
	case PostureCellBlind:
		dim.Status = PostureCellBlind
		dim.Summary = "No coverage observed for the hook surface."
	default:
		if !in.HasRuntimeEvidence {
			dim.Status = PostureCellNotConfigured
			dim.Summary = "Runtime has not observed any coverage signal yet."
		} else {
			dim.Status = PostureCellPartial
			dim.Summary = "Coverage signal is incomplete."
		}
	}
	if rt.HasFreshHeartbeat && !rt.HasFreshRealEvent {
		dim.Evidence = "Heartbeat is fresh; real coverage will appear after the next tool call."
	}
	return dim
}

func buildEnforcementDimension(in PostureInputs) RuntimePostureDimension {
	dim := RuntimePostureDimension{
		ID:    PostureDimEnforcement,
		Label: "Enforcement",
	}
	cfg := in.Cfg
	if cfg == nil {
		dim.Status = PostureCellNotConfigured
		dim.Summary = "No config loaded."
		return dim
	}
	enforcers := []string{}
	missing := []string{}
	if in.HookInstalled {
		enforcers = append(enforcers, "hooks")
	}
	if len(cfg.MCPServers) > 0 && cfg.Gateway.Enabled {
		enforcers = append(enforcers, "gateway")
	} else if len(cfg.MCPServers) > 0 {
		missing = append(missing, "gateway disabled but MCP servers configured")
	}
	if cfg.Quarantine.Enabled {
		enforcers = append(enforcers, "quarantine")
	}
	if cfg.ForwardProxy.Enabled {
		enforcers = append(enforcers, "egress controls")
	} else {
		// Per-agent egress policies still count as enforcement
		// even when the top-level forward proxy is off.
		for _, a := range cfg.Agents {
			if a.Egress != nil {
				enforcers = append(enforcers, "egress controls")
				break
			}
		}
	}
	switch {
	case len(enforcers) == 0:
		dim.Status = PostureCellBlind
		dim.Summary = "No enforcement controls active."
	case len(missing) > 0:
		dim.Status = PostureCellPartial
		dim.Summary = "Active: " + strings.Join(enforcers, ", ") + ". Gaps: " + strings.Join(missing, "; ") + "."
	default:
		dim.Status = PostureCellOK
		dim.Summary = "Active: " + strings.Join(enforcers, ", ") + "."
	}
	return dim
}

func buildIdentityContextDimension(in PostureInputs) RuntimePostureDimension {
	dim := RuntimePostureDimension{
		ID:    PostureDimIdentityContext,
		Label: "Identity context",
	}
	if !in.Identity.RequireSignature {
		// Signature gate is the floor. Even a fully populated identity
		// context cannot promote this state — context is enrichment,
		// not authority. This must keep warning users that signed
		// identity is off.
		dim.Status = PostureCellWarn
		dim.Summary = "Signature is not required. Local development mode."
		dim.Evidence = "Set identity.require_signature=true to enforce signed identity on every request."
		return dim
	}
	dim.Status = PostureCellOK
	contextMapped := identityContextMapped(in)
	switch {
	case contextMapped && in.Identity.RequireDelegation:
		dim.Summary = "Signed identity, delegation enforced, external context mapped."
	case contextMapped:
		dim.Summary = "Signed identity with external context mapped. Delegation not enforced."
	default:
		dim.Summary = "Local signed identity required (Ed25519)."
		if in.Identity.RequireDelegation {
			dim.Summary += " Delegation chain enforced."
		}
		dim.Summary += " External identity context not configured."
	}
	return dim
}

// identityContextMapped reports whether any configured Principal carries
// non-empty PrincipalContextConfig. The check stays vendor-neutral on
// purpose: it asks "is there any external context at all" not "which
// IdP is in use". Provider is display metadata only — never branched on.
func identityContextMapped(in PostureInputs) bool {
	if in.Cfg == nil {
		return false
	}
	for _, p := range in.Cfg.Identity.Principals {
		if !principalContextEmpty(p.Context) {
			return true
		}
	}
	return false
}

func principalContextEmpty(c config.PrincipalContextConfig) bool {
	return c.Issuer == "" && c.Subject == "" && c.Audience == "" &&
		c.ClientID == "" && c.TenantID == "" && c.Provider == "" &&
		c.Source == "" && c.ExpiresAt == "" && c.ClaimsHash == "" &&
		!c.Verified && len(c.Groups) == 0 && len(c.Scopes) == 0
}

func buildEvidenceDimension(in PostureInputs) RuntimePostureDimension {
	dim := RuntimePostureDimension{
		ID:    PostureDimEvidence,
		Label: "Evidence",
	}
	switch {
	case !in.RuntimeStoreReady:
		dim.Status = PostureCellNotConfigured
		dim.Summary = "Runtime store is not reachable."
	case !in.AuditChainValid:
		dim.Status = PostureCellWarn
		dim.Summary = "Audit chain integrity check failed."
	default:
		dim.Status = PostureCellOK
		dim.Summary = "Runtime + audit evidence is durable. Audit chain verified."
	}
	if in.AuditChainEntries > 0 {
		dim.Evidence = "Audit chain spans " + intToStr(in.AuditChainEntries) + " entries."
	}
	return dim
}

// buildSignals collects the gaps + next actions the page surfaces
// under the dimensions block. The list is intentionally short
// (top 3-4 items) — the legacy hardening section below carries
// the long tail of auditcheck findings.
func buildSignals(in PostureInputs, dims []RuntimePostureDimension) []RuntimePostureSignal {
	signals := []RuntimePostureSignal{}
	for _, dim := range dims {
		switch dim.Status {
		case PostureCellWarn, PostureCellBlind, PostureCellPartial, PostureCellStale, PostureCellNotConfigured:
			signals = append(signals, RuntimePostureSignal{
				ID:        "dim-" + dim.ID,
				Dimension: dim.ID,
				Status:    dimensionSignalStatus(dim.Status),
				Severity:  dimensionSignalSeverity(dim.Status),
				Title:     dim.Label + ": " + dimensionStatusLabel(dim.Status),
				Detail:    dim.Summary,
				Evidence:  dim.Evidence,
				Source:    "runtime",
			})
		}
	}
	return signals
}

// buildHardeningSummary wraps the existing auditcheck output for
// the secondary section. SuppressScore = true means the template
// hides the grade and the score; the counts and the fixable
// count remain visible so the operator still has a path to
// remediation. Reason is the one-line copy the template renders
// in place of the suppressed grade.
func buildHardeningSummary(in PostureInputs, suppress bool) RuntimeHardeningSummary {
	h := RuntimeHardeningSummary{
		Score:        in.AuditcheckScore,
		Grade:        in.AuditcheckGrade,
		TotalChecks:  len(in.Auditcheck),
		Critical:     in.AuditcheckSummary.Critical,
		High:         in.AuditcheckSummary.High,
		Medium:       in.AuditcheckSummary.Medium,
		Info:         in.AuditcheckSummary.Info,
		FixableCount: in.FixableCount,
		Suppressed:   suppress,
	}
	if suppress {
		h.Reason = "Runtime evidence required before showing a hardening grade."
	}
	return h
}

// dimensionSignalStatus maps a dimension status into the
// signal-level status enum the template uses to colour the
// signal pill.
func dimensionSignalStatus(s string) string {
	switch s {
	case PostureCellWarn, PostureCellPartial, PostureCellStale:
		return "warn"
	case PostureCellBlind, PostureCellNotConfigured:
		return "fail"
	default:
		return "info"
	}
}

// dimensionSignalSeverity converts a dimension status into the
// auditcheck-style severity word the template uses for the badge.
// Blind / not_configured for connection or coverage are high
// because they're operator-visible gaps that gate everything
// else; warn states are medium.
func dimensionSignalSeverity(s string) string {
	switch s {
	case PostureCellBlind, PostureCellNotConfigured:
		return "high"
	case PostureCellWarn, PostureCellPartial:
		return "medium"
	case PostureCellStale:
		return "low"
	default:
		return "info"
	}
}

// dimensionStatusLabel pretty-prints a dimension status for the
// signal title.
func dimensionStatusLabel(s string) string {
	switch s {
	case PostureCellNotConfigured:
		return "not configured"
	case PostureCellPartial:
		return "partial"
	case PostureCellBlind:
		return "blind"
	case PostureCellStale:
		return "stale"
	case PostureCellWarn:
		return "needs attention"
	default:
		return s
	}
}

func safeDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// intToStr is a small zero-import int formatter so the file does
// not reach for strconv just for one usage. Audit chain entries
// are non-negative so we do not need to handle the sign bit.
func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-" + intToStr(-n)
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
