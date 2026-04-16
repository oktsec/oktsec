package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
	"github.com/oktsec/oktsec/internal/identity"
	"github.com/oktsec/oktsec/internal/llm"
	"github.com/oktsec/oktsec/internal/policy"
	"github.com/oktsec/oktsec/internal/verdict"
)

// MessageRequest is the incoming message from an agent.
type MessageRequest struct {
	From      string            `json:"from"`
	To        string            `json:"to"`
	Content   string            `json:"content"`
	Signature string            `json:"signature,omitempty"`
	Timestamp string            `json:"timestamp"`
	Intent    string            `json:"intent,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// MessageResponse is returned to the sending agent.
type MessageResponse struct {
	Status         string                  `json:"status"`
	MessageID      string                  `json:"message_id"`
	PolicyDecision string                  `json:"policy_decision"`
	RulesTriggered []engine.FindingSummary `json:"rules_triggered"`
	VerifiedSender bool                    `json:"verified_sender"`
	QuarantineID   string                  `json:"quarantine_id,omitempty"`
	ExpiresAt      string                  `json:"expires_at,omitempty"`
	Remediation    string                  `json:"remediation,omitempty"`
	Suggestion     string                  `json:"suggestion,omitempty"`
}

// Handler processes /v1/message requests through the full pipeline.
type Handler struct {
	cfg         *config.Config
	keys        *identity.KeyStore
	policy      *policy.Evaluator
	scanner     *engine.Scanner
	audit       *audit.Store
	webhooks    *WebhookNotifier
	rateLimiter RateStore
	window      *MessageWindow
	sessions            *sessionStore
	llmQueue            *llm.Queue              // nil if LLM disabled
	signalDetector      *llm.SignalDetector     // nil if triage disabled
	escalationTracker   *llm.EscalationTracker  // nil if LLM escalation disabled
	logger              *slog.Logger

	denialMu           sync.Mutex
	consecutiveDenials map[string]int // key: "agent:session"

	// ipLimiter runs BEFORE parseRequest so unauth attackers can't trigger
	// JSON decode + MaxBytesReader allocation loops just to exhaust the
	// proxy. Nil when PerIP <= 0 (opt-out).
	ipLimiter RateStore
}

// NewHandler creates a message handler with all dependencies.
func NewHandler(cfg *config.Config, keys *identity.KeyStore, pol *policy.Evaluator, scanner *engine.Scanner, auditStore *audit.Store, webhooks *WebhookNotifier, logger *slog.Logger) *Handler {
	// Derive per-IP rate limit: explicit config wins, otherwise 10x per-agent.
	// Per-agent is stricter by design — the same attacker can use many agent
	// names but can't easily rotate IPs, so IP is the right coarse gate.
	perIP := cfg.RateLimit.PerIP
	if perIP == 0 && cfg.RateLimit.PerAgent > 0 {
		perIP = cfg.RateLimit.PerAgent * 10
	}

	h := &Handler{
		cfg:                cfg,
		keys:               keys,
		policy:             pol,
		scanner:            scanner,
		audit:              auditStore,
		webhooks:           webhooks,
		rateLimiter:        NewRateLimiter(cfg.RateLimit.PerAgent, cfg.RateLimit.WindowS),
		window:             NewMessageWindow(10, time.Hour),
		sessions:           newSessionStore(sessionDefaultTTL),
		logger:             logger,
		consecutiveDenials: make(map[string]int),
	}
	if perIP > 0 {
		h.ipLimiter = NewRateLimiter(perIP, cfg.RateLimit.WindowS)
	}
	return h
}

// Close stops background goroutines (rate limiter eviction, message window eviction, session eviction).
func (h *Handler) Close() {
	h.rateLimiter.Stop()
	if h.ipLimiter != nil {
		h.ipLimiter.Stop()
	}
	h.window.Stop()
	h.sessions.Stop()
}

// SetLLMQueue attaches the async LLM analysis queue to the handler.
func (h *Handler) SetLLMQueue(q *llm.Queue) {
	h.llmQueue = q
}

// SetSignalDetector attaches the pre-LLM triage filter.
func (h *Handler) SetSignalDetector(d *llm.SignalDetector) {
	h.signalDetector = d
}

// SetEscalationTracker attaches the LLM-driven verdict escalation tracker.
func (h *Handler) SetEscalationTracker(t *llm.EscalationTracker) {
	h.escalationTracker = t
}

// ServeHTTP handles POST /v1/message.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// Pre-parse IP gate. Keeping this before parseRequest means a flood of
	// malformed 10MB bodies can't force JSON decodes — we reject on a cheap
	// map lookup. agent-level rate limit still applies after parse.
	if h.ipLimiter != nil {
		if !h.ipLimiter.Allow(clientIP(r)) {
			rateLimitHits.Inc()
			writeJSON(w, http.StatusTooManyRequests, map[string]string{
				"error": "rate limit exceeded (ip)",
			})
			return
		}
	}

	req, err := h.parseRequest(r)
	if err != nil {
		h.logger.Warn("bad request", "error", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	// Rate limit check (before any expensive operations)
	if !h.rateLimiter.Allow(req.From) {
		rateLimitHits.Inc()
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": "rate limit exceeded",
		})
		return
	}

	msgID := uuid.New().String()
	entry := audit.Entry{
		ID:          msgID,
		Timestamp:   req.Timestamp,
		FromAgent:   req.From,
		ToAgent:     req.To,
		ContentHash: sha256Hash(req.Content),
		Intent:      req.Intent,
	}

	// Session tracking (metadata enrichment only — never rejects)
	if sid := r.Header.Get("X-Oktsec-Session"); sid != "" {
		entry.SessionID = sid
	} else {
		entry.SessionID = h.sessions.Resolve(req.From)
	}

	// Step 1: Identity verification. If the agent has a key_version pinned
	// in config, the client must echo it in X-Oktsec-Key-Version and sign
	// the V2 canonical payload — that's what prevents replaying a v1
	// signature after a key rotation.
	reqKeyVersion := parseKeyVersion(r.Header.Get("X-Oktsec-Key-Version"))
	sigStatus, verified, fingerprint := h.verifyIdentity(req, reqKeyVersion)
	entry.SignatureVerified = sigStatus
	entry.PubkeyFingerprint = fingerprint

	switch sigStatus {
	case 1:
		signatureVerified.WithLabelValues("verified").Inc()
	case -1:
		signatureVerified.WithLabelValues("invalid").Inc()
	default:
		signatureVerified.WithLabelValues("unsigned").Inc()
	}

	if code, resp := h.checkIdentity(sigStatus, msgID); resp != nil {
		h.rejectAndLog(w, code, *resp, &entry, start)
		return
	}
	if sigStatus == 0 {
		h.logger.Warn("unverified sender identity", "from", req.From, "to", req.To, "message_id", msgID)
	}

	// Step 1b: Delegation chain verification
	if code, resp := h.checkDelegation(r, req.To, msgID, verified, &entry); resp != nil {
		h.rejectAndLog(w, code, *resp, &entry, start)
		return
	}

	// Step 2: Agent suspension check
	if agent, ok := h.cfg.Agents[req.From]; ok && agent.Suspended {
		resp := MessageResponse{Status: audit.StatusRejected, MessageID: msgID, PolicyDecision: audit.DecisionAgentSuspended, VerifiedSender: verified}
		h.rejectAndLog(w, http.StatusForbidden, resp, &entry, start)
		return
	}
	if agent, ok := h.cfg.Agents[req.To]; ok && agent.Suspended {
		resp := MessageResponse{Status: audit.StatusRejected, MessageID: msgID, PolicyDecision: audit.DecisionRecipientSuspended, VerifiedSender: verified}
		h.rejectAndLog(w, http.StatusForbidden, resp, &entry, start)
		return
	}

	// Step 3: ACL check
	if !h.policy.CheckACL(req.From, req.To).Allowed {
		resp := MessageResponse{Status: audit.StatusRejected, MessageID: msgID, PolicyDecision: audit.DecisionACLDenied, VerifiedSender: verified}
		h.rejectAndLog(w, http.StatusForbidden, resp, &entry, start)
		return
	}

	// Step 4: Content scan
	outcome, err := h.scanContent(r.Context(), req.Content)
	if err != nil {
		h.logger.Error("scan failed", "error", err, "message_id", msgID)
		entry.Status = "error"
		entry.PolicyDecision = "scan_error"
		entry.LatencyMs = time.Since(start).Milliseconds()
		h.audit.Log(entry)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "content scan failed — retry or check server logs"})
		return
	}

	// Step 4b: Apply per-rule action overrides from config
	verdict.ApplyRuleOverrides(h.cfg.Rules, outcome)

	// Step 5: Apply BlockedContent per-agent filter
	h.applyBlockedContent(req.From, outcome)

	// Step 5b: Intent validation (deterministic pattern matching, no LLM)
	if req.Intent != "" {
		intentResult := ValidateIntent(req.Intent, req.Content)
		if intentResult.Status == "mismatch" {
			h.logger.Warn("intent mismatch", "from", req.From, "intent", req.Intent, "reason", intentResult.Reason, "message_id", msgID)
			if verdict.Severity(outcome.Verdict) < verdict.Severity(engine.VerdictFlag) {
				outcome.Verdict = engine.VerdictFlag
			}
		}
	} else if h.cfg.Server.RequireIntent {
		h.logger.Warn("missing required intent", "from", req.From, "message_id", msgID)
		if verdict.Severity(outcome.Verdict) < verdict.Severity(engine.VerdictFlag) {
			outcome.Verdict = engine.VerdictFlag
		}
	}

	// Step 6: Split injection detection (multi-message window)
	h.scanConcatenated(r.Context(), req.From, req.Content, outcome)

	// Step 6b: Re-apply rule overrides to any findings introduced by concatenated scan
	verdict.ApplyRuleOverrides(h.cfg.Rules, outcome)

	// Step 7: Multi-message verdict escalation
	h.escalateByHistory(req.From, outcome)

	// Step 7b: LLM-driven agent escalation (async feedback loop)
	if h.escalationTracker != nil && h.escalationTracker.IsEscalated(req.From) {
		outcome.Verdict = verdict.EscalateOneLevel(outcome.Verdict)
	}

	// Step 8: Apply verdict
	status, policyDecision, httpStatus := verdictToResponse(outcome.Verdict)
	rulesJSON := verdict.EncodeFindings(outcome.Findings)

	entry.Status = status
	entry.PolicyDecision = policyDecision
	entry.RulesTriggered = rulesJSON
	entry.LatencyMs = time.Since(start).Milliseconds()
	h.audit.Log(entry)

	// Record Prometheus metrics
	messagesTotal.WithLabelValues(status, policyDecision).Inc()
	messageLatency.WithLabelValues(status).Observe(time.Since(start).Seconds())
	for _, f := range outcome.Findings {
		rulesTriggered.WithLabelValues(f.RuleID, f.Severity).Inc()
	}

	qr := h.enqueueIfQuarantined(outcome.Verdict, msgID, req, rulesJSON)
	h.notifyIfSevere(outcome.Verdict, status, msgID, req, outcome.Findings)
	h.notifyByRuleOverrides(msgID, req, outcome.Findings)

	resp := MessageResponse{
		Status:         status,
		MessageID:      msgID,
		PolicyDecision: policyDecision,
		RulesTriggered: outcome.Findings,
		VerifiedSender: verified,
		QuarantineID:   qr.ID,
		ExpiresAt:      qr.ExpiresAt,
	}

	// Add remediation guidance for block/quarantine verdicts
	if outcome.Verdict == engine.VerdictBlock || outcome.Verdict == engine.VerdictQuarantine {
		resp.Remediation = topRemediation(outcome.Findings)
		resp.Suggestion = suggestionForDecision(policyDecision)
		h.recordDenial(req.From, entry.SessionID)
		// Export testcase for blocked/quarantined messages
		if h.cfg.Audit.ExportBlocked {
			for _, f := range outcome.Findings {
				_, _ = audit.ExportTestcase(audit.Testcase{
					RuleID:    f.RuleID,
					Type:      "true_positive",
					Source:    "production",
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					Agent:     req.From,
					Tool:      req.To,
					Content:   req.Content,
					Severity:  f.Severity,
					Verdict:   string(outcome.Verdict),
				})
			}
		}
	} else {
		h.resetDenials(req.From, entry.SessionID)
	}

	writeJSON(w, httpStatus, resp)

	// Stage 10: Async LLM analysis (non-blocking, after response sent)
	if h.llmQueue != nil {
		h.submitToLLM(msgID, req, outcome)
	}
}

// submitToLLM sends a message to the async LLM analysis queue if configured.
func (h *Handler) submitToLLM(msgID string, req *MessageRequest, outcome *engine.ScanOutcome) {
	if h.cfg.LLM.MinContentLength > 0 && len(req.Content) < h.cfg.LLM.MinContentLength {
		return
	}

	// When a signal detector is attached, it is the sole gatekeeper for
	// LLM analysis. It checks keywords, URLs, new agent pairs, random
	// sampling, and skip-verdicts. This replaces the analyze config
	// (clean/flagged/quarantined/blocked) and catches semantic threats
	// that rules miss but have suspicious indicators.
	//
	// When no signal detector is attached, the analyze config controls
	// which verdict types are sent to the LLM (original behavior).
	if h.signalDetector != nil {
		sig := h.signalDetector.Detect(req.From, req.To, req.Content, string(outcome.Verdict))
		if !sig.ShouldAnalyze {
			return
		}
	} else {
		analyze := h.cfg.LLM.Analyze
		switch outcome.Verdict {
		case engine.VerdictClean:
			if !analyze.Clean {
				return
			}
		case engine.VerdictFlag:
			if !analyze.Flagged {
				return
			}
		case engine.VerdictQuarantine:
			if !analyze.Quarantined {
				return
			}
		case engine.VerdictBlock:
			if !analyze.Blocked {
				return
			}
		}
	}

	h.llmQueue.Submit(llm.AnalysisRequest{
		MessageID:      msgID,
		FromAgent:      req.From,
		ToAgent:        req.To,
		Content:        req.Content,
		Intent:         req.Intent,
		CurrentVerdict: outcome.Verdict,
		Findings:       outcome.Findings,
		Timestamp:      time.Now(),
	})
}

// clientIP returns a stable key for rate-limiting by source.
// Honours X-Forwarded-For (first hop) when the proxy sits behind an LB;
// otherwise falls back to RemoteAddr sans port.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if comma := strings.IndexByte(xff, ','); comma > 0 {
			return strings.TrimSpace(xff[:comma])
		}
		return strings.TrimSpace(xff)
	}
	addr := r.RemoteAddr
	if colon := strings.LastIndexByte(addr, ':'); colon > 0 {
		return addr[:colon]
	}
	return addr
}

func (h *Handler) parseRequest(r *http.Request) (*MessageRequest, error) {
	// Limit request body to 10 MB to prevent resource exhaustion.
	r.Body = http.MaxBytesReader(nil, r.Body, 10<<20)
	var req MessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if req.From == "" || req.To == "" || req.Content == "" {
		return nil, fmt.Errorf("from, to, and content are required")
	}
	if req.Timestamp == "" {
		req.Timestamp = time.Now().UTC().Format(time.RFC3339)
	} else {
		ts, err := time.Parse(time.RFC3339, req.Timestamp)
		if err != nil {
			return nil, fmt.Errorf("invalid timestamp format: %w", err)
		}
		age := time.Since(ts)
		if age > 5*time.Minute {
			return nil, fmt.Errorf("timestamp too old (age: %s, max: 5m)", age.Truncate(time.Second))
		}
		if age < -30*time.Second {
			return nil, fmt.Errorf("timestamp is in the future")
		}
	}
	return &req, nil
}

func (h *Handler) checkIdentity(sigStatus int, msgID string) (int, *MessageResponse) {
	if sigStatus == -1 {
		resp := MessageResponse{Status: audit.StatusRejected, MessageID: msgID, PolicyDecision: audit.DecisionIdentityRejected}
		return http.StatusForbidden, &resp
	}
	if sigStatus == 0 && h.cfg.Identity.RequireSignature {
		resp := MessageResponse{Status: audit.StatusRejected, MessageID: msgID, PolicyDecision: audit.DecisionSignatureRequired}
		return http.StatusUnauthorized, &resp
	}
	return 0, nil
}

func (h *Handler) rejectAndLog(w http.ResponseWriter, httpStatus int, resp MessageResponse, entry *audit.Entry, start time.Time) {
	entry.Status = resp.Status
	entry.PolicyDecision = resp.PolicyDecision
	entry.LatencyMs = time.Since(start).Milliseconds()
	h.audit.Log(*entry)

	// Add suggestion guidance for the policy decision
	resp.Suggestion = suggestionForDecision(resp.PolicyDecision)

	// Track consecutive denials per agent+session
	h.recordDenial(entry.FromAgent, entry.SessionID)

	writeJSON(w, httpStatus, resp)
}

// applyBlockedContent escalates verdict to block if any finding's category
// matches the agent's blocked_content list. Thin wrapper over verdict.ApplyBlockedContent.
func (h *Handler) applyBlockedContent(agentName string, outcome *engine.ScanOutcome) {
	agent, ok := h.cfg.Agents[agentName]
	if !ok {
		return
	}
	verdict.ApplyBlockedContent(agent, outcome)
}

// escalateByHistory checks recent audit history for the sender and escalates
// the current verdict if the agent has been repeatedly blocked.
func (h *Handler) escalateByHistory(agent string, outcome *engine.ScanOutcome) {
	// Only escalate if current verdict is flag or quarantine
	if outcome.Verdict != engine.VerdictFlag && outcome.Verdict != engine.VerdictQuarantine {
		return
	}

	since := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	entries, err := h.audit.Query(audit.QueryOpts{
		Agent:    agent,
		Statuses: []string{audit.StatusBlocked, audit.StatusQuarantined},
		Since:    since,
		Limit:    100,
	})
	if err != nil {
		return
	}

	// Count entries where this agent was the sender
	recentBlocks := 0
	for _, e := range entries {
		if e.FromAgent == agent {
			recentBlocks++
		}
	}

	if recentBlocks >= 5 && outcome.Verdict == engine.VerdictQuarantine {
		outcome.Verdict = engine.VerdictBlock
	} else if recentBlocks >= 3 && outcome.Verdict == engine.VerdictFlag {
		outcome.Verdict = engine.VerdictQuarantine
	}
}

// scanConcatenated adds the current message to the sliding window and, if the
// individual verdict is not already severe (block/quarantine), scans the
// concatenation of recent messages from the same sender. If the concatenated
// scan produces a more severe verdict, it escalates the outcome.
func (h *Handler) scanConcatenated(ctx context.Context, agent, content string, outcome *engine.ScanOutcome) {
	h.window.Add(agent, content)

	// Skip if already severe -- no point rescanning
	if verdict.Severity(outcome.Verdict) >= verdict.Severity(engine.VerdictQuarantine) {
		return
	}

	concat := h.window.Concatenated(agent)
	if concat == "" {
		return // single message, nothing to cross-check
	}

	concatOutcome, err := h.scanContent(ctx, concat)
	if err != nil {
		h.logger.Error("concatenated scan failed", "error", err, "agent", agent)
		return
	}

	if verdict.Severity(concatOutcome.Verdict) > verdict.Severity(outcome.Verdict) {
		outcome.Verdict = concatOutcome.Verdict
		outcome.Findings = concatOutcome.Findings
	}
}

func (h *Handler) scanContent(ctx context.Context, content string) (*engine.ScanOutcome, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return h.scanner.ScanContent(ctx, content)
}

func verdictToResponse(v engine.ScanVerdict) (status, policyDecision string, httpStatus int) {
	switch v {
	case engine.VerdictBlock:
		return audit.StatusBlocked, audit.DecisionContentBlocked, http.StatusForbidden
	case engine.VerdictQuarantine:
		return audit.StatusQuarantined, audit.DecisionContentQuarantined, http.StatusAccepted
	case engine.VerdictFlag:
		return audit.StatusDelivered, audit.DecisionContentFlagged, http.StatusOK
	default:
		return audit.StatusDelivered, audit.DecisionAllow, http.StatusOK
	}
}

type quarantineResult struct {
	ID        string
	ExpiresAt string
}

func (h *Handler) enqueueIfQuarantined(v engine.ScanVerdict, msgID string, req *MessageRequest, rulesJSON string) quarantineResult {
	if v != engine.VerdictQuarantine {
		return quarantineResult{}
	}
	expiryHours := h.cfg.Quarantine.ExpiryHours
	if expiryHours <= 0 {
		expiryHours = 24
	}
	expiresAt := time.Now().Add(time.Duration(expiryHours) * time.Hour).UTC().Format(time.RFC3339)
	qItem := audit.QuarantineItem{
		ID:             msgID,
		AuditEntryID:   msgID,
		Content:        req.Content,
		FromAgent:      req.From,
		ToAgent:        req.To,
		Status:         audit.QStatusPending,
		ExpiresAt:      expiresAt,
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
		RulesTriggered: rulesJSON,
		Signature:      req.Signature,
		Timestamp:      req.Timestamp,
	}
	if err := h.audit.Enqueue(qItem); err != nil {
		h.logger.Error("quarantine enqueue failed", "error", err, "id", msgID)
		return quarantineResult{}
	}
	quarantinePending.Inc()
	return quarantineResult{ID: msgID, ExpiresAt: expiresAt}
}

func (h *Handler) notifyIfSevere(v engine.ScanVerdict, status, msgID string, req *MessageRequest, findings []engine.FindingSummary) {
	if v != engine.VerdictBlock && v != engine.VerdictQuarantine {
		return
	}
	h.webhooks.Notify(WebhookEvent{
		Event:     fmt.Sprintf("message_%s", status),
		MessageID: msgID,
		From:      req.From,
		To:        req.To,
		Severity:  verdict.TopSeverity(findings),
		Timestamp: req.Timestamp,
	})
}

// resolveWebhookRef resolves a notify reference to a URL.
// If ref contains "://" it is treated as a raw URL (backward compat).
// Otherwise it is looked up as a named webhook channel.
func (h *Handler) resolveWebhookRef(ref string) string {
	if strings.Contains(ref, "://") {
		return ref
	}
	if wh := h.cfg.WebhookByName(ref); wh != nil {
		return wh.URL
	}
	return ""
}

// notifyByRuleOverrides sends webhook notifications for rules that have notify URLs configured.
// Falls back to category-level webhooks when a rule has no explicit notify configuration.
func (h *Handler) notifyByRuleOverrides(msgID string, req *MessageRequest, findings []engine.FindingSummary) {
	if len(h.cfg.Rules) == 0 && len(h.cfg.CategoryWebhooks) == 0 {
		return
	}

	// Build lookups: ruleID -> notify refs, ruleID -> template
	type ruleNotify struct {
		Refs     []string
		Template string
	}
	notifyMap := make(map[string]ruleNotify)
	for _, ra := range h.cfg.Rules {
		if len(ra.Notify) > 0 {
			notifyMap[ra.ID] = ruleNotify{Refs: ra.Notify, Template: ra.Template}
		}
	}

	// Build category -> notify refs lookup
	catNotifyMap := make(map[string][]string)
	for _, cw := range h.cfg.CategoryWebhooks {
		if len(cw.Notify) > 0 {
			catNotifyMap[cw.Category] = cw.Notify
		}
	}

	for _, f := range findings {
		event := WebhookEvent{
			Event:     "rule_triggered",
			MessageID: msgID,
			From:      req.From,
			To:        req.To,
			Severity:  f.Severity,
			Rule:      f.RuleID,
			RuleName:  f.Name,
			Category:  f.Category,
			Match:     f.Match,
			Timestamp: req.Timestamp,
		}

		// Use rule-level notify if available, else fall back to category-level
		if rn, ok := notifyMap[f.RuleID]; ok {
			for _, ref := range rn.Refs {
				url := h.resolveWebhookRef(ref)
				if url == "" {
					continue
				}
				h.webhooks.NotifyTemplated(url, rn.Template, event)
			}
		} else if catRefs, ok := catNotifyMap[f.Category]; ok {
			for _, ref := range catRefs {
				url := h.resolveWebhookRef(ref)
				if url == "" {
					continue
				}
				h.webhooks.NotifyTemplated(url, "", event)
			}
		}
	}
}

// parseKeyVersion parses the X-Oktsec-Key-Version header. An empty / malformed
// header collapses to 0 (meaning "v1 signature, no version pin").
func parseKeyVersion(raw string) int64 {
	if raw == "" {
		return 0
	}
	var v int64
	if _, err := fmt.Sscanf(raw, "%d", &v); err != nil {
		return 0
	}
	return v
}

func (h *Handler) verifyIdentity(req *MessageRequest, reqKeyVersion int64) (sigStatus int, verified bool, fingerprint string) {
	if req.Signature == "" {
		return 0, false, "" // unsigned
	}

	pubKey, ok := h.keys.Get(req.From)
	if !ok {
		h.logger.Warn("no public key for agent", "agent", req.From)
		return -1, false, "" // unknown agent
	}

	// Look up the pinned key version for this agent (0 = no pinning).
	var expectedVersion int64
	if agent, found := h.cfg.Agents[req.From]; found {
		expectedVersion = agent.KeyVersion
	}

	var result identity.VerifyResult
	switch {
	case expectedVersion > 0:
		// Agent has a pinned version; client MUST echo the right one and
		// sign the V2 payload that commits to it. A missing or mismatched
		// header is treated as an invalid signature — never falls back to
		// v1, which would re-open the post-rotation replay window.
		if reqKeyVersion != expectedVersion {
			h.logger.Warn("key version mismatch",
				"agent", req.From, "expected", expectedVersion, "got", reqKeyVersion)
			return -1, false, identity.Fingerprint(pubKey)
		}
		result = identity.VerifyMessageV2(pubKey, req.From, req.To, req.Content, req.Timestamp, reqKeyVersion, req.Signature)
	default:
		// Legacy path: no pinning. Accept V1 or V2 — V2 wins if the client
		// supplied a header AND the signature matches, otherwise V1.
		if reqKeyVersion > 0 {
			if r := identity.VerifyMessageV2(pubKey, req.From, req.To, req.Content, req.Timestamp, reqKeyVersion, req.Signature); r.Verified {
				result = r
				break
			}
		}
		result = identity.VerifyMessage(pubKey, req.From, req.To, req.Content, req.Timestamp, req.Signature)
	}

	if !result.Verified {
		return -1, false, result.Fingerprint
	}

	// Check if the key has been revoked
	if revoked, err := h.audit.IsRevoked(result.Fingerprint); err == nil && revoked {
		h.logger.Warn("agent key is revoked", "agent", req.From, "fingerprint", result.Fingerprint)
		return -1, false, result.Fingerprint
	}

	return 1, true, result.Fingerprint
}

// checkDelegation verifies the delegation chain from the X-Oktsec-Delegation
// header and populates the audit entry. Returns an HTTP response if the
// request should be rejected (invalid chain or missing when required).
func (h *Handler) checkDelegation(r *http.Request, recipient, msgID string, verified bool, entry *audit.Entry) (int, *MessageResponse) {
	header := r.Header.Get("X-Oktsec-Delegation")

	if header == "" {
		// No delegation header — only reject if required
		if h.cfg.Identity.RequireDelegation {
			resp := MessageResponse{
				Status:         audit.StatusRejected,
				MessageID:      msgID,
				PolicyDecision: audit.DecisionDelegationRequired,
				VerifiedSender: verified,
			}
			return http.StatusUnauthorized, &resp
		}
		return 0, nil
	}

	// Header present — always verify (invalid = reject regardless of RequireDelegation)
	result := h.verifyDelegation(header, recipient)
	if !result.Valid {
		h.logger.Warn("delegation chain invalid",
			"message_id", msgID, "reason", result.Reason)
		resp := MessageResponse{
			Status:         audit.StatusRejected,
			MessageID:      msgID,
			PolicyDecision: audit.DecisionDelegationInvalid,
			VerifiedSender: verified,
		}
		return http.StatusForbidden, &resp
	}

	// Valid chain — populate audit entry
	entry.DelegationChainHash = result.ChainHash
	entry.RootAgent = result.Root
	entry.AgentDepth = result.Depth

	// Build human-readable chain summary
	if result.Depth <= 2 {
		entry.DelegationChain = result.Root + " -> " + result.Delegate
	} else {
		entry.DelegationChain = fmt.Sprintf("%s -> ... -> %s (%d hops)", result.Root, result.Delegate, result.Depth)
	}

	// ParentAgent is the delegator from the last token (the one that delegated to the current sender)
	// For a chain like human -> A -> B, the ParentAgent of B is A.
	// result.Root is the first delegator, result.Delegate is the final delegate.
	// We parse the chain once more to get the parent from the last token.
	entry.ParentAgent = h.extractParentAgent(header)

	return 0, nil
}

// verifyDelegation decodes and verifies a base64-encoded delegation chain
// from the X-Oktsec-Delegation HTTP header. Checks signature, expiry, scope,
// depth, and chain linkage for every token in the chain.
func (h *Handler) verifyDelegation(header, recipient string) identity.ChainVerifyResult {
	data, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return identity.ChainVerifyResult{Valid: false, Reason: "invalid base64 encoding"}
	}

	var chain identity.DelegationChain
	if err := json.Unmarshal(data, &chain); err != nil {
		return identity.ChainVerifyResult{Valid: false, Reason: "invalid chain JSON"}
	}

	if len(chain) == 0 {
		return identity.ChainVerifyResult{Valid: false, Reason: "empty delegation chain"}
	}

	// Check that the final delegate's scope allows the recipient
	last := chain[len(chain)-1]
	if !scopeAllowsRecipient(last.Scope, recipient) {
		return identity.ChainVerifyResult{
			Valid:  false,
			Reason: fmt.Sprintf("recipient %q not in delegation scope", recipient),
		}
	}

	// Resolve public keys from the handler's keystore
	resolver := func(agent string) ed25519.PublicKey {
		pub, ok := h.keys.Get(agent)
		if !ok {
			return nil
		}
		return pub
	}

	return identity.VerifyChain(chain, resolver)
}

// extractParentAgent decodes the delegation header and returns the delegator
// from the last token in the chain (the immediate parent of the current agent).
func (h *Handler) extractParentAgent(header string) string {
	data, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return ""
	}
	var chain identity.DelegationChain
	if err := json.Unmarshal(data, &chain); err != nil {
		return ""
	}
	if len(chain) == 0 {
		return ""
	}
	return chain[len(chain)-1].Delegator
}

// scopeAllowsRecipient checks if the recipient is covered by the scope list.
func scopeAllowsRecipient(scope []string, recipient string) bool {
	for _, s := range scope {
		if s == "*" || s == recipient {
			return true
		}
	}
	return false
}

// topRemediation returns the remediation text from the highest-severity
// finding. Severity order: critical > high > medium > low > info.
func topRemediation(findings []engine.FindingSummary) string {
	if len(findings) == 0 {
		return ""
	}
	best := findings[0]
	for _, f := range findings[1:] {
		if severityRank(f.Severity) > severityRank(best.Severity) {
			best = f
		}
	}
	return best.Remediation
}

// severityRank returns a numeric rank for severity comparison.
func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// suggestionForDecision returns generic guidance for the given policy decision
// so agents know what to try instead of retrying the same blocked action.
func suggestionForDecision(decision string) string {
	switch decision {
	case audit.DecisionContentBlocked:
		return "Review the flagged patterns and rephrase without shell metacharacters, credential references, or injection patterns."
	case audit.DecisionContentQuarantined:
		return "The message has been held for human review. Rephrase to avoid suspicious patterns, or wait for an operator to release it."
	case audit.DecisionIdentityRejected:
		return "Provide a valid Ed25519 signature. Verify the signing key matches the registered public key for this agent."
	case audit.DecisionSignatureRequired:
		return "This proxy requires signed messages. Include an Ed25519 signature in the request."
	case audit.DecisionDelegationInvalid:
		return "Provide a valid delegation chain with current, non-expired tokens."
	case audit.DecisionDelegationRequired:
		return "This proxy requires delegation chains. Include a valid X-Oktsec-Delegation header."
	case audit.DecisionACLDenied:
		return "This agent is not authorized to message this recipient. Check the ACL configuration."
	case audit.DecisionAgentSuspended:
		return "This agent has been suspended. Contact an administrator to restore access."
	case audit.DecisionRecipientSuspended:
		return "The recipient agent is suspended. Try a different recipient or contact an administrator."
	default:
		return ""
	}
}

// denialKey builds a key for the consecutive denial tracker from agent + session.
func denialKey(agent, session string) string {
	return agent + ":" + session
}

// recordDenial increments the consecutive denial counter for an agent session.
// Logs a warning when the agent has been repeatedly blocked (3+ times).
func (h *Handler) recordDenial(agent, session string) {
	h.denialMu.Lock()
	defer h.denialMu.Unlock()
	key := denialKey(agent, session)
	h.consecutiveDenials[key]++
	count := h.consecutiveDenials[key]
	if count >= 3 {
		h.logger.Warn("agent repeatedly blocked",
			"agent", agent,
			"session", session,
			"consecutive_denials", count,
		)
	}
}

// resetDenials resets the consecutive denial counter on successful delivery.
func (h *Handler) resetDenials(agent, session string) {
	h.denialMu.Lock()
	defer h.denialMu.Unlock()
	delete(h.consecutiveDenials, denialKey(agent, session))
}

// consecutiveDenialCount returns the current count for testing.
func (h *Handler) consecutiveDenialCount(agent, session string) int {
	h.denialMu.Lock()
	defer h.denialMu.Unlock()
	return h.consecutiveDenials[denialKey(agent, session)]
}

func sha256Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Log is best-effort; header already sent so we cannot change the status code.
		slog.Default().Error("writeJSON: encode failed", "error", err)
	}
}
