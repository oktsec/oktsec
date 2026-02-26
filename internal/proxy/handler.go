package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
	"github.com/oktsec/oktsec/internal/identity"
	"github.com/oktsec/oktsec/internal/policy"
)

// MessageRequest is the incoming message from an agent.
type MessageRequest struct {
	From      string            `json:"from"`
	To        string            `json:"to"`
	Content   string            `json:"content"`
	Signature string            `json:"signature,omitempty"`
	Timestamp string            `json:"timestamp"`
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
}

// Handler processes /v1/message requests through the full pipeline.
type Handler struct {
	cfg         *config.Config
	keys        *identity.KeyStore
	policy      *policy.Evaluator
	scanner     *engine.Scanner
	audit       *audit.Store
	webhooks    *WebhookNotifier
	rateLimiter *RateLimiter
	window      *MessageWindow
	logger      *slog.Logger
}

// NewHandler creates a message handler with all dependencies.
func NewHandler(cfg *config.Config, keys *identity.KeyStore, pol *policy.Evaluator, scanner *engine.Scanner, auditStore *audit.Store, webhooks *WebhookNotifier, logger *slog.Logger) *Handler {
	return &Handler{
		cfg:         cfg,
		keys:        keys,
		policy:      pol,
		scanner:     scanner,
		audit:       auditStore,
		webhooks:    webhooks,
		rateLimiter: NewRateLimiter(cfg.RateLimit.PerAgent, cfg.RateLimit.WindowS),
		window:      NewMessageWindow(10, time.Hour),
		logger:      logger,
	}
}

// ServeHTTP handles POST /v1/message.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	req, err := h.parseRequest(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// Rate limit check (before any expensive operations)
	if !h.rateLimiter.Allow(req.From) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": fmt.Sprintf("rate limit exceeded for agent %q", req.From),
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
	}

	// Step 1: Identity verification
	sigStatus, verified, fingerprint := h.verifyIdentity(req)
	entry.SignatureVerified = sigStatus
	entry.PubkeyFingerprint = fingerprint

	if code, resp := h.checkIdentity(sigStatus, msgID); resp != nil {
		h.rejectAndLog(w, code, *resp, &entry, start)
		return
	}
	if sigStatus == 0 {
		h.logger.Warn("unverified sender identity", "from", req.From, "to", req.To, "message_id", msgID)
	}

	// Step 2: Agent suspension check
	if agent, ok := h.cfg.Agents[req.From]; ok && agent.Suspended {
		resp := MessageResponse{Status: "rejected", MessageID: msgID, PolicyDecision: "agent_suspended", VerifiedSender: verified}
		h.rejectAndLog(w, http.StatusForbidden, resp, &entry, start)
		return
	}
	if agent, ok := h.cfg.Agents[req.To]; ok && agent.Suspended {
		resp := MessageResponse{Status: "rejected", MessageID: msgID, PolicyDecision: "recipient_suspended", VerifiedSender: verified}
		h.rejectAndLog(w, http.StatusForbidden, resp, &entry, start)
		return
	}

	// Step 3: ACL check
	if !h.policy.CheckACL(req.From, req.To).Allowed {
		resp := MessageResponse{Status: "rejected", MessageID: msgID, PolicyDecision: "acl_denied", VerifiedSender: verified}
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "scan failed"})
		return
	}

	// Step 4b: Apply per-rule action overrides from config
	h.applyRuleOverrides(outcome)

	// Step 5: Apply BlockedContent per-agent filter
	h.applyBlockedContent(req.From, outcome)

	// Step 6: Split injection detection (multi-message window)
	h.scanConcatenated(r.Context(), req.From, req.Content, outcome)

	// Step 6b: Re-apply rule overrides to any findings introduced by concatenated scan
	h.applyRuleOverrides(outcome)

	// Step 7: Multi-message verdict escalation
	h.escalateByHistory(req.From, outcome)

	// Step 8: Apply verdict
	status, policyDecision, httpStatus := verdictToResponse(outcome.Verdict)
	rulesJSON := encodeFindings(outcome.Findings)

	entry.Status = status
	entry.PolicyDecision = policyDecision
	entry.RulesTriggered = rulesJSON
	entry.LatencyMs = time.Since(start).Milliseconds()
	h.audit.Log(entry)

	quarantineID := h.enqueueIfQuarantined(outcome.Verdict, msgID, req, rulesJSON)
	h.notifyIfSevere(outcome.Verdict, status, msgID, req, outcome.Findings)
	h.notifyByRuleOverrides(msgID, req, outcome.Findings)

	writeJSON(w, httpStatus, MessageResponse{
		Status:         status,
		MessageID:      msgID,
		PolicyDecision: policyDecision,
		RulesTriggered: outcome.Findings,
		VerifiedSender: verified,
		QuarantineID:   quarantineID,
	})
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
		resp := MessageResponse{Status: "rejected", MessageID: msgID, PolicyDecision: "identity_rejected"}
		return http.StatusForbidden, &resp
	}
	if sigStatus == 0 && h.cfg.Identity.RequireSignature {
		resp := MessageResponse{Status: "rejected", MessageID: msgID, PolicyDecision: "signature_required"}
		return http.StatusUnauthorized, &resp
	}
	return 0, nil
}

func (h *Handler) rejectAndLog(w http.ResponseWriter, httpStatus int, resp MessageResponse, entry *audit.Entry, start time.Time) {
	entry.Status = resp.Status
	entry.PolicyDecision = resp.PolicyDecision
	entry.LatencyMs = time.Since(start).Milliseconds()
	h.audit.Log(*entry)
	writeJSON(w, httpStatus, resp)
}

// applyBlockedContent escalates verdict to block if any finding's category
// matches the agent's blocked_content list.
func (h *Handler) applyBlockedContent(agentName string, outcome *engine.ScanOutcome) {
	agent, ok := h.cfg.Agents[agentName]
	if !ok || len(agent.BlockedContent) == 0 || len(outcome.Findings) == 0 {
		return
	}
	blocked := make(map[string]bool, len(agent.BlockedContent))
	for _, cat := range agent.BlockedContent {
		blocked[cat] = true
	}
	for _, f := range outcome.Findings {
		if blocked[f.Category] {
			outcome.Verdict = engine.VerdictBlock
			return
		}
	}
}

// applyRuleOverrides applies per-rule action overrides from cfg.Rules[].
// - "ignore" removes findings from the outcome entirely
// - "block"/"quarantine"/"allow-and-flag" overrides that finding's verdict contribution
// Findings without a matching rule keep the default severity-based verdict.
func (h *Handler) applyRuleOverrides(outcome *engine.ScanOutcome) {
	if len(h.cfg.Rules) == 0 || len(outcome.Findings) == 0 {
		return
	}

	// Build lookup: ruleID → action
	overrides := make(map[string]string, len(h.cfg.Rules))
	for _, ra := range h.cfg.Rules {
		overrides[ra.ID] = ra.Action
	}

	// Filter findings and recalculate verdict
	var kept []engine.FindingSummary
	newVerdict := engine.VerdictClean

	for _, f := range outcome.Findings {
		action, hasOverride := overrides[f.RuleID]
		if hasOverride && action == "ignore" {
			continue // drop finding entirely
		}

		kept = append(kept, f)

		// Determine this finding's verdict
		var v engine.ScanVerdict
		if hasOverride {
			switch action {
			case "block":
				v = engine.VerdictBlock
			case "quarantine":
				v = engine.VerdictQuarantine
			case "allow-and-flag":
				v = engine.VerdictFlag
			}
		} else {
			v = defaultSeverityVerdict(f.Severity)
		}

		// Keep the most severe verdict
		if verdictSeverity(v) > verdictSeverity(newVerdict) {
			newVerdict = v
		}
	}

	outcome.Findings = kept
	outcome.Verdict = newVerdict
}

// defaultSeverityVerdict maps a severity string to the default verdict.
// Mirrors the logic in engine.buildOutcome but operates on string severity.
func defaultSeverityVerdict(severity string) engine.ScanVerdict {
	switch severity {
	case "critical":
		return engine.VerdictBlock
	case "high":
		return engine.VerdictQuarantine
	case "medium":
		return engine.VerdictFlag
	default:
		return engine.VerdictClean
	}
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
		Statuses: []string{"blocked", "quarantined"},
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

	// Skip if already severe — no point rescanning
	if verdictSeverity(outcome.Verdict) >= verdictSeverity(engine.VerdictQuarantine) {
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

	if verdictSeverity(concatOutcome.Verdict) > verdictSeverity(outcome.Verdict) {
		outcome.Verdict = concatOutcome.Verdict
		outcome.Findings = concatOutcome.Findings
	}
}

// verdictSeverity maps a verdict to a numeric severity for comparison.
func verdictSeverity(v engine.ScanVerdict) int {
	switch v {
	case engine.VerdictBlock:
		return 3
	case engine.VerdictQuarantine:
		return 2
	case engine.VerdictFlag:
		return 1
	default:
		return 0
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
		return "blocked", "content_blocked", http.StatusForbidden
	case engine.VerdictQuarantine:
		return "quarantined", "content_quarantined", http.StatusAccepted
	case engine.VerdictFlag:
		return "delivered", "content_flagged", http.StatusOK
	default:
		return "delivered", "allow", http.StatusOK
	}
}

func encodeFindings(findings []engine.FindingSummary) string {
	if len(findings) == 0 {
		return "[]"
	}
	if b, err := json.Marshal(findings); err == nil {
		return string(b)
	}
	return "[]"
}

func (h *Handler) enqueueIfQuarantined(verdict engine.ScanVerdict, msgID string, req *MessageRequest, rulesJSON string) string {
	if verdict != engine.VerdictQuarantine {
		return ""
	}
	expiryHours := h.cfg.Quarantine.ExpiryHours
	if expiryHours <= 0 {
		expiryHours = 24
	}
	qItem := audit.QuarantineItem{
		ID:             msgID,
		AuditEntryID:   msgID,
		Content:        req.Content,
		FromAgent:      req.From,
		ToAgent:        req.To,
		Status:         "pending",
		ExpiresAt:      time.Now().Add(time.Duration(expiryHours) * time.Hour).UTC().Format(time.RFC3339),
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
		RulesTriggered: rulesJSON,
		Signature:      req.Signature,
		Timestamp:      req.Timestamp,
	}
	if err := h.audit.Enqueue(qItem); err != nil {
		h.logger.Error("quarantine enqueue failed", "error", err, "id", msgID)
		return ""
	}
	return msgID
}

func (h *Handler) notifyIfSevere(verdict engine.ScanVerdict, status, msgID string, req *MessageRequest, findings []engine.FindingSummary) {
	if verdict != engine.VerdictBlock && verdict != engine.VerdictQuarantine {
		return
	}
	h.webhooks.Notify(WebhookEvent{
		Event:     fmt.Sprintf("message_%s", status),
		MessageID: msgID,
		From:      req.From,
		To:        req.To,
		Severity:  topSeverity(findings),
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
func (h *Handler) notifyByRuleOverrides(msgID string, req *MessageRequest, findings []engine.FindingSummary) {
	if len(h.cfg.Rules) == 0 {
		return
	}

	// Build lookups: ruleID → notify refs, ruleID → template
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

	for _, f := range findings {
		rn, ok := notifyMap[f.RuleID]
		if !ok {
			continue
		}
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
		for _, ref := range rn.Refs {
			url := h.resolveWebhookRef(ref)
			if url == "" {
				continue
			}
			h.webhooks.NotifyTemplated(url, rn.Template, event)
		}
	}
}

func (h *Handler) verifyIdentity(req *MessageRequest) (sigStatus int, verified bool, fingerprint string) {
	if req.Signature == "" {
		return 0, false, "" // unsigned
	}

	pubKey, ok := h.keys.Get(req.From)
	if !ok {
		h.logger.Warn("no public key for agent", "agent", req.From)
		return -1, false, "" // unknown agent
	}

	result := identity.VerifyMessage(pubKey, req.From, req.To, req.Content, req.Timestamp, req.Signature)
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

func sha256Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func topSeverity(findings []engine.FindingSummary) string {
	if len(findings) == 0 {
		return "none"
	}
	return findings[0].Severity
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Log is best-effort; header already sent so we cannot change the status code.
		slog.Default().Error("writeJSON: encode failed", "error", err)
	}
}
