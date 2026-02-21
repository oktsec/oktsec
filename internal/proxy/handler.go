package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
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
	Status         string                   `json:"status"`
	MessageID      string                   `json:"message_id"`
	PolicyDecision string                   `json:"policy_decision"`
	RulesTriggered []engine.FindingSummary   `json:"rules_triggered"`
	VerifiedSender bool                     `json:"verified_sender"`
}

// Handler processes /v1/message requests through the full pipeline.
type Handler struct {
	cfg      *config.Config
	keys     *identity.KeyStore
	policy   *policy.Evaluator
	scanner  *engine.Scanner
	audit    *audit.Store
	webhooks *WebhookNotifier
	logger   *slog.Logger
}

// NewHandler creates a message handler with all dependencies.
func NewHandler(cfg *config.Config, keys *identity.KeyStore, pol *policy.Evaluator, scanner *engine.Scanner, auditStore *audit.Store, webhooks *WebhookNotifier, logger *slog.Logger) *Handler {
	return &Handler{
		cfg:      cfg,
		keys:     keys,
		policy:   pol,
		scanner:  scanner,
		audit:    auditStore,
		webhooks: webhooks,
		logger:   logger,
	}
}

// ServeHTTP handles POST /v1/message.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req MessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	if req.From == "" || req.To == "" || req.Content == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "from, to, and content are required"})
		return
	}

	if req.Timestamp == "" {
		req.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	msgID := uuid.New().String()
	contentHash := sha256Hash(req.Content)

	// Build audit entry (will be completed at the end)
	entry := audit.Entry{
		ID:          msgID,
		Timestamp:   req.Timestamp,
		FromAgent:   req.From,
		ToAgent:     req.To,
		ContentHash: contentHash,
	}

	// Step 1: Identity verification
	sigStatus, verified, fingerprint := h.verifyIdentity(&req)
	entry.SignatureVerified = sigStatus
	entry.PubkeyFingerprint = fingerprint

	if sigStatus == -1 {
		// Invalid signature → reject immediately
		entry.Status = "rejected"
		entry.PolicyDecision = "identity_rejected"
		entry.LatencyMs = time.Since(start).Milliseconds()
		h.audit.Log(entry)
		writeJSON(w, http.StatusForbidden, MessageResponse{
			Status:         "rejected",
			MessageID:      msgID,
			PolicyDecision: "identity_rejected",
			VerifiedSender: false,
		})
		return
	}

	if sigStatus == 0 && h.cfg.Identity.RequireSignature {
		// Unsigned message when signatures are required
		entry.Status = "rejected"
		entry.PolicyDecision = "signature_required"
		entry.LatencyMs = time.Since(start).Milliseconds()
		h.audit.Log(entry)
		writeJSON(w, http.StatusUnauthorized, MessageResponse{
			Status:         "rejected",
			MessageID:      msgID,
			PolicyDecision: "signature_required",
			VerifiedSender: false,
		})
		return
	}

	// Step 2: ACL check
	decision := h.policy.CheckACL(req.From, req.To)
	if !decision.Allowed {
		entry.Status = "rejected"
		entry.PolicyDecision = "acl_denied"
		entry.LatencyMs = time.Since(start).Milliseconds()
		h.audit.Log(entry)
		writeJSON(w, http.StatusForbidden, MessageResponse{
			Status:         "rejected",
			MessageID:      msgID,
			PolicyDecision: "acl_denied",
			VerifiedSender: verified,
		})
		return
	}

	// Step 3: Content scan with Aguara
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	outcome, err := h.scanner.ScanContent(ctx, req.Content)
	if err != nil {
		h.logger.Error("scan failed", "error", err, "message_id", msgID)
		entry.Status = "error"
		entry.PolicyDecision = "scan_error"
		entry.LatencyMs = time.Since(start).Milliseconds()
		h.audit.Log(entry)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "scan failed"})
		return
	}

	// Step 4: Apply verdict
	var status string
	var policyDecision string
	var httpStatus int

	switch outcome.Verdict {
	case engine.VerdictBlock:
		status = "blocked"
		policyDecision = "content_blocked"
		httpStatus = http.StatusForbidden
	case engine.VerdictQuarantine:
		status = "quarantined"
		policyDecision = "content_quarantined"
		httpStatus = http.StatusOK
	case engine.VerdictFlag:
		status = "delivered"
		policyDecision = "content_flagged"
		httpStatus = http.StatusOK
	default:
		status = "delivered"
		policyDecision = "allow"
		httpStatus = http.StatusOK
	}

	// Encode triggered rules
	rulesJSON := "[]"
	if len(outcome.Findings) > 0 {
		if b, err := json.Marshal(outcome.Findings); err == nil {
			rulesJSON = string(b)
		}
	}

	entry.Status = status
	entry.PolicyDecision = policyDecision
	entry.RulesTriggered = rulesJSON
	entry.LatencyMs = time.Since(start).Milliseconds()
	h.audit.Log(entry)

	// Send webhook notifications for blocked/quarantined
	if outcome.Verdict == engine.VerdictBlock || outcome.Verdict == engine.VerdictQuarantine {
		h.webhooks.Notify(WebhookEvent{
			Event:     fmt.Sprintf("message_%s", status),
			MessageID: msgID,
			From:      req.From,
			To:        req.To,
			Severity:  topSeverity(outcome.Findings),
			Timestamp: req.Timestamp,
		})
	}

	writeJSON(w, httpStatus, MessageResponse{
		Status:         status,
		MessageID:      msgID,
		PolicyDecision: policyDecision,
		RulesTriggered: outcome.Findings,
		VerifiedSender: verified,
	})
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
