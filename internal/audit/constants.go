package audit

// Status constants for audit log entries.
const (
	StatusDelivered   = "delivered"
	StatusBlocked     = "blocked"
	StatusRejected    = "rejected"
	StatusQuarantined = "quarantined"
	// StatusModified: delivered with detected content redacted in
	// transit (AARM decision MODIFY).
	StatusModified = "modified"
	// StatusStepUp: held pending explicit additional approval (AARM
	// decision STEP_UP) — distinct from quarantined, which is
	// content-driven review (AARM DEFER).
	StatusStepUp = "step_up"
)

// Quarantine status constants.
const (
	QStatusPending  = "pending"
	QStatusApproved = "approved"
	QStatusRejected = "rejected"
	QStatusExpired  = "expired"
	// QStatusConsumed: an approved step-up item already spent by a
	// retried call — approvals are single-use.
	QStatusConsumed = "consumed"
)

// Alert event constants for webhook notifications.
const (
	AlertEventBlocked        = "blocked"
	AlertEventQuarantined    = "quarantined"
	AlertEventLLMThreat      = "llm_threat"
	AlertEventAnomaly        = "anomaly"
	AlertEventAgentSuspended = "agent_suspended"
	AlertEventBudgetWarning  = "budget_warning"
	AlertEventAgentRisk      = "agent_risk_elevated"
	AlertEventRuleTriggered  = "rule_triggered"
)

// Alert delivery status constants.
const (
	AlertStatusSent   = "sent"
	AlertStatusFailed = "failed"
)

// Severity constants for rule findings and alerts.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
	SeverityNone     = "none"
)

// Policy decision constants.
const (
	DecisionAllow                    = "allow"
	DecisionContentBlocked           = "content_blocked"
	DecisionContentQuarantined       = "content_quarantined"
	DecisionContentFlagged           = "content_flagged"
	DecisionContentRedacted          = "content_redacted"
	DecisionStepUpApproval           = "step_up_approval"
	DecisionStepUpApproved           = "step_up_approved"
	DecisionACLDenied                = "acl_denied"
	DecisionAgentSuspended           = "agent_suspended"
	DecisionRecipientSuspended       = "recipient_suspended"
	DecisionIdentityRejected         = "identity_rejected"
	DecisionSignatureRequired        = "signature_required"
	DecisionRateLimited              = "rate_limited"
	DecisionToolNotAllowed           = "tool_not_allowed"
	DecisionConstraintViolated       = "constraint_violated"
	DecisionScanError                = "scan_error"
	DecisionDelegationInvalid        = "delegation_invalid"
	DecisionDelegationRequired       = "delegation_required"
	DecisionDelegationScopeViolation = "delegation_scope_violation"
	DecisionDelegationDepthExceeded  = "delegation_depth_exceeded"
	DecisionConcurrencyExceeded      = "concurrency_exceeded"
)
