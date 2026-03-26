package audit

// Status constants for audit log entries.
const (
	StatusDelivered   = "delivered"
	StatusBlocked     = "blocked"
	StatusRejected    = "rejected"
	StatusQuarantined = "quarantined"
)

// Quarantine status constants.
const (
	QStatusPending  = "pending"
	QStatusApproved = "approved"
	QStatusRejected = "rejected"
	QStatusExpired  = "expired"
)

// Alert event constants for webhook notifications.
const (
	AlertEventBlocked          = "blocked"
	AlertEventQuarantined      = "quarantined"
	AlertEventLLMThreat        = "llm_threat"
	AlertEventAnomaly          = "anomaly"
	AlertEventAgentSuspended   = "agent_suspended"
	AlertEventBudgetWarning    = "budget_warning"
	AlertEventAgentRisk        = "agent_risk_elevated"
	AlertEventRuleTriggered    = "rule_triggered"
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
	DecisionAllow              = "allow"
	DecisionContentBlocked     = "content_blocked"
	DecisionContentQuarantined = "content_quarantined"
	DecisionContentFlagged     = "content_flagged"
	DecisionACLDenied          = "acl_denied"
	DecisionAgentSuspended     = "agent_suspended"
	DecisionRecipientSuspended = "recipient_suspended"
	DecisionIdentityRejected   = "identity_rejected"
	DecisionSignatureRequired  = "signature_required"
	DecisionRateLimited          = "rate_limited"
	DecisionToolNotAllowed       = "tool_not_allowed"
	DecisionConstraintViolated   = "constraint_violated"
	DecisionScanError            = "scan_error"
	DecisionDelegationInvalid        = "delegation_invalid"
	DecisionDelegationRequired       = "delegation_required"
	DecisionDelegationScopeViolation = "delegation_scope_violation"
)
