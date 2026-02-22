package audit

// Entry represents a single audit log record.
type Entry struct {
	ID                string `json:"id"`
	Timestamp         string `json:"timestamp"`
	FromAgent         string `json:"from_agent"`
	ToAgent           string `json:"to_agent"`
	ContentHash       string `json:"content_hash"`
	SignatureVerified int    `json:"signature_verified"` // 1=verified, 0=unsigned, -1=invalid
	PubkeyFingerprint string `json:"pubkey_fingerprint,omitempty"`
	Status            string `json:"status"` // delivered, blocked, quarantined, rejected
	RulesTriggered    string `json:"rules_triggered,omitempty"` // JSON array
	PolicyDecision    string `json:"policy_decision"`
	LatencyMs         int64  `json:"latency_ms"`
}

// RevokedKey represents a revoked agent public key.
type RevokedKey struct {
	Fingerprint string `json:"fingerprint"`
	AgentName   string `json:"agent_name"`
	RevokedAt   string `json:"revoked_at"`
	Reason      string `json:"reason,omitempty"`
}

// QuarantineItem represents a message held for human review.
type QuarantineItem struct {
	ID             string `json:"id"`
	AuditEntryID   string `json:"audit_entry_id"`
	Content        string `json:"content"`
	FromAgent      string `json:"from_agent"`
	ToAgent        string `json:"to_agent"`
	Status         string `json:"status"` // pending, approved, rejected, expired
	ReviewedBy     string `json:"reviewed_by,omitempty"`
	ReviewedAt     string `json:"reviewed_at,omitempty"`
	ExpiresAt      string `json:"expires_at"`
	CreatedAt      string `json:"created_at"`
	RulesTriggered string `json:"rules_triggered,omitempty"`
	Signature      string `json:"signature,omitempty"`
	Timestamp      string `json:"timestamp"`
}

// QuarantineStats holds counts grouped by quarantine status.
type QuarantineStats struct {
	Pending  int `json:"pending"`
	Approved int `json:"approved"`
	Rejected int `json:"rejected"`
	Expired  int `json:"expired"`
	Total    int `json:"total"`
}

// RuleStat holds aggregated trigger counts for a single rule.
type RuleStat struct {
	RuleID   string `json:"rule_id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

// AgentRisk holds risk scoring for an agent based on audit history.
type AgentRisk struct {
	Agent       string  `json:"agent"`
	Total       int     `json:"total"`
	Blocked     int     `json:"blocked"`
	Quarantined int     `json:"quarantined"`
	RiskScore   float64 `json:"risk_score"`
}
