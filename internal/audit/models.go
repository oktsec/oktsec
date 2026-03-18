// Package audit provides the SQLite-backed audit trail for message events,
// key revocation tracking, and quarantine queue management.
package audit

// Entry represents a single audit log record.
type Entry struct {
	ID                string `json:"id"`
	Timestamp         string `json:"timestamp"`
	FromAgent         string `json:"from_agent"`
	ToAgent           string `json:"to_agent"`
	ToolName          string `json:"tool_name,omitempty"`        // tool executed (e.g., "Bash", "Write") — distinct from agent
	ContentHash       string `json:"content_hash"`
	SignatureVerified int    `json:"signature_verified"` // 1=verified, 0=unsigned, -1=invalid
	PubkeyFingerprint string `json:"pubkey_fingerprint,omitempty"`
	Status            string `json:"status"`                    // delivered, blocked, quarantined, rejected
	RulesTriggered    string `json:"rules_triggered,omitempty"` // JSON array
	PolicyDecision    string `json:"policy_decision"`
	LatencyMs         int64  `json:"latency_ms"`
	Intent            string `json:"intent,omitempty"`           // declared intent from sender (tool args for gateway)
	SessionID         string `json:"session_id,omitempty"`       // MCP session ID for sub-agent tracking
	PrevHash          string `json:"prev_hash,omitempty"`        // hash chain: previous entry hash
	EntryHash         string `json:"entry_hash,omitempty"`       // hash chain: this entry's hash
	ProxySignature      string `json:"proxy_signature,omitempty"`  // Ed25519 signature by proxy
	DelegationChainHash string `json:"delegation_chain_hash,omitempty"` // SHA-256 of verified delegation chain
	DelegationChain     string `json:"delegation_chain,omitempty"`      // human-readable chain: "human -> agent-a -> agent-b"
}

// ReasoningEntry captures the model's chain-of-thought for a tool call.
// Stored separately from audit_log because reasoning data is large and
// not every event has it. Linked via audit_entry_id.
type ReasoningEntry struct {
	ID            string `json:"id"`
	AuditEntryID  string `json:"audit_entry_id"`
	SessionID     string `json:"session_id"`
	ToolUseID     string `json:"tool_use_id,omitempty"`
	Reasoning     string `json:"reasoning"`
	ReasoningHash string `json:"reasoning_hash"`
	PlanStep      int    `json:"plan_step,omitempty"`
	PlanTotal     int    `json:"plan_total,omitempty"`
	Timestamp     string `json:"timestamp"`
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

// EdgeStat holds aggregated message counts for a single from→to edge.
type EdgeStat struct {
	From         string  `json:"from"`
	To           string  `json:"to"`
	Delivered    int     `json:"delivered"`
	Blocked      int     `json:"blocked"`
	Quarantined  int     `json:"quarantined"`
	Rejected     int     `json:"rejected"`
	Total        int     `json:"total"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`
}

// ToolStat holds aggregated tool usage counts for an agent→tool edge.
type ToolStat struct {
	Agent string `json:"agent"`
	Tool  string `json:"tool"`
	Total int    `json:"total"`
}

// AgentRisk holds risk scoring for an agent based on audit history and LLM analysis.
type AgentRisk struct {
	Agent       string  `json:"agent"`
	Total       int     `json:"total"`
	Blocked     int     `json:"blocked"`
	Quarantined int     `json:"quarantined"`
	RiskScore   float64 `json:"risk_score"`

	// LLM-enriched fields (populated when LLM data is available)
	LLMAvgRisk      float64 `json:"llm_avg_risk,omitempty"`
	LLMMaxRisk      float64 `json:"llm_max_risk,omitempty"`
	LLMAnalysisCount int    `json:"llm_analysis_count,omitempty"`
	LLMThreatCount  int     `json:"llm_threat_count,omitempty"`
	LLMConfirmed    int     `json:"llm_confirmed,omitempty"`
}
