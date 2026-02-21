package audit

// Entry represents a single audit log record.
type Entry struct {
	ID                 string `json:"id"`
	Timestamp          string `json:"timestamp"`
	FromAgent          string `json:"from_agent"`
	ToAgent            string `json:"to_agent"`
	ContentHash        string `json:"content_hash"`
	SignatureVerified  int    `json:"signature_verified"` // 1=verified, 0=unsigned, -1=invalid
	PubkeyFingerprint string `json:"pubkey_fingerprint,omitempty"`
	Status             string `json:"status"` // delivered, blocked, quarantined, rejected
	RulesTriggered     string `json:"rules_triggered,omitempty"` // JSON array
	PolicyDecision     string `json:"policy_decision"`
	LatencyMs          int64  `json:"latency_ms"`
}
