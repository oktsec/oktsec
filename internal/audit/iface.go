// Package audit defines the audit store interface and its composable sub-interfaces.
// Implementations: SQLiteStore (built-in), PostgresStore (planned).
package audit

import (
	"crypto/ed25519"
)

// AuditStore is the full audit store interface. All consumers that need
// the complete store use this type. Composed of smaller interfaces for
// consumers that only need a subset.
type AuditStore interface {
	AuditLogger
	AuditQuerier
	QuarantineManager
	KeyManager
	ReasoningStore
	LLMStore
	AlertStore
	SessionTracer
	ChainVerifier
	AuditAdmin
	EventHub

	// SetProxyKey sets the Ed25519 key used to sign audit chain entries.
	SetProxyKey(key ed25519.PrivateKey)

	// Flush waits for all pending writes to complete.
	Flush()

	// Close shuts down the store and releases resources.
	Close() error
}

// AuditLogger writes audit entries. Used by proxy handler, gateway,
// hooks, forward proxy, and stdio proxy.
type AuditLogger interface {
	Log(entry Entry)
}

// AuditQuerier reads audit entries and statistics. Used by dashboard,
// CLI commands (logs, status), and MCP tools.
type AuditQuerier interface {
	Query(opts QueryOpts) ([]Entry, error)
	QueryByID(id string) (*Entry, error)
	QueryStats() (*StatusCounts, error)
	QueryAgentStats(agent string) (*StatusCounts, error)
	QueryHourlyStats() (map[int]int, error)
	QueryTopRules(limit int, since string) ([]RuleStat, error)
	QueryAgentTopRules(agent string, limit int, since string) ([]RuleStat, error)
	QueryEdgeRules(from, to string, limit int, since string) ([]RuleStat, error)
	QueryTrafficAgents() ([]string, error)
	QueryUnsignedRate() (unsigned, total int, err error)
	QueryUnsignedByAgent() ([]UnsignedByAgent, error)
	QueryAvgLatency() (int, error)
	QueryAgentRisk(since string) ([]AgentRisk, error)
	QueryEdgeStats(since string) ([]EdgeStat, error)
	QueryToolStats(since string) ([]ToolStat, error)
}

// QuarantineManager handles the quarantine queue for human review.
type QuarantineManager interface {
	Enqueue(item QuarantineItem) error
	QuarantineByID(id string) (*QuarantineItem, error)
	QuarantinePending(limit int) ([]QuarantineItem, error)
	QuarantineQuery(status, agent, since, until string, limit int) ([]QuarantineItem, error)
	QuarantineApprove(id, reviewedBy string) error
	QuarantineReject(id, reviewedBy string) error
	QuarantineExpireOld() (int, error)
	QuarantineStats() (*QuarantineStats, error)
}

// KeyManager handles Ed25519 key revocation tracking.
type KeyManager interface {
	RevokeKey(fingerprint, agentName, reason string) error
	IsRevoked(fingerprint string) (bool, error)
	ListRevokedKeys() ([]RevokedKey, error)
}

// ReasoningStore persists model chain-of-thought linked to audit events.
type ReasoningStore interface {
	LogReasoning(r ReasoningEntry) error
	QueryReasoningBySession(sessionID string) ([]ReasoningEntry, error)
	QueryReasoningByAuditID(auditEntryID string) (*ReasoningEntry, error)
}

// LLMStore manages LLM analysis results and statistics.
type LLMStore interface {
	LogLLMAnalysis(a LLMAnalysis) error
	QueryLLMAnalyses(limit int) ([]LLMAnalysis, error)
	QueryLLMAnalysisByID(id string) (*LLMAnalysis, error)
	QueryLLMAnalysisByMessage(messageID string) (*LLMAnalysis, error)
	QueryLLMStats() (*LLMStats, error)
	QueryLLMTriageCounts() LLMTriageCounts
	QueryLLMAgentHistory(agent string, excludeID string, limit int) ([]LLMAnalysis, error)
	QueryAgentLLMRisk() (map[string]*AgentLLMRisk, error)
	UpdateLLMReviewStatus(id, status string) error
}

// AlertStore manages alert entries.
type AlertStore interface {
	LogAlert(a AlertEntry) error
	QueryAlerts(limit, offset int) ([]AlertEntry, error)
	AlertStats() (AlertStats, error)
}

// SessionTracer reconstructs agent session timelines and inventories.
type SessionTracer interface {
	BuildSessionTrace(sessionID string) (*SessionTrace, error)
	QuerySessions(since string, limit int) ([]SessionSummary, error)
}

// ChainVerifier provides access to the hash chain for tamper detection.
type ChainVerifier interface {
	QueryChainEntries(limit int) ([]ChainEntry, error)
}

// AuditAdmin handles maintenance operations.
type AuditAdmin interface {
	PurgeOldEntries(retentionDays int) (int, error)
	ClearAll() error
}

// EventHub provides real-time audit event pub/sub.
type EventHub interface {
	Subscribe() chan Entry
	Unsubscribe(ch chan Entry)
}
