package proxy

import (
	"strings"
)

// IntentResult describes the outcome of intent validation.
type IntentResult struct {
	Status string // "match", "mismatch", "missing"
	Reason string
}

// intentKeywords maps common intent keywords to content patterns that should
// appear when that intent is declared. This is a lightweight, deterministic
// check — no LLM involved.
var intentKeywords = map[string][]string{
	"code_review":   {"review", "PR", "pull request", "diff", "approve", "merge", "lgtm"},
	"deploy":        {"deploy", "release", "rollout", "ship", "production", "staging", "k8s"},
	"debug":         {"debug", "error", "stack trace", "exception", "fix", "bug", "crash"},
	"monitoring":    {"alert", "metric", "uptime", "latency", "cpu", "memory", "health"},
	"testing":       {"test", "coverage", "assert", "spec", "passed", "failed", "flaky"},
	"documentation": {"doc", "readme", "guide", "example", "api reference", "changelog"},
	"security":      {"vulnerability", "cve", "patch", "audit", "credential", "token", "key"},
	"data":          {"query", "database", "table", "export", "import", "csv", "sql", "schema"},
}

// ValidateIntent checks whether the declared intent aligns with message content.
// Returns "match" if at least one keyword pattern appears in content,
// "mismatch" if the intent is declared but no patterns match,
// "missing" if no intent is provided.
func ValidateIntent(intent, content string) IntentResult {
	if intent == "" {
		return IntentResult{Status: "missing", Reason: "no intent declared"}
	}

	intentLower := strings.ToLower(strings.TrimSpace(intent))
	contentLower := strings.ToLower(content)

	// Check each known intent category
	for keyword, patterns := range intentKeywords {
		if !strings.Contains(intentLower, keyword) {
			continue
		}
		for _, p := range patterns {
			if strings.Contains(contentLower, strings.ToLower(p)) {
				return IntentResult{Status: "match", Reason: "intent aligns with content"}
			}
		}
		// Matched intent keyword but no content patterns found
		return IntentResult{
			Status: "mismatch",
			Reason: "declared intent '" + keyword + "' but content does not match expected patterns",
		}
	}

	// Unknown intent category — cannot validate, treat as match to avoid false positives
	return IntentResult{Status: "match", Reason: "unregistered intent category — skipped"}
}
