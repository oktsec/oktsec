package engine

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/garagon/aguara"
	"github.com/oktsec/oktsec/rules"
)

// credentialPatterns matches known API key and secret formats for redaction.
// When a credential is detected in match text, it's truncated to prevent
// secrets from leaking through API responses, audit trail, or webhooks.
var credentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`sk-ant-[a-zA-Z0-9_-]{10,}`),
	regexp.MustCompile(`sk-[a-zA-Z0-9_-]{10,}`),
	regexp.MustCompile(`ghp_[a-zA-Z0-9]{10,}`),
	regexp.MustCompile(`gho_[a-zA-Z0-9]{10,}`),
	regexp.MustCompile(`ghs_[a-zA-Z0-9]{10,}`),
	regexp.MustCompile(`ghr_[a-zA-Z0-9]{10,}`),
	regexp.MustCompile(`github_pat_[a-zA-Z0-9_]{10,}`),
	regexp.MustCompile(`AKIA[0-9A-Z]{4,}`),
	regexp.MustCompile(`xox[bpas]-[a-zA-Z0-9-]{10,}`),
	regexp.MustCompile(`glpat-[a-zA-Z0-9_-]{10,}`),
	regexp.MustCompile(`sk_live_[a-zA-Z0-9]{10,}`),
	regexp.MustCompile(`sk_test_[a-zA-Z0-9]{10,}`),
	regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{10,}`),
	regexp.MustCompile(`-----BEGIN[A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}`),
}

// redactMatch replaces known credential patterns with truncated versions
// to prevent secrets from leaking through API responses or audit trail.
func redactMatch(s string) string {
	for _, re := range credentialPatterns {
		s = re.ReplaceAllStringFunc(s, func(match string) string {
			if len(match) > 10 {
				return match[:10] + "***"
			}
			return match[:4] + "***"
		})
	}
	return s
}

// ScanVerdict is the proxy's decision based on scan findings.
type ScanVerdict string

const (
	VerdictClean      ScanVerdict = "clean"
	VerdictBlock      ScanVerdict = "block"
	VerdictQuarantine ScanVerdict = "quarantine"
	VerdictFlag       ScanVerdict = "flag"
)

// ScanOutcome holds the result of content scanning.
type ScanOutcome struct {
	Verdict  ScanVerdict
	Findings []FindingSummary
}

// FindingSummary is a simplified finding for the proxy response.
type FindingSummary struct {
	RuleID   string `json:"rule_id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Category string `json:"category,omitempty"`
	Match    string `json:"match,omitempty"`
}

// ruleCache holds pre-loaded rule metadata.
type ruleCache struct {
	list    []aguara.RuleInfo
	details map[string]*aguara.RuleDetail
}

// Scanner wraps the Aguara engine for in-process content scanning.
type Scanner struct {
	mu      sync.RWMutex
	opts    []aguara.Option
	tempDir string // temp dir for embedded IAP rules
	cache   *ruleCache
}

// NewScanner creates a scanner with oktsec's IAP rules + Aguara's built-in rules.
// If customRulesDir is non-empty, rules from that directory are also loaded.
func NewScanner(customRulesDir string, extraOpts ...aguara.Option) *Scanner {
	s := &Scanner{}

	// Extract embedded IAP rules to a temp directory
	dir, err := extractEmbeddedRules()
	if err == nil && dir != "" {
		s.tempDir = dir
		s.opts = append(s.opts, aguara.WithCustomRules(dir))
	}

	if customRulesDir != "" {
		s.opts = append(s.opts, aguara.WithCustomRules(customRulesDir))
	}

	s.opts = append(s.opts, extraOpts...)
	return s
}

// ScanContent scans message content and returns a verdict.
func (s *Scanner) ScanContent(ctx context.Context, content string) (*ScanOutcome, error) {
	return s.ScanContentAs(ctx, content, "message.md")
}

// ScanContentAs scans content with a specific virtual filename for target matching.
// Use this when the content represents a specific file type (e.g., "openclaw.json")
// so that rules with file-type targets can match correctly.
func (s *Scanner) ScanContentAs(ctx context.Context, content, filename string) (*ScanOutcome, error) {
	result, err := aguara.ScanContent(ctx, content, filename, s.opts...)
	if err != nil {
		return nil, fmt.Errorf("aguara scan: %w", err)
	}
	return buildOutcome(result), nil
}

// buildOutcome converts Aguara scan results into a proxy verdict.
func buildOutcome(result *aguara.ScanResult) *ScanOutcome {
	outcome := &ScanOutcome{
		Verdict: VerdictClean,
	}

	for _, f := range result.Findings {
		summary := FindingSummary{
			RuleID:   f.RuleID,
			Name:     f.RuleName,
			Severity: f.Severity.String(),
			Category: f.Category,
			Match:    truncate(redactMatch(f.MatchedText), 200),
		}
		outcome.Findings = append(outcome.Findings, summary)

		// Escalate verdict based on severity
		switch {
		case f.Severity >= aguara.SeverityCritical && outcome.Verdict != VerdictBlock:
			outcome.Verdict = VerdictBlock
		case f.Severity >= aguara.SeverityHigh && outcome.Verdict == VerdictClean:
			outcome.Verdict = VerdictQuarantine
		case f.Severity >= aguara.SeverityMedium && outcome.Verdict == VerdictClean:
			outcome.Verdict = VerdictFlag
		}
	}

	return outcome
}

// Close cleans up temporary files.
func (s *Scanner) Close() {
	if s.tempDir != "" {
		_ = os.RemoveAll(s.tempDir) //nolint:errcheck // best-effort cleanup
	}
}

// RulesCount returns the total number of loaded rules (Aguara + IAP).
func (s *Scanner) RulesCount(ctx context.Context) int {
	result, err := aguara.ScanContent(ctx, "test", "test.md", s.opts...)
	if err != nil {
		return 0
	}
	return result.RulesLoaded
}

// ensureCache builds the rule cache if it hasn't been built yet.
func (s *Scanner) ensureCache() *ruleCache {
	s.mu.RLock()
	c := s.cache
	s.mu.RUnlock()
	if c != nil {
		return c
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache != nil {
		return s.cache
	}

	list := aguara.ListRules(s.opts...)
	details := make(map[string]*aguara.RuleDetail, len(list))
	for _, ri := range list {
		if d, err := aguara.ExplainRule(ri.ID, s.opts...); err == nil {
			details[ri.ID] = d
		}
	}
	s.cache = &ruleCache{list: list, details: details}
	return s.cache
}

// InvalidateCache forces the next ListRules/ExplainRule call to reload from disk.
func (s *Scanner) InvalidateCache() {
	s.mu.Lock()
	s.cache = nil
	s.mu.Unlock()
}

// AddCustomRulesDir appends a custom rules directory and invalidates the cache.
func (s *Scanner) AddCustomRulesDir(dir string) {
	s.mu.Lock()
	s.opts = append(s.opts, aguara.WithCustomRules(dir))
	s.cache = nil
	s.mu.Unlock()
}

// ListRules returns metadata for all loaded rules (Aguara built-in + IAP + custom).
func (s *Scanner) ListRules() []aguara.RuleInfo {
	return s.ensureCache().list
}

// ExplainRule returns detailed information about a specific rule by ID.
func (s *Scanner) ExplainRule(id string) (*aguara.RuleDetail, error) {
	c := s.ensureCache()
	if d, ok := c.details[id]; ok {
		return d, nil
	}
	return nil, fmt.Errorf("rule %q not found", id)
}

// extractEmbeddedRules writes the embedded IAP rule YAMLs to a temp directory.
func extractEmbeddedRules() (string, error) {
	dir, err := os.MkdirTemp("", "oktsec-rules-*")
	if err != nil {
		return "", err
	}

	embedded := rules.FS()
	err = fs.WalkDir(embedded, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		ext := filepath.Ext(path)
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, err := fs.ReadFile(embedded, path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, filepath.Base(path)), data, 0o644)
	})
	if err != nil {
		_ = os.RemoveAll(dir) //nolint:errcheck // best-effort cleanup
		return "", err
	}
	return dir, nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
