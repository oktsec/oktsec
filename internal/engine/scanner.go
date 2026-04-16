package engine

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"

	"github.com/garagon/aguara"
	"github.com/oktsec/oktsec/rules"
)

// credentialPattern ties a regex to a symbolic credential type. Replacement
// emits a typed placeholder (e.g. "[REDACTED:ANTHROPIC_KEY:len=48]") instead
// of echoing a prefix of the secret — previous behaviour exposed the first 10
// chars, which is enough to GitHub-search or fingerprint a rotated key.
type credentialPattern struct {
	re       *regexp.Regexp
	credType string
}

var credentialPatterns = []credentialPattern{
	{regexp.MustCompile(`sk-ant-[a-zA-Z0-9_-]{10,}`), "ANTHROPIC_KEY"},
	{regexp.MustCompile(`ghp_[a-zA-Z0-9]{10,}`), "GITHUB_PAT"},
	{regexp.MustCompile(`gho_[a-zA-Z0-9]{10,}`), "GITHUB_OAUTH"},
	{regexp.MustCompile(`ghs_[a-zA-Z0-9]{10,}`), "GITHUB_SERVER_TOKEN"},
	{regexp.MustCompile(`ghr_[a-zA-Z0-9]{10,}`), "GITHUB_REFRESH"},
	{regexp.MustCompile(`github_pat_[a-zA-Z0-9_]{10,}`), "GITHUB_PAT_FGT"},
	{regexp.MustCompile(`AKIA[0-9A-Z]{4,}`), "AWS_ACCESS_KEY"},
	{regexp.MustCompile(`xox[bpas]-[a-zA-Z0-9-]{10,}`), "SLACK_TOKEN"},
	{regexp.MustCompile(`glpat-[a-zA-Z0-9_-]{10,}`), "GITLAB_PAT"},
	{regexp.MustCompile(`sk_live_[a-zA-Z0-9]{10,}`), "STRIPE_LIVE"},
	{regexp.MustCompile(`sk_test_[a-zA-Z0-9]{10,}`), "STRIPE_TEST"},
	{regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{10,}`), "SENDGRID_KEY"},
	{regexp.MustCompile(`-----BEGIN[A-Z ]*PRIVATE KEY-----`), "PEM_PRIVATE_KEY"},
	{regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}`), "JWT"},
	{regexp.MustCompile(`sk-[a-zA-Z0-9_-]{10,}`), "OPENAI_KEY"},
}

// redactMatch replaces known credential patterns with typed placeholders.
// The placeholder records length but never the content, so credential search
// engines (GitHub dorks, Have-I-Been-Pwned etc.) can't fingerprint from audit
// trail leakage. Exported callers see only [REDACTED:TYPE:len=N].
func redactMatch(s string) string {
	for _, cp := range credentialPatterns {
		re := cp.re
		credType := cp.credType
		s = re.ReplaceAllStringFunc(s, func(match string) string {
			return fmt.Sprintf("[REDACTED:%s:len=%d]", credType, len(match))
		})
	}
	return s
}

// RedactContent replaces known credential patterns with truncated versions.
// Exported for use by testcase export and other callers that need to sanitize
// content before writing to disk.
func RedactContent(s string) string {
	return redactMatch(s)
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
	RuleID      string `json:"rule_id"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Category    string `json:"category,omitempty"`
	Match       string `json:"match,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// ruleCache holds pre-loaded rule metadata.
type ruleCache struct {
	list    []aguara.RuleInfo
	details map[string]*aguara.RuleDetail
}

// Scanner wraps the Aguara engine for in-process content scanning.
//
// Uses Aguara's cached Scanner API (v0.13.0+) for compiled-once, reuse-always
// scanning. The hot-loaded objects (compiled scanner + metadata cache) live
// behind atomic.Pointer so ScanContent() is lock-free on the fast path —
// critical at high RPS where an RWMutex becomes a visible contention point.
// writeMu serializes *rebuilds* only.
type Scanner struct {
	writeMu sync.Mutex
	cached  atomic.Pointer[aguara.Scanner] // compiled scanner, reused across all requests
	opts    []aguara.Option                // kept for hot-reload (InvalidateCache rebuilds)
	optsMu  sync.Mutex                     // guards opts during rebuild
	tempDir string                         // temp dir for embedded IAP rules
	cache   atomic.Pointer[ruleCache]      // metadata cache for ListRules/ExplainRule
}

// NewScanner creates a scanner with oktsec's IAP rules + Aguara's built-in rules.
// Rules are compiled once at startup and reused across all requests.
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

	// Build cached scanner (compile rules once). On failure we leave the
	// pointer nil and fall back to per-request scanning.
	if cached, err := aguara.NewScanner(s.opts...); err == nil {
		s.cached.Store(cached)
	}

	return s
}

// ScanContent scans message content and returns a verdict.
func (s *Scanner) ScanContent(ctx context.Context, content string) (*ScanOutcome, error) {
	return s.ScanContentAs(ctx, content, "message.md")
}

// ScanContentAs scans content with a specific virtual filename for target matching.
// Use this when the content represents a specific file type (e.g., "openclaw.json")
// so that rules with file-type targets can match correctly.
// NFKC normalization is handled internally by Aguara (v0.9.0+).
func (s *Scanner) ScanContentAs(ctx context.Context, content, filename string) (*ScanOutcome, error) {
	var result *aguara.ScanResult
	var err error
	if cached := s.cached.Load(); cached != nil {
		result, err = cached.ScanContent(ctx, content, filename)
	} else {
		result, err = aguara.ScanContent(ctx, content, filename, s.optsCopy()...)
	}
	if err != nil {
		return nil, fmt.Errorf("aguara scan: %w", err)
	}
	return buildOutcome(result), nil
}

// ScanContentWithTool scans content with tool context, enabling Aguara's
// built-in tool exemptions (e.g., TC-005 dropped on Edit/Write).
// Use this when the tool name is known (hooks handler, gateway tool calls).
func (s *Scanner) ScanContentWithTool(ctx context.Context, content, toolName string) (*ScanOutcome, error) {
	return s.ScanContentAsWithTool(ctx, content, "message.md", toolName)
}

// ScanContentAsWithTool scans content with both filename and tool context.
func (s *Scanner) ScanContentAsWithTool(ctx context.Context, content, filename, toolName string) (*ScanOutcome, error) {
	var result *aguara.ScanResult
	var err error
	cached := s.cached.Load()
	switch {
	case cached != nil && toolName != "":
		result, err = cached.ScanContentAs(ctx, content, filename, toolName)
	case cached != nil:
		result, err = cached.ScanContent(ctx, content, filename)
	default:
		opts := s.optsCopy()
		if toolName != "" {
			opts = append(opts, aguara.WithToolName(toolName))
		}
		result, err = aguara.ScanContent(ctx, content, filename, opts...)
	}
	if err != nil {
		return nil, fmt.Errorf("aguara scan: %w", err)
	}
	return buildOutcome(result), nil
}

// optsCopy returns a defensive copy of the current options so callers in the
// lock-free path don't alias a slice that InvalidateCache might grow.
func (s *Scanner) optsCopy() []aguara.Option {
	s.optsMu.Lock()
	defer s.optsMu.Unlock()
	out := make([]aguara.Option, len(s.opts))
	copy(out, s.opts)
	return out
}

// buildOutcome converts Aguara scan results into a proxy verdict.
func buildOutcome(result *aguara.ScanResult) *ScanOutcome {
	outcome := &ScanOutcome{
		Verdict: VerdictClean,
	}

	for _, f := range result.Findings {
		summary := FindingSummary{
			RuleID:      f.RuleID,
			Name:        f.RuleName,
			Severity:    f.Severity.String(),
			Category:    f.Category,
			Match:       truncate(redactMatch(f.MatchedText), 200),
			Remediation: f.Remediation,
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
	if cached := s.cached.Load(); cached != nil {
		return cached.RulesLoaded()
	}
	result, err := aguara.ScanContent(ctx, "test", "test.md", s.optsCopy()...)
	if err != nil {
		return 0
	}
	return result.RulesLoaded
}

// ensureCache builds the rule cache if it hasn't been built yet.
// Readers are lock-free via atomic.Pointer; only the builder takes writeMu
// to serialize rebuilds.
func (s *Scanner) ensureCache() *ruleCache {
	if c := s.cache.Load(); c != nil {
		return c
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if c := s.cache.Load(); c != nil {
		return c
	}

	cached := s.cached.Load()
	opts := s.optsCopy()

	var list []aguara.RuleInfo
	if cached != nil {
		list = cached.ListRules()
	} else {
		list = aguara.ListRules(opts...)
	}
	details := make(map[string]*aguara.RuleDetail, len(list))
	for _, ri := range list {
		var d *aguara.RuleDetail
		var err error
		if cached != nil {
			d, err = cached.ExplainRule(ri.ID)
		} else {
			d, err = aguara.ExplainRule(ri.ID, opts...)
		}
		if err == nil {
			details[ri.ID] = d
		}
	}
	c := &ruleCache{list: list, details: details}
	s.cache.Store(c)
	return c
}

// InvalidateCache forces the next ListRules/ExplainRule call to reload from disk.
// Also rebuilds the cached Aguara scanner with the current options.
// Used by the LLM rule generator to trigger hot-reload after new rules are approved.
func (s *Scanner) InvalidateCache() {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.cache.Store(nil)
	if cached, err := aguara.NewScanner(s.optsCopy()...); err == nil {
		s.cached.Store(cached)
	}
}

// AddCustomRulesDir appends a custom rules directory and rebuilds the scanner.
func (s *Scanner) AddCustomRulesDir(dir string) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.optsMu.Lock()
	s.opts = append(s.opts, aguara.WithCustomRules(dir))
	optsSnap := make([]aguara.Option, len(s.opts))
	copy(optsSnap, s.opts)
	s.optsMu.Unlock()
	s.cache.Store(nil)
	if cached, err := aguara.NewScanner(optsSnap...); err == nil {
		s.cached.Store(cached)
	}
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
