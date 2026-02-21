package engine

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/garagon/aguara"
	"github.com/oktsec/oktsec/rules"
)

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
	Match    string `json:"match,omitempty"`
}

// Scanner wraps the Aguara engine for in-process content scanning.
type Scanner struct {
	opts    []aguara.Option
	tempDir string // temp dir for embedded IAP rules
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
	result, err := aguara.ScanContent(ctx, content, "message.md", s.opts...)
	if err != nil {
		return nil, fmt.Errorf("aguara scan: %w", err)
	}

	outcome := &ScanOutcome{
		Verdict: VerdictClean,
	}

	for _, f := range result.Findings {
		summary := FindingSummary{
			RuleID:   f.RuleID,
			Name:     f.RuleName,
			Severity: f.Severity.String(),
			Match:    truncate(f.MatchedText, 200),
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

	return outcome, nil
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

// ListRules returns metadata for all loaded rules (Aguara built-in + IAP + custom).
func (s *Scanner) ListRules() []aguara.RuleInfo {
	return aguara.ListRules(s.opts...)
}

// ExplainRule returns detailed information about a specific rule by ID.
func (s *Scanner) ExplainRule(id string) (*aguara.RuleDetail, error) {
	return aguara.ExplainRule(id, s.opts...)
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
