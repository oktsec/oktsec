package engine

import (
	"context"
	"testing"
)

func TestTruncate(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is a long string", 10, "this is a ..."},
		{"", 5, ""},
	}
	for _, tc := range tests {
		got := truncate(tc.input, tc.maxLen)
		if got != tc.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tc.input, tc.maxLen, got, tc.want)
		}
	}
}

func TestBuildOutcome_NoFindings(t *testing.T) {
	s := NewScanner("")
	defer s.Close()

	outcome, err := s.ScanContent(context.Background(), "Hello, how are you?")
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Verdict != VerdictClean {
		t.Errorf("verdict = %s, want clean", outcome.Verdict)
	}
	if len(outcome.Findings) != 0 {
		t.Errorf("findings count = %d, want 0", len(outcome.Findings))
	}
}

func TestListRules_ReturnsRules(t *testing.T) {
	s := NewScanner("")
	defer s.Close()

	rules := s.ListRules()
	if len(rules) == 0 {
		t.Error("ListRules should return at least one rule")
	}
}

func TestExplainRule_Found(t *testing.T) {
	s := NewScanner("")
	defer s.Close()

	detail, err := s.ExplainRule("IAP-001")
	if err != nil {
		t.Fatalf("ExplainRule(IAP-001) error: %v", err)
	}
	if detail.ID != "IAP-001" {
		t.Errorf("detail.ID = %q, want IAP-001", detail.ID)
	}
}

func TestExplainRule_NotFound(t *testing.T) {
	s := NewScanner("")
	defer s.Close()

	_, err := s.ExplainRule("NONEXISTENT-999")
	if err == nil {
		t.Error("ExplainRule for non-existent rule should return error")
	}
}

func TestInvalidateCache(t *testing.T) {
	s := NewScanner("")
	defer s.Close()

	// Build cache
	_ = s.ListRules()

	// Invalidate
	s.InvalidateCache()

	// Should rebuild on next call
	rules := s.ListRules()
	if len(rules) == 0 {
		t.Error("ListRules after cache invalidation should return rules")
	}
}

func TestIAPRuleCount(t *testing.T) {
	count := IAPRuleCount()
	if count < 2 {
		t.Errorf("IAPRuleCount = %d, want >= 2", count)
	}
}

func TestExtractRulesDir(t *testing.T) {
	dir, err := ExtractRulesDir()
	if err != nil {
		t.Fatal(err)
	}
	if dir == "" {
		t.Error("ExtractRulesDir returned empty string")
	}
	// Cleanup
	t.Cleanup(func() {
		// dir is cleaned up by caller
	})
}

func TestScanContentAs_DifferentFilenames(t *testing.T) {
	s := NewScanner("")
	defer s.Close()

	// Same content scanned with different filenames should work without errors
	content := "Hello, this is a test"
	for _, fname := range []string{"message.md", "config.json", "test.yaml"} {
		outcome, err := s.ScanContentAs(context.Background(), content, fname)
		if err != nil {
			t.Errorf("ScanContentAs(%q) error: %v", fname, err)
		}
		if outcome == nil {
			t.Errorf("ScanContentAs(%q) returned nil outcome", fname)
		}
	}
}

func TestRedactMatch_JWTToken(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
	got := redactMatch("Token: " + jwt)
	if got == "Token: "+jwt {
		t.Error("JWT should be redacted")
	}
}

func TestRedactMatch_MultipleCredentials(t *testing.T) {
	input := "Key1: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef and Key2: sk-ant-api03-abc123def456ghi789jkl"
	got := redactMatch(input)
	if got == input {
		t.Error("multiple credentials should be redacted")
	}
}

func TestNewScanner_Close(t *testing.T) {
	s := NewScanner("")
	// Should not panic on close
	s.Close()
	// Double close should be safe
	s.Close()
}

func TestAddCustomRulesDir(t *testing.T) {
	s := NewScanner("")
	defer s.Close()

	// Build cache first
	_ = s.ListRules()

	// Add custom dir (even if it doesn't exist, it shouldn't panic)
	s.AddCustomRulesDir(t.TempDir())

	// Cache should be invalidated
	// Next ListRules call should rebuild cache
	rules := s.ListRules()
	if len(rules) == 0 {
		t.Error("ListRules after AddCustomRulesDir should return rules")
	}
}
