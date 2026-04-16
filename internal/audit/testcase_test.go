package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExportTestcase(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	tc := Testcase{
		RuleID:    "TC-005",
		Type:      "true_positive",
		Source:    "production",
		Timestamp: "2026-04-07T12:00:00Z",
		Agent:     "test-agent",
		Tool:      "Bash",
		Content:   "rm -rf /",
		Severity:  "critical",
		Verdict:   "block",
	}

	path, err := ExportTestcase(tc)
	if err != nil {
		t.Fatal(err)
	}
	if path == "" {
		t.Fatal("expected non-empty path")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "TC-005") {
		t.Error("expected rule_id in output")
	}
	if !strings.Contains(content, "rm -rf /") {
		t.Error("expected content in output")
	}
}

func TestExportTestcase_RedactsCredentials(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	tc := Testcase{
		RuleID:    "IAP-003",
		Type:      "true_positive",
		Source:    "production",
		Timestamp: "2026-04-07T12:00:00Z",
		Agent:     "test-agent",
		Tool:      "send_message",
		Content:   "Use key: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZab",
		Severity:  "high",
		Verdict:   "block",
	}

	path, err := ExportTestcase(tc)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if strings.Contains(content, "ABCDEFGHIJ") {
		t.Error("credential not redacted")
	}
}

func TestLoadTestcases(t *testing.T) {
	dir := t.TempDir()

	// Write a sample testcase file
	yaml := `rule_id: TC-005
type: true_positive
source: production
timestamp: "2026-04-07T12:00:00Z"
agent: test-agent
tool: Bash
content: rm -rf /
severity: critical
verdict: block
`
	if err := os.WriteFile(filepath.Join(dir, "block-tc-005.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	cases, err := LoadTestcases(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 1 {
		t.Fatalf("expected 1 testcase, got %d", len(cases))
	}
	if cases[0].RuleID != "TC-005" {
		t.Errorf("rule_id: got %q, want TC-005", cases[0].RuleID)
	}
}

func TestLoadTestcases_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	cases, err := LoadTestcases(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 0 {
		t.Errorf("expected 0 testcases, got %d", len(cases))
	}
}

func TestLoadTestcases_NonExistent(t *testing.T) {
	cases, err := LoadTestcases("/nonexistent/path/xyz")
	if err != nil {
		t.Fatal(err)
	}
	if cases != nil {
		t.Errorf("expected nil, got %v", cases)
	}
}
