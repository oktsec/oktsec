package proxy

import (
	"testing"

	"github.com/oktsec/oktsec/internal/engine"
	"github.com/oktsec/oktsec/internal/verdict"
)

func TestVerdictToStdio(t *testing.T) {
	tests := []struct {
		verdict    engine.ScanVerdict
		wantStatus string
		wantDec    string
	}{
		{engine.VerdictBlock, "blocked", "content_blocked"},
		{engine.VerdictQuarantine, "quarantined", "content_quarantined"},
		{engine.VerdictFlag, "delivered", "content_flagged"},
		{engine.VerdictClean, "delivered", "allow"},
	}
	for _, tc := range tests {
		status, dec := verdictToStdio(tc.verdict)
		if status != tc.wantStatus {
			t.Errorf("verdictToStdio(%s) status = %q, want %q", tc.verdict, status, tc.wantStatus)
		}
		if dec != tc.wantDec {
			t.Errorf("verdictToStdio(%s) decision = %q, want %q", tc.verdict, dec, tc.wantDec)
		}
	}
}

func TestEncodeStdioFindings_Empty(t *testing.T) {
	got := verdict.EncodeFindings(nil)
	if got != "[]" {
		t.Errorf("EncodeFindings(nil) = %q, want %q", got, "[]")
	}
}

func TestEncodeStdioFindings_WithData(t *testing.T) {
	findings := []engine.FindingSummary{
		{RuleID: "IAP-001", Name: "test", Severity: "high"},
	}
	got := verdict.EncodeFindings(findings)
	if got == "[]" {
		t.Error("EncodeFindings should return non-empty JSON")
	}
}
