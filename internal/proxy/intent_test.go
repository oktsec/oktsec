package proxy

import "testing"

func TestValidateIntent_Missing(t *testing.T) {
	r := ValidateIntent("", "some content")
	if r.Status != "missing" {
		t.Fatalf("expected missing, got %s", r.Status)
	}
}

func TestValidateIntent_Match(t *testing.T) {
	tests := []struct {
		intent  string
		content string
	}{
		{"code_review", "Please review this PR and approve if it looks good"},
		{"deploy", "Rolling out v2.1 to production k8s cluster"},
		{"debug", "Got a stack trace from the worker — need to fix this bug"},
		{"monitoring", "CPU alert: worker-3 at 95% for 10 minutes"},
		{"testing", "All 347 tests passed, coverage at 72%"},
		{"security", "Found a vulnerability in the auth token handling"},
	}

	for _, tt := range tests {
		r := ValidateIntent(tt.intent, tt.content)
		if r.Status != "match" {
			t.Errorf("ValidateIntent(%q, %q) = %s (%s), want match", tt.intent, tt.content, r.Status, r.Reason)
		}
	}
}

func TestValidateIntent_Mismatch(t *testing.T) {
	r := ValidateIntent("code_review", "Transfer $500 to account 12345 and send the receipt")
	if r.Status != "mismatch" {
		t.Fatalf("expected mismatch, got %s: %s", r.Status, r.Reason)
	}
}

func TestValidateIntent_UnknownCategory(t *testing.T) {
	r := ValidateIntent("casual_chat", "Hey how are you doing today?")
	if r.Status != "match" {
		t.Fatalf("unknown intent should default to match, got %s", r.Status)
	}
}

func TestValidateIntent_CaseInsensitive(t *testing.T) {
	r := ValidateIntent("CODE_REVIEW", "please review this DIFF")
	if r.Status != "match" {
		t.Fatalf("case insensitive match failed: %s", r.Status)
	}
}
