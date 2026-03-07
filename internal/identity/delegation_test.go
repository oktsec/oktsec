package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestCreateAndVerifyDelegation(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	token := CreateDelegation(priv, "parent", "child", []string{"target-a", "target-b"}, time.Hour)

	// Valid: recipient in scope
	result := VerifyDelegation(pub, token, "target-a")
	if !result.Valid {
		t.Fatalf("expected valid delegation, got: %s", result.Reason)
	}

	// Valid: other recipient in scope
	result = VerifyDelegation(pub, token, "target-b")
	if !result.Valid {
		t.Fatalf("expected valid for target-b: %s", result.Reason)
	}

	// Invalid: recipient not in scope
	result = VerifyDelegation(pub, token, "target-c")
	if result.Valid {
		t.Fatal("expected rejection for target-c")
	}
	if result.Reason == "" {
		t.Fatal("expected reason for rejection")
	}
}

func TestDelegation_WildcardScope(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	token := CreateDelegation(priv, "parent", "child", []string{"*"}, time.Hour)

	result := VerifyDelegation(pub, token, "anyone")
	if !result.Valid {
		t.Fatalf("wildcard scope should allow anyone: %s", result.Reason)
	}
}

func TestDelegation_Expired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	token := CreateDelegation(priv, "parent", "child", []string{"*"}, -time.Hour) // already expired

	result := VerifyDelegation(pub, token, "target")
	if result.Valid {
		t.Fatal("expired delegation should be rejected")
	}
}

func TestDelegation_WrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)

	token := CreateDelegation(priv, "parent", "child", []string{"*"}, time.Hour)

	result := VerifyDelegation(otherPub, token, "target")
	if result.Valid {
		t.Fatal("wrong key should fail verification")
	}
}

func TestDelegation_NilToken(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	result := VerifyDelegation(pub, nil, "target")
	if result.Valid {
		t.Fatal("nil token should be invalid")
	}
}

func TestDelegation_TamperedSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	token := CreateDelegation(priv, "parent", "child", []string{"target"}, time.Hour)

	// Tamper with scope
	token.Scope = []string{"*"}

	result := VerifyDelegation(pub, token, "target")
	if result.Valid {
		t.Fatal("tampered token should fail signature verification")
	}
}

func TestScopeAllows(t *testing.T) {
	tests := []struct {
		scope     []string
		recipient string
		want      bool
	}{
		{[]string{"a", "b"}, "a", true},
		{[]string{"a", "b"}, "c", false},
		{[]string{"*"}, "anything", true},
		{nil, "a", false},
		{[]string{}, "a", false},
	}
	for _, tt := range tests {
		got := scopeAllows(tt.scope, tt.recipient)
		if got != tt.want {
			t.Errorf("scopeAllows(%v, %q) = %v, want %v", tt.scope, tt.recipient, got, tt.want)
		}
	}
}
