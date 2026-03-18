package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

// --- Legacy single-hop tests (backward compat) ---

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

// --- Chain tests ---

// testKeys generates n named keypairs and returns a resolver function.
func testKeys(names ...string) (map[string]ed25519.PrivateKey, func(string) ed25519.PublicKey) {
	privKeys := make(map[string]ed25519.PrivateKey, len(names))
	pubKeys := make(map[string]ed25519.PublicKey, len(names))
	for _, name := range names {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		privKeys[name] = priv
		pubKeys[name] = pub
	}
	resolver := func(agent string) ed25519.PublicKey {
		return pubKeys[agent]
	}
	return privKeys, resolver
}

func TestVerifyChain_TwoHop(t *testing.T) {
	keys, resolver := testKeys("human", "agent-a", "agent-b")

	// Human delegates to Agent A
	hop0 := CreateChainedDelegation(
		keys["human"], "human", "agent-a",
		[]string{"*"}, nil, time.Hour, "", 0, 3,
	)

	// Agent A delegates to Agent B (narrower scope)
	hop1 := CreateChainedDelegation(
		keys["agent-a"], "agent-a", "agent-b",
		[]string{"target-x", "target-y"}, []string{"Bash", "Read"}, time.Hour,
		hop0.TokenID, 1, 3,
	)

	chain := DelegationChain{*hop0, *hop1}
	result := VerifyChain(chain, resolver)

	if !result.Valid {
		t.Fatalf("expected valid chain, got: %s", result.Reason)
	}
	if result.Root != "human" {
		t.Errorf("root = %q, want human", result.Root)
	}
	if result.Delegate != "agent-b" {
		t.Errorf("delegate = %q, want agent-b", result.Delegate)
	}
	if result.Depth != 2 {
		t.Errorf("depth = %d, want 2", result.Depth)
	}
	if len(result.Tools) != 2 {
		t.Errorf("tools = %v, want [Bash Read]", result.Tools)
	}
	if result.ChainHash == "" {
		t.Error("chain hash should not be empty")
	}
}

func TestVerifyChain_ThreeHop(t *testing.T) {
	keys, resolver := testKeys("human", "a", "b", "c")

	hop0 := CreateChainedDelegation(keys["human"], "human", "a", []string{"*"}, nil, time.Hour, "", 0, 5)
	hop1 := CreateChainedDelegation(keys["a"], "a", "b", []string{"*"}, []string{"Bash", "Read", "Write"}, time.Hour, hop0.TokenID, 1, 5)
	hop2 := CreateChainedDelegation(keys["b"], "b", "c", []string{"target-z"}, []string{"Read"}, time.Hour, hop1.TokenID, 2, 5)

	chain := DelegationChain{*hop0, *hop1, *hop2}
	result := VerifyChain(chain, resolver)

	if !result.Valid {
		t.Fatalf("3-hop chain should be valid: %s", result.Reason)
	}
	if result.Root != "human" {
		t.Errorf("root = %q", result.Root)
	}
	if result.Delegate != "c" {
		t.Errorf("delegate = %q", result.Delegate)
	}
	// Tools should narrow: nil -> [Bash,Read,Write] -> [Read] = [Read]
	if len(result.Tools) != 1 || result.Tools[0] != "Read" {
		t.Errorf("tools = %v, want [Read]", result.Tools)
	}
}

func TestVerifyChain_Empty(t *testing.T) {
	_, resolver := testKeys("a")
	result := VerifyChain(nil, resolver)
	if result.Valid {
		t.Fatal("empty chain should be invalid")
	}
}

func TestVerifyChain_BrokenLinkage(t *testing.T) {
	keys, resolver := testKeys("human", "a", "b")

	hop0 := CreateChainedDelegation(keys["human"], "human", "a", []string{"*"}, nil, time.Hour, "", 0, 3)
	hop1 := CreateChainedDelegation(keys["a"], "a", "b", []string{"*"}, nil, time.Hour, "wrong-parent-id", 1, 3)

	chain := DelegationChain{*hop0, *hop1}
	result := VerifyChain(chain, resolver)

	if result.Valid {
		t.Fatal("broken linkage should be invalid")
	}
	if result.Reason == "" {
		t.Fatal("should have a reason")
	}
}

func TestVerifyChain_ScopeEscalation(t *testing.T) {
	keys, resolver := testKeys("human", "a", "b")

	hop0 := CreateChainedDelegation(keys["human"], "human", "a", []string{"target-x"}, nil, time.Hour, "", 0, 3)
	// Agent A tries to delegate with broader scope than it received
	hop1 := CreateChainedDelegation(keys["a"], "a", "b", []string{"*"}, nil, time.Hour, hop0.TokenID, 1, 3)

	chain := DelegationChain{*hop0, *hop1}
	result := VerifyChain(chain, resolver)

	if result.Valid {
		t.Fatal("scope escalation should be rejected")
	}
}

func TestVerifyChain_DepthExceeded(t *testing.T) {
	keys, resolver := testKeys("human", "a", "b")

	hop0 := CreateChainedDelegation(keys["human"], "human", "a", []string{"*"}, nil, time.Hour, "", 0, 1) // max_depth=1
	hop1 := CreateChainedDelegation(keys["a"], "a", "b", []string{"*"}, nil, time.Hour, hop0.TokenID, 1, 1)
	// depth 1 == max_depth 1, so this is OK

	chain := DelegationChain{*hop0, *hop1}
	result := VerifyChain(chain, resolver)
	if !result.Valid {
		t.Fatalf("depth 1 with max 1 should be valid: %s", result.Reason)
	}

	// Now try depth 2 with max_depth 1
	keys2, resolver2 := testKeys("human", "a", "b", "c")
	h0 := CreateChainedDelegation(keys2["human"], "human", "a", []string{"*"}, nil, time.Hour, "", 0, 1)
	h1 := CreateChainedDelegation(keys2["a"], "a", "b", []string{"*"}, nil, time.Hour, h0.TokenID, 1, 1)
	h2 := CreateChainedDelegation(keys2["b"], "b", "c", []string{"*"}, nil, time.Hour, h1.TokenID, 2, 1) // exceeds

	chain2 := DelegationChain{*h0, *h1, *h2}
	result2 := VerifyChain(chain2, resolver2)
	if result2.Valid {
		t.Fatal("depth 2 with max 1 should be rejected")
	}
}

func TestVerifyChain_ContinuityBreak(t *testing.T) {
	keys, resolver := testKeys("human", "a", "b", "rogue")

	hop0 := CreateChainedDelegation(keys["human"], "human", "a", []string{"*"}, nil, time.Hour, "", 0, 3)
	// Rogue signs as if it were "a" delegating to "b", but uses wrong key
	hop1 := CreateChainedDelegation(keys["rogue"], "a", "b", []string{"*"}, nil, time.Hour, hop0.TokenID, 1, 3)

	chain := DelegationChain{*hop0, *hop1}
	result := VerifyChain(chain, resolver)

	if result.Valid {
		t.Fatal("impersonation should be rejected (wrong key for delegator)")
	}
}

func TestVerifyChain_ExpiredHop(t *testing.T) {
	keys, resolver := testKeys("human", "a", "b")

	hop0 := CreateChainedDelegation(keys["human"], "human", "a", []string{"*"}, nil, time.Hour, "", 0, 3)
	hop1 := CreateChainedDelegation(keys["a"], "a", "b", []string{"*"}, nil, -time.Hour, hop0.TokenID, 1, 3) // expired

	chain := DelegationChain{*hop0, *hop1}
	result := VerifyChain(chain, resolver)

	if result.Valid {
		t.Fatal("expired hop should invalidate chain")
	}
}

func TestVerifyChain_UnknownDelegator(t *testing.T) {
	keys, _ := testKeys("human", "a")
	// Resolver that only knows "human"
	resolver := func(agent string) ed25519.PublicKey {
		if agent == "human" {
			return keys["human"].Public().(ed25519.PublicKey)
		}
		return nil
	}

	hop0 := CreateChainedDelegation(keys["human"], "human", "a", []string{"*"}, nil, time.Hour, "", 0, 3)
	hop1 := CreateChainedDelegation(keys["a"], "a", "b", []string{"*"}, nil, time.Hour, hop0.TokenID, 1, 3)

	chain := DelegationChain{*hop0, *hop1}
	result := VerifyChain(chain, resolver)

	if result.Valid {
		t.Fatal("unknown delegator should be rejected")
	}
}

func TestFormatChain(t *testing.T) {
	chain := DelegationChain{
		{Delegator: "human", Delegate: "agent-a"},
		{Delegator: "agent-a", Delegate: "agent-b"},
		{Delegator: "agent-b", Delegate: "agent-c"},
	}
	got := FormatChain(chain)
	want := "human -> agent-a -> agent-b -> agent-c"
	if got != want {
		t.Errorf("FormatChain = %q, want %q", got, want)
	}
}

func TestFormatChain_Empty(t *testing.T) {
	if FormatChain(nil) != "" {
		t.Error("empty chain should return empty string")
	}
}

// --- Helper tests ---

func TestScopeIsSubset(t *testing.T) {
	tests := []struct {
		child, parent []string
		want          bool
	}{
		{[]string{"a"}, []string{"a", "b"}, true},
		{[]string{"a", "b"}, []string{"a", "b"}, true},
		{[]string{"c"}, []string{"a", "b"}, false},
		{[]string{"a"}, []string{"*"}, true},
		{[]string{"*"}, []string{"a"}, false}, // escalation
		{[]string{"*"}, []string{"*"}, true},
		{nil, []string{"a"}, true},
		{[]string{}, []string{"a"}, true},
	}
	for _, tt := range tests {
		got := scopeIsSubset(tt.child, tt.parent)
		if got != tt.want {
			t.Errorf("scopeIsSubset(%v, %v) = %v, want %v", tt.child, tt.parent, got, tt.want)
		}
	}
}

func TestIntersectTools(t *testing.T) {
	tests := []struct {
		a, b []string
		want int
	}{
		{nil, []string{"Bash"}, 1},
		{[]string{"Bash"}, nil, 1},
		{[]string{"Bash", "Read"}, []string{"Read", "Write"}, 1},
		{[]string{"Bash", "Read"}, []string{"Bash", "Read"}, 2},
		{[]string{"Bash"}, []string{"Read"}, 0},
	}
	for _, tt := range tests {
		got := intersectTools(tt.a, tt.b)
		if len(got) != tt.want {
			t.Errorf("intersectTools(%v, %v) = %v (len %d), want len %d", tt.a, tt.b, got, len(got), tt.want)
		}
	}
}

func TestTokenID_Deterministic(t *testing.T) {
	keys, _ := testKeys("human")

	t1 := CreateChainedDelegation(keys["human"], "human", "agent", []string{"*"}, nil, time.Hour, "", 0, 3)
	if t1.TokenID == "" {
		t.Fatal("token ID should not be empty")
	}

	// Recompute should match
	recomputed := computeTokenID(t1)
	if recomputed != t1.TokenID {
		t.Errorf("recomputed token ID %q != original %q", recomputed, t1.TokenID)
	}
}
