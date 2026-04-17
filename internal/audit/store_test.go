package audit

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := NewStore(dbPath, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestQueryEdgeStats(t *testing.T) {
	store := newTestStore(t)

	entries := []Entry{
		{ID: "e1", Timestamp: time.Now().UTC().Format(time.RFC3339), FromAgent: "a", ToAgent: "b", ContentHash: "h", Status: "delivered", PolicyDecision: "allow"},
		{ID: "e2", Timestamp: time.Now().UTC().Format(time.RFC3339), FromAgent: "a", ToAgent: "b", ContentHash: "h", Status: "delivered", PolicyDecision: "allow"},
		{ID: "e3", Timestamp: time.Now().UTC().Format(time.RFC3339), FromAgent: "a", ToAgent: "b", ContentHash: "h", Status: "blocked", PolicyDecision: "content_blocked"},
		{ID: "e4", Timestamp: time.Now().UTC().Format(time.RFC3339), FromAgent: "b", ToAgent: "c", ContentHash: "h", Status: "delivered", PolicyDecision: "allow"},
		{ID: "e5", Timestamp: time.Now().UTC().Format(time.RFC3339), FromAgent: "c", ToAgent: "a", ContentHash: "h", Status: "quarantined", PolicyDecision: "content_quarantined"},
	}
	for _, e := range entries {
		store.Log(e)
	}
	store.Flush()

	stats, err := store.QueryEdgeStats("")
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 3 {
		t.Fatalf("got %d edges, want 3", len(stats))
	}

	// Find a→b edge (should have highest total = 3)
	var ab *EdgeStat
	for i := range stats {
		if stats[i].From == "a" && stats[i].To == "b" {
			ab = &stats[i]
			break
		}
	}
	if ab == nil {
		t.Fatal("a→b edge not found")
	}
	if ab.Total != 3 {
		t.Errorf("a→b total = %d, want 3", ab.Total)
	}
	if ab.Delivered != 2 {
		t.Errorf("a→b delivered = %d, want 2", ab.Delivered)
	}
	if ab.Blocked != 1 {
		t.Errorf("a→b blocked = %d, want 1", ab.Blocked)
	}
}

func TestRevokeAndListKeys(t *testing.T) {
	store := newTestStore(t)

	if err := store.RevokeKey("fp-abc", "agent-a", "compromised"); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeKey("fp-def", "agent-b", "rotated"); err != nil {
		t.Fatal(err)
	}

	// IsRevoked
	revoked, err := store.IsRevoked("fp-abc")
	if err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Error("fp-abc should be revoked")
	}
	revoked, err = store.IsRevoked("fp-unknown")
	if err != nil {
		t.Fatal(err)
	}
	if revoked {
		t.Error("fp-unknown should not be revoked")
	}

	// ListRevokedKeys
	keys, err := store.ListRevokedKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d revoked keys, want 2", len(keys))
	}
	// Verify both agents present
	agents := map[string]bool{}
	for _, k := range keys {
		agents[k.AgentName] = true
	}
	if !agents["agent-a"] || !agents["agent-b"] {
		t.Errorf("missing agents in revoked keys: %+v", keys)
	}

	// RevokeKey with same fingerprint overwrites (INSERT OR REPLACE)
	if err := store.RevokeKey("fp-abc", "agent-a", "new reason"); err != nil {
		t.Fatal(err)
	}
	keys, _ = store.ListRevokedKeys()
	if len(keys) != 2 {
		t.Errorf("got %d keys after re-revoke, want 2", len(keys))
	}
}

func TestQueryStatsAndAgentStats(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC().Format(time.RFC3339)

	entries := []Entry{
		{ID: "s1", Timestamp: now, FromAgent: "a", ToAgent: "b", ContentHash: "h", Status: "delivered", PolicyDecision: "allow"},
		{ID: "s2", Timestamp: now, FromAgent: "a", ToAgent: "b", ContentHash: "h", Status: "blocked", PolicyDecision: "content_blocked"},
		{ID: "s3", Timestamp: now, FromAgent: "b", ToAgent: "a", ContentHash: "h", Status: "quarantined", PolicyDecision: "content_quarantined"},
		{ID: "s4", Timestamp: now, FromAgent: "c", ToAgent: "a", ContentHash: "h", Status: "rejected", PolicyDecision: "identity_rejected"},
	}
	for _, e := range entries {
		store.Log(e)
	}
	store.Flush()

	// QueryStats (global)
	sc, err := store.QueryStats()
	if err != nil {
		t.Fatal(err)
	}
	if sc.Total != 4 || sc.Delivered != 1 || sc.Blocked != 1 || sc.Quarantined != 1 || sc.Rejected != 1 {
		t.Errorf("stats = %+v", sc)
	}

	// QueryAgentStats
	as, err := store.QueryAgentStats("a")
	if err != nil {
		t.Fatal(err)
	}
	// agent "a" appears in s1(from), s2(from), s3(to), s4(to) = 4 entries
	if as.Total != 4 {
		t.Errorf("agent-a total = %d, want 4", as.Total)
	}
}

func TestQueryHourlyStats(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC().Format(time.RFC3339)

	store.Log(Entry{ID: "h1", Timestamp: now, FromAgent: "a", ToAgent: "b", ContentHash: "h", Status: "delivered", PolicyDecision: "allow"})
	store.Log(Entry{ID: "h2", Timestamp: now, FromAgent: "a", ToAgent: "b", ContentHash: "h", Status: "delivered", PolicyDecision: "allow"})
	store.Flush()

	stats, err := store.QueryHourlyStats()
	if err != nil {
		t.Fatal(err)
	}
	// Should have at least one hour bucket
	total := 0
	for _, c := range stats {
		total += c
	}
	if total != 2 {
		t.Errorf("hourly total = %d, want 2", total)
	}
}

func TestQueryTopRulesAndEdgeRules(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC().Format(time.RFC3339)
	rules := `[{"rule_id":"PI-001","name":"Prompt Injection","severity":"critical"},{"rule_id":"CRED-001","name":"Credential Leak","severity":"high"}]`

	store.Log(Entry{ID: "r1", Timestamp: now, FromAgent: "a", ToAgent: "b", ContentHash: "h", Status: "blocked", PolicyDecision: "content_blocked", RulesTriggered: rules})
	store.Log(Entry{ID: "r2", Timestamp: now, FromAgent: "a", ToAgent: "b", ContentHash: "h", Status: "blocked", PolicyDecision: "content_blocked", RulesTriggered: `[{"rule_id":"PI-001","name":"Prompt Injection","severity":"critical"}]`})
	store.Flush()

	// QueryTopRules
	top, err := store.QueryTopRules(5, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(top) != 2 {
		t.Fatalf("got %d rules, want 2", len(top))
	}
	if top[0].RuleID != "PI-001" || top[0].Count != 2 {
		t.Errorf("top rule = %+v, want PI-001 count=2", top[0])
	}

	// QueryEdgeRules
	er, err := store.QueryEdgeRules("a", "b", 5, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(er) != 2 {
		t.Fatalf("got %d edge rules, want 2", len(er))
	}

	// Non-existent edge returns empty
	er, err = store.QueryEdgeRules("x", "y", 5, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(er) != 0 {
		t.Errorf("got %d edge rules for x→y, want 0", len(er))
	}
}

func TestQueryAgentRisk(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC().Format(time.RFC3339)

	store.Log(Entry{ID: "ar1", Timestamp: now, FromAgent: "bad-agent", ToAgent: "b", ContentHash: "h", Status: "blocked", PolicyDecision: "content_blocked"})
	store.Log(Entry{ID: "ar2", Timestamp: now, FromAgent: "bad-agent", ToAgent: "b", ContentHash: "h", Status: "blocked", PolicyDecision: "content_blocked"})
	store.Log(Entry{ID: "ar3", Timestamp: now, FromAgent: "bad-agent", ToAgent: "b", ContentHash: "h", Status: "delivered", PolicyDecision: "allow"})
	store.Log(Entry{ID: "ar4", Timestamp: now, FromAgent: "good-agent", ToAgent: "b", ContentHash: "h", Status: "delivered", PolicyDecision: "allow"})
	store.Flush()

	risks, err := store.QueryAgentRisk("")
	if err != nil {
		t.Fatal(err)
	}
	if len(risks) < 2 {
		t.Fatalf("got %d agents, want >= 2", len(risks))
	}
	// bad-agent should be first (highest risk) and good-agent should score 0.
	if risks[0].Agent != "bad-agent" {
		t.Errorf("highest risk agent = %q, want bad-agent", risks[0].Agent)
	}

	// Scoring formula: confidence * (80*blockRatio + 40*quarRatio) where
	// confidence = min(1, total/10). Here bad-agent has total=3, blocks=2,
	// quar=0 → 0.3 * (80 * 2/3) = 16. The absolute number matters less
	// than the ordering (bad > good) and the fact that a 1-in-3 block
	// rate no longer pegs the score at 100 — that's the bug this
	// replaces. Keep the assertion as a loose band so future tweaks to
	// the weights don't break the test for trivial reasons.
	if risks[0].RiskScore < 10 || risks[0].RiskScore > 40 {
		t.Errorf("bad-agent risk = %.1f, expected ~16 (low-sample block rate), got out of [10,40] band", risks[0].RiskScore)
	}
	// good-agent should be last with zero risk.
	if risks[len(risks)-1].RiskScore != 0 {
		t.Errorf("good-agent risk = %.1f, want 0", risks[len(risks)-1].RiskScore)
	}
}

func TestQueryByID(t *testing.T) {
	store := newTestStore(t)

	store.Log(Entry{ID: "byid-1", Timestamp: "2026-02-24T10:00:00Z", FromAgent: "a", ToAgent: "b", ContentHash: "h", Status: "delivered", PolicyDecision: "allow"})
	store.Flush()
	time.Sleep(20 * time.Millisecond) // ensure write loop completes

	e, err := store.QueryByID("byid-1")
	if err != nil {
		t.Fatal(err)
	}
	if e == nil || e.FromAgent != "a" {
		t.Errorf("QueryByID = %+v", e)
	}

	// Miss returns nil, nil
	e, err = store.QueryByID("nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if e != nil {
		t.Error("expected nil for nonexistent")
	}
}

func TestEntryJSON(t *testing.T) {
	e := Entry{ID: "j1", Status: "delivered"}
	b := EntryJSON(e)
	if len(b) == 0 {
		t.Fatal("empty JSON")
	}
	if !containsStr(string(b), `"id":"j1"`) {
		t.Errorf("JSON missing id: %s", b)
	}
}

func TestHubBroadcast(t *testing.T) {
	store := newTestStore(t)
	ch := store.Subscribe()
	defer store.Unsubscribe(ch)

	store.Log(Entry{ID: "hub1", Timestamp: time.Now().UTC().Format(time.RFC3339), FromAgent: "a", ToAgent: "b", ContentHash: "h", Status: "delivered", PolicyDecision: "allow"})
	store.Flush()

	select {
	case e := <-ch:
		if e.ID != "hub1" {
			t.Errorf("broadcast entry ID = %q, want hub1", e.ID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no broadcast received")
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestStoreLogAndQuery(t *testing.T) {
	store := newTestStore(t)

	store.Log(Entry{
		ID:                "msg-1",
		Timestamp:         "2026-02-22T10:00:00Z",
		FromAgent:         "agent-a",
		ToAgent:           "agent-b",
		ContentHash:       "abc123",
		SignatureVerified: 1,
		PubkeyFingerprint: "fp123",
		Status:            "delivered",
		PolicyDecision:    "allow",
		LatencyMs:         5,
	})

	store.Log(Entry{
		ID:                "msg-2",
		Timestamp:         "2026-02-22T10:01:00Z",
		FromAgent:         "agent-c",
		ToAgent:           "agent-b",
		ContentHash:       "def456",
		SignatureVerified: -1,
		Status:            "rejected",
		PolicyDecision:    "identity_rejected",
		LatencyMs:         0,
	})

	// Wait for async writes
	store.Flush()

	// Query all
	entries, err := store.Query(QueryOpts{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("got %d entries, want 2", len(entries))
	}

	// Query by status
	blocked, err := store.Query(QueryOpts{Status: "rejected"})
	if err != nil {
		t.Fatal(err)
	}
	if len(blocked) != 1 {
		t.Errorf("got %d rejected, want 1", len(blocked))
	}

	// Query unverified
	unverified, err := store.Query(QueryOpts{Unverified: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(unverified) != 1 {
		t.Errorf("got %d unverified, want 1", len(unverified))
	}

	// Query by agent
	agentEntries, err := store.Query(QueryOpts{Agent: "agent-a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(agentEntries) != 1 {
		t.Errorf("got %d entries for agent-a, want 1", len(agentEntries))
	}
}

func TestQueryUnsignedByAgent(t *testing.T) {
	store := newTestStore(t)

	now := time.Now().UTC().Format(time.RFC3339)
	entries := []Entry{
		{ID: "u1", Timestamp: now, FromAgent: "alice", ToAgent: "bob", ContentHash: "h", Status: "delivered", PolicyDecision: "allow", SignatureVerified: 1},
		{ID: "u2", Timestamp: now, FromAgent: "alice", ToAgent: "bob", ContentHash: "h", Status: "delivered", PolicyDecision: "allow", SignatureVerified: 0},
		{ID: "u3", Timestamp: now, FromAgent: "bob", ToAgent: "alice", ContentHash: "h", Status: "delivered", PolicyDecision: "allow", SignatureVerified: 0},
		{ID: "u4", Timestamp: now, FromAgent: "bob", ToAgent: "alice", ContentHash: "h", Status: "delivered", PolicyDecision: "allow", SignatureVerified: 0},
	}
	for _, e := range entries {
		store.Log(e)
	}
	store.Flush()

	results, err := store.QueryUnsignedByAgent()
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d agents, want 2", len(results))
	}

	// bob has 2 total (both unsigned), alice has 2 total (1 unsigned)
	agentMap := make(map[string]UnsignedByAgent)
	for _, r := range results {
		agentMap[r.Agent] = r
	}

	if a, ok := agentMap["alice"]; !ok {
		t.Error("missing alice")
	} else {
		if a.Total != 2 {
			t.Errorf("alice total = %d, want 2", a.Total)
		}
		if a.Unsigned != 1 {
			t.Errorf("alice unsigned = %d, want 1", a.Unsigned)
		}
	}

	if b, ok := agentMap["bob"]; !ok {
		t.Error("missing bob")
	} else {
		if b.Total != 2 {
			t.Errorf("bob total = %d, want 2", b.Total)
		}
		if b.Unsigned != 2 {
			t.Errorf("bob unsigned = %d, want 2", b.Unsigned)
		}
	}
}

func TestCountRulePrefix(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC().Format(time.RFC3339)

	memRules := `[{"rule_id":"MEM-001","name":"AI tool memory file write","severity":"critical"}]`
	iapRules := `[{"rule_id":"IAP-007","name":"Tool description prompt injection","severity":"critical"}]`
	mixedRules := `[{"rule_id":"MEM-003","name":"Shell alias injection","severity":"critical"},{"rule_id":"TC-011","name":"Persistence","severity":"critical"}]`

	store.Log(Entry{ID: "m1", Timestamp: now, FromAgent: "a", ToAgent: "b", ContentHash: "h1", Status: "blocked", PolicyDecision: "content_blocked", RulesTriggered: memRules})
	store.Log(Entry{ID: "m2", Timestamp: now, FromAgent: "a", ToAgent: "b", ContentHash: "h2", Status: "blocked", PolicyDecision: "content_blocked", RulesTriggered: iapRules})
	store.Log(Entry{ID: "m3", Timestamp: now, FromAgent: "a", ToAgent: "b", ContentHash: "h3", Status: "blocked", PolicyDecision: "content_blocked", RulesTriggered: mixedRules})
	store.Flush()

	// MEM- prefix should match 2 entries (m1 and m3)
	count, err := store.CountRulePrefix("MEM-")
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Errorf("CountRulePrefix(MEM-) = %d, want 2", count)
	}

	// IAP- prefix should match 1 entry (m2)
	count, err = store.CountRulePrefix("IAP-")
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("CountRulePrefix(IAP-) = %d, want 1", count)
	}

	// TC- prefix should match 1 entry (m3)
	count, err = store.CountRulePrefix("TC-")
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("CountRulePrefix(TC-) = %d, want 1", count)
	}

	// Nonexistent prefix should return 0
	count, err = store.CountRulePrefix("NONE-")
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("CountRulePrefix(NONE-) = %d, want 0", count)
	}
}

func TestCountRulePrefix_EmptyDB(t *testing.T) {
	store := newTestStore(t)

	count, err := store.CountRulePrefix("MEM-")
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("CountRulePrefix on empty DB = %d, want 0", count)
	}
}
