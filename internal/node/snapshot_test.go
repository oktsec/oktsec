package node

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	_ "modernc.org/sqlite"
)

// buildAt is a convenience wrapper that pins the snapshot's
// generated_at, IdentityStore directory and DBPath to the test temp
// space so no test ever reaches the real ~/.oktsec.
func buildAt(t *testing.T, opts Options) Snapshot {
	t.Helper()
	if opts.IdentityStore.Dir == "" {
		opts.IdentityStore = IdentityStore{Dir: filepath.Join(t.TempDir(), "node")}
	}
	if opts.DBPath == "" {
		// Pin to a guaranteed-missing path so we never leak into the
		// developer's ~/.oktsec/oktsec.db. Tests that need a real DB
		// set DBPath explicitly.
		opts.DBPath = filepath.Join(t.TempDir(), "node-test-default.db")
	}
	if opts.Now.IsZero() {
		opts.Now = time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	}
	snap, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return snap
}

func TestSnapshot_NoConfigNoDB(t *testing.T) {
	snap := buildAt(t, Options{ConfigPath: filepath.Join(t.TempDir(), "missing.yaml")})
	if snap.SchemaVersion != SchemaSnapshot {
		t.Fatalf("schema version: %q", snap.SchemaVersion)
	}
	if snap.Node.IdentityStatus != "missing" {
		t.Fatalf("identity status: %q", snap.Node.IdentityStatus)
	}
	if snap.Config.Status != "missing" {
		t.Fatalf("config status: %q", snap.Config.Status)
	}
	if snap.Config.DBAvailable {
		t.Fatalf("db should not be available")
	}
	if snap.Posture.Overall != "setup_pending" {
		t.Fatalf("posture should be setup_pending without config, got %q", snap.Posture.Overall)
	}
	if !hasWarning(snap.Warnings, WarnConfigMissing) {
		t.Fatalf("expected config_missing warning, got %#v", snap.Warnings)
	}
	if !hasWarning(snap.Warnings, WarnNodeIdentityMissing) {
		t.Fatalf("expected node_identity_missing warning, got %#v", snap.Warnings)
	}
}

func TestSnapshot_ConfigPresentDBMissing(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")
	cfg := minimalCfg()
	cfg.DBPath = filepath.Join(dir, "does-not-exist.db")
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatalf("save: %v", err)
	}
	snap := buildAt(t, Options{ConfigPath: cfgPath, DBPath: cfg.DBPath})
	if snap.Config.Status != "present" {
		t.Fatalf("expected config present, got %q", snap.Config.Status)
	}
	if snap.Config.DBAvailable {
		t.Fatalf("db must not be available")
	}
	if _, err := os.Stat(cfg.DBPath); err == nil {
		t.Fatalf("snapshot must not create the audit DB at %s", cfg.DBPath)
	}
	if !hasWarning(snap.Warnings, WarnDBMissing) {
		t.Fatalf("expected db_missing warning, got %#v", snap.Warnings)
	}
}

func TestSnapshot_RuntimeTablesMissingAreReported(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")
	cfg := minimalCfg()
	cfg.DBPath = filepath.Join(dir, "oktsec.db")
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatalf("save cfg: %v", err)
	}
	// Create an empty SQLite DB without any tables. Snapshot must
	// observe it and report missing tables.
	db, err := sql.Open("sqlite", cfg.DBPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec("CREATE TABLE marker(x INT)"); err != nil {
		t.Fatalf("create marker: %v", err)
	}
	_ = db.Close()
	snap := buildAt(t, Options{ConfigPath: cfgPath, DBPath: cfg.DBPath})
	if !snap.Config.DBAvailable {
		t.Fatalf("db should be available")
	}
	if !hasWarning(snap.Warnings, WarnAuditTableMissing) {
		t.Fatalf("expected audit_table_missing warning")
	}
	if !hasWarning(snap.Warnings, WarnRuntimeTableMissing) {
		t.Fatalf("expected runtime_table_missing warning")
	}
	if !hasWarning(snap.Warnings, WarnActivityTableMissing) {
		t.Fatalf("expected activity_table_missing warning")
	}
	if snap.Evidence.AuditAvailable || snap.Evidence.RuntimeAvailable || snap.Evidence.ActivityAvailable {
		t.Fatalf("availability flags should be false when tables are missing")
	}
}

func TestSnapshot_WithAuditRows(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")
	cfg := minimalCfg()
	cfg.DBPath = filepath.Join(dir, "oktsec.db")
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatalf("save: %v", err)
	}
	seedAuditDB(t, cfg.DBPath, 3, 1)
	snap := buildAt(t, Options{
		ConfigPath: cfgPath,
		DBPath:     cfg.DBPath,
		Since:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if !snap.Evidence.AuditAvailable {
		t.Fatalf("audit should be available")
	}
	if snap.Evidence.AuditEntries < 4 {
		t.Fatalf("expected at least 4 audit entries, got %d", snap.Evidence.AuditEntries)
	}
	if snap.Evidence.Decisions.Blocked != 1 {
		t.Fatalf("expected 1 blocked decision, got %d", snap.Evidence.Decisions.Blocked)
	}
	if snap.Evidence.AuditChainHead == "" {
		t.Fatalf("audit chain head should be populated")
	}
}

func TestSnapshot_InventoryRedacted(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")
	cfg := minimalCfg()
	cfg.Agents = map[string]config.Agent{
		"researcher": {Suspended: false, Tags: []string{"alpha"}},
		"analyst":    {Suspended: true},
	}
	cfg.Identity.Principals = []config.PrincipalConfig{
		{ID: "researcher", Kind: "agent", WorkspaceID: "ws-123", AllowedSurfaces: []string{"mcp_http"}},
	}
	cfg.MCPServers = map[string]config.MCPServerConfig{
		"filesystem": {Transport: "stdio", Command: "/usr/bin/npx", Args: []string{"--workdir", "/Users/dev/secret"}, Env: map[string]string{"K": "v"}},
		"remote":     {Transport: "http", URL: "https://user:pw@mcp.example.com/api?token=topsecret"},
	}
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatalf("save: %v", err)
	}
	snap := buildAt(t, Options{ConfigPath: cfgPath})
	raw := requireJSON(t, snap)
	// Banned strings the redaction must keep out of the JSON.
	banned := []string{
		"/usr/bin/npx",
		"/Users/dev/secret",
		"user:pw@",
		"topsecret",
		"ws-123",
	}
	for _, b := range banned {
		if strings.Contains(raw, b) {
			t.Errorf("snapshot leaked %q", b)
		}
	}
	if len(snap.Inventory.Agents) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(snap.Inventory.Agents))
	}
	// Sorted by id.
	if snap.Inventory.Agents[0].ID != "analyst" || snap.Inventory.Agents[1].ID != "researcher" {
		t.Fatalf("agents not sorted: %v", snap.Inventory.Agents)
	}
	if len(snap.Inventory.MCPServers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(snap.Inventory.MCPServers))
	}
}

func TestSnapshot_RejectsSymlinkedDB(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")
	cfg := minimalCfg()
	real := filepath.Join(dir, "real.db")
	link := filepath.Join(dir, "linked.db")
	seedAuditDB(t, real, 1, 0)
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	cfg.DBPath = link
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatalf("save: %v", err)
	}
	snap := buildAt(t, Options{ConfigPath: cfgPath, DBPath: cfg.DBPath})
	if snap.Config.DBAvailable {
		t.Fatalf("snapshot must refuse symlinked DB path")
	}
	if !hasWarning(snap.Warnings, WarnDBUnreachable) {
		t.Fatalf("expected db_unreachable warning, got %#v", snap.Warnings)
	}
}

func TestPosture_HeartbeatNeverProtects(t *testing.T) {
	// Regression: heartbeats are diagnostic only. A recent heartbeat
	// proves the hook endpoint is reachable, not that any real
	// action was inspected. Posture must not flip to protected from
	// heartbeat evidence alone.
	cfg := minimalCfg()
	surfaces := SnapshotSurfaces{
		MCPGateway:      SurfaceGateway{Configured: true, Enabled: true},
		Hooks:           SurfaceHooks{Configured: true, HeartbeatRecent: true, FreshRealEvent: false},
		EgressProxy:     SurfaceEgress{Configured: true, Enabled: true},
		AgentMessageAPI: SurfaceAgentMsg{Configured: true},
		StdioProxy:      SurfaceStdio{Configured: true},
	}
	got := computePosture(cfg, runtimeDBInspection{HasRecentHeartbeat: true}, auditDBInspection{Available: true}, surfaces)
	if got.SurfaceCounts.Protected != 0 {
		t.Fatalf("heartbeat alone must not mark any surface protected, got Protected=%d", got.SurfaceCounts.Protected)
	}
	if got.Overall == "protected" {
		t.Fatalf("overall posture must not be protected from heartbeat alone, got %q", got.Overall)
	}
}

func TestPosture_StaleRuntimeEventsAreObservedNotProtected(t *testing.T) {
	// Regression: a runtime_hook_events row in the window but
	// outside the freshness threshold counts as observed, not
	// protected. Without this distinction an install that ran one
	// real action 23h ago looks just as protected as one that
	// gated a tool call moments ago.
	cfg := minimalCfg()
	surfaces := SnapshotSurfaces{
		MCPGateway:      SurfaceGateway{Configured: true, Enabled: true},
		Hooks:           SurfaceHooks{Configured: true},
		EgressProxy:     SurfaceEgress{Configured: true, Enabled: true},
		AgentMessageAPI: SurfaceAgentMsg{Configured: true},
		StdioProxy:      SurfaceStdio{Configured: true},
	}
	rt := runtimeDBInspection{
		Available:         true,
		Events:            4, // in window, but stale (no HasFreshRealEvent)
		HasFreshRealEvent: false,
	}
	got := computePosture(cfg, rt, auditDBInspection{Available: true, Entries: 1}, surfaces)
	if got.SurfaceCounts.Protected != 0 {
		t.Fatalf("stale runtime events must not mark surfaces protected, got Protected=%d", got.SurfaceCounts.Protected)
	}
	if got.SurfaceCounts.Observed == 0 {
		t.Fatalf("stale runtime events must show up as observed, got %+v", got.SurfaceCounts)
	}
}

func TestPosture_FreshRealEventCanProtect(t *testing.T) {
	cfg := minimalCfg()
	surfaces := SnapshotSurfaces{
		MCPGateway:      SurfaceGateway{Configured: true, Enabled: true},
		Hooks:           SurfaceHooks{Configured: true, FreshRealEvent: true},
		EgressProxy:     SurfaceEgress{Configured: false},
		AgentMessageAPI: SurfaceAgentMsg{Configured: false},
		StdioProxy:      SurfaceStdio{Configured: false},
	}
	rt := runtimeDBInspection{Available: true, Events: 4, HasFreshRealEvent: true}
	got := computePosture(cfg, rt, auditDBInspection{Available: true, Entries: 5}, surfaces)
	if got.SurfaceCounts.Protected == 0 {
		t.Fatalf("fresh real evidence must support protected, got %+v", got.SurfaceCounts)
	}
	if got.Overall != "protected" {
		t.Fatalf("overall should be protected, got %q", got.Overall)
	}
}

func TestSnapshot_PostgresBackendSkipsSQLiteInspection(t *testing.T) {
	// Regression: a stale local SQLite file must not be counted as
	// Postgres audit evidence. Snapshot must emit
	// postgres_snapshot_limited and leave audit/runtime/activity
	// availability false even if the local DB exists and contains
	// rows.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")
	stalePath := filepath.Join(dir, "stale-local.db")
	seedAuditDB(t, stalePath, 5, 2)
	cfg := minimalCfg()
	cfg.DBBackend = "postgres"
	// DBPath here mimics a stale local SQLite the operator forgot
	// to delete after migrating to Postgres.
	cfg.DBPath = stalePath
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatalf("save: %v", err)
	}
	snap := buildAt(t, Options{ConfigPath: cfgPath, DBPath: stalePath})
	if !hasWarning(snap.Warnings, WarnPostgresSnapshotLimited) {
		t.Fatalf("expected postgres_snapshot_limited warning, got %#v", snap.Warnings)
	}
	if snap.Evidence.AuditAvailable || snap.Evidence.RuntimeAvailable || snap.Evidence.ActivityAvailable {
		t.Fatalf("postgres config must not surface stale SQLite evidence: %+v", snap.Evidence)
	}
	if snap.Evidence.AuditEntries != 0 || snap.Evidence.Decisions.Allowed != 0 || snap.Evidence.Decisions.Blocked != 0 {
		t.Fatalf("postgres config must report zero counts, got %+v", snap.Evidence)
	}
	if snap.Config.DBAvailable {
		t.Fatalf("db_available must be false for postgres in Order 1")
	}
}

func TestSnapshot_NeverMutatesConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")
	cfg := minimalCfg()
	cfg.DBPath = filepath.Join(dir, "oktsec.db")
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatalf("save: %v", err)
	}
	beforeBytes, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read before: %v", err)
	}
	_ = buildAt(t, Options{ConfigPath: cfgPath})
	afterBytes, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if string(beforeBytes) != string(afterBytes) {
		t.Fatalf("snapshot mutated oktsec.yaml")
	}
}

func TestSnapshot_OutputContainsNoSensitiveKeys(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")
	cfg := minimalCfg()
	cfg.Server.APIKey = "super-secret-api-key"
	cfg.LLM.APIKey = "sk-live-shouldnotleak"
	cfg.Identity.Principals = []config.PrincipalConfig{
		{ID: "p1", Tokens: []config.PrincipalTokenConfig{{ID: "t1", Hash: "sha256:abc:def"}}},
	}
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatalf("save: %v", err)
	}
	snap := buildAt(t, Options{ConfigPath: cfgPath})
	raw := requireJSON(t, snap)
	for _, banned := range []string{"super-secret-api-key", "sk-live-shouldnotleak", "sha256:abc:def"} {
		if strings.Contains(raw, banned) {
			t.Errorf("snapshot leaked %q", banned)
		}
	}
}

// minimalCfg returns a config that passes validation. Tests that need
// more keys mutate fields directly.
func minimalCfg() *config.Config {
	return &config.Config{
		Version:  "1",
		Identity: config.IdentityConfig{KeysDir: "/tmp/keys"},
		Server:   config.ServerConfig{Port: 8080, LogLevel: "info"},
	}
}

// seedAuditDB creates an audit_log table with the columns
// QueryChainEntries reads, then inserts the requested number of
// delivered + blocked rows with valid chain links. We don't use
// audit.NewStore because that would test the production batcher; for
// snapshot read-only inspection, a plain sql.DB is enough.
func seedAuditDB(t *testing.T, path string, delivered, blocked int) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`CREATE TABLE audit_log (
		id TEXT PRIMARY KEY,
		timestamp TEXT NOT NULL,
		from_agent TEXT NOT NULL,
		to_agent TEXT NOT NULL,
		content_hash TEXT NOT NULL,
		signature_verified INTEGER,
		pubkey_fingerprint TEXT,
		status TEXT NOT NULL,
		rules_triggered TEXT,
		policy_decision TEXT NOT NULL,
		latency_ms INTEGER,
		intent TEXT DEFAULT '',
		session_id TEXT DEFAULT '',
		tool_name TEXT DEFAULT '',
		prev_hash TEXT DEFAULT '',
		entry_hash TEXT DEFAULT '',
		proxy_signature TEXT DEFAULT ''
	)`); err != nil {
		t.Fatalf("create audit_log: %v", err)
	}
	insert := func(status, decision string, at time.Time, prev string) string {
		id := status + "-" + at.Format("150405")
		entryHash := "hash-" + id
		_, err := db.Exec(`INSERT INTO audit_log
			(id, timestamp, from_agent, to_agent, content_hash, status, rules_triggered, policy_decision, latency_ms, signature_verified, prev_hash, entry_hash)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, at.UTC().Format(time.RFC3339), "agent-a", "agent-b", "content", status, "[]", decision, 5, 1, prev, entryHash)
		if err != nil {
			t.Fatalf("insert %s: %v", status, err)
		}
		return entryHash
	}
	prev := ""
	base := time.Date(2026, 5, 21, 10, 0, 0, 0, time.UTC)
	for i := 0; i < delivered; i++ {
		prev = insert("delivered", "allow", base.Add(time.Duration(i)*time.Minute), prev)
	}
	for i := 0; i < blocked; i++ {
		prev = insert("blocked", "block", base.Add(time.Duration(delivered+i)*time.Minute), prev)
	}
}

func hasWarning(ws []Warning, code string) bool {
	for _, w := range ws {
		if w.Code == code {
			return true
		}
	}
	return false
}

// seedSignedAuditChain creates an audit_log table with three rows
// linked by valid prev_hash / entry_hash and signed with the
// provided proxy private key. Returns the entry IDs in chain order
// so a follow-up test can tamper with a specific row.
func seedSignedAuditChain(t *testing.T, path string, proxyPriv ed25519.PrivateKey) []string {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`CREATE TABLE audit_log (
		id TEXT PRIMARY KEY,
		timestamp TEXT NOT NULL,
		from_agent TEXT NOT NULL,
		to_agent TEXT NOT NULL,
		content_hash TEXT NOT NULL,
		signature_verified INTEGER,
		pubkey_fingerprint TEXT,
		status TEXT NOT NULL,
		rules_triggered TEXT,
		policy_decision TEXT NOT NULL,
		latency_ms INTEGER,
		intent TEXT DEFAULT '',
		session_id TEXT DEFAULT '',
		tool_name TEXT DEFAULT '',
		prev_hash TEXT DEFAULT '',
		entry_hash TEXT DEFAULT '',
		proxy_signature TEXT DEFAULT ''
	)`); err != nil {
		t.Fatalf("create audit_log: %v", err)
	}
	base := time.Date(2026, 5, 21, 10, 0, 0, 0, time.UTC)
	prev := ""
	ids := make([]string, 0, 3)
	for i, row := range []struct{ status, decision string }{
		{"delivered", "allow"},
		{"delivered", "allow"},
		{"blocked", "content_blocked"},
	} {
		id := "row-" + time.Duration(i).String()
		ts := base.Add(time.Duration(i) * time.Minute).Format(time.RFC3339)
		hash := audit.ComputeEntryHash(prev, id, ts, "agent-a", "agent-b", "content-hash", row.status, row.decision, "[]", 1)
		sig := audit.SignEntryHash(proxyPriv, hash)
		if _, err := db.Exec(`INSERT INTO audit_log
			(id, timestamp, from_agent, to_agent, content_hash, status, rules_triggered, policy_decision, latency_ms, signature_verified, prev_hash, entry_hash, proxy_signature)
			VALUES (?, ?, 'agent-a', 'agent-b', 'content-hash', ?, '[]', ?, 5, 1, ?, ?, ?)`,
			id, ts, row.status, row.decision, prev, hash, sig,
		); err != nil {
			t.Fatalf("insert chain row: %v", err)
		}
		prev = hash
		ids = append(ids, id)
	}
	return ids
}

// seedPartiallySignedChain creates an audit_log with three linked
// rows where only the first row carries a proxy_signature. Hashes
// are valid end-to-end so VerifyChain passes on the hash chain.
// Used to lock down the contract that audit_chain_signatures_checked
// must require FULL signature coverage, not "at least one".
func seedPartiallySignedChain(t *testing.T, path string, proxyPriv ed25519.PrivateKey) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`CREATE TABLE audit_log (
		id TEXT PRIMARY KEY,
		timestamp TEXT NOT NULL,
		from_agent TEXT NOT NULL,
		to_agent TEXT NOT NULL,
		content_hash TEXT NOT NULL,
		signature_verified INTEGER,
		pubkey_fingerprint TEXT,
		status TEXT NOT NULL,
		rules_triggered TEXT,
		policy_decision TEXT NOT NULL,
		latency_ms INTEGER,
		intent TEXT DEFAULT '',
		session_id TEXT DEFAULT '',
		tool_name TEXT DEFAULT '',
		prev_hash TEXT DEFAULT '',
		entry_hash TEXT DEFAULT '',
		proxy_signature TEXT DEFAULT ''
	)`); err != nil {
		t.Fatalf("create audit_log: %v", err)
	}
	base := time.Date(2026, 5, 21, 10, 0, 0, 0, time.UTC)
	prev := ""
	for i, row := range []struct {
		status, decision string
		signed           bool
	}{
		{"delivered", "allow", true},
		{"delivered", "allow", false},
		{"blocked", "content_blocked", false},
	} {
		id := "row-partial-" + time.Duration(i).String()
		ts := base.Add(time.Duration(i) * time.Minute).Format(time.RFC3339)
		hash := audit.ComputeEntryHash(prev, id, ts, "agent-a", "agent-b", "ch", row.status, row.decision, "[]", 1)
		sig := ""
		if row.signed {
			sig = audit.SignEntryHash(proxyPriv, hash)
		}
		if _, err := db.Exec(`INSERT INTO audit_log
			(id, timestamp, from_agent, to_agent, content_hash, status, rules_triggered, policy_decision, latency_ms, signature_verified, prev_hash, entry_hash, proxy_signature)
			VALUES (?, ?, 'agent-a', 'agent-b', 'ch', ?, '[]', ?, 5, 1, ?, ?, ?)`,
			id, ts, row.status, row.decision, prev, hash, sig,
		); err != nil {
			t.Fatalf("insert partial row: %v", err)
		}
		prev = hash
	}
}

// writeProxyKeys persists an Ed25519 keypair under keysDir/proxy.{pub,key}
// using the same PEM types internal/identity uses for proxy keys, so
// loadProxyPubKeyForSnapshot picks them up the same way the real
// product does.
func writeProxyKeys(t *testing.T, keysDir string) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatalf("mkdir keys: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate proxy: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "OKTSEC ED25519 PUBLIC KEY", Bytes: pub})
	if err := os.WriteFile(filepath.Join(keysDir, "proxy.pub"), pubPEM, 0o644); err != nil {
		t.Fatalf("write proxy.pub: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "OKTSEC ED25519 PRIVATE KEY", Bytes: priv})
	if err := os.WriteFile(filepath.Join(keysDir, "proxy.key"), privPEM, 0o600); err != nil {
		t.Fatalf("write proxy.key: %v", err)
	}
	return pub, priv
}

func TestSnapshot_VerifiesSignaturesWithCustomKeysDir(t *testing.T) {
	// Regression: if the operator configures identity.keys_dir,
	// the snapshot must verify proxy signatures against THAT key,
	// not whatever lives under the default ~/.oktsec/keys/. A
	// passing signature check is recorded as
	// audit_chain_signatures_checked=true + key fingerprint.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")
	customKeys := filepath.Join(dir, "custom-keys")
	_, priv := writeProxyKeys(t, customKeys)

	cfg := minimalCfg()
	cfg.Identity.KeysDir = customKeys
	cfg.DBPath = filepath.Join(dir, "oktsec.db")
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatalf("save cfg: %v", err)
	}
	seedSignedAuditChain(t, cfg.DBPath, priv)

	snap := buildAt(t, Options{
		ConfigPath: cfgPath,
		DBPath:     cfg.DBPath,
		Since:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if !snap.Evidence.AuditChainVerified {
		t.Fatalf("expected chain to verify, got %+v", snap.Evidence)
	}
	if !snap.Evidence.AuditChainSignaturesChecked {
		t.Fatalf("expected signatures to be checked against custom keys_dir, got %+v", snap.Evidence)
	}
	if snap.Evidence.AuditChainKeyFingerprint == "" {
		t.Fatalf("expected key fingerprint to be reported when signatures checked")
	}
	if hasWarning(snap.Warnings, WarnAuditChainSignaturesNotChecked) {
		t.Fatalf("must not warn about missing signatures when custom keys_dir provided")
	}
}

func TestSnapshot_TamperedSignatureWithCustomKeysDir(t *testing.T) {
	// Regression: tampering with proxy_signature on any chain row
	// must surface as audit_chain_verified=false when the
	// configured keys_dir is used to verify. Order 1 evidence must
	// not paper over a swapped/forged signature with hash-only
	// "valid" success.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")
	customKeys := filepath.Join(dir, "custom-keys")
	_, priv := writeProxyKeys(t, customKeys)

	cfg := minimalCfg()
	cfg.Identity.KeysDir = customKeys
	cfg.DBPath = filepath.Join(dir, "oktsec.db")
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatalf("save cfg: %v", err)
	}
	ids := seedSignedAuditChain(t, cfg.DBPath, priv)
	if len(ids) == 0 {
		t.Fatal("seed produced no rows")
	}
	// Replace the second row's signature with one produced by a
	// different key — the hash stays valid, but the signature
	// check must fail.
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen other: %v", err)
	}
	db, err := sql.Open("sqlite", cfg.DBPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	var entryHash string
	if err := db.QueryRow(`SELECT entry_hash FROM audit_log WHERE id = ?`, ids[1]).Scan(&entryHash); err != nil {
		t.Fatalf("read entry_hash: %v", err)
	}
	bogusSig := audit.SignEntryHash(otherPriv, entryHash)
	if _, err := db.Exec(`UPDATE audit_log SET proxy_signature = ? WHERE id = ?`, bogusSig, ids[1]); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	_ = db.Close()

	snap := buildAt(t, Options{
		ConfigPath: cfgPath,
		DBPath:     cfg.DBPath,
		Since:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if snap.Evidence.AuditChainVerified {
		t.Fatalf("tampered signature must cause audit_chain_verified=false")
	}
	// Under the strict contract, SignaturesChecked is a positive
	// claim — "every signature in scope verified". A failed
	// signature breaks that claim, so the field must be false.
	// The key fingerprint stays populated because the verifier did
	// load and use the configured key.
	if snap.Evidence.AuditChainSignaturesChecked {
		t.Fatalf("tampered signature must drop audit_chain_signatures_checked to false")
	}
	if snap.Evidence.AuditChainKeyFingerprint == "" {
		t.Fatalf("key fingerprint should still be reported even when verification failed")
	}
}

func TestSnapshot_HashOnlyWhenNoProxyKey(t *testing.T) {
	// Regression: no proxy.pub in identity.keys_dir => hash chain
	// alone is verified, AuditChainSignaturesChecked=false, and the
	// snapshot emits audit_chain_signatures_not_checked so consumers
	// do not mistake the result for full evidence.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")
	// Make the keys dir but DO NOT write proxy.pub there.
	customKeys := filepath.Join(dir, "custom-keys")
	if err := os.MkdirAll(customKeys, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cfg := minimalCfg()
	cfg.Identity.KeysDir = customKeys
	cfg.DBPath = filepath.Join(dir, "oktsec.db")
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatalf("save cfg: %v", err)
	}
	// Need a proxy key to seed valid signed rows for the hash chain
	// to be intact; the seeded signatures will not be checked
	// because the loader can't find the key.
	_, sigPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	seedSignedAuditChain(t, cfg.DBPath, sigPriv)

	snap := buildAt(t, Options{
		ConfigPath: cfgPath,
		DBPath:     cfg.DBPath,
		Since:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if !snap.Evidence.AuditChainVerified {
		t.Fatalf("hash chain alone should verify, got %+v", snap.Evidence)
	}
	if snap.Evidence.AuditChainSignaturesChecked {
		t.Fatalf("signatures must be reported NOT checked without a reachable proxy.pub")
	}
	if !hasWarning(snap.Warnings, WarnAuditChainSignaturesNotChecked) {
		t.Fatalf("expected audit_chain_signatures_not_checked warning, got %#v", snap.Warnings)
	}
}

func TestSnapshot_PartiallySignedChainDoesNotClaimSignaturesChecked(t *testing.T) {
	// Regression: a 3-row chain with one signed row and two
	// unsigned rows must NOT report audit_chain_signatures_checked.
	// audit.VerifyChain skips empty signatures, so without this
	// guard the field would report "signed" for a mostly-unsigned
	// range and overclaim evidence to a fleet report.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")
	customKeys := filepath.Join(dir, "custom-keys")
	_, priv := writeProxyKeys(t, customKeys)

	cfg := minimalCfg()
	cfg.Identity.KeysDir = customKeys
	cfg.DBPath = filepath.Join(dir, "oktsec.db")
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatalf("save: %v", err)
	}
	seedPartiallySignedChain(t, cfg.DBPath, priv)

	snap := buildAt(t, Options{
		ConfigPath: cfgPath,
		DBPath:     cfg.DBPath,
		Since:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if !snap.Evidence.AuditChainVerified {
		t.Fatalf("partial chain hash links must verify, got %+v", snap.Evidence)
	}
	if snap.Evidence.AuditChainSignaturesChecked {
		t.Fatalf("partial signature coverage must NOT set signatures_checked=true")
	}
	if !hasWarning(snap.Warnings, WarnAuditChainSignaturesPartial) {
		t.Fatalf("expected audit_chain_signatures_partial warning, got %#v", snap.Warnings)
	}
	if hasWarning(snap.Warnings, WarnAuditChainSignaturesNotChecked) {
		t.Fatalf("partial coverage must use the partial warning, not the no-key one")
	}
}

func TestSnapshot_AllUnsignedChainEmitsNotCheckedWarning(t *testing.T) {
	// Regression: a chain where every row is unsigned (e.g. legacy
	// data before proxy signing was enabled) must use the
	// "not_checked" warning code, not "partial". This keeps the
	// two failure modes cleanly separated for consumers.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")
	customKeys := filepath.Join(dir, "custom-keys")
	writeProxyKeys(t, customKeys) // key exists but rows are unsigned

	cfg := minimalCfg()
	cfg.Identity.KeysDir = customKeys
	cfg.DBPath = filepath.Join(dir, "oktsec.db")
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatalf("save: %v", err)
	}
	seedAuditDB(t, cfg.DBPath, 2, 1) // uses bogus hashes, no proxy_signature

	snap := buildAt(t, Options{
		ConfigPath: cfgPath,
		DBPath:     cfg.DBPath,
		Since:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if snap.Evidence.AuditChainSignaturesChecked {
		t.Fatalf("all-unsigned chain must NOT set signatures_checked=true")
	}
	if hasWarning(snap.Warnings, WarnAuditChainSignaturesPartial) {
		t.Fatalf("all-unsigned must not emit the partial-coverage warning")
	}
	if !hasWarning(snap.Warnings, WarnAuditChainSignaturesNotChecked) {
		t.Fatalf("expected audit_chain_signatures_not_checked for unsigned chain, got %#v", snap.Warnings)
	}
}

func TestSnapshot_CustomKeysDirMissingProxyDoesNotFallBackToDefault(t *testing.T) {
	// Regression: even if the default ~/.oktsec/keys/proxy.pub
	// exists on the developer's machine, a config with a custom
	// identity.keys_dir that lacks proxy.pub must NOT silently
	// substitute the default key — that would make the snapshot
	// claim integrity using an unrelated key.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oktsec.yaml")
	customKeys := filepath.Join(dir, "custom-keys")
	if err := os.MkdirAll(customKeys, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cfg := minimalCfg()
	cfg.Identity.KeysDir = customKeys
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatalf("save: %v", err)
	}
	pub, _ := loadProxyPubKeyForSnapshot(customKeys)
	if pub != nil {
		t.Fatalf("custom keys_dir without proxy.pub must return nil, got %x", pub)
	}
}
