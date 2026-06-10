package node

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/safefile"
)

// Options controls SnapshotBuilder.Build. All fields are optional;
// zero values fall back to sensible defaults.
type Options struct {
	// ConfigPath is the path to oktsec.yaml. Empty means "use
	// config.ResolveConfigPath with no flag".
	ConfigPath string

	// DBPath overrides the resolved audit-database path. When
	// empty, the snapshot uses cfg.DBPath if available and falls
	// back to config.DefaultDBPath. Tests pin this so the snapshot
	// never reaches the operator's real ~/.oktsec/oktsec.db.
	DBPath string

	// IdentityStore is the node identity store to consult. Zero
	// value uses DefaultIdentityStore.
	IdentityStore IdentityStore

	// Since/Until define the snapshot range. Zero Since defaults
	// to 24h ago; zero Until means "now".
	Since time.Time
	Until time.Time

	// IncludeDiscovery requests MCP client discovery in the
	// inventory. Order 1 ignores this flag and emits a
	// client_discovery_not_included warning instead.
	IncludeDiscovery bool

	// PolicyBundlePath points at a local signed policy bundle the
	// operator copied onto the node. When set, Order 4B reports its
	// declared policy_hash in the snapshot's policy block. Empty
	// means "no locally-declared active policy" (policy_status none).
	PolicyBundlePath string

	// PolicyTrustFingerprint is the operator-configured policy signing
	// key fingerprint (sha256:<hex>) the node verifies a bundle's
	// signature against (Order 4C.1). Empty means the node reports the
	// bundle but cannot claim it is verified (no_trust_anchor).
	PolicyTrustFingerprint string

	// OktsecVersion / OktsecCommit override the version stamped
	// into the snapshot. CLI fills these from version.go; tests
	// pin them so golden output stays deterministic.
	OktsecVersion string
	OktsecCommit  string

	// Now overrides time.Now for the GeneratedAt field. Used by
	// tests; production callers leave it zero.
	Now time.Time
}

// chainScanLimit caps the number of chain entries the snapshot
// reads. Verification runs over a bounded window so a 50M-row audit
// log cannot stall a snapshot.
const chainScanLimit = 5000

// defaultSince is the default range floor when Options.Since is zero.
const defaultSince = 24 * time.Hour

// Build assembles the full Snapshot. It is read-only by construction:
// no DB is created, no migrations run, and no external client is
// queried. Partial state is reported via warnings.
func Build(ctx context.Context, opts Options) (Snapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	since := opts.Since
	if since.IsZero() {
		since = now.Add(-defaultSince)
	}
	until := opts.Until
	if !until.IsZero() {
		until = until.UTC()
	}

	snap := Snapshot{
		SchemaVersion: SchemaSnapshot,
		GeneratedAt:   now.UTC().Format(time.RFC3339),
		Range: SnapshotRange{
			Since: since.UTC().Format(time.RFC3339),
		},
		Node: SnapshotNode{
			IdentityStatus: "missing",
			GOOS:           runtime.GOOS,
			GOARCH:         runtime.GOARCH,
			OktsecVersion:  opts.OktsecVersion,
			Commit:         opts.OktsecCommit,
			Profile:        ProfileLocal,
		},
		Config: SnapshotConfig{Status: "missing"},
		Inventory: SnapshotInventory{
			Agents:     []InventoryAgent{},
			Principals: []InventoryPrincipal{},
			MCPServers: []InventoryMCPServer{},
			Tools:      []InventoryTool{},
			Clients:    []InventoryClient{},
		},
	}
	if !until.IsZero() {
		snap.Range.Until = until.Format(time.RFC3339)
	}

	idStore := opts.IdentityStore
	if idStore.Dir == "" {
		idStore = DefaultIdentityStore()
	}
	idStatus := idStore.Status()
	snap.Node.IdentityStatus = idStatus.Status
	if idStatus.Identity != nil {
		snap.Node.NodeID = idStatus.Identity.NodeID
		snap.Node.HostFingerprint = idStatus.Identity.HostFingerprint
		snap.Node.PublicKeyFingerprint = idStatus.Identity.PublicKeyFingerprint
		if idStatus.Identity.InstallProfile != "" {
			snap.Node.Profile = idStatus.Identity.InstallProfile
		}
	}
	snap.Warnings = append(snap.Warnings, idStatus.Warnings...)

	cfg, cfgPath, cfgWarnings := loadConfigForSnapshot(opts.ConfigPath)
	snap.Warnings = append(snap.Warnings, cfgWarnings...)
	populateConfigSection(&snap, cfg, cfgPath)
	populateSurfacesSection(&snap, cfg)
	populateInventorySection(&snap, cfg, opts.IncludeDiscovery)

	// Policy reporting (Order 4B) is independent of the audit DB, so
	// populate it before any DB-dependent early return below — the
	// block must appear on every snapshot a 4B+ node emits.
	policySec, policyWarnings := buildPolicySection(opts.PolicyBundlePath, opts.PolicyTrustFingerprint)
	snap.Policy = policySec
	snap.Warnings = append(snap.Warnings, policyWarnings...)

	// Postgres-backed installs must not be inspected as if they
	// were SQLite — that would silently report stale ~/.oktsec/oktsec.db
	// contents (or any leftover from a prior local run) as the
	// authoritative audit evidence and ship false positives to a
	// future fleet report. Order 1 emits a structured warning and
	// stops short of opening any DB handle.
	if cfg != nil && strings.EqualFold(cfg.DBBackend, "postgres") {
		snap.Config.DBAvailable = false
		snap.Warnings = append(snap.Warnings, Warning{
			Code:    WarnPostgresSnapshotLimited,
			Message: "Postgres-backed installs are not inspected in Order 1; audit/runtime/activity counts are omitted.",
		})
		snap.Posture = computePosture(cfg, runtimeDBInspection{}, auditDBInspection{}, snap.Surfaces)
		return snap, nil
	}

	dbPath := opts.DBPath
	if dbPath == "" {
		dbPath = resolveSnapshotDBPath(cfg)
	}
	avail := inspectSQLiteAvailability(dbPath)
	snap.Config.DBAvailable = avail.Available
	if !avail.Available {
		switch avail.Reason {
		case "missing":
			snap.Warnings = append(snap.Warnings, Warning{
				Code:    WarnDBMissing,
				Message: "Audit database has not been created yet.",
			})
		default:
			snap.Warnings = append(snap.Warnings, Warning{
				Code:    WarnDBUnreachable,
				Message: "Audit database is not safe to open read-only.",
			})
		}
		snap.Posture = computePosture(cfg, runtimeDBInspection{}, auditDBInspection{}, snap.Surfaces)
		return snap, nil
	}

	db, err := openSQLiteReadOnly(dbPath)
	if err != nil {
		snap.Warnings = append(snap.Warnings, Warning{
			Code:    WarnDBUnreachable,
			Message: "Could not open audit database read-only: " + err.Error(),
		})
		snap.Config.DBAvailable = false
		snap.Posture = computePosture(cfg, runtimeDBInspection{}, auditDBInspection{}, snap.Surfaces)
		return snap, nil
	}
	defer func() { _ = db.Close() }()

	auditInfo, err := inspectAuditSQLite(ctx, db, since, until, chainScanLimit)
	if err != nil {
		snap.Warnings = append(snap.Warnings, Warning{
			Code:    WarnAuditTableMissing,
			Message: err.Error(),
		})
	} else if !auditInfo.Available {
		snap.Warnings = append(snap.Warnings, Warning{
			Code:    WarnAuditTableMissing,
			Message: "audit_log table is not present.",
		})
	}
	runtimeInfo, err := inspectRuntimeSQLite(ctx, db, since, until)
	if err != nil {
		snap.Warnings = append(snap.Warnings, Warning{
			Code:    WarnRuntimeTableMissing,
			Message: err.Error(),
		})
	} else if !runtimeInfo.Available {
		snap.Warnings = append(snap.Warnings, Warning{
			Code:    WarnRuntimeTableMissing,
			Message: "runtime_* tables are not present.",
		})
	}
	activityInfo, err := inspectActivitySQLite(ctx, db, since, until)
	if err != nil {
		snap.Warnings = append(snap.Warnings, Warning{
			Code:    WarnActivityTableMissing,
			Message: err.Error(),
		})
	} else if !activityInfo.Available {
		snap.Warnings = append(snap.Warnings, Warning{
			Code:    WarnActivityTableMissing,
			Message: "activity_events table is not present.",
		})
	}

	chain := verifyAuditChainBounded(ctx, db, auditInfo.Available, chainScanLimit, configuredKeysDir(cfg))
	if !chain.Available && auditInfo.Available {
		snap.Warnings = append(snap.Warnings, Warning{
			Code:    WarnAuditChainUnavailable,
			Message: chain.Reason,
		})
	}
	if auditInfo.Available && auditInfo.Entries > 0 && !chain.SignaturesChecked {
		// Two distinct failure modes that both end at
		// SignaturesChecked=false:
		//
		//   partial coverage: at least one row carries a
		//   signature, but the scope also contains unsigned rows.
		//   Calling this "signed" would overclaim — compliance
		//   evidence needs a separate code so the consumer can
		//   distinguish "no key reachable" from "mixed coverage".
		//
		//   no signed evidence: either proxy.pub could not be
		//   located or every row in scope is unsigned. Either
		//   way the snapshot only proved hashes.
		//
		// The chain may still have failed for a non-signature
		// reason (broken hash link); audit_chain_verified is the
		// definitive overall result and consumers must read it
		// alongside this warning.
		if chain.SignedEntries > 0 && chain.UnsignedEntries > 0 {
			snap.Warnings = append(snap.Warnings, Warning{
				Code:    WarnAuditChainSignaturesPartial,
				Message: "Some audit entries in scope carry proxy signatures and others do not; full-range Ed25519 verification NOT proven. See audit_chain_verified for the hash/overall result.",
			})
		} else {
			snap.Warnings = append(snap.Warnings, Warning{
				Code:    WarnAuditChainSignaturesNotChecked,
				Message: "Ed25519 proxy signatures were NOT verified (no reachable proxy public key or no signed entries in scope). See audit_chain_verified for the hash/overall result.",
			})
		}
	}

	activePrincipals, err := distinctActivePrincipalsSQLite(ctx, db, since, until)
	if err != nil {
		activePrincipals = 0
	}

	snap.Evidence = SnapshotEvidence{
		AuditAvailable:              auditInfo.Available,
		AuditEntries:                auditInfo.Entries,
		AuditChainHead:              chain.Head,
		AuditChainVerified:          chain.Verified,
		AuditChainVerificationScope: chain.Scope,
		AuditChainSignaturesChecked: chain.SignaturesChecked,
		AuditChainKeyFingerprint:    chain.KeyFingerprint,
		AuditOldestAt:               auditInfo.OldestAt,
		AuditNewestAt:               auditInfo.NewestAt,
		RuntimeAvailable:            runtimeInfo.Available,
		RuntimeSessions:             runtimeInfo.Sessions,
		RuntimeEvents:               runtimeInfo.Events,
		RuntimeToolEvents:           runtimeInfo.ToolEvents,
		ActivityAvailable:           activityInfo.Available,
		ActivityEvents:              activityInfo.Events,
		Decisions: DecisionCounts{
			Allowed:     auditInfo.Allowed,
			Flagged:     auditInfo.Flagged,
			Quarantined: auditInfo.Quarantined,
			Blocked:     auditInfo.Blocked,
			Rejected:    auditInfo.Rejected,
		},
	}

	// Wire hook-surface freshness from runtime info into the
	// surfaces section now that the DB has been inspected.
	snap.Surfaces.Hooks.FreshRealEvent = runtimeInfo.HasFreshRealEvent
	snap.Surfaces.Hooks.HeartbeatRecent = runtimeInfo.HasRecentHeartbeat

	snap.Posture = computePosture(cfg, runtimeInfo, auditInfo, snap.Surfaces)
	snap.Posture.RuntimeSessions = runtimeInfo.Sessions
	snap.Posture.ActivePrincipals = activePrincipals
	snap.Posture.BlockedActions = auditInfo.Blocked
	snap.Posture.QuarantinedActions = auditInfo.Quarantined

	return snap, nil
}

// loadConfigForSnapshot resolves the config path (falling back to the
// default resolver) and loads the file. Failures are turned into
// warnings rather than fatal errors so a missing config still emits a
// usable snapshot.
func loadConfigForSnapshot(explicit string) (*config.Config, string, []Warning) {
	path := explicit
	if path == "" {
		path, _ = config.ResolveConfigPath("", false)
	}
	if path == "" {
		return nil, "", []Warning{{Code: WarnConfigMissing, Message: "No config path could be resolved."}}
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, path, []Warning{{Code: WarnConfigMissing, Message: "Config file does not exist: " + PathTail(path)}}
		}
		return nil, path, []Warning{{Code: WarnConfigInvalid, Message: "Could not stat config: " + err.Error()}}
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, path, []Warning{{Code: WarnConfigInvalid, Message: "Config did not load: " + err.Error()}}
	}
	return cfg, path, nil
}

// populateConfigSection fills snap.Config from the loaded config.
// path may be set even when cfg is nil (e.g. parse failure or
// not-yet-created file). Status disambiguates the two: a path that
// does not exist on disk is "missing"; a path whose contents could
// not be parsed is "invalid".
func populateConfigSection(snap *Snapshot, cfg *config.Config, path string) {
	if cfg == nil {
		if path != "" {
			snap.Config.PathTail = PathTail(path)
			snap.Config.PathHash = PathHash(path)
			if _, err := os.Stat(path); err == nil {
				snap.Config.Status = "invalid"
				snap.Config.ConfigHash = hashFileBytes(path)
			} else {
				snap.Config.Status = "missing"
			}
		}
		return
	}
	snap.Config.Status = "present"
	snap.Config.PathTail = PathTail(path)
	snap.Config.PathHash = PathHash(path)
	snap.Config.ConfigHash = hashFileBytes(path)
	snap.Config.DefaultPolicy = cfg.DefaultPolicy
	if snap.Config.DefaultPolicy == "" {
		snap.Config.DefaultPolicy = "allow"
	}
	snap.Config.SignatureRequired = cfg.Identity.RequireSignature
	snap.Config.DelegationRequired = cfg.Identity.RequireDelegation
	snap.Config.DBBackend = cfg.DBBackend
	if snap.Config.DBBackend == "" {
		snap.Config.DBBackend = "sqlite"
	}
	if cfg.Deployment.Profile != "" {
		snap.Node.Profile = cfg.Deployment.Profile
	}
}

// populateSurfacesSection derives configured/enabled booleans from
// cfg. Runtime freshness (FreshRealEvent, HeartbeatRecent) is added
// later once the DB has been inspected.
func populateSurfacesSection(snap *Snapshot, cfg *config.Config) {
	if cfg == nil {
		return
	}
	snap.Surfaces.MCPGateway = SurfaceGateway{
		Configured:    cfg.Gateway.Port != 0 || cfg.Gateway.Enabled || len(cfg.MCPServers) > 0,
		Enabled:       cfg.Gateway.Enabled,
		AuthRequired:  requireAuthBool(cfg.Gateway.SurfaceAuthConfig, cfg.Deployment.Profile),
		BackendCount:  len(cfg.MCPServers),
		ScanResponses: cfg.Gateway.ScanResponses,
	}
	snap.Surfaces.StdioProxy = SurfaceStdio{
		Configured: len(cfg.MCPServers) > 0,
		Source:     "config_only",
	}
	snap.Surfaces.Hooks = SurfaceHooks{
		Configured:   true, // hooks endpoint is always wired when oktsec runs
		AuthRequired: requireAuthBool(cfg.Hooks.SurfaceAuthConfig, cfg.Deployment.Profile),
	}
	snap.Surfaces.EgressProxy = SurfaceEgress{
		Configured:         cfg.ForwardProxy.Port != 0 || cfg.ForwardProxy.Enabled,
		Enabled:            cfg.ForwardProxy.Enabled,
		AuthRequired:       requireAuthBool(cfg.ForwardProxy.SurfaceAuthConfig, cfg.Deployment.Profile),
		AllowedDomainCount: len(cfg.ForwardProxy.AllowedDomains),
		BlockedDomainCount: len(cfg.ForwardProxy.BlockedDomains),
	}
	snap.Surfaces.AgentMessageAPI = SurfaceAgentMsg{
		Configured:         len(cfg.Agents) > 0 || cfg.Server.Port != 0,
		SignatureRequired:  cfg.Identity.RequireSignature,
		DelegationRequired: cfg.Identity.RequireDelegation,
	}
}

// requireAuthBool resolves the surface auth knob to a concrete bool
// for snapshot reporting. "auto" follows the deployment profile.
func requireAuthBool(s config.SurfaceAuthConfig, profile string) bool {
	switch strings.ToLower(s.RequireAuth) {
	case "true":
		return true
	case "false":
		return false
	default:
		return strings.ToLower(profile) == ProfileEnterprise
	}
}

// populateInventorySection fills the inventory arrays from cfg. All
// arrays are returned sorted so two snapshots diff cleanly.
func populateInventorySection(snap *Snapshot, cfg *config.Config, includeDiscovery bool) {
	if cfg == nil {
		return
	}
	for name, agent := range cfg.Agents {
		ia := InventoryAgent{
			ID:        name,
			Suspended: agent.Suspended,
		}
		if len(agent.Tags) > 0 {
			ia.Tags = append([]string(nil), agent.Tags...)
			sort.Strings(ia.Tags)
		}
		snap.Inventory.Agents = append(snap.Inventory.Agents, ia)
	}
	sort.Slice(snap.Inventory.Agents, func(i, j int) bool {
		return snap.Inventory.Agents[i].ID < snap.Inventory.Agents[j].ID
	})

	for _, p := range cfg.Identity.Principals {
		ip := InventoryPrincipal{
			ID:              p.ID,
			Kind:            p.Kind,
			WorkspaceIDHash: HashString(p.WorkspaceID),
			Surfaces:        append([]string(nil), p.AllowedSurfaces...),
		}
		sort.Strings(ip.Surfaces)
		snap.Inventory.Principals = append(snap.Inventory.Principals, ip)
	}
	sort.Slice(snap.Inventory.Principals, func(i, j int) bool {
		return snap.Inventory.Principals[i].ID < snap.Inventory.Principals[j].ID
	})

	for name, server := range cfg.MCPServers {
		snap.Inventory.MCPServers = append(snap.Inventory.MCPServers, RedactMCPServerConfig(name, server))
	}
	sort.Slice(snap.Inventory.MCPServers, func(i, j int) bool {
		return snap.Inventory.MCPServers[i].Name < snap.Inventory.MCPServers[j].Name
	})

	// Tools and Clients are runtime-derived; Order 1 keeps them as
	// empty arrays plus a warning when discovery was requested.
	if includeDiscovery {
		snap.Warnings = append(snap.Warnings, Warning{
			Code:    WarnClientDiscoveryNotIncluded,
			Message: "Client discovery is not included in this Oktsec version's node snapshot.",
		})
	}
}

// chainResult is the bounded chain verification result wired into
// SnapshotEvidence.
//
//	Available           false => "we did not run the verifier"
//	                    (table missing, query error, etc).
//	Verified            overall pass under available checks
//	                    (hash chain links AND any signature that
//	                    was checked).
//	SignaturesChecked   STRICT: true only when every entry in the
//	                    verified scope had a proxy_signature and
//	                    every signature verified against the
//	                    configured key. Mixed signed/unsigned
//	                    coverage leaves this false.
//	SignedEntries /     diagnostic counters for the partial-coverage
//	  UnsignedEntries   warning path; consumers can derive coverage
//	                    ratio without re-querying audit_log.
type chainResult struct {
	Available         bool
	Verified          bool
	SignaturesChecked bool
	SignedEntries     int
	UnsignedEntries   int
	KeyFingerprint    string
	Head              string
	Scope             string
	Reason            string
}

// verifyAuditChainBounded reads up to limit chain rows and runs
// audit.VerifyChain. The proxy public key is loaded from the
// keysDir argument (the operator's configured identity.keys_dir,
// not the default) so a custom-keys deployment is verified against
// the actual signing key. If no key is locatable, the chain hash
// portion is still verified and SignaturesChecked is reported as
// false.
func verifyAuditChainBounded(ctx context.Context, db *sql.DB, auditAvailable bool, limit int, keysDir string) chainResult {
	if !auditAvailable {
		return chainResult{Reason: "audit_log table is not present"}
	}
	rows, err := db.QueryContext(ctx,
		`SELECT id, timestamp, from_agent, to_agent, content_hash, status,
		 COALESCE(policy_decision,''), COALESCE(rules_triggered,''), COALESCE(signature_verified,0),
		 COALESCE(prev_hash,''), COALESCE(entry_hash,''), COALESCE(proxy_signature,'')
		 FROM audit_log WHERE entry_hash != '' ORDER BY timestamp ASC LIMIT ?`, limit,
	)
	if err != nil {
		return chainResult{Reason: "chain query failed: " + err.Error()}
	}
	defer func() { _ = rows.Close() }()

	var entries []audit.ChainEntry
	for rows.Next() {
		var ce audit.ChainEntry
		if err := rows.Scan(&ce.ID, &ce.Timestamp, &ce.FromAgent, &ce.ToAgent,
			&ce.ContentHash, &ce.Status,
			&ce.PolicyDecision, &ce.RulesTriggered, &ce.SignatureVerified,
			&ce.PrevHash, &ce.EntryHash, &ce.ProxySignature); err != nil {
			return chainResult{Reason: "chain scan failed: " + err.Error()}
		}
		entries = append(entries, ce)
	}
	if err := rows.Err(); err != nil {
		return chainResult{Reason: "chain rows err: " + err.Error()}
	}
	if len(entries) == 0 {
		return chainResult{Available: true, Verified: true, Scope: "empty"}
	}

	proxyPub, keyFP := loadProxyPubKeyForSnapshot(keysDir)
	res := audit.VerifyChain(entries, proxyPub)
	scope := "bounded"
	if len(entries) < limit {
		scope = "all"
	}

	// Count signed vs unsigned entries so the strict
	// SignaturesChecked claim only fires when the full scope is
	// covered. audit.VerifyChain only verifies non-empty
	// proxy_signature values; a chain of 5000 rows with one
	// signature would otherwise let consumers misread the result
	// as "the range was signed".
	var signed, unsigned int
	for _, e := range entries {
		if e.ProxySignature != "" {
			signed++
		} else {
			unsigned++
		}
	}
	sigChecked := proxyPub != nil && unsigned == 0 && signed > 0 && res.Valid

	return chainResult{
		Available:         true,
		Verified:          res.Valid,
		SignaturesChecked: sigChecked,
		SignedEntries:     signed,
		UnsignedEntries:   unsigned,
		KeyFingerprint:    keyFP,
		Head:              entries[len(entries)-1].EntryHash,
		Scope:             scope,
	}
}

// loadProxyPubKeyForSnapshot reads proxy.pub from keysDir first and
// falls back to config.DefaultKeysDir only if keysDir is empty or
// the configured file does not exist. Returns nil + "" when no key
// is reachable so chain verification proceeds hash-only.
//
// Falling back to the default keys dir when keysDir was specified
// but missing the proxy key would let a misconfigured node silently
// verify against the wrong key, so that path explicitly errors out
// (returns nil + "") instead of substituting the default.
func loadProxyPubKeyForSnapshot(keysDir string) (ed25519.PublicKey, string) {
	candidates := []string{}
	switch keysDir {
	case "":
		candidates = append(candidates, filepath.Join(config.DefaultKeysDir(), "proxy.pub"))
	default:
		// Only look at the configured location. Refusing to fall
		// back is intentional: a custom keys_dir without proxy.pub
		// is a misconfiguration, not a license to verify against
		// some unrelated default-dir key.
		candidates = append(candidates, filepath.Join(keysDir, "proxy.pub"))
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err != nil {
			continue
		}
		data, err := safefile.ReadFileMax(candidate, maxKeyBytes)
		if err != nil {
			continue
		}
		pub, ok := parseEd25519PublicKeyPEM(data)
		if !ok {
			continue
		}
		return pub, fingerprintPublicKey(pub)
	}
	return nil, ""
}

// configuredKeysDir returns the operator-configured identity.keys_dir
// (empty string when no config is present, which signals the default
// keys dir to loadProxyPubKeyForSnapshot).
func configuredKeysDir(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	return cfg.Identity.KeysDir
}

// resolveSnapshotDBPath mirrors the CLI's defaultDBPath logic but
// without consulting cfgFile (we already loaded the config above).
func resolveSnapshotDBPath(cfg *config.Config) string {
	if cfg != nil && cfg.DBPath != "" {
		return cfg.DBPath
	}
	return config.DefaultDBPath()
}

// hashFileBytes reads up to 1MB of path and returns "sha256:<hex>".
// Returns "" on any failure (used for diagnostic-only ConfigHash).
func hashFileBytes(path string) string {
	data, err := safefile.ReadFileMax(path, 1<<20)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// computePosture turns the surfaces / runtime / audit observations
// into the dashboard coverage vocabulary. The logic is conservative:
// only call a surface protected when we have concrete *real* runtime
// evidence within the snapshot window. Heartbeats are diagnostic
// only — they prove the hook ingestion endpoint is reachable but do
// not prove a single real action was inspected. Treating them as
// protection would let an idle install masquerade as locked down.
// Each configured surface is counted exactly once across protected
// / observed / blind / stale; surfaces that are not configured go
// to NotConfigured.
func computePosture(cfg *config.Config, rt runtimeDBInspection, aud auditDBInspection, sf SnapshotSurfaces) SnapshotPosture {
	labels := []string{
		classifySurfaceCoverage(sf.MCPGateway.Configured, sf.MCPGateway.Enabled, rt.HasFreshRealEvent, rt.Events > 0 || aud.Entries > 0),
		classifySurfaceCoverage(sf.Hooks.Configured, true, sf.Hooks.FreshRealEvent, sf.Hooks.HeartbeatRecent || rt.Events > 0),
		classifySurfaceCoverage(sf.EgressProxy.Configured, sf.EgressProxy.Enabled, false, aud.Entries > 0),
		classifySurfaceCoverage(sf.AgentMessageAPI.Configured, true, false, aud.Entries > 0),
		classifySurfaceCoverage(sf.StdioProxy.Configured, false, false, aud.Entries > 0),
	}
	var counts PostureCounts
	for _, c := range labels {
		switch c {
		case "protected":
			counts.Protected++
		case "observed":
			counts.Observed++
		case "blind":
			counts.Blind++
		case "stale":
			counts.Stale++
		case "not_configured":
			counts.NotConfigured++
		}
	}

	overall := "blind"
	switch {
	case cfg == nil:
		overall = "setup_pending"
	case counts.Protected > 0:
		overall = "protected"
	case counts.Observed > 0:
		overall = "observing"
	case counts.Blind > 0 || counts.NotConfigured > 0:
		overall = "blind"
	}
	if !aud.Available && cfg != nil && counts.Protected == 0 && counts.Observed == 0 {
		overall = "blind"
	}
	return SnapshotPosture{
		Overall:       overall,
		SurfaceCounts: counts,
	}
}

// classifySurfaceCoverage returns a coverage label for a single
// surface from a few cheap signals.
//
//	configured = surface is wired up in oktsec.yaml
//	enabled    = surface is on (gateway.enabled, forward_proxy.enabled, etc.)
//	freshReal  = a real action was observed in the snapshot window
//	             — heartbeats and keepalives do NOT count
//	observed   = any diagnostic evidence (heartbeat, audit row,
//	             post-action telemetry) was seen in the window
//
// Only freshReal AND enabled can produce "protected"; anything weaker
// is at most "observed" so an idle install never overclaims.
func classifySurfaceCoverage(configured, enabled, freshReal, observed bool) string {
	if !configured {
		return "not_configured"
	}
	if freshReal && enabled {
		return "protected"
	}
	if observed {
		return "observed"
	}
	return "blind"
}

// parseEd25519PublicKeyPEM decodes a PEM-wrapped Ed25519 public key
// (32 raw bytes) and returns it along with an ok flag. Accepts any
// PEM type so the proxy key file produced by either internal/identity
// or older fixtures is readable; raw-binary fallback covers test data.
func parseEd25519PublicKeyPEM(data []byte) (ed25519.PublicKey, bool) {
	if block, _ := pem.Decode(data); block != nil {
		if len(block.Bytes) == ed25519.PublicKeySize {
			return ed25519.PublicKey(append([]byte(nil), block.Bytes...)), true
		}
	}
	if len(data) == ed25519.PublicKeySize {
		return ed25519.PublicKey(append([]byte(nil), data...)), true
	}
	return nil, false
}

// MarshalSnapshot is a small helper so callers don't repeat the
// indented json.Marshal dance.
func MarshalSnapshot(s Snapshot) ([]byte, error) {
	buf, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal snapshot: %w", err)
	}
	return append(buf, '\n'), nil
}
