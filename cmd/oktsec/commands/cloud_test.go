package commands

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oktsec/oktsec/internal/node"
)

// runCloud executes `oktsec cloud <args...>` through the real root
// command, returning combined stdout and the error.
func runCloud(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := NewRoot()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"cloud"}, args...))
	err := root.Execute()
	return out.String(), err
}

// withLocalCloudDialer lets the SSRF-guarded client reach a local
// httptest server (which the guard would otherwise correctly refuse).
func withLocalCloudDialer(t *testing.T) {
	t.Helper()
	prev := cloudDialContext
	cloudDialContext = (&net.Dialer{}).DialContext
	t.Cleanup(func() { cloudDialContext = prev })
	// httptest serves plain http; the product default refuses it.
	t.Setenv("OKTSEC_CLOUD_INSECURE_HTTP", "1")
}

// fakeCloud is a minimal Cloud: register issues a token once, evidence
// accepts signed envelopes.
func fakeCloud(t *testing.T) (*httptest.Server, *struct {
	Registers, Evidence int
	LastEvidence        map[string]any
}) {
	t.Helper()
	state := &struct {
		Registers, Evidence int
		LastEvidence        map[string]any
	}{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/node/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer enroll-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		state.Registers++
		w.Header().Set("Content-Type", "application/json")
		if state.Registers == 1 {
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token": "node-token-secret", "pinned": true,
				"trust_fingerprint": "sha256:" + strings.Repeat("ab", 32),
			})
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"pinned": true})
	})
	mux.HandleFunc("POST /v1/evidence/envelope", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer node-token-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var env map[string]any
		_ = json.NewDecoder(r.Body).Decode(&env)
		state.Evidence++
		state.LastEvidence = env
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "accepted_signed"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, state
}

func TestCloudEnrollPersistsStateAndIsIdempotent(t *testing.T) {
	store := withTestNodeStore(t)
	if _, err := store.Init("dev"); err != nil {
		t.Fatal(err)
	}
	withLocalCloudDialer(t)
	srv, state := fakeCloud(t)

	out, err := runCloud(t, "enroll", "--url", srv.URL, "--token", "enroll-secret")
	if err != nil {
		t.Fatalf("enroll: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Enrolled node node_") {
		t.Fatalf("enroll output: %s", out)
	}
	if strings.Contains(out, "node-token-secret") || strings.Contains(out, "enroll-secret") {
		t.Fatal("enroll output must never contain secrets")
	}

	// State files exist with owner-only permissions.
	for _, p := range []string{filepath.Join(store.Dir, "cloud.json"), filepath.Join(store.Dir, "cloud-token")} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("missing %s: %v", p, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s permissions = %v, want 0600", p, info.Mode().Perm())
		}
	}
	st, err := store.LoadCloudState()
	if err != nil {
		t.Fatal(err)
	}
	if st.TrustFingerprint != "sha256:"+strings.Repeat("ab", 32) {
		t.Fatalf("trust fingerprint not taken from Cloud's answer: %q", st.TrustFingerprint)
	}

	// Re-enroll: idempotent (server answers 200, no new token), token kept.
	if _, err := runCloud(t, "enroll", "--url", srv.URL, "--token", "enroll-secret"); err != nil {
		t.Fatalf("re-enroll: %v", err)
	}
	if tok, err := store.LoadCloudToken(); err != nil || tok != "node-token-secret" {
		t.Fatalf("token must survive re-enroll: %q %v", tok, err)
	}
	if state.Registers != 2 {
		t.Fatalf("registers = %d", state.Registers)
	}

	// Re-enroll WITHOUT flags must not wipe previously stored pull
	// settings (flags > response > existing state).
	st2, _ := store.LoadCloudState()
	st2.PullURL = "https://cloud.example.com/pull/o/f/cap/"
	if err := store.SaveCloudState(st2); err != nil {
		t.Fatal(err)
	}
	if _, err := runCloud(t, "enroll", "--url", srv.URL, "--token", "enroll-secret"); err != nil {
		t.Fatalf("third enroll: %v", err)
	}
	st3, _ := store.LoadCloudState()
	if st3.PullURL != st2.PullURL || st3.TrustFingerprint == "" {
		t.Fatalf("re-enroll wiped pull state: %+v", st3)
	}
}

func TestCloudEnrollRefusesPlaintextHTTP(t *testing.T) {
	store := withTestNodeStore(t)
	if _, err := store.Init("dev"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OKTSEC_CLOUD_INSECURE_HTTP", "0")
	_, err := runCloud(t, "enroll", "--url", "http://cloud.example.com", "--token", "x")
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("plaintext URL must be refused: %v", err)
	}
}

func TestCloudSyncOnceReportsEvidence(t *testing.T) {
	store := withTestNodeStore(t)
	if _, err := store.Init("dev"); err != nil {
		t.Fatal(err)
	}
	withLocalCloudDialer(t)
	srv, state := fakeCloud(t)
	_, configPath := writeV2ApplyConfig(t)
	withTestCfgFile(t, configPath)
	withTestSnapshotDBPath(t, filepath.Join(t.TempDir(), "absent-audit.db"))

	if _, err := runCloud(t, "enroll", "--url", srv.URL, "--token", "enroll-secret"); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	out, err := runCloud(t, "sync", "--once")
	if err != nil {
		t.Fatalf("sync: %v\n%s", err, out)
	}
	if state.Evidence != 1 {
		t.Fatalf("evidence posts = %d, want 1", state.Evidence)
	}
	// The reported envelope is a real signed envelope for THIS node.
	sig, _ := state.LastEvidence["signature"].(map[string]any)
	if sig["value"] == "" || state.LastEvidence["node_id"] == "" {
		t.Fatalf("evidence is not a signed envelope: %v", state.LastEvidence)
	}
}

func TestCloudSyncPullsAppliesThenReports(t *testing.T) {
	store := withTestNodeStore(t)
	id, err := store.Init("dev")
	if err != nil {
		t.Fatal(err)
	}
	withLocalCloudDialer(t)
	srv, state := fakeCloud(t)
	_, configPath := writeV2ApplyConfig(t)
	withTestCfgFile(t, configPath)
	withTestSnapshotDBPath(t, filepath.Join(t.TempDir(), "absent-audit.db"))

	// A signed pull store targeting this node, served from a local dir.
	raw, fp := signV2Bundle(t, supportedAgentBodyV2("node", id.NodeID))
	pullDir := writePullStore(t, raw, "node", id.NodeID, "bundles/b.json")

	if _, err := runCloud(t, "enroll", "--url", srv.URL, "--token", "enroll-secret",
		"--pull-url", fileURL(pullDir), "--trust-fingerprint", fp); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	out, err := runCloud(t, "sync", "--once", "--config", configPath)
	if err != nil {
		t.Fatalf("sync: %v\n%s", err, out)
	}
	if !strings.Contains(out, "applied policy") {
		t.Fatalf("sync must report the apply: %s", out)
	}
	// The bundle cache exists so snapshots echo the active policy...
	if _, err := os.Stat(store.CloudBundlePath()); err != nil {
		t.Fatalf("bundle cache missing: %v", err)
	}
	// ...and the reported snapshot carries the applied policy block.
	snap, _ := state.LastEvidence["snapshot"].(map[string]any)
	pol, _ := snap["policy"].(map[string]any)
	if pol == nil || pol["policy_status"] != "active" {
		t.Fatalf("reported snapshot must echo the applied policy, got %v", pol)
	}
	if pol["applied_sequence"] == nil {
		t.Fatalf("policy block missing assignment echo: %v", pol)
	}

	// Second sync: pull is a clean no-op, evidence still reported.
	if _, err := runCloud(t, "sync", "--once", "--config", configPath); err != nil {
		t.Fatalf("second sync: %v", err)
	}
	if state.Evidence != 2 {
		t.Fatalf("evidence posts = %d, want 2", state.Evidence)
	}
}

func TestCloudSyncExitStagesAndValidation(t *testing.T) {
	store := withTestNodeStore(t)
	if _, err := store.Init("dev"); err != nil {
		t.Fatal(err)
	}
	withLocalCloudDialer(t)

	// Not enrolled: clear remediation error.
	if _, err := runCloud(t, "sync", "--once"); err == nil ||
		!strings.Contains(err.Error(), "not enrolled") {
		t.Fatalf("unenrolled sync must say so: %v", err)
	}
	// Exactly one of --once / --interval.
	if _, err := runCloud(t, "sync"); err == nil {
		t.Fatal("sync without mode must fail")
	}
	if _, err := runCloud(t, "sync", "--once", "--interval", "5m"); err == nil {
		t.Fatal("sync with both modes must fail")
	}
	// Interval floor.
	st := &node.CloudState{URL: "https://cloud.example.com", EnrolledAt: "2026-06-10T00:00:00Z"}
	if err := store.SaveCloudState(st); err != nil {
		t.Fatal(err)
	}
	if _, err := runCloud(t, "sync", "--interval", "5s"); err == nil ||
		!strings.Contains(err.Error(), "at least") {
		t.Fatalf("sub-minute interval must be refused: %v", err)
	}

	// Pull failure carries the stage exit code.
	if err := store.SaveCloudToken("tok"); err != nil {
		t.Fatal(err)
	}
	st.PullURL = fileURL(t.TempDir()) // empty store: index fetch fails
	st.TrustFingerprint = "sha256:" + strings.Repeat("cd", 32)
	if err := store.SaveCloudState(st); err != nil {
		t.Fatal(err)
	}
	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "oktsec.yaml")
	if err := os.WriteFile(cfgPath, []byte("version: \"1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := runCloud(t, "sync", "--once", "--config", cfgPath)
	var syncErr *cloudSyncError
	if !errors.As(err, &syncErr) || syncErr.code != 2 {
		t.Fatalf("pull failure must carry exit code 2: %v", err)
	}
}

func TestCloudStatusShowsNoSecrets(t *testing.T) {
	store := withTestNodeStore(t)
	if _, err := store.Init("dev"); err != nil {
		t.Fatal(err)
	}
	st := &node.CloudState{
		URL: "https://cloud.example.com", EnrolledAt: "2026-06-10T00:00:00Z",
		PullURL: "https://cloud.example.com/pull/x/y/SECRETCAP/", TrustFingerprint: "sha256:" + strings.Repeat("ef", 32),
	}
	if err := store.SaveCloudState(st); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveCloudToken("node-token-secret"); err != nil {
		t.Fatal(err)
	}
	out, err := runCloud(t, "status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if strings.Contains(out, "node-token-secret") || strings.Contains(out, "SECRETCAP") {
		t.Fatalf("status must not print secrets:\n%s", out)
	}
	if !strings.Contains(out, "configured") || !strings.Contains(out, "true") {
		t.Fatalf("status must show connection state:\n%s", out)
	}
}
