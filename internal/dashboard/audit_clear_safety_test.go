package dashboard

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/identity"
)

// newAuditClearTestServer wires a Server backed by a real audit store
// in a temp dir so we can hit /dashboard/api/audit/clear and inspect the
// archive directory afterwards. Returns the server, the bound store,
// and the temp dir (which doubles as the cfgPath dir for default
// archive resolution).
func newAuditClearTestServer(t *testing.T) (*Server, *audit.Store, string) {
	t.Helper()
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := audit.NewStore(filepath.Join(dir, "test.db"), logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := &config.Config{
		Version: "1",
		Server:  config.ServerConfig{Port: 0},
		DBPath:  filepath.Join(dir, "test.db"),
		Agents: map[string]config.Agent{
			"agent-a": {CanMessage: []string{"agent-b"}},
		},
	}
	srv := NewServer(cfg, filepath.Join(dir, "oktsec.yaml"), store, identity.NewKeyStore(), sharedScanner, logger)

	// Seed three rows so we can prove they survive a refused clear.
	now := time.Now().UTC().Format(time.RFC3339)
	for _, id := range []string{"r1", "r2", "r3"} {
		store.Log(audit.Entry{
			ID: id, Timestamp: now, FromAgent: "agent-a", ToAgent: "agent-b",
			ContentHash: "h", Status: "delivered", PolicyDecision: "allow",
		})
	}
	store.Flush()
	return srv, store, dir
}

// TestAuditClear_RefusesWithoutConfirmToken proves the dashboard cannot
// destroy evidence on a bare POST. Earlier behavior wiped the audit log
// silently the moment any caller hit the endpoint; now the request
// returns an explicit refusal and rows stay intact.
func TestAuditClear_RefusesWithoutConfirmToken(t *testing.T) {
	srv, store, _ := newAuditClearTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("POST", "/dashboard/api/audit/clear", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if got := body["status"]; got != "refused" {
		t.Errorf("status field = %v, want refused", got)
	}

	st, err := store.EvidenceStatus()
	if err != nil {
		t.Fatal(err)
	}
	if st.TotalRows != 3 {
		t.Errorf("rows after refused clear = %d, want 3 (evidence must survive)", st.TotalRows)
	}
}

// TestAuditClear_WritesArchiveBeforeDeleting confirms the safe path
// produces a .jsonl.gz under <cfgDir>/archives and only then deletes.
func TestAuditClear_WritesArchiveBeforeDeleting(t *testing.T) {
	srv, store, dir := newAuditClearTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("POST", "/dashboard/api/audit/clear?confirm=archive-and-clear", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if got := body["status"]; got != "cleared" {
		t.Errorf("status = %v, want cleared", got)
	}
	if got, _ := body["archived_rows"].(float64); int(got) != 3 {
		t.Errorf("archived_rows = %v, want 3", body["archived_rows"])
	}
	archive, _ := body["archive"].(string)
	if archive == "" {
		t.Fatal("archive path missing in response")
	}
	if _, err := os.Stat(archive); err != nil {
		t.Errorf("archive file missing: %v", err)
	}
	// Default archive dir lives next to the config file.
	wantPrefix := filepath.Join(dir, "archives")
	if filepath.Dir(archive) != wantPrefix {
		t.Errorf("archive dir = %q, want %q", filepath.Dir(archive), wantPrefix)
	}

	st, err := store.EvidenceStatus()
	if err != nil {
		t.Fatal(err)
	}
	if st.TotalRows != 0 {
		t.Errorf("rows after clear = %d, want 0", st.TotalRows)
	}
}

// TestEvidenceStatus_EndpointReportsKeepForever proves the visible
// status block reads the right policy string for the default install.
func TestEvidenceStatus_EndpointReportsKeepForever(t *testing.T) {
	srv, _, _ := newAuditClearTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	req := httptest.NewRequest("GET", "/dashboard/api/evidence/status", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if body["retention_policy"] != "keep_forever" {
		t.Errorf("retention_policy = %v, want keep_forever", body["retention_policy"])
	}
	if got, _ := body["total_rows"].(float64); int(got) != 3 {
		t.Errorf("total_rows = %v, want 3", body["total_rows"])
	}
}
