package dashboard

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/identity"
)

// TestClaudeCodeHealthEndpoint_NotInstalled verifies the dashboard
// reports the right status string when no Claude state exists. The
// dashboard pill code in Phase 4 will read this verbatim, so locking
// it in here prevents accidental copy drift later.
func TestClaudeCodeHealthEndpoint_NotInstalled(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := audit.NewStore(filepath.Join(dir, "test.db"), logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	// Point HOME at an empty temp dir so the connector inspector sees
	// a clean machine. PATH is cleared so the host's real `claude`
	// binary (if any) does not flip Detected to true.
	emptyHome := t.TempDir()
	t.Setenv("HOME", emptyHome)
	t.Setenv("PATH", "")

	cfg := &config.Config{
		Version: "1",
		Server:  config.ServerConfig{Port: 0},
		DBPath:  filepath.Join(dir, "test.db"),
		Agents:  map[string]config.Agent{},
	}
	srv := NewServer(cfg, filepath.Join(dir, "oktsec.yaml"), store, identity.NewKeyStore(), sharedScanner, logger)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	// Use ?project=<empty-temp-dir> so the handler does not pick up
	// this repo's project state by accident.
	u := "/dashboard/api/connectors/claude-code/health?" + url.Values{"project": {emptyHome}}.Encode()
	req := httptest.NewRequest("GET", u, nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Health struct {
			Status string `json:"status"`
		} `json:"health"`
		Inventory struct {
			Detected bool `json:"detected"`
		} `json:"inventory"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding response: %v; body=%s", err, w.Body.String())
	}
	if body.Health.Status != "not_installed" {
		t.Errorf("status = %q, want not_installed (body=%s)", body.Health.Status, w.Body.String())
	}
	if body.Inventory.Detected {
		t.Error("inventory.Detected should be false on an empty home")
	}
}
