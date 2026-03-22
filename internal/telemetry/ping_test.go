package telemetry

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

var testInfo = Info{
	Version: "v0.11.2",
	Agents:  3,
	Rules:   230,
	Gateway: true,
	LLM:     false,
	Enforce: false,
}

func TestPing_SendsOnce(t *testing.T) {
	var hits int
	var lastQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		lastQuery = r.URL.RawQuery
		if r.Method != http.MethodHead {
			t.Errorf("expected HEAD, got %s", r.Method)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()

	pingWithURL(srv.URL, testInfo, dir)
	if hits != 1 {
		t.Errorf("expected 1 ping, got %d", hits)
	}

	// Verify query params
	if lastQuery == "" {
		t.Fatal("no query params sent")
	}
	for _, param := range []string{"v=", "os=", "arch=", "agents=", "rules=", "gw=", "llm=", "mode="} {
		if !contains(lastQuery, param) {
			t.Errorf("missing param %q in query: %s", param, lastQuery)
		}
	}

	// Second call with same version should not ping
	pingWithURL(srv.URL, testInfo, dir)
	if hits != 1 {
		t.Errorf("expected still 1 ping for same version, got %d", hits)
	}

	// New version should ping again
	newVersion := testInfo
	newVersion.Version = "v0.12.0"
	pingWithURL(srv.URL, newVersion, dir)
	if hits != 2 {
		t.Errorf("expected 2 pings after version upgrade, got %d", hits)
	}

	// Same new version again should not ping
	pingWithURL(srv.URL, newVersion, dir)
	if hits != 2 {
		t.Errorf("expected still 2 pings, got %d", hits)
	}

	// Verify marker file has latest version
	marker := filepath.Join(dir, markerFile)
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("marker file not created: %v", err)
	}
	if string(data) != "v0.12.0\n" {
		t.Errorf("marker has %q, want %q", string(data), "v0.12.0\n")
	}
}

func TestPing_OptOut_Env(t *testing.T) {
	t.Setenv("OKTSEC_NO_TELEMETRY", "1")

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
	}))
	defer srv.Close()

	pingWithURL(srv.URL, testInfo, t.TempDir())
	if hits != 0 {
		t.Errorf("expected 0 pings with opt-out, got %d", hits)
	}
}

func TestPing_OptOut_File(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	oktsecDir := filepath.Join(home, ".oktsec")
	_ = os.MkdirAll(oktsecDir, 0700)
	_ = os.WriteFile(filepath.Join(oktsecDir, ".no-telemetry"), []byte(""), 0600)

	t.Setenv("HOME", home)

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
	}))
	defer srv.Close()

	pingWithURL(srv.URL, testInfo, t.TempDir())
	if hits != 0 {
		t.Errorf("expected 0 pings with .no-telemetry file, got %d", hits)
	}
}

func TestPing_ServerDown(t *testing.T) {
	pingWithURL("http://127.0.0.1:1", testInfo, t.TempDir())
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
