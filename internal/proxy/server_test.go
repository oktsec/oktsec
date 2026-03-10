package proxy

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/netutil"
)

func TestNewServer_Minimal(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := &config.Config{
		Version: "1",
		Server:  config.ServerConfig{Port: 0},
		DBPath:  filepath.Join(dir, "test.db"),
		Agents:  make(map[string]config.Agent),
	}

	srv, err := NewServer(cfg, "", logger)
	if err != nil {
		t.Fatal(err)
	}

	// Port 0 means OS-assigned -- actual port is now set
	_ = srv.Port()
	if srv.DashboardCode() == "" {
		t.Error("dashboard code should not be empty")
	}
	if srv.AuditStore() == nil {
		t.Error("audit store should not be nil")
	}

	// Cleanup
	ctx := context.Background()
	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("shutdown error: %v", err)
	}
}

func TestNewServer_WithKeysDir(t *testing.T) {
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	_ = os.MkdirAll(keysDir, 0o700)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := &config.Config{
		Version:  "1",
		Server:   config.ServerConfig{Port: 0},
		DBPath:   filepath.Join(dir, "test.db"),
		Identity: config.IdentityConfig{KeysDir: keysDir},
		Agents:   make(map[string]config.Agent),
	}

	srv, err := NewServer(cfg, "", logger)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
}

func TestListenAutoPort_FindsPort(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Port 0 = let OS assign
	ln, port, err := netutil.ListenAutoPort("127.0.0.1", 0, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	if port <= 0 {
		t.Errorf("port = %d, want > 0", port)
	}
}

func TestIsAddrInUse_NilError(t *testing.T) {
	if netutil.IsAddrInUse(nil) {
		t.Error("nil error should not be addr in use")
	}
}
