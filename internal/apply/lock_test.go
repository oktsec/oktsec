package apply

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAcquireApplyLock_ExclusiveAndRelease(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "oktsec.yaml")

	l1, err := AcquireApplyLock(cfg)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	// Second acquire while held must fail (exclusive).
	if _, err := AcquireApplyLock(cfg); err == nil {
		t.Fatal("second acquire must fail while the lock is held")
	} else if !strings.Contains(err.Error(), "another apply holds the lock") {
		t.Fatalf("expected held-lock message, got %v", err)
	}
	// The lock file is mode 0600.
	if info, err := os.Lstat(ApplyLockPath(cfg)); err != nil {
		t.Fatalf("lstat lock: %v", err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("lock mode = %v, want 0600", info.Mode().Perm())
	}
	// Release frees the lock file.
	if err := l1.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, err := os.Lstat(ApplyLockPath(cfg)); !os.IsNotExist(err) {
		t.Fatalf("lock file should be gone after release, lstat err=%v", err)
	}
	// Release again is a no-op.
	if err := l1.Release(); err != nil {
		t.Fatalf("second release must be a no-op, got %v", err)
	}
	// A fresh acquire succeeds after release.
	l2, err := AcquireApplyLock(cfg)
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	if err := l2.Release(); err != nil {
		t.Fatalf("release l2: %v", err)
	}
}

func TestAcquireApplyLock_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "oktsec.yaml")
	lockPath := ApplyLockPath(cfg)

	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, lockPath); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	if _, err := AcquireApplyLock(cfg); err == nil {
		t.Fatal("a symlink at the lock path must be rejected")
	} else if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}

func TestRestoreConfigV2FromBackup_RestoresPriorBytes(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "oktsec.yaml")
	backup := filepath.Join(dir, "oktsec.yaml.bak.20260101T000000Z")

	if err := os.WriteFile(backup, []byte("prior\n"), 0o600); err != nil {
		t.Fatalf("write backup: %v", err)
	}
	if err := os.WriteFile(cfg, []byte("changed\n"), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	if err := RestoreConfigV2FromBackup(cfg, backup); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got, err := os.ReadFile(cfg) //nolint:gosec // test path
	if err != nil {
		t.Fatalf("read restored cfg: %v", err)
	}
	if string(got) != "prior\n" {
		t.Fatalf("restored contents = %q, want %q", string(got), "prior\n")
	}
}

func TestRestoreConfigV2FromBackup_EmptyBackupIsError(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "oktsec.yaml")
	if err := os.WriteFile(cfg, []byte("x"), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	if err := RestoreConfigV2FromBackup(cfg, ""); err == nil {
		t.Fatal("restore with empty backup path must error")
	}
}
