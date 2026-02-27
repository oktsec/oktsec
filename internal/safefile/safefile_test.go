package safefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRejectSymlink_RegularFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "regular.txt")
	if err := os.WriteFile(f, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := RejectSymlink(f); err != nil {
		t.Errorf("regular file should pass: %v", err)
	}
}

func TestRejectSymlink_Symlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	link := filepath.Join(dir, "link.txt")

	if err := os.WriteFile(target, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	err := RejectSymlink(link)
	if err == nil {
		t.Fatal("expected error for symlink")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRejectSymlink_NonExistent(t *testing.T) {
	err := RejectSymlink("/nonexistent/path/abc123")
	if err == nil {
		t.Fatal("expected error for non-existent path")
	}
}

func TestReadFile_RegularFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "data.txt")
	want := []byte("hello world")
	if err := os.WriteFile(f, want, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestReadFile_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	link := filepath.Join(dir, "link.txt")

	if err := os.WriteFile(target, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, err := ReadFile(link)
	if err == nil {
		t.Fatal("expected error for symlink")
	}
}

func TestReadFileMax_WithinLimit(t *testing.T) {
	f := filepath.Join(t.TempDir(), "small.txt")
	data := []byte("small data")
	if err := os.WriteFile(f, data, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFileMax(f, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		t.Errorf("got %q, want %q", got, data)
	}
}

func TestReadFileMax_ExceedsLimit(t *testing.T) {
	f := filepath.Join(t.TempDir(), "big.txt")
	data := make([]byte, 2048)
	if err := os.WriteFile(f, data, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := ReadFileMax(f, 1024)
	if err == nil {
		t.Fatal("expected error for oversized file")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestReadFileMax_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	link := filepath.Join(dir, "link.txt")

	if err := os.WriteFile(target, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, err := ReadFileMax(link, 1<<20)
	if err == nil {
		t.Fatal("expected error for symlink")
	}
}
