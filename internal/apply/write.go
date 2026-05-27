package apply

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/safefile"
	"gopkg.in/yaml.v3"
)

// maxConfigBytes caps the original config the backup reads (mirrors config.Load).
const maxConfigBytes = 1 << 20 // 1 MiB

// ErrNoProjection is returned when Commit is given a plan with no computed
// target config (DryRun must run first and succeed).
var ErrNoProjection = errors.New("apply: plan has no projected config to commit")

// Commit writes the plan's projected config to targetConfig using a backup +
// atomic-replace protocol. Call it only for a plan that has changes and no
// unsupported items; it returns the created backup path.
//
// Sequence (spec 7A.3 §4 steps 13-19 / §5): marshal the projection ->
// revalidate it by re-parsing (independent of the in-memory Validate) ->
// exclusive backup of the EXACT original bytes in the same directory ->
// exclusive temp write -> fsync -> atomic same-dir rename -> parent dir fsync.
// Nothing mutates the config path until the projected config has validated AND
// the backup exists; if the rename fails the original config and the backup
// both remain.
func Commit(plan *Plan, targetConfig string) (string, error) {
	if plan == nil || plan.projected == nil {
		return "", ErrNoProjection
	}

	// 13-14: marshal deterministically, then revalidate by re-parsing the
	// bytes that will actually be written — not the in-memory struct.
	data, err := yaml.Marshal(plan.projected)
	if err != nil {
		return "", fmt.Errorf("apply: marshal projected config: %w", err)
	}
	var reparsed config.Config
	if err := yaml.Unmarshal(data, &reparsed); err != nil {
		return "", fmt.Errorf("apply: projected config does not re-parse: %w", err)
	}
	if err := reparsed.Validate(); err != nil {
		return "", fmt.Errorf("apply: projected config invalid after marshal: %w", err)
	}

	// Re-check the config path right before writing: never follow a symlink,
	// never write through a directory or irregular file.
	info, err := os.Lstat(targetConfig)
	if err != nil {
		return "", fmt.Errorf("apply: stat config %q: %w", targetConfig, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("apply: config %q is a symlink (rejected for security)", targetConfig)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("apply: config %q is not a regular file", targetConfig)
	}
	mode := info.Mode().Perm()

	// Backup uses the exact original bytes (pre-migration, pre-defaults), so
	// it round-trips the operator's file verbatim — not the re-marshaled form.
	orig, err := safefile.ReadFileMax(targetConfig, maxConfigBytes)
	if err != nil {
		return "", fmt.Errorf("apply: read original config: %w", err)
	}

	// 15: exclusive timestamped backup in the same directory. If this fails,
	// the config is untouched.
	backupPath := targetConfig + ".bak." + time.Now().UTC().Format("20060102T150405Z")
	if err := writeExclusive(backupPath, orig, mode); err != nil {
		return "", fmt.Errorf("apply: create backup %q: %w", backupPath, err)
	}

	// 16-19: atomic replace. On failure the original config and the backup
	// both remain; the temp file is removed.
	if err := atomicReplace(targetConfig, data, mode); err != nil {
		return backupPath, fmt.Errorf("apply: atomic replace %q (backup kept at %q): %w", targetConfig, backupPath, err)
	}
	return backupPath, nil
}

// writeExclusive creates path with O_EXCL — it never overwrites an existing
// file and never follows a symlink at path — writes data, fsyncs, and closes.
// On any write/sync failure the partial file is removed.
func writeExclusive(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

// atomicReplace writes data to an exclusively-created temp file in path's
// directory, fsyncs it, chmods to mode, atomically renames it over path, then
// fsyncs the parent directory. On any failure before the rename the temp file
// is removed and path is left untouched.
func atomicReplace(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return err
	}
	// Parent fsync makes the rename durable across a crash.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
