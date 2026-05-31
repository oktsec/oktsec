package apply

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

// ApplyLock is an exclusive, file-based advisory lock that scopes the full
// policy_bundle.v2 apply critical section (load state, evaluate sequence,
// write config, persist state) to a single in-flight apply for a given
// config/state target.
//
// The lock is implemented as an O_CREATE|O_EXCL lock file placed next to the
// config path. Exclusive creation is atomic on the target platforms (this is a
// pure-Go, no-CGO project), so two concurrent applies cannot both observe the
// lock as free. A leftover lock from a crashed prior apply is NOT auto-stolen,
// because auto-stealing would reintroduce the very race the lock prevents.
// Instead acquisition fails with a clear message naming the lock path so an
// operator can remove it after confirming no apply is running. The lock file
// records the owning pid and an RFC3339 timestamp to aid that decision.
type ApplyLock struct {
	path     string
	released bool
}

// ApplyLockPath returns the lock file path that sits next to the config file.
func ApplyLockPath(configPath string) string {
	return configPath + ".policy-apply.lock"
}

// AcquireApplyLock acquires the exclusive apply lock for configPath. It must be
// released via Release in all paths (success, refusal, error, panic) using a
// defer at the call site. The lock file is created with O_CREATE|O_EXCL so the
// acquisition is atomic; if it already exists, acquisition fails rather than
// waiting or stealing it.
func AcquireApplyLock(configPath string) (*ApplyLock, error) {
	lockPath := ApplyLockPath(configPath)

	// Reject a symlink at the lock path before creating, mirroring the
	// symlink discipline used for the config and state files in write.go and
	// state_v2.go. We do not want an attacker-planted symlink to redirect the
	// lock file (or its later removal) outside the intended directory.
	if info, err := os.Lstat(lockPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("apply lock %q is a symlink", lockPath)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("apply lock %q is not a regular file", lockPath)
		}
		// A regular lock file already exists: another apply holds the lock,
		// or a prior apply crashed without releasing it. Do not steal it.
		return nil, fmt.Errorf(
			"another apply holds the lock %q; if none is running, remove that file and retry",
			lockPath,
		)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("stat apply lock: %w", err)
	}

	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			// Lost the create race to a concurrent apply.
			return nil, fmt.Errorf(
				"another apply holds the lock %q; if none is running, remove that file and retry",
				lockPath,
			)
		}
		return nil, fmt.Errorf("create apply lock: %w", err)
	}
	// Record owner pid and timestamp so a stale lock can be reasoned about.
	contents := "pid=" + strconv.Itoa(os.Getpid()) + " acquired=" + time.Now().UTC().Format(time.RFC3339) + "\n"
	if _, werr := f.WriteString(contents); werr != nil {
		_ = f.Close()
		_ = os.Remove(lockPath)
		return nil, fmt.Errorf("write apply lock: %w", werr)
	}
	if cerr := f.Close(); cerr != nil {
		_ = os.Remove(lockPath)
		return nil, fmt.Errorf("close apply lock: %w", cerr)
	}
	return &ApplyLock{path: lockPath}, nil
}

// Release removes the lock file. It is safe to call multiple times and is a
// no-op after the first successful removal, so it can be deferred and also
// called explicitly. A removal error is returned so callers can surface a
// leaked lock, but Release marks the lock released regardless to keep the
// no-op-on-repeat contract.
func (l *ApplyLock) Release() error {
	if l == nil || l.released {
		return nil
	}
	l.released = true
	if err := os.Remove(l.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove apply lock: %w", err)
	}
	return nil
}
