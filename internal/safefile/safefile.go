// Package safefile provides file I/O helpers that reject symlinks and
// enforce size limits. Use these instead of os.ReadFile for any
// security-sensitive path (config, keys, state databases).
package safefile

import (
	"fmt"
	"os"
)

// RejectSymlink returns an error if path is a symbolic link.
// It uses Lstat (not Stat) so the check is not followed through the link.
func RejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symbolic link (rejected for security)", path)
	}
	return nil
}

// ReadFile reads path after verifying it is not a symlink.
func ReadFile(path string) ([]byte, error) {
	if err := RejectSymlink(path); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

// ReadFileMax reads path after verifying it is not a symlink and that
// the file size does not exceed maxBytes.
func ReadFileMax(path string, maxBytes int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symbolic link (rejected for security)", path)
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("%s is too large (%d bytes, max %d)", path, info.Size(), maxBytes)
	}
	return os.ReadFile(path)
}
