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
