//go:build windows

package safefile

import (
	"fmt"
	"os"
)

// ReadFile reads path after verifying it is not a symlink.
// On Windows, O_NOFOLLOW is not available so we fall back to Lstat+ReadFile.
func ReadFile(path string) ([]byte, error) {
	if err := RejectSymlink(path); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

// ReadFileMax reads path after verifying it is not a symlink and that
// the file size does not exceed maxBytes.
// On Windows, O_NOFOLLOW is not available so we fall back to Lstat+ReadFile.
func ReadFileMax(path string, maxBytes int64) ([]byte, error) {
	if err := RejectSymlink(path); err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("%s is too large (%d bytes, max %d)", path, info.Size(), maxBytes)
	}
	return os.ReadFile(path)
}
