//go:build !windows

package safefile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// ReadFile reads path using O_NOFOLLOW to atomically reject symlinks
// (no TOCTOU window between check and read).
func ReadFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s is a symbolic link (rejected for security)", path)
		}
		return nil, err
	}
	defer f.Close()

	return io.ReadAll(f)
}

// ReadFileMax reads path using O_NOFOLLOW to atomically reject symlinks
// and verifies the file size does not exceed maxBytes via Fstat on the
// open file descriptor (no TOCTOU window).
func ReadFileMax(path string, maxBytes int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s is a symbolic link (rejected for security)", path)
		}
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("%s is too large (%d bytes, max %d)", path, info.Size(), maxBytes)
	}

	return io.ReadAll(io.LimitReader(f, maxBytes))
}
