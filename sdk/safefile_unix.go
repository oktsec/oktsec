//go:build !windows

package sdk

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// readFileNoFollow reads a file, atomically rejecting symlinks via O_NOFOLLOW.
func readFileNoFollow(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s is a symbolic link (rejected for security)", path)
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()

	return io.ReadAll(f)
}
