//go:build windows

package sdk

import (
	"fmt"
	"os"
)

// readFileNoFollow reads a file after checking it is not a symlink.
// On Windows, O_NOFOLLOW is not available so we use Lstat.
func readFileNoFollow(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symbolic link (rejected for security)", path)
	}
	return os.ReadFile(path)
}
