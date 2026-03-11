package config

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

var (
	homeDirOnce  sync.Once
	homeDirValue string
)

// HomeDir returns the oktsec home directory.
// Uses ~/.oktsec/ on macOS/Linux, %LOCALAPPDATA%\oktsec\ on Windows.
// Creates the directory with 0o700 permissions on first call.
func HomeDir() string {
	homeDirOnce.Do(func() {
		switch runtime.GOOS {
		case "windows":
			dir := os.Getenv("LOCALAPPDATA")
			if dir == "" {
				home, _ := os.UserHomeDir()
				dir = filepath.Join(home, "AppData", "Local")
			}
			homeDirValue = filepath.Join(dir, "oktsec")
		default:
			home, _ := os.UserHomeDir()
			homeDirValue = filepath.Join(home, ".oktsec")
		}
		_ = os.MkdirAll(homeDirValue, 0o700)
	})
	return homeDirValue
}

// DefaultConfigPath returns ~/.oktsec/config.yaml.
func DefaultConfigPath() string {
	return filepath.Join(HomeDir(), "config.yaml")
}

// DefaultKeysDir returns ~/.oktsec/keys/.
func DefaultKeysDir() string {
	return filepath.Join(HomeDir(), "keys")
}

// DefaultDBPath returns ~/.oktsec/oktsec.db.
func DefaultDBPath() string {
	return filepath.Join(HomeDir(), "oktsec.db")
}

// DefaultEnvPath returns ~/.oktsec/.env.
func DefaultEnvPath() string {
	return filepath.Join(HomeDir(), ".env")
}

// ResolveConfigPath finds the config file using cascading resolution:
//  1. flagValue if flagExplicit is true (user passed --config)
//  2. $OKTSEC_CONFIG env var
//  3. ./oktsec.yaml in current directory (backward compat)
//  4. ~/.oktsec/config.yaml (home default)
//
// Returns the resolved path and whether the file exists on disk.
func ResolveConfigPath(flagValue string, flagExplicit bool) (path string, found bool) {
	// 1. Explicit CLI flag
	if flagExplicit && flagValue != "" {
		_, err := os.Stat(flagValue)
		return flagValue, err == nil
	}

	// 2. Environment variable
	if envPath := os.Getenv("OKTSEC_CONFIG"); envPath != "" {
		_, err := os.Stat(envPath)
		return envPath, err == nil
	}

	// 3. Local oktsec.yaml (backward compat)
	local := "oktsec.yaml"
	if _, err := os.Stat(local); err == nil {
		abs, _ := filepath.Abs(local)
		if abs != "" {
			return abs, true
		}
		return local, true
	}

	// 4. Home default
	home := DefaultConfigPath()
	_, err := os.Stat(home)
	return home, err == nil
}
