package config

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// LoadEnv reads a .env file and returns key-value pairs.
// Supports KEY=VALUE lines; ignores comments (#) and blank lines.
// Returns nil if the file does not exist.
func LoadEnv(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	env := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		env[strings.TrimSpace(k)] = stripQuotes(strings.TrimSpace(v))
	}
	return env, sc.Err()
}

// stripQuotes removes surrounding single or double quotes from a value.
func stripQuotes(s string) string {
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		return s[1 : len(s)-1]
	}
	return s
}

// ApplyEnv merges .env secrets into a Config.
// Only sets fields that are empty in the config (explicit config wins).
func ApplyEnv(cfg *Config, env map[string]string) {
	if cfg == nil || env == nil {
		return
	}
	if cfg.Server.APIKey == "" {
		if v, ok := env["OKTSEC_API_KEY"]; ok {
			cfg.Server.APIKey = v
		}
	}
}

// EnsureEnvFile creates a .env file with a random API key if it doesn't exist.
// Uses O_CREATE|O_EXCL for atomic create-if-not-exists. Sets permissions to 0o600.
func EnsureEnvFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return nil // already exists
		}
		return err
	}
	defer func() { _ = f.Close() }()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		_ = os.Remove(path) // clean up empty file
		return fmt.Errorf("generating API key: %w", err)
	}

	_, err = fmt.Fprintf(f, "# oktsec secrets — auto-generated, do not commit\nOKTSEC_API_KEY=%s\n", hex.EncodeToString(key))
	return err
}
