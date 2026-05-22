package node

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/oktsec/oktsec/internal/config"
)

// HashString returns "sha256:<hex>" for s. Empty input returns "".
func HashString(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// PathTail returns the last segment of a filesystem path. It accepts
// both POSIX and Windows-style separators so the same redaction works
// on every platform the binary runs on.
//
// Examples:
//
//	"/Users/a/b/file.txt" -> "file.txt"
//	"/Users/a/project"     -> "project"
//	"C:\\Users\\a\\b.txt"  -> "b.txt"
func PathTail(path string) string {
	if path == "" {
		return ""
	}
	// Normalize both separators so Windows-style paths shrink
	// correctly on Unix-built binaries (and vice versa).
	p := strings.TrimRight(path, "/\\")
	if p == "" {
		// Path was only separators ("/", "\\\\", etc).
		return ""
	}
	if i := strings.LastIndexAny(p, "/\\"); i >= 0 {
		return p[i+1:]
	}
	// No separator at all; use filepath.Base for OS-specific edge
	// cases (e.g. Windows volume names like "C:").
	return filepath.Base(p)
}

// PathHash returns HashString of the path. Used so two snapshots from
// the same node can correlate config/db locations without leaking the
// absolute filesystem layout.
func PathHash(path string) string {
	return HashString(path)
}

// CommandTail returns the basename of a command string (the binary
// name without args). Empty input returns "".
//
// The MCPServerConfig contract keeps args in a separate field, so
// CommandTail treats the first whitespace-delimited token as the
// executable. Operators with binary paths that contain spaces should
// keep the path quoted or move flags into Args — without that
// contract a "/Program Files/node.exe --flag" string is ambiguous.
func CommandTail(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	if idx := strings.IndexAny(cmd, " \t"); idx >= 0 {
		cmd = cmd[:idx]
	}
	return PathTail(cmd)
}

// URLHostHash returns HashString of the URL's host (without
// userinfo or port). If parsing fails, returns "". Query strings,
// credentials, and paths are never hashed.
func URLHostHash(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	if host == "" {
		return ""
	}
	return HashString(strings.ToLower(host))
}

// RedactMCPServerConfig converts an MCPServerConfig into a redacted
// InventoryMCPServer. Raw command paths, URL credentials, args, env
// values, and full URLs are stripped.
func RedactMCPServerConfig(name string, in config.MCPServerConfig) InventoryMCPServer {
	out := InventoryMCPServer{
		Name:      name,
		Transport: in.Transport,
		EnvCount:  len(in.Env),
	}
	if in.Command != "" {
		out.CommandTail = CommandTail(in.Command)
	}
	if len(in.Args) > 0 {
		out.ArgsCount = len(in.Args)
	}
	if in.URL != "" {
		out.URLHostHash = URLHostHash(in.URL)
	}
	return out
}
