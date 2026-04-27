package claudecode

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
)

// rawSettings is just enough of the Claude Code settings.json shape
// to extract hooks. Anything not modeled here is left as raw JSON in
// the parent map and ignored, so unknown keys never cause Read to
// fail. The shape mirrors the public docs at code.claude.com/docs/en/hooks.
type rawSettings struct {
	Hooks map[string]json.RawMessage `json:"hooks,omitempty"`
}

// rawHookEntry covers both shapes Claude Code accepts under one event:
//   { "matcher": "*", "hooks": [ { "type": "command", "command": "..." } ] }
//
// The "hooks" inner array can also be a single object in some older
// configs; we accept both via json.RawMessage and decode lazily.
type rawHookEntry struct {
	Matcher string            `json:"matcher,omitempty"`
	Hooks   []rawHookHandler  `json:"hooks,omitempty"`
}

type rawHookHandler struct {
	Type    string `json:"type,omitempty"`    // command | http | mcp_tool | prompt | agent
	Command string `json:"command,omitempty"`
	URL     string `json:"url,omitempty"`
}

// readSettings loads a single Claude settings file and unmarshals it
// into rawSettings. Returns (nil, nil) when the file does not exist
// — that is the normal "no project settings yet" case and not a
// problem the operator needs to act on.
func readSettings(path string) (*rawSettings, *ConnectorProblem) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, &ConnectorProblem{
			Code:     "CC-SETTINGS-READ",
			Severity: "warning",
			Title:    fmt.Sprintf("Unable to read %s", path),
			Detail:   err.Error(),
		}
	}
	if len(data) == 0 {
		// An empty file is legal but parses as null; treat as "no settings".
		return &rawSettings{}, nil
	}
	var s rawSettings
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, &ConnectorProblem{
			Code:     "CC-SETTINGS-PARSE",
			Severity: "warning",
			Title:    fmt.Sprintf("Unable to parse %s", path),
			Detail:   err.Error(),
		}
	}
	return &s, nil
}

// sortedKeys returns map keys in deterministic order so JSON output
// from the doctor command does not jitter between runs. Centralized
// here because every reader needs the same trick.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
