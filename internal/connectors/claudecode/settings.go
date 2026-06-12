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
//
// Disable / restrict knobs are surfaced because the Phase 2 installer
// must refuse to write hooks the operator (or a managed policy) has
// globally disabled. The inventory reports them as ConnectorProblem
// rows so the doctor can explain the situation before any write.
type rawSettings struct {
	Hooks                 map[string]json.RawMessage `json:"hooks,omitempty"`
	DisableAllHooks       *bool                      `json:"disableAllHooks,omitempty"`
	AllowManagedHooksOnly *bool                      `json:"allowManagedHooksOnly,omitempty"`
	AllowedHTTPHookURLs   *[]string                  `json:"allowedHttpHookUrls,omitempty"`
}

// rawHookEntry is the lossy projection used by the inventory's
// HookRef rendering path (read-only). It only models the fields the
// dashboard / doctor surface display, so unknown handler fields
// (timeout, statusMessage, env, headers, allowedEnvVars, etc.) are
// dropped. NEVER use rawHookEntry for the write round-trip — see
// preservedHookEntry instead.
type rawHookEntry struct {
	Matcher string           `json:"matcher,omitempty"`
	Hooks   []rawHookHandler `json:"hooks,omitempty"`
}

type rawHookHandler struct {
	Type    string `json:"type,omitempty"` // command | http | mcp_tool | prompt | agent
	Command string `json:"command,omitempty"`
	URL     string `json:"url,omitempty"`
}

// preservedHookEntry is the install/uninstall round-trip shape:
// the matcher is decoded so we can split entries by matcher, but
// each handler is kept as raw JSON so unknown fields the operator
// added (timeout, statusMessage, env, headers, allowedEnvVars,
// future Claude additions) round-trip verbatim. Inventory HookRef
// rendering does NOT need this preservation; it stays on
// rawHookEntry.
type preservedHookEntry struct {
	Matcher string            `json:"matcher,omitempty"`
	Hooks   []json.RawMessage `json:"hooks,omitempty"`
}

// handlerOwnership decodes just enough of a raw handler payload to
// classify it as oktsec-owned (v2), legacy oktsec (v1), or operator
// content. Used by applyManifest / stripManifest so the round-trip
// path never has to fully decode a handler whose unknown fields
// must be preserved.
func handlerOwnership(raw json.RawMessage) (isV2, isLegacy bool) {
	var probe rawHookHandler
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false, false
	}
	switch {
	case isManifestV2Handler(probe):
		return true, false
	case isLegacyOktsecHandler(probe):
		return false, true
	default:
		return false, false
	}
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
