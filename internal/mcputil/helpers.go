// Package mcputil provides convenience helpers that bridge the gap between
// the go-sdk's raw JSON tool arguments and the typed helpers that mcp-go
// used to ship (GetString, GetInt, NewToolResultText, etc.).
package mcputil

import (
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// GetString extracts a string value from raw JSON arguments.
// Returns defaultVal if the key is absent or not a string.
func GetString(raw json.RawMessage, key, defaultVal string) string {
	m := parseArgs(raw)
	if m == nil {
		return defaultVal
	}
	v, ok := m[key]
	if !ok {
		return defaultVal
	}
	s, ok := v.(string)
	if !ok {
		return defaultVal
	}
	return s
}

// GetInt extracts an integer value from raw JSON arguments.
// JSON numbers are float64, so this truncates to int.
// Returns defaultVal if the key is absent or not a number.
func GetInt(raw json.RawMessage, key string, defaultVal int) int {
	m := parseArgs(raw)
	if m == nil {
		return defaultVal
	}
	v, ok := m[key]
	if !ok {
		return defaultVal
	}
	f, ok := v.(float64)
	if !ok {
		return defaultVal
	}
	return int(f)
}

// GetArguments returns the tool arguments as a map.
// Returns nil if parsing fails.
func GetArguments(raw json.RawMessage) map[string]any {
	return parseArgs(raw)
}

// NewToolResultText creates a successful CallToolResult with text content.
func NewToolResultText(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
}

// NewToolResultError creates an error CallToolResult with text content.
func NewToolResultError(msg string) *mcp.CallToolResult {
	var r mcp.CallToolResult
	r.SetError(fmt.Errorf("%s", msg))
	return &r
}

func parseArgs(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	return m
}
