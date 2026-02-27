package mcputil

import (
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestGetString(t *testing.T) {
	raw := json.RawMessage(`{"name":"alice","count":42}`)

	if got := GetString(raw, "name", ""); got != "alice" {
		t.Errorf("GetString(name) = %q, want alice", got)
	}
	if got := GetString(raw, "missing", "default"); got != "default" {
		t.Errorf("GetString(missing) = %q, want default", got)
	}
	if got := GetString(raw, "count", "default"); got != "default" {
		t.Errorf("GetString(count) = %q, want default (wrong type)", got)
	}
	if got := GetString(nil, "name", "default"); got != "default" {
		t.Errorf("GetString(nil) = %q, want default", got)
	}
}

func TestGetInt(t *testing.T) {
	raw := json.RawMessage(`{"count":42,"name":"alice"}`)

	if got := GetInt(raw, "count", 0); got != 42 {
		t.Errorf("GetInt(count) = %d, want 42", got)
	}
	if got := GetInt(raw, "missing", 10); got != 10 {
		t.Errorf("GetInt(missing) = %d, want 10", got)
	}
	if got := GetInt(raw, "name", 10); got != 10 {
		t.Errorf("GetInt(name) = %d, want 10 (wrong type)", got)
	}
	if got := GetInt(nil, "count", 5); got != 5 {
		t.Errorf("GetInt(nil) = %d, want 5", got)
	}
}

func TestGetArguments(t *testing.T) {
	raw := json.RawMessage(`{"a":"1","b":2}`)
	m := GetArguments(raw)
	if m == nil {
		t.Fatal("GetArguments returned nil")
	}
	if m["a"] != "1" {
		t.Errorf("m[a] = %v, want 1", m["a"])
	}

	if m := GetArguments(nil); m != nil {
		t.Errorf("GetArguments(nil) = %v, want nil", m)
	}
}

func TestNewToolResultText(t *testing.T) {
	r := NewToolResultText("hello")
	if r.IsError {
		t.Error("expected IsError=false")
	}
	if len(r.Content) != 1 {
		t.Fatalf("content len = %d, want 1", len(r.Content))
	}
	tc, ok := r.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content[0] type = %T, want *mcp.TextContent", r.Content[0])
	}
	if tc.Text != "hello" {
		t.Errorf("text = %q, want hello", tc.Text)
	}
}

func TestNewToolResultError(t *testing.T) {
	r := NewToolResultError("something broke")
	if !r.IsError {
		t.Error("expected IsError=true")
	}
	if len(r.Content) != 1 {
		t.Fatalf("content len = %d, want 1", len(r.Content))
	}
	tc, ok := r.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content[0] type = %T, want *mcp.TextContent", r.Content[0])
	}
	if tc.Text != "something broke" {
		t.Errorf("text = %q, want 'something broke'", tc.Text)
	}
}
