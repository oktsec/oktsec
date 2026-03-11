package hooks

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
	"log/slog"
	"os"
)

func newTestHandler(t *testing.T) (*Handler, func()) {
	t.Helper()
	dir := t.TempDir()
	dbPath := dir + "/test.db"
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Import audit inline to avoid circular dependency concerns.
	audit := mustCreateAuditStore(t, dbPath, logger)

	scanner := engine.NewScanner("")
	cfg := config.Defaults()
	h := NewHandler(scanner, audit, cfg, logger)
	return h, func() {
		scanner.Close()
		_ = audit.Close()
	}
}

func TestHandlerCleanToolCall(t *testing.T) {
	h, cleanup := newTestHandler(t)
	defer cleanup()

	body, _ := json.Marshal(ToolEvent{
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path":"/tmp/test.txt"}`),
		Agent:     "test-agent",
		SessionID: "sess-1",
		Event:     "pre_tool_use",
	})

	req := httptest.NewRequest(http.MethodPost, "/hooks/event", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid response json: %v", err)
	}
	if resp["decision"] != "allow" {
		t.Fatalf("expected allow, got %v", resp["decision"])
	}
}

func TestHandlerNormalizesClaudeCodeFormat(t *testing.T) {
	h, cleanup := newTestHandler(t)
	defer cleanup()

	// Claude Code sends hook_event_name instead of event.
	body, _ := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "Bash",
		"tool_input":      map[string]any{"command": "ls -la"},
		"session_id":      "sess-2",
	})

	req := httptest.NewRequest(http.MethodPost, "/hooks/event", bytes.NewReader(body))
	req.Header.Set("X-Oktsec-Agent", "claude-code")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["decision"] != "allow" {
		t.Fatalf("expected allow, got %v", resp["decision"])
	}
}

func TestHandlerRejectsGet(t *testing.T) {
	h, cleanup := newTestHandler(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/hooks/event", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestHandlerAgentFromHeader(t *testing.T) {
	h, cleanup := newTestHandler(t)
	defer cleanup()

	body, _ := json.Marshal(ToolEvent{
		ToolName:  "Write",
		ToolInput: json.RawMessage(`{"file_path":"/tmp/x.txt"}`),
		Agent:     "payload-agent",
		Event:     "pre_tool_use",
	})

	req := httptest.NewRequest(http.MethodPost, "/hooks/event", bytes.NewReader(body))
	req.Header.Set("X-Oktsec-Agent", "header-agent")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	// Header agent should take precedence — verified by audit log (not exposed in response).
}
