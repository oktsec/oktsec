package dashboard

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/identity"
	"github.com/oktsec/oktsec/internal/runtime"
)

// newRuntimeGraphTestServer wires a Server backed by a real
// audit + runtime store so the buildGraph decision tree picks
// the runtime path. Returns the server, the runtime store, the
// audit store (so the test can Flush between writes), and a
// helper closure that posts a hook-event JSON directly into
// runtime via Normalize+RecordHook (bypasses the hook handler
// for hermetic seeding).
func newRuntimeGraphTestServer(t *testing.T) (*Server, *runtime.Store, *audit.Store) {
	t.Helper()
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	auditStore, err := audit.NewStore(filepath.Join(dir, "test.db"), logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = auditStore.Close() })

	cfg := &config.Config{
		Version: "1",
		Server:  config.ServerConfig{Port: 0},
		DBPath:  filepath.Join(dir, "test.db"),
		Agents:  map[string]config.Agent{},
	}
	srv := NewServer(cfg, filepath.Join(dir, "oktsec.yaml"), auditStore, identity.NewKeyStore(), sharedScanner, logger)
	rs := srv.runtimeStore()
	if rs == nil {
		t.Fatal("expected runtime store to auto-build")
	}
	return srv, rs, auditStore
}

// seedRuntimeEvent posts one normalized event into the runtime
// store. Tests use this instead of the hook handler so the
// seeded payload directly drives the runtime tables without
// audit + activity contention.
func seedRuntimeEvent(t *testing.T, rs *runtime.Store, body string, sessionID string, principalID string, ts time.Time, outcome runtime.OutcomeRefs) {
	t.Helper()
	env, err := runtime.Normalize([]byte(body), runtime.IdentityResolution{
		PrincipalID: principalID,
		ClientID:    "local-codex",
		SessionID:   sessionID,
	}, ts)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if err := rs.RecordHook(context.Background(), env, outcome); err != nil {
		t.Fatalf("record: %v", err)
	}
}

func graphResponse(t *testing.T, srv *Server, cookie *http.Cookie, handler http.Handler, rng string) map[string]any {
	t.Helper()
	url := "/dashboard/api/graph"
	if rng != "" {
		url += "?range=" + rng
	}
	req := httptest.NewRequest("GET", url, nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v; body=%s", err, w.Body.String())
	}
	return out
}

func nodeNames(g map[string]any) []string {
	out := []string{}
	if nodes, ok := g["nodes"].([]any); ok {
		for _, n := range nodes {
			if m, ok := n.(map[string]any); ok {
				if name, _ := m["name"].(string); name != "" {
					out = append(out, name)
				}
			}
		}
	}
	return out
}

func edgeKeys(g map[string]any) []string {
	out := []string{}
	if edges, ok := g["edges"].([]any); ok {
		for _, e := range edges {
			if m, ok := e.(map[string]any); ok {
				from, _ := m["from"].(string)
				to, _ := m["to"].(string)
				out = append(out, from+"->"+to)
			}
		}
	}
	return out
}

func toolEdgeKeys(g map[string]any) []string {
	out := []string{}
	if edges, ok := g["tool_edges"].([]any); ok {
		for _, e := range edges {
			if m, ok := e.(map[string]any); ok {
				agent, _ := m["agent"].(string)
				tool, _ := m["tool"].(string)
				total := 0
				if t, ok := m["total"].(float64); ok {
					total = int(t)
				}
				out = append(out, agent+"->"+tool+":"+strItoa(total))
			}
		}
	}
	return out
}

func strItoa(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-" + strItoa(-n)
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// TestRuntimeGraph_RootToolCall — root-only tool call shows
// local-codex -> Read in the runtime graph.
func TestRuntimeGraph_RootToolCall(t *testing.T) {
	srv, rs, auditStore := newRuntimeGraphTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"SessionStart","session_id":"sess-root"}`,
		"sess-root", "local-codex", now.Add(-5*time.Minute), runtime.OutcomeRefs{})
	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"PreToolUse","session_id":"sess-root","tool_name":"Read","tool_use_id":"u1"}`,
		"sess-root", "local-codex", now.Add(-4*time.Minute), runtime.OutcomeRefs{Status: "delivered"})
	auditStore.Flush()
	srv.invalidateGraphCache()

	g := graphResponse(t, srv, cookie, handler, "1h")
	nodes := strings.Join(nodeNames(g), ",")
	if !strings.Contains(nodes, "local-codex") {
		t.Errorf("expected local-codex node; got %s", nodes)
	}
	tools := strings.Join(toolEdgeKeys(g), ",")
	if !strings.Contains(tools, "local-codex->Read:1") {
		t.Errorf("expected tool edge local-codex->Read:1; got %s", tools)
	}
}

// TestRuntimeGraph_SubagentToolCall — root + subagent + tool
// chain renders as root -> subagent/research -> Read.
func TestRuntimeGraph_SubagentToolCall(t *testing.T) {
	srv, rs, auditStore := newRuntimeGraphTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"SessionStart","session_id":"sess-sub"}`,
		"sess-sub", "local-codex", now.Add(-5*time.Minute), runtime.OutcomeRefs{})
	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"SubagentStart","session_id":"sess-sub","agent_id":"sa-1","agent_type":"research"}`,
		"sess-sub", "local-codex", now.Add(-4*time.Minute), runtime.OutcomeRefs{})
	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"PreToolUse","session_id":"sess-sub","agent_id":"sa-1","agent_type":"research","tool_name":"Read","tool_use_id":"u2"}`,
		"sess-sub", "local-codex", now.Add(-3*time.Minute), runtime.OutcomeRefs{Status: "delivered"})
	auditStore.Flush()
	srv.invalidateGraphCache()

	g := graphResponse(t, srv, cookie, handler, "1h")
	edges := strings.Join(edgeKeys(g), ",")
	tools := strings.Join(toolEdgeKeys(g), ",")
	if !strings.Contains(edges, "local-codex->subagent/research") {
		t.Errorf("expected actor edge local-codex->subagent/research; got edges=%s", edges)
	}
	if !strings.Contains(tools, "subagent/research->Read:1") {
		t.Errorf("expected tool edge subagent/research->Read:1; got tools=%s", tools)
	}
}

// TestRuntimeGraph_LazySubagentKeepsParent — even when the only
// event is a tool call from a subagent (no SubagentStart), the
// inferred root + subagent + tool render.
func TestRuntimeGraph_LazySubagentKeepsParent(t *testing.T) {
	srv, rs, auditStore := newRuntimeGraphTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"PreToolUse","session_id":"sess-lazy","agent_id":"sa-late","agent_type":"investigator","tool_name":"Bash","tool_use_id":"u3"}`,
		"sess-lazy", "local-codex", now.Add(-2*time.Minute), runtime.OutcomeRefs{Status: "delivered"})
	auditStore.Flush()
	srv.invalidateGraphCache()

	g := graphResponse(t, srv, cookie, handler, "1h")
	edges := strings.Join(edgeKeys(g), ",")
	tools := strings.Join(toolEdgeKeys(g), ",")
	if !strings.Contains(edges, "->subagent/investigator") {
		t.Errorf("expected actor edge ending in subagent/investigator; got edges=%s", edges)
	}
	if !strings.Contains(tools, "subagent/investigator->Bash:1") {
		t.Errorf("expected tool edge subagent/investigator->Bash:1; got tools=%s", tools)
	}
}

// TestRuntimeGraph_HeartbeatOnlyDoesNotFallbackToLegacy seeds a
// heartbeat in runtime AND a legacy audit row that would render
// as local-codex -> list_agents under the audit-driven graph.
// The runtime path must short-circuit the legacy fallback so the
// audit-side phantom never resurfaces.
func TestRuntimeGraph_HeartbeatOnlyDoesNotFallbackToLegacy(t *testing.T) {
	srv, rs, auditStore := newRuntimeGraphTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	// Heartbeat event in runtime — filtered before projection.
	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"SessionStart","session_id":"heartbeat-2026-graph"}`,
		"heartbeat-2026-graph", "local-codex", now.Add(-3*time.Minute), runtime.OutcomeRefs{})
	// Legacy audit row that the old graph would surface.
	auditStore.Log(audit.Entry{
		ID:             "legacy-1",
		Timestamp:      now.Add(-5 * time.Minute).Format(time.RFC3339),
		FromAgent:      "local-codex",
		ToAgent:        "list_agents",
		Status:         "delivered",
		PolicyDecision: "allow",
	})
	auditStore.Flush()
	srv.invalidateGraphCache()

	g := graphResponse(t, srv, cookie, handler, "1h")
	for _, key := range edgeKeys(g) {
		if key == "local-codex->list_agents" {
			t.Errorf("legacy audit edge resurfaced under heartbeat-only runtime: %v", edgeKeys(g))
		}
	}
}

// TestRuntimeGraph_DedupesPreAndPostToolUse — Pre+Post events
// sharing a tool_use_id must produce one tool edge with total 1.
func TestRuntimeGraph_DedupesPreAndPostToolUse(t *testing.T) {
	srv, rs, auditStore := newRuntimeGraphTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"PreToolUse","session_id":"sess-dedupe","tool_name":"Read","tool_use_id":"shared-1"}`,
		"sess-dedupe", "local-codex", now.Add(-4*time.Minute), runtime.OutcomeRefs{Status: "delivered"})
	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"PostToolUse","session_id":"sess-dedupe","tool_name":"Read","tool_use_id":"shared-1","tool_response":"ok"}`,
		"sess-dedupe", "local-codex", now.Add(-3*time.Minute), runtime.OutcomeRefs{Status: "delivered"})
	auditStore.Flush()
	srv.invalidateGraphCache()

	g := graphResponse(t, srv, cookie, handler, "1h")
	tools := toolEdgeKeys(g)
	for _, key := range tools {
		if strings.HasPrefix(key, "local-codex->Read:") && key != "local-codex->Read:1" {
			t.Errorf("tool edge total != 1 for deduped Pre/Post pair: %s", key)
		}
	}
}

// TestRuntimeGraph_DoesNotCreateShadowEdgesForActorHierarchy —
// observed root->subagent must NOT appear in shadow_edges.
// Actor hierarchy is not policy ACL.
func TestRuntimeGraph_DoesNotCreateShadowEdgesForActorHierarchy(t *testing.T) {
	srv, rs, auditStore := newRuntimeGraphTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"SessionStart","session_id":"sess-shadow"}`,
		"sess-shadow", "local-codex", now.Add(-5*time.Minute), runtime.OutcomeRefs{})
	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"SubagentStart","session_id":"sess-shadow","agent_id":"sa-2","agent_type":"explorer"}`,
		"sess-shadow", "local-codex", now.Add(-4*time.Minute), runtime.OutcomeRefs{})
	auditStore.Flush()
	srv.invalidateGraphCache()

	g := graphResponse(t, srv, cookie, handler, "1h")
	if shadow, ok := g["shadow_edges"].([]any); ok && len(shadow) > 0 {
		t.Errorf("ShadowEdges non-empty for runtime actor hierarchy: %v", shadow)
	}
}

// TestRuntimeGraph_RangeFilter — an event 2h ago must NOT
// appear in the 1h window but MUST appear in the 6h window.
func TestRuntimeGraph_RangeFilter(t *testing.T) {
	srv, rs, auditStore := newRuntimeGraphTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"PreToolUse","session_id":"sess-range","tool_name":"Read","tool_use_id":"r1"}`,
		"sess-range", "local-codex", now.Add(-2*time.Hour), runtime.OutcomeRefs{Status: "delivered"})
	auditStore.Flush()
	srv.invalidateGraphCache()

	g1h := graphResponse(t, srv, cookie, handler, "1h")
	if strings.Contains(strings.Join(toolEdgeKeys(g1h), ","), "local-codex->Read") {
		t.Errorf("event from 2h ago leaked into 1h window: %v", toolEdgeKeys(g1h))
	}

	srv.invalidateGraphCache()
	g6h := graphResponse(t, srv, cookie, handler, "6h")
	if !strings.Contains(strings.Join(toolEdgeKeys(g6h), ","), "local-codex->Read") {
		t.Errorf("event from 2h ago missing from 6h window: %v", toolEdgeKeys(g6h))
	}
}

// TestRuntimeGraph_NoRawPayloadInJSON — the JSON response must
// not contain raw tool input/output strings; only hashes are
// allowed off the persisted runtime row.
func TestRuntimeGraph_NoRawPayloadInJSON(t *testing.T) {
	srv, rs, auditStore := newRuntimeGraphTestServer(t)
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)
	now := time.Now().UTC()

	seedRuntimeEvent(t, rs,
		`{"hook_event_name":"PreToolUse","session_id":"sess-redact","tool_name":"Bash","tool_use_id":"r2","tool_input":{"command":"echo SUPER_SECRET"}}`,
		"sess-redact", "local-codex", now.Add(-2*time.Minute), runtime.OutcomeRefs{Status: "delivered"})
	auditStore.Flush()
	srv.invalidateGraphCache()

	req := httptest.NewRequest("GET", "/dashboard/api/graph?range=1h", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	body := w.Body.String()
	if strings.Contains(body, "SUPER_SECRET") {
		t.Errorf("graph JSON leaks raw tool input: %s", body)
	}
}
