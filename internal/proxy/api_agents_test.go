package proxy

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestAgentAPI(t *testing.T) (*AgentAPI, *http.ServeMux) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		Version: "1",
		Identity: config.IdentityConfig{
			KeysDir: filepath.Join(dir, "keys"),
		},
		Agents: map[string]config.Agent{
			"existing-agent": {
				CanMessage:  []string{"other-agent"},
				Description: "Test agent",
				CreatedBy:   "test",
			},
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	keys := identity.NewKeyStore()
	auditStore, err := audit.NewStore(filepath.Join(dir, "test.db"), logger)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditStore.Close() })

	api := NewAgentAPI(cfg, filepath.Join(dir, "oktsec.yaml"), keys, auditStore, logger)
	mux := http.NewServeMux()
	api.Register(mux)
	return api, mux
}

func TestAgentAPI_List(t *testing.T) {
	_, mux := newTestAgentAPI(t)

	req := httptest.NewRequest("GET", "/v1/agents", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var agents []AgentResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &agents))
	assert.Len(t, agents, 1)
	assert.Equal(t, "existing-agent", agents[0].Name)
}

func TestAgentAPI_Get(t *testing.T) {
	_, mux := newTestAgentAPI(t)

	req := httptest.NewRequest("GET", "/v1/agents/existing-agent", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var agent AgentResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &agent))
	assert.Equal(t, "existing-agent", agent.Name)
	assert.Equal(t, "Test agent", agent.Description)
}

func TestAgentAPI_Get_NotFound(t *testing.T) {
	_, mux := newTestAgentAPI(t)

	req := httptest.NewRequest("GET", "/v1/agents/nonexistent", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAgentAPI_Create(t *testing.T) {
	api, mux := newTestAgentAPI(t)

	body, _ := json.Marshal(AgentCreateRequest{
		Name:        "new-agent",
		Description: "A new agent",
		CanMessage:  []string{"existing-agent"},
		Tags:        []string{"prod"},
	})

	req := httptest.NewRequest("POST", "/v1/agents", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var agent AgentResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &agent))
	assert.Equal(t, "new-agent", agent.Name)
	assert.Equal(t, "A new agent", agent.Description)
	assert.Equal(t, "api", agent.CreatedBy)

	// Verify in config
	_, exists := api.cfg.Agents["new-agent"]
	assert.True(t, exists)
}

func TestAgentAPI_Create_InvalidName(t *testing.T) {
	_, mux := newTestAgentAPI(t)

	body, _ := json.Marshal(AgentCreateRequest{Name: "bad name!"})
	req := httptest.NewRequest("POST", "/v1/agents", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAgentAPI_Create_Conflict(t *testing.T) {
	_, mux := newTestAgentAPI(t)

	body, _ := json.Marshal(AgentCreateRequest{Name: "existing-agent"})
	req := httptest.NewRequest("POST", "/v1/agents", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestAgentAPI_Create_InvalidJSON(t *testing.T) {
	_, mux := newTestAgentAPI(t)

	req := httptest.NewRequest("POST", "/v1/agents", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAgentAPI_Update(t *testing.T) {
	api, mux := newTestAgentAPI(t)

	desc := "Updated description"
	body, _ := json.Marshal(AgentUpdateRequest{
		Description: &desc,
		CanMessage:  []string{"agent-a", "agent-b"},
	})

	req := httptest.NewRequest("PUT", "/v1/agents/existing-agent", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var agent AgentResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &agent))
	assert.Equal(t, "Updated description", agent.Description)
	assert.Equal(t, []string{"agent-a", "agent-b"}, agent.CanMessage)

	// Verify in config
	assert.Equal(t, "Updated description", api.cfg.Agents["existing-agent"].Description)
}

func TestAgentAPI_Update_NotFound(t *testing.T) {
	_, mux := newTestAgentAPI(t)

	body, _ := json.Marshal(AgentUpdateRequest{})
	req := httptest.NewRequest("PUT", "/v1/agents/nonexistent", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAgentAPI_Update_PartialFields(t *testing.T) {
	api, mux := newTestAgentAPI(t)

	// Only update suspended, leave everything else
	suspended := true
	body, _ := json.Marshal(AgentUpdateRequest{Suspended: &suspended})

	req := httptest.NewRequest("PUT", "/v1/agents/existing-agent", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, api.cfg.Agents["existing-agent"].Suspended)
	// Description should be unchanged
	assert.Equal(t, "Test agent", api.cfg.Agents["existing-agent"].Description)
}

func TestAgentAPI_Delete(t *testing.T) {
	api, mux := newTestAgentAPI(t)

	req := httptest.NewRequest("DELETE", "/v1/agents/existing-agent", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	_, exists := api.cfg.Agents["existing-agent"]
	assert.False(t, exists)
}

func TestAgentAPI_Delete_NotFound(t *testing.T) {
	_, mux := newTestAgentAPI(t)

	req := httptest.NewRequest("DELETE", "/v1/agents/nonexistent", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAgentAPI_ToggleSuspend(t *testing.T) {
	api, mux := newTestAgentAPI(t)

	// First toggle: false -> true
	req := httptest.NewRequest("POST", "/v1/agents/existing-agent/suspend", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, api.cfg.Agents["existing-agent"].Suspended)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "true", resp["suspended"])

	// Second toggle: true -> false
	req = httptest.NewRequest("POST", "/v1/agents/existing-agent/suspend", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.False(t, api.cfg.Agents["existing-agent"].Suspended)
}

func TestAgentAPI_ToggleSuspend_NotFound(t *testing.T) {
	_, mux := newTestAgentAPI(t)

	req := httptest.NewRequest("POST", "/v1/agents/nonexistent/suspend", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAgentAPI_RotateKeys(t *testing.T) {
	_, mux := newTestAgentAPI(t)

	req := httptest.NewRequest("POST", "/v1/agents/existing-agent/keys", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "rotated", resp["status"])
	assert.Equal(t, "existing-agent", resp["agent"])
	assert.NotEmpty(t, resp["fingerprint"])
}

func TestAgentAPI_RotateKeys_NotFound(t *testing.T) {
	_, mux := newTestAgentAPI(t)

	req := httptest.NewRequest("POST", "/v1/agents/nonexistent/keys", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAgentAPI_RotateKeys_NoKeysDir(t *testing.T) {
	api, mux := newTestAgentAPI(t)
	api.cfg.Identity.KeysDir = ""

	req := httptest.NewRequest("POST", "/v1/agents/existing-agent/keys", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAgentAPI_Create_EmptyName(t *testing.T) {
	_, mux := newTestAgentAPI(t)

	body, _ := json.Marshal(AgentCreateRequest{Name: ""})
	req := httptest.NewRequest("POST", "/v1/agents", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAgentAPI_Update_InvalidJSON(t *testing.T) {
	_, mux := newTestAgentAPI(t)

	req := httptest.NewRequest("PUT", "/v1/agents/existing-agent", bytes.NewReader([]byte("bad")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
