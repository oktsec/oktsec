package proxy

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/identity"
)

// agentAPINameRe validates agent names: alphanumeric, hyphens, underscores.
var agentAPINameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

// AgentAPI handles REST endpoints for agent CRUD operations.
type AgentAPI struct {
	cfg     *config.Config
	cfgPath string
	keys    *identity.KeyStore
	audit   *audit.Store
	logger  *slog.Logger
}

// NewAgentAPI creates the agent REST API handler.
func NewAgentAPI(cfg *config.Config, cfgPath string, keys *identity.KeyStore, auditStore *audit.Store, logger *slog.Logger) *AgentAPI {
	return &AgentAPI{
		cfg:     cfg,
		cfgPath: cfgPath,
		keys:    keys,
		audit:   auditStore,
		logger:  logger,
	}
}

// Register mounts agent API routes on the given mux.
func (a *AgentAPI) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/agents", a.list)
	mux.HandleFunc("POST /v1/agents", a.create)
	mux.HandleFunc("GET /v1/agents/{name}", a.get)
	mux.HandleFunc("PUT /v1/agents/{name}", a.update)
	mux.HandleFunc("DELETE /v1/agents/{name}", a.delete)
	mux.HandleFunc("POST /v1/agents/{name}/keys", a.rotateKeys)
	mux.HandleFunc("POST /v1/agents/{name}/suspend", a.toggleSuspend)
}

// AgentResponse is the JSON representation of an agent.
type AgentResponse struct {
	Name           string   `json:"name"`
	Description    string   `json:"description,omitempty"`
	CanMessage     []string `json:"can_message"`
	BlockedContent []string `json:"blocked_content,omitempty"`
	AllowedTools   []string `json:"allowed_tools,omitempty"`
	Suspended      bool     `json:"suspended"`
	Location       string   `json:"location,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	CreatedBy      string   `json:"created_by,omitempty"`
	CreatedAt      string   `json:"created_at,omitempty"`
	HasKey         bool     `json:"has_key"`
}

// AgentCreateRequest is the JSON body for creating an agent.
type AgentCreateRequest struct {
	Name           string   `json:"name"`
	Description    string   `json:"description,omitempty"`
	CanMessage     []string `json:"can_message"`
	BlockedContent []string `json:"blocked_content,omitempty"`
	AllowedTools   []string `json:"allowed_tools,omitempty"`
	Location       string   `json:"location,omitempty"`
	Tags           []string `json:"tags,omitempty"`
}

// AgentUpdateRequest is the JSON body for updating an agent.
type AgentUpdateRequest struct {
	Description    *string  `json:"description,omitempty"`
	CanMessage     []string `json:"can_message,omitempty"`
	BlockedContent []string `json:"blocked_content,omitempty"`
	AllowedTools   []string `json:"allowed_tools,omitempty"`
	Location       *string  `json:"location,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	Suspended      *bool    `json:"suspended,omitempty"`
}

func (a *AgentAPI) agentToResponse(name string, agent config.Agent) AgentResponse {
	_, hasKey := a.keys.Get(name)
	return AgentResponse{
		Name:           name,
		Description:    agent.Description,
		CanMessage:     agent.CanMessage,
		BlockedContent: agent.BlockedContent,
		AllowedTools:   agent.AllowedTools,
		Suspended:      agent.Suspended,
		Location:       agent.Location,
		Tags:           agent.Tags,
		CreatedBy:      agent.CreatedBy,
		CreatedAt:      agent.CreatedAt,
		HasKey:         hasKey,
	}
}

func (a *AgentAPI) list(w http.ResponseWriter, r *http.Request) {
	agents := make([]AgentResponse, 0, len(a.cfg.Agents))
	for name, agent := range a.cfg.Agents {
		agents = append(agents, a.agentToResponse(name, agent))
	}
	writeJSON(w, http.StatusOK, agents)
}

func (a *AgentAPI) get(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	agent, ok := a.cfg.Agents[name]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
		return
	}
	writeJSON(w, http.StatusOK, a.agentToResponse(name, agent))
}

func (a *AgentAPI) create(w http.ResponseWriter, r *http.Request) {
	var req AgentCreateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || !agentAPINameRe.MatchString(req.Name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid agent name (alphanumeric, hyphens, underscores)"})
		return
	}

	if _, exists := a.cfg.Agents[req.Name]; exists {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "agent already exists"})
		return
	}

	if a.cfg.Agents == nil {
		a.cfg.Agents = make(map[string]config.Agent)
	}

	agent := config.Agent{
		CanMessage:     req.CanMessage,
		Description:    strings.TrimSpace(req.Description),
		CreatedBy:      "api",
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
		Location:       strings.TrimSpace(req.Location),
		Tags:           req.Tags,
		BlockedContent: req.BlockedContent,
		AllowedTools:   req.AllowedTools,
	}
	a.cfg.Agents[req.Name] = agent
	a.saveConfig("agent create")

	writeJSON(w, http.StatusCreated, a.agentToResponse(req.Name, agent))
}

func (a *AgentAPI) update(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	agent, ok := a.cfg.Agents[name]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
		return
	}

	var req AgentUpdateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.Description != nil {
		agent.Description = strings.TrimSpace(*req.Description)
	}
	if req.CanMessage != nil {
		agent.CanMessage = req.CanMessage
	}
	if req.BlockedContent != nil {
		agent.BlockedContent = req.BlockedContent
	}
	if req.AllowedTools != nil {
		agent.AllowedTools = req.AllowedTools
	}
	if req.Location != nil {
		agent.Location = strings.TrimSpace(*req.Location)
	}
	if req.Tags != nil {
		agent.Tags = req.Tags
	}
	if req.Suspended != nil {
		agent.Suspended = *req.Suspended
	}

	a.cfg.Agents[name] = agent
	a.saveConfig("agent update")

	writeJSON(w, http.StatusOK, a.agentToResponse(name, agent))
}

func (a *AgentAPI) delete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, ok := a.cfg.Agents[name]; !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
		return
	}

	delete(a.cfg.Agents, name)
	a.saveConfig("agent delete")

	w.WriteHeader(http.StatusNoContent)
}

func (a *AgentAPI) rotateKeys(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, ok := a.cfg.Agents[name]; !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
		return
	}

	if a.cfg.Identity.KeysDir == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "keys_dir not configured"})
		return
	}

	// Revoke old key if it exists
	if oldPub, ok := a.keys.Get(name); ok {
		fingerprint := identity.Fingerprint(oldPub)
		if err := a.audit.RevokeKey(fingerprint, name, "key rotation via API"); err != nil {
			a.logger.Error("failed to revoke old key", "error", err, "agent", name)
		}
	}

	// Generate new keypair
	kp, err := identity.GenerateKeypair(name)
	if err != nil {
		a.logger.Error("keygen failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "key generation failed"})
		return
	}

	if err := os.MkdirAll(a.cfg.Identity.KeysDir, 0o700); err != nil {
		a.logger.Error("cannot create keys dir", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot create keys directory"})
		return
	}

	if err := kp.Save(a.cfg.Identity.KeysDir); err != nil {
		a.logger.Error("save key failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "key save failed"})
		return
	}

	// Reload keys
	if err := a.keys.ReloadFromDir(a.cfg.Identity.KeysDir); err != nil {
		a.logger.Error("key reload failed", "error", err)
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":      "rotated",
		"agent":       name,
		"fingerprint": identity.Fingerprint(kp.PublicKey),
	})
}

func (a *AgentAPI) toggleSuspend(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	agent, ok := a.cfg.Agents[name]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
		return
	}

	agent.Suspended = !agent.Suspended
	a.cfg.Agents[name] = agent
	a.saveConfig("agent suspend toggle")

	writeJSON(w, http.StatusOK, map[string]string{
		"agent":     name,
		"suspended": boolStr(agent.Suspended),
	})
}

func (a *AgentAPI) saveConfig(op string) {
	if a.cfgPath == "" {
		return
	}
	if err := a.cfg.Save(a.cfgPath); err != nil {
		a.logger.Error("failed to save config after "+op, "error", err)
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
