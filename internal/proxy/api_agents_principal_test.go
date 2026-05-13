package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The HTTP agent CRUD must refuse a reserved principal name like
// _proxy. Accepting it would let an external caller register a
// "_proxy" agent and a subsequent key rotation would overwrite the
// audit-chain signing key.
func TestAgentAPI_Create_RejectsReservedPrincipal(t *testing.T) {
	_, mux := newTestAgentAPI(t)

	for _, name := range []string{"_proxy", "_internal", "_anything"} {
		t.Run(name, func(t *testing.T) {
			body, _ := json.Marshal(AgentCreateRequest{Name: name})
			req := httptest.NewRequest("POST", "/v1/agents", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code, "POST /v1/agents %q must return 400", name)
		})
	}
}

// Traversal names must also be refused with a 400. Pinning this here
// (in addition to the existing TestAgentAPI_Create_InvalidName) makes
// the contract explicit for future contributors.
func TestAgentAPI_Create_RejectsTraversalPrincipal(t *testing.T) {
	_, mux := newTestAgentAPI(t)

	body, _ := json.Marshal(AgentCreateRequest{Name: "../../escape"})
	req := httptest.NewRequest("POST", "/v1/agents", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
