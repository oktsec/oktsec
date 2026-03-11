package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
}

func TestRequireAPIKey_EmptyKeyPassesThrough(t *testing.T) {
	handler := requireAPIKey("")(okHandler())

	req := httptest.NewRequest("GET", "/v1/agents", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireAPIKey_ValidBearerToken(t *testing.T) {
	handler := requireAPIKey("test-secret-key")(okHandler())

	req := httptest.NewRequest("GET", "/v1/agents", nil)
	req.Header.Set("Authorization", "Bearer test-secret-key")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireAPIKey_ValidXAPIKeyHeader(t *testing.T) {
	handler := requireAPIKey("test-secret-key")(okHandler())

	req := httptest.NewRequest("GET", "/v1/agents", nil)
	req.Header.Set("X-API-Key", "test-secret-key")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireAPIKey_MissingKey(t *testing.T) {
	handler := requireAPIKey("test-secret-key")(okHandler())

	req := httptest.NewRequest("GET", "/v1/agents", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), `"error":"unauthorized"`)
}

func TestRequireAPIKey_WrongKey(t *testing.T) {
	handler := requireAPIKey("test-secret-key")(okHandler())

	req := httptest.NewRequest("GET", "/v1/agents", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), `"error":"unauthorized"`)
}

func TestRequireAPIKey_WrongXAPIKey(t *testing.T) {
	handler := requireAPIKey("test-secret-key")(okHandler())

	req := httptest.NewRequest("GET", "/v1/agents", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireAPIKey_BearerPrecedenceOverXAPIKey(t *testing.T) {
	handler := requireAPIKey("correct-key")(okHandler())

	// Both headers set; Bearer is checked first.
	req := httptest.NewRequest("GET", "/v1/agents", nil)
	req.Header.Set("Authorization", "Bearer correct-key")
	req.Header.Set("X-API-Key", "wrong-key")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireAPIKey_BearerWithExtraSpaces(t *testing.T) {
	handler := requireAPIKey("my-key")(okHandler())

	req := httptest.NewRequest("GET", "/v1/agents", nil)
	req.Header.Set("Authorization", "Bearer   my-key  ")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireAPIKey_NonBearerAuthScheme(t *testing.T) {
	handler := requireAPIKey("my-key")(okHandler())

	// Basic auth scheme should not be parsed as Bearer.
	req := httptest.NewRequest("GET", "/v1/agents", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireAPIKey_JSONContentType(t *testing.T) {
	handler := requireAPIKey("secret")(okHandler())

	req := httptest.NewRequest("GET", "/v1/agents", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
}
