package dashboard

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newDownstream() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func doCSRF(t *testing.T, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Host = "localhost:8080"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	csrfGuard(newDownstream()).ServeHTTP(rr, req)
	return rr
}

func TestCSRFGuard_AllowsSafeMethods(t *testing.T) {
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		rr := doCSRF(t, m, "/dashboard/api/foo", nil)
		if rr.Code != http.StatusOK {
			t.Errorf("%s without origin should pass, got %d", m, rr.Code)
		}
	}
}

func TestCSRFGuard_RejectsCrossOriginPOST(t *testing.T) {
	rr := doCSRF(t, http.MethodPost, "/dashboard/api/foo", map[string]string{
		"Origin": "http://evil.example.com",
	})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("cross-origin POST should be 403, got %d", rr.Code)
	}
}

// Browsers always attach Origin on state-changing requests, so an absent
// Origin means a non-browser client (curl, SDK, test harness). Those are
// outside the browser-CSRF threat model and should pass through — the real
// gate for non-browser clients is the session cookie + access code.
func TestCSRFGuard_AllowsMissingOriginOnPOST(t *testing.T) {
	rr := doCSRF(t, http.MethodPost, "/dashboard/api/foo", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST without origin+referer (non-browser client) should pass, got %d", rr.Code)
	}
}

func TestCSRFGuard_AllowsSameOriginPOST(t *testing.T) {
	rr := doCSRF(t, http.MethodPost, "/dashboard/api/foo", map[string]string{
		"Origin": "http://localhost:8080",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("same-origin POST should pass, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestCSRFGuard_FallsBackToReferer(t *testing.T) {
	rr := doCSRF(t, http.MethodPost, "/dashboard/api/foo", map[string]string{
		"Referer": "http://localhost:8080/dashboard",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("referer-matched POST should pass, got %d", rr.Code)
	}
}

func TestCSRFGuard_LoginExempt(t *testing.T) {
	rr := doCSRF(t, http.MethodPost, "/dashboard/login", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("login POST should bypass csrf guard, got %d", rr.Code)
	}
}

func TestCSRFGuard_DeleteMethodChecked(t *testing.T) {
	rr := doCSRF(t, http.MethodDelete, "/dashboard/rules/custom/1", map[string]string{
		"Origin": "http://evil.example.com",
	})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("cross-origin DELETE should be 403, got %d", rr.Code)
	}
}
