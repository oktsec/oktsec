package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 1. The login page renders with 200 and carries the contract copy
// the dashboard UX spec defines: brand, "Dashboard access" title,
// the "oktsec run" reference, and the visible "Access code" label.
// Each one is the operator-facing text that has to stay stable so a
// well-known login page renders the same way across releases.
func TestLogin_RendersContractCopy(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/dashboard/login", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		`>oktsec<`,
		"Dashboard access",
		"Access code",
		"oktsec run",
		"Local dashboard",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("login body missing %q", want)
		}
	}
}

// 2. The login page must not mention auth features that do not exist
// in the community edition. The dashboard UX spec lists these as
// hard-banned terms; a regression here would mislead operators or
// reviewers into thinking the local access-code flow is something
// it is not.
func TestLogin_DoesNotAdvertiseUnsupportedAuth(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/dashboard/login", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	body := strings.ToLower(rr.Body.String())
	for _, banned := range []string{"sso", "saml", "passkey", "rbac", "cloud login", "user account", "admin console", "enterprise login"} {
		if strings.Contains(body, banned) {
			t.Errorf("login body contains forbidden auth term %q", banned)
		}
	}
}

// 3. Form contract: posts to /dashboard/login, the input has the
// numeric constraints the access-code flow expects, and the visible
// label is wired to the input via for/id (not just sr-only). Spec
// rule: keep visible label, autocomplete=off, inputmode=numeric,
// pattern=\d{8}, maxlength=8, autofocus.
func TestLogin_FormContract(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/dashboard/login", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	body := rr.Body.String()
	for _, want := range []string{
		`action="/dashboard/login"`,
		`autocomplete="off"`,
		`<label for="login-code"`,
		`id="login-code"`,
		`name="code"`,
		`maxlength="8"`,
		`pattern="\d{8}"`,
		`inputmode="numeric"`,
		`autofocus`,
		`type="submit"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("login form missing required attribute / element %q", want)
		}
	}
}

// 4. Error renders inside a role="alert" so screen readers announce
// it the moment the page reaches the user. Spec contract.
func TestLogin_ErrorUsesAlertRole(t *testing.T) {
	var buf strings.Builder
	if err := loginTmpl.Execute(&buf, struct{ Error string }{Error: "Invalid code"}); err != nil {
		t.Fatalf("execute login template: %v", err)
	}
	body := buf.String()
	if !strings.Contains(body, `role="alert"`) {
		t.Errorf("error block must use role=\"alert\"; body = %s", body)
	}
	if !strings.Contains(body, "Invalid code") {
		t.Errorf("error message text not rendered; body = %s", body)
	}
}

// 5. Dashboard static assets (fonts, JS, images) must be reachable
// without a session. Otherwise the auth middleware redirects the
// browser's pre-auth font request to /dashboard/login HTML, which
// the browser tries to decode as a font and fails with a console
// error before the operator can sign in. Regression guard for the
// pre-auth asset 302 issue observed during dashboard smoke testing.
func TestLogin_StaticAssetsBypassAuth(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()

	for _, path := range []string{
		"/dashboard/static/dashboard.css",
		"/dashboard/static/fonts/Inter.woff2",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code == http.StatusFound {
			t.Errorf("GET %s without session returned 302 to login; static assets must bypass auth", path)
		}
		// 200 (asset present) and 404 (asset absent in this build) are
		// both acceptable here — the regression we are guarding is
		// "the browser gets HTML when it asks for a binary".
		if rr.Code != http.StatusOK && rr.Code != http.StatusNotFound {
			t.Errorf("GET %s status = %d; want 200 or 404", path, rr.Code)
		}
	}
}
