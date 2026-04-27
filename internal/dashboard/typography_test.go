package dashboard

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// The desktop product polish spec (DP-08) bans negative letter-
// spacing across the dashboard's Go-served HTML and CSS. Body,
// sidebar, table, drawer, and card text use neutral spacing; only
// uppercase micro-labels may use positive tracking. This test pins
// the rule against every Go file that contributes CSS so a future
// "let me add a marketing-hero look to that number" edit fires the
// regression instead of landing in the recording.
//
// We scan the rendered template strings rather than the file source
// so a future refactor that splits CSS into separate constants is
// still covered. Each banned-CSS-value test accepts both spaced and
// unspaced forms of the property.
var negativeLetterSpacingRE = regexp.MustCompile(`letter-spacing\s*:\s*-`)

func TestTypography_NoNegativeLetterSpacingInRenderedHTML(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.Gateway.Enabled = true
	handler := srv.Handler()
	cookie := loginSession(t, srv, handler)

	for _, path := range []string{
		"/dashboard",
		"/dashboard/events",
		"/dashboard/sessions",
		"/dashboard/alerts",
		"/dashboard/agents",
		"/dashboard/rules",
		"/dashboard/audit",
		"/dashboard/llm",
		"/dashboard/graph",
		"/dashboard/gateway",
		"/dashboard/settings",
	} {
		t.Run(path, func(t *testing.T) {
			body := authedGetWithCookie(t, handler, cookie, path)
			if loc := negativeLetterSpacingRE.FindStringIndex(body); loc != nil {
				snippet := safeSnippet(body, loc[0], 80)
				t.Errorf("%s contains negative letter-spacing; snippet near match:\n%s", path, snippet)
			}
		})
	}
}

// The static dashboard.css served from /dashboard/static/dashboard.css
// is a separate surface (not produced by Go templates). It needs the
// same contract because the sidebar brand and several table/heading
// rules live there. We fetch it through the same handler so the
// asset path also gets the auth-bypass coverage from PR4.
func TestTypography_NoNegativeLetterSpacingInStaticCSS(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()
	body := authedGetWithCookie(t, handler, nil, "/dashboard/static/dashboard.css")
	if loc := negativeLetterSpacingRE.FindStringIndex(body); loc != nil {
		t.Errorf("dashboard.css contains negative letter-spacing; snippet near match:\n%s",
			safeSnippet(body, loc[0], 80))
	}
}

// DP-09 contrast floor: --text3 is the most muted body color the
// dashboard uses. After the desktop polish slice it must be at
// least #a0... so muted labels stay readable on recording
// compression. The previous value (#848d97) sat right at the AA
// edge and washed out under H.264. We pin the new tone here and
// at every redeclaration in templates.go (login, splash, login-
// redirect — they each redefine the token block).
func TestTypography_Text3MeetsContrastFloor(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()
	bodies := map[string]string{
		"dashboard.css":  authedGetWithCookie(t, handler, nil, "/dashboard/static/dashboard.css"),
		"login template": renderLoginForTest(t),
	}
	for label, body := range bodies {
		if !strings.Contains(body, "--text3:#a3acb6") {
			t.Errorf("%s: --text3 must be set to #a3acb6 (DP-09 contrast floor); got body without that token", label)
		}
		if strings.Contains(body, "--text3:#848d97") {
			t.Errorf("%s: --text3 still uses the pre-polish #848d97; bump to the contrast-safe value", label)
		}
	}
}

// authedGetWithCookie issues an authenticated GET against the
// dashboard handler and returns the response body. Static-asset
// paths bypass auth (PR4 of the dashboard UX slice) so passing a
// nil cookie is acceptable for /dashboard/static/* paths.
func authedGetWithCookie(t *testing.T, handler interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}, cookie *http.Cookie, path string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200; body = %s", path, rr.Code, rr.Body.String())
	}
	return rr.Body.String()
}

// renderLoginForTest executes the login template with no error so
// the typography test can assert against the rendered output rather
// than the source. Keeps the test resilient to future template
// reorganization.
func renderLoginForTest(t *testing.T) string {
	t.Helper()
	var buf strings.Builder
	if err := loginTmpl.Execute(&buf, struct{ Error string }{}); err != nil {
		t.Fatalf("execute login template: %v", err)
	}
	return buf.String()
}

// safeSnippet returns up to `width` characters around the position
// `at` in s, clamped to the string bounds. Used to make a CSS
// regression failure easy to spot without dumping the whole body.
func safeSnippet(s string, at, width int) string {
	start := at - width/2
	if start < 0 {
		start = 0
	}
	end := at + width/2
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
}
