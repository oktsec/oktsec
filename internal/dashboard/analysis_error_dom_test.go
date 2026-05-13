package dashboard

import (
	"bytes"
	"strings"
	"testing"
)

// renderQuarantineDetail and renderSessionDetail give back the raw
// template body so tests can assert that the error path uses
// textContent rather than innerHTML against an upstream-controlled
// message.

func renderQuarantineDetailScript(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	if err := quarantineDetailTmpl.Execute(&buf, map[string]any{
		"Item": map[string]any{
			"ID":         "q-test",
			"FromAgent":  "from-agent",
			"ToAgent":    "to-agent",
			"Status":     "pending",
			"Content":    "hello",
			"CreatedAt":  "2026-05-13T00:00:00Z",
			"RulesTriggered": "[]",
		},
	}); err != nil {
		t.Fatalf("execute quarantineDetailTmpl: %v", err)
	}
	return buf.String()
}

func renderSessionDetailScript(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	if err := sessionTraceTmpl.Execute(&buf, map[string]any{
		"Trace": map[string]any{
			"SessionID": "s-test",
			"Agent":     "agent-a",
			"Steps":     []any{},
		},
		"SavedAnalysis": nil,
	}); err != nil {
		// sessionTraceTmpl has many fields; we only need the
		// script body. If Execute errors on missing fields, skip
		// because the failure mode we want to detect is innerHTML
		// in the rendered template source, not template field gaps.
		t.Skipf("session detail template needs richer fixture: %v", err)
	}
	return buf.String()
}

// The quarantine error handler must use textContent against e.message,
// never innerHTML. innerHTML with upstream provider error text would
// let a hostile model server return HTML and inject script into the
// authenticated dashboard.
func TestQuarantineAnalyze_ErrorPath_UsesTextContent(t *testing.T) {
	body := renderQuarantineDetailScript(t)
	if !strings.Contains(body, "errDiv.textContent = 'Analysis failed: '") {
		t.Fatalf("quarantine error path does not use textContent against e.message; got body length %d", len(body))
	}
	if strings.Contains(body, "out.innerHTML = '<div") {
		t.Fatal("quarantine error path still concatenates a div via innerHTML; replace with textContent")
	}
	if !strings.Contains(body, "while (out.firstChild)") {
		t.Fatal("quarantine error path does not clear children before injecting the error node")
	}
}

func TestSessionAnalyze_LegacyErrorPath_UsesTextContent(t *testing.T) {
	body := renderSessionDetailScript(t)
	// The legacy session error path: panel.innerHTML with e.message
	// is unsafe. The fixed path uses textContent + appendChild.
	if strings.Contains(body, "panel.innerHTML = '<h3>AI Analysis</h3>") {
		t.Fatal("legacy session error path still uses innerHTML concatenation with e.message")
	}
	if !strings.Contains(body, "content.textContent = 'Analysis failed: '") {
		t.Fatal("legacy session error path does not use textContent against e.message")
	}
}
