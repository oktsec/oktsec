package dashboard

import (
	"strings"
	"testing"

	"github.com/oktsec/oktsec/internal/config"
)

// At 1440px desktop widths the Pipeline Health row clipped its
// last stage label ("Guard" → "Gua") because the heading + 11
// stages + a long rules/mode/chain summary all shared one flex
// row that overflowed mid-word. DP-SMOKE-04 fix: the summary
// carries a .pipeline-meta class, and a max-width:1599px media
// query flips it to flex-basis:100% so it wraps onto its own
// row beneath the stages on narrower desktop widths. 1920px+
// keeps the inline single-row layout.
//
// The test pins both halves of the contract: the .pipeline-meta
// class is on the summary div, and the media query is present in
// the rendered Overview <style> block. Removing either would let
// the clip regress without firing this test.
func TestPipelineMeta_HasResponsiveWrapHook(t *testing.T) {
	srv := newTestServer(t)
	// Populated state so the Overview renders the pipeline row
	// (the empty state hides the matrix and surrounding cards).
	srv.cfg.Agents["smoke-agent"] = config.Agent{}

	body := getOverviewBody(t, srv)

	if !strings.Contains(body, `class="pipeline-meta"`) {
		t.Errorf("Pipeline Health summary must carry class=\"pipeline-meta\" so the responsive wrap rule can target it")
	}
	if !strings.Contains(body, "@media(max-width:1599px){.pipeline-meta") {
		t.Errorf("Overview must include the .pipeline-meta media query that wraps the summary onto its own row at narrower desktop widths")
	}
}
