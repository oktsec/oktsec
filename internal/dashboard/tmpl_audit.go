package dashboard

import "html/template"

var auditTmpl = template.Must(template.New("audit").Funcs(tmplFuncs).Parse(layoutHead + `
<style>
/* ── Agent Runtime Posture (Phase 4A) ─────────────────── */
.rp-hero{display:flex;align-items:flex-start;gap:24px;padding:28px 32px;background:linear-gradient(135deg,var(--surface) 0%,rgba(56,139,253,0.04) 100%);border:1px solid var(--border);border-radius:14px;margin-bottom:24px;position:relative;overflow:hidden}
.rp-hero::after{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--accent-light),transparent);opacity:0.4}
.rp-hero-body{flex:1}
.rp-eyebrow{font-size:0.65rem;text-transform:uppercase;letter-spacing:0.6px;color:var(--text3);font-weight:600;margin-bottom:6px}
.rp-title{font-size:1.25rem;font-weight:700;color:var(--text);letter-spacing:0;margin-bottom:6px}
.rp-summary{font-size:0.875rem;color:var(--text2);line-height:1.55;max-width:780px}
.rp-status-pill{display:inline-block;padding:4px 12px;border-radius:6px;font-size:0.7rem;font-weight:600;letter-spacing:0.04em;text-transform:uppercase;margin-left:12px;vertical-align:middle}
.rp-status-pill.s-protected{background:rgba(63,185,80,0.12);color:var(--success);border:1px solid rgba(63,185,80,0.30)}
.rp-status-pill.s-observing{background:rgba(56,139,253,0.10);color:var(--accent);border:1px solid rgba(56,139,253,0.25)}
.rp-status-pill.s-degraded{background:rgba(210,153,34,0.10);color:var(--warn);border:1px solid rgba(210,153,34,0.25)}
.rp-status-pill.s-blind{background:rgba(248,81,73,0.10);color:var(--danger);border:1px solid rgba(248,81,73,0.25)}
.rp-status-pill.s-setup_pending{background:transparent;color:var(--text3);border:1px solid var(--border)}

.rp-section-title{font-size:0.6875rem;text-transform:uppercase;letter-spacing:0.6px;color:var(--text3);font-weight:600;margin:24px 0 12px;padding-left:2px}
.rp-dim-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin-bottom:24px}
.rp-dim{padding:14px 16px;background:var(--surface);border:1px solid var(--border);border-radius:10px}
.rp-dim-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:6px}
.rp-dim-label{font-size:0.8125rem;font-weight:600;color:var(--text)}
.rp-dim-pill{display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.62rem;font-weight:700;text-transform:uppercase;letter-spacing:0.5px}
.rp-dim-pill.cell-ok,.rp-dim-pill.cell-protected{background:rgba(63,185,80,0.12);color:var(--success);border:1px solid rgba(63,185,80,0.30)}
.rp-dim-pill.cell-observed{background:rgba(56,139,253,0.10);color:var(--accent);border:1px solid rgba(56,139,253,0.25)}
.rp-dim-pill.cell-partial,.rp-dim-pill.cell-warn,.rp-dim-pill.cell-stale{background:rgba(210,153,34,0.10);color:var(--warn);border:1px solid rgba(210,153,34,0.25)}
.rp-dim-pill.cell-blind{background:rgba(248,81,73,0.10);color:var(--danger);border:1px solid rgba(248,81,73,0.25)}
.rp-dim-pill.cell-not_configured{background:transparent;color:var(--text3);border:1px solid var(--border)}
.rp-dim-summary{font-size:0.78rem;color:var(--text2);line-height:1.5;margin-bottom:6px}
.rp-dim-evidence{font-size:0.7rem;color:var(--text3);font-family:var(--mono);word-break:break-word}

.rp-signals{margin-bottom:24px}
.rp-signal{display:flex;align-items:flex-start;gap:14px;padding:12px 16px;background:var(--surface);border:1px solid var(--border);border-radius:8px;margin-bottom:8px}
.rp-signal-sev{flex-shrink:0;min-width:64px;padding-top:1px}
.rp-signal-sev .ps-sev{display:inline-block;font-size:0.6rem;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;padding:3px 8px;border-radius:4px}
.rp-signal-body{flex:1;min-width:0}
.rp-signal-title{font-size:0.8rem;font-weight:600;color:var(--text)}
.rp-signal-detail{font-size:0.75rem;color:var(--text3);margin-top:4px;line-height:1.5}

.rp-hardening{padding:18px 22px;background:var(--surface);border:1px solid var(--border);border-radius:12px;margin-bottom:20px}
.rp-hardening-head{display:flex;align-items:baseline;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:8px}
.rp-hardening-title{font-size:0.9rem;font-weight:600;color:var(--text)}
.rp-hardening-meta{font-size:0.75rem;color:var(--text3)}
.rp-hardening-meta strong{color:var(--text2);font-weight:600}
.rp-hardening-grade{font-size:0.78rem;color:var(--text2);margin-top:6px}
.rp-hardening-grade .g{display:inline-block;padding:2px 10px;border-radius:4px;font-weight:700;background:var(--surface2);color:var(--text);border:1px solid var(--border);font-family:var(--mono);margin-right:6px}
.rp-hardening-suppressed{font-size:0.75rem;color:var(--text3);font-style:italic;margin-top:6px}

/* ── Security Posture v2 (legacy classes still used by findings list) ── */

/* Status bar */
.ps-status{display:flex;justify-content:space-between;align-items:center;padding:10px 0;margin-bottom:20px;border-bottom:1px solid var(--border);font-size:0.75rem;color:var(--text3)}
.ps-status a,.ps-status button{font-size:0.75rem}

/* AI Assessment */
.ps-ai-summary{padding:20px 24px;background:var(--surface);border:1px solid var(--accent-border);border-radius:12px;margin-bottom:20px;position:relative}
.ps-ai-summary::before{content:'';position:absolute;left:0;top:12px;bottom:12px;width:3px;background:var(--accent-light);border-radius:2px}
.ps-ai-hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
.ps-ai-hdr span:first-child{font-size:0.8125rem;font-weight:600;color:var(--text);display:flex;align-items:center;gap:8px}
.ps-ai-model{font-size:0.65rem;color:var(--text3);font-family:var(--mono);font-weight:400;padding:2px 8px;background:var(--surface2);border-radius:4px}
.ps-ai-text{font-size:0.8125rem;color:var(--text2);line-height:1.65}

/* Findings */
.ps-section-title{font-size:0.6875rem;text-transform:uppercase;letter-spacing:0.6px;color:var(--text3);font-weight:600;margin-bottom:12px;padding-left:2px}
.ps-findings{background:var(--surface);border:1px solid var(--border);border-radius:12px;overflow:hidden;margin-bottom:24px}
.ps-finding{display:flex;align-items:flex-start;gap:14px;padding:16px 20px;border-bottom:1px solid var(--border);transition:background 0.15s}
.ps-finding:last-child{border-bottom:none}
.ps-finding:hover{background:rgba(255,255,255,0.01)}
.ps-fixable{border-left:3px solid var(--success)}
.ps-fixed{background:rgba(63,185,80,0.04);border-left:3px solid var(--success)}
.ps-f-sev{flex-shrink:0;min-width:70px;padding-top:2px}
.ps-sev{display:inline-block;font-size:0.6rem;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;padding:3px 8px;border-radius:4px;text-align:center}
.ps-sev.sev-critical{background:rgba(248,81,73,0.12);color:#f85149;border:1px solid rgba(248,81,73,0.25)}
.ps-sev.sev-high{background:rgba(248,81,73,0.08);color:#f85149;border:1px solid rgba(248,81,73,0.2)}
.ps-sev.sev-medium{background:rgba(210,153,34,0.1);color:#d29922;border:1px solid rgba(210,153,34,0.25)}
.ps-sev.sev-low,.ps-sev.sev-info{background:var(--surface2);color:var(--text3);border:1px solid var(--border)}
.ps-sev.sev-fixed{background:rgba(63,185,80,0.12);color:var(--success);border:1px solid rgba(63,185,80,0.3)}
.ps-f-body{flex:1;min-width:0}
.ps-f-title{font-size:0.8125rem;font-weight:600;color:var(--text);line-height:1.4}
.ps-f-product{display:inline-block;font-size:0.6rem;font-weight:500;color:var(--text3);background:var(--surface2);padding:1px 6px;border-radius:3px;margin-left:8px;vertical-align:middle;font-family:var(--mono);letter-spacing:0.3px}
.ps-f-detail{font-size:0.75rem;color:var(--text3);margin-top:5px;line-height:1.55}
.ps-f-risk{font-size:0.75rem;color:var(--accent-light);margin-top:6px;padding:6px 10px;background:rgba(139,92,246,0.04);border-radius:6px;border-left:2px solid var(--accent-light);line-height:1.5}
.ps-f-rem{margin-top:8px}
.ps-f-rem code{font-family:var(--mono);font-size:0.7rem;color:var(--text2);background:var(--bg);padding:4px 10px;border-radius:4px;border:1px solid var(--border);display:inline-block}
.ps-f-act{flex-shrink:0;display:flex;align-items:center;padding-top:2px}

/* Buttons */
.ps-fix-btn{padding:6px 18px;background:rgba(35,134,54,0.1);border:1px solid #238636;color:#3fb950;border-radius:6px;font-size:0.72rem;font-weight:600;cursor:pointer;transition:background 0.15s,box-shadow 0.15s;font-family:var(--sans)}
.ps-fix-btn:hover{background:rgba(35,134,54,0.2);box-shadow:0 0 8px rgba(63,185,80,0.15)}
.ps-cfg-btn{padding:6px 14px;border:1px solid var(--border);color:var(--text3);border-radius:6px;font-size:0.72rem;font-weight:500;text-decoration:none;transition:background 0.15s,border-color 0.15s,color 0.15s}
.ps-cfg-btn:hover{border-color:var(--border-hover);color:var(--text2);background:var(--surface2)}
.ps-enrich-btn{padding:7px 18px;background:rgba(139,92,246,0.06);border:1px solid var(--accent-border);color:var(--accent-light);border-radius:6px;font-size:0.75rem;font-weight:500;cursor:pointer;transition:background 0.15s,border-color 0.15s;display:flex;align-items:center;gap:6px}
.ps-enrich-btn:hover{background:rgba(139,92,246,0.12);border-color:var(--accent-light)}

/* Loading */
.htmx-indicator{display:none}
.htmx-request .htmx-indicator,.htmx-request.htmx-indicator{display:inline}
.ps-spinner{display:inline-block;width:14px;height:14px;border:2px solid var(--border);border-top-color:var(--accent-light);border-radius:50%;animation:spin 0.6s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

/* Info toggle */
.ps-info-toggle{font-size:0.72rem;color:var(--text3);cursor:pointer;padding:8px 0;display:flex;align-items:center;gap:6px;background:none;border:none;font-family:var(--sans)}
.ps-info-toggle:hover{color:var(--text2)}
.ps-info-items{display:none}
.ps-info-items.open{display:block}

/* Filter chips + copy button */
.ps-filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}
.ps-filter{padding:5px 12px;background:transparent;border:1px solid var(--border);border-radius:6px;color:var(--text3);font-size:0.72rem;cursor:pointer;font-family:var(--sans);font-weight:500;transition:background 0.12s,color 0.12s,border-color 0.12s}
.ps-filter:hover{color:var(--text2);border-color:var(--border-hover)}
.ps-filter.active{background:var(--accent);border-color:var(--accent);color:#fff}
.ps-f-rem{position:relative}
.ps-rem-copy{margin-left:6px;padding:3px 8px;font-size:0.65rem;font-family:var(--sans);font-weight:500;background:var(--surface2);border:1px solid var(--border);color:var(--text3);border-radius:4px;cursor:pointer;vertical-align:middle;transition:color 0.12s,border-color 0.12s}
.ps-rem-copy:hover{color:var(--text);border-color:var(--border-hover)}
.ps-rem-copy.copied{color:var(--success);border-color:rgba(63,185,80,0.4)}
.ps-empty-filter{padding:24px;text-align:center;color:var(--text3);font-size:0.8rem}

@media(max-width:768px){
  .ps-findings .ps-finding{flex-wrap:wrap}
}
</style>

<p class="page-desc">Runtime evidence first. Hardening checks below as secondary context.</p>

{{if .Sandbox}}
<div style="display:flex;align-items:center;gap:8px;padding:10px 16px;border:1px solid var(--border);border-radius:10px;margin-bottom:20px;font-size:0.8125rem;color:var(--text3)">
  <strong style="color:var(--text2)">Sandbox</strong> &middot; Sample config with intentional security issues.
  <a href="/dashboard/audit" style="margin-left:auto;color:var(--text2);text-decoration:none;font-weight:500">Exit sandbox &rarr;</a>
</div>
{{end}}

{{with .Posture}}
<!-- Hero — runtime-first -->
<div class="rp-hero">
  <div class="rp-hero-body">
    <div class="rp-eyebrow">Agent Runtime Posture</div>
    <div class="rp-title">{{.Title}}<span class="rp-status-pill s-{{.Status}}">{{.Status}}</span></div>
    <div class="rp-summary">{{.Summary}}</div>
  </div>
</div>

<!-- Runtime dimensions -->
<div class="rp-section-title">Runtime dimensions</div>
<div class="rp-dim-grid">
  {{range .Dimensions}}
  <div class="rp-dim">
    <div class="rp-dim-head">
      <span class="rp-dim-label">{{.Label}}</span>
      <span class="rp-dim-pill cell-{{.Status}}">{{.Status}}</span>
    </div>
    <div class="rp-dim-summary">{{.Summary}}</div>
    {{if .Evidence}}<div class="rp-dim-evidence">{{.Evidence}}</div>{{end}}
  </div>
  {{end}}
</div>

{{if .Signals}}
<div class="rp-section-title">Gaps and next actions</div>
<div class="rp-signals">
  {{range .Signals}}
  <div class="rp-signal">
    <div class="rp-signal-sev"><span class="ps-sev sev-{{.Severity}}">{{.Severity}}</span></div>
    <div class="rp-signal-body">
      <div class="rp-signal-title">{{.Title}}</div>
      {{if .Detail}}<div class="rp-signal-detail">{{.Detail}}</div>{{end}}
      {{if .Evidence}}<div class="rp-signal-detail">{{.Evidence}}</div>{{end}}
    </div>
  </div>
  {{end}}
</div>
{{end}}

<!-- Hardening — secondary section -->
<div class="rp-section-title">Hardening checks</div>
<div id="rp-hardening" class="rp-hardening">
  <div class="rp-hardening-head">
    <span class="rp-hardening-title">Static deployment checks</span>
    <span class="rp-hardening-meta">
      <strong>{{.Hardening.TotalChecks}}</strong> check{{if ne .Hardening.TotalChecks 1}}s{{end}} available{{if gt .Hardening.FixableCount 0}}, <strong>{{.Hardening.FixableCount}}</strong> auto-fixable{{end}}.
    </span>
  </div>
  {{if .Hardening.Suppressed}}
  <div class="rp-hardening-suppressed">{{.Hardening.Reason}}</div>
  {{else}}
  <div class="rp-hardening-grade">
    <span class="g">Grade {{.Hardening.Grade}}</span>based on static deployment checks.
  </div>
  {{end}}
</div>
{{end}}

<!-- Status bar — audit trail + AI enrich (legacy advisory section) -->
<div class="ps-status">
  <div>
    Audit trail: {{formatNum .ChainCount}} entries{{if .ChainValid}}, integrity verified{{end}}
  </div>
  {{if .LLMEnabled}}
  <button class="ps-enrich-btn" hx-post="/dashboard/api/audit/enrich" hx-target="#posture-findings" hx-swap="innerHTML" hx-indicator="#enrich-spin">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a4 4 0 0 0-4 4v2H6a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V10a2 2 0 0 0-2-2h-2V6a4 4 0 0 0-4-4z"/></svg>
    {{if .SavedAnalysis}}Re-analyze with AI{{else}}Analyze with AI{{end}}
  </button>
  <span id="enrich-spin" class="htmx-indicator" style="margin-left:6px"><span class="ps-spinner"></span></span>
  {{end}}
</div>

{{with .Evidence}}
<!-- Evidence store status -->
<div class="ps-section-title">Evidence store</div>
<div style="background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px 20px;margin-bottom:20px;display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;font-size:0.8125rem">
  <div>
    <div style="color:var(--text3);font-size:0.65rem;text-transform:uppercase;letter-spacing:0.6px;margin-bottom:4px">Rows</div>
    <div style="color:var(--text);font-weight:600">{{formatNum .TotalRows}}</div>
  </div>
  <div>
    <div style="color:var(--text3);font-size:0.65rem;text-transform:uppercase;letter-spacing:0.6px;margin-bottom:4px">Oldest</div>
    <div style="color:var(--text2);font-family:var(--mono);font-size:0.75rem">{{if .OldestTimestamp}}{{.OldestTimestamp}}{{else}}—{{end}}</div>
  </div>
  <div>
    <div style="color:var(--text3);font-size:0.65rem;text-transform:uppercase;letter-spacing:0.6px;margin-bottom:4px">Newest</div>
    <div style="color:var(--text2);font-family:var(--mono);font-size:0.75rem">{{if .NewestTimestamp}}{{.NewestTimestamp}}{{else}}—{{end}}</div>
  </div>
  <div>
    <div style="color:var(--text3);font-size:0.65rem;text-transform:uppercase;letter-spacing:0.6px;margin-bottom:4px">Retention</div>
    <div style="color:var(--text2);font-family:var(--mono);font-size:0.75rem">{{.RetentionPolicy}}</div>
  </div>
  <div style="grid-column:1 / -1">
    <div style="color:var(--text3);font-size:0.65rem;text-transform:uppercase;letter-spacing:0.6px;margin-bottom:4px">Database</div>
    <div style="color:var(--text2);font-family:var(--mono);font-size:0.75rem;word-break:break-all">{{if .DBBackend}}{{.DBBackend}}: {{end}}{{.DBPath}}</div>
    {{if .ArchiveDirectory}}<div style="color:var(--text3);font-size:0.7rem;margin-top:4px">Archives written to <span style="font-family:var(--mono)">{{.ArchiveDirectory}}</span> before any auto-purge.</div>{{end}}
  </div>
</div>
{{end}}

<!-- Findings -->
<div class="ps-section-title">Findings</div>
{{if gt .TotalChecks 0}}
<div class="ps-filters" role="tablist" aria-label="Filter findings by severity or fixability">
  <button class="ps-filter active" data-filter="all" onclick="psFilter('all',this)">All ({{.TotalChecks}})</button>
  {{if gt .Summary.Critical 0}}<button class="ps-filter" data-filter="critical" onclick="psFilter('critical',this)">Critical ({{.Summary.Critical}})</button>{{end}}
  {{if gt .Summary.High 0}}<button class="ps-filter" data-filter="high" onclick="psFilter('high',this)">High ({{.Summary.High}})</button>{{end}}
  {{if gt .Summary.Medium 0}}<button class="ps-filter" data-filter="medium" onclick="psFilter('medium',this)">Medium ({{.Summary.Medium}})</button>{{end}}
  {{if gt .FixableCount 0}}<button class="ps-filter" data-filter="fixable" onclick="psFilter('fixable',this)">Fixable ({{.FixableCount}})</button>{{end}}
</div>
{{end}}
<div class="ps-findings" id="posture-findings">
{{if .SavedAnalysis}}
<div class="ps-ai-summary" style="margin:16px 20px;border-radius:10px">
  <div class="ps-ai-hdr">
    <span>AI Assessment</span>
    <span class="ps-ai-model">{{.AnalysisModel}}</span>
  </div>
  <div class="ps-ai-text">{{.SavedAnalysis}}</div>
</div>
{{end}}
{{range .AllFindings}}{{if ne (printf "%s" .Severity) "INFO"}}
<div class="ps-finding{{if isFixable .CheckID}} ps-fixable{{end}}" id="f-{{.CheckID}}" data-sev="{{lower (printf "%s" .Severity)}}" data-fixable="{{if isFixable .CheckID}}1{{else}}0{{end}}" data-product="{{if .Product}}{{.Product}}{{else}}Oktsec{{end}}">
  <div class="ps-f-sev"><span class="ps-sev sev-{{lower (printf "%s" .Severity)}}">{{.Severity}}</span></div>
  <div class="ps-f-body">
    <span class="ps-f-title">{{.Title}}{{if .Product}}<span class="ps-f-product">{{.Product}}</span>{{end}}</span>
    {{if .Detail}}<div class="ps-f-detail">{{.Detail}}</div>{{end}}
    {{if not (isFixable .CheckID)}}{{if .Remediation}}<div class="ps-f-rem"><code>{{.Remediation}}</code><button type="button" class="ps-rem-copy" onclick="psCopyRem(this)" aria-label="Copy remediation command">Copy</button></div>{{end}}{{end}}
  </div>
  <div class="ps-f-act">
    {{if isFixable .CheckID}}
    <button class="ps-fix-btn" hx-post="/dashboard/api/audit/fix/{{.CheckID}}" hx-target="#f-{{.CheckID}}" hx-swap="outerHTML">Fix</button>
    {{else if .FixURL}}
    <a href="{{.FixURL}}" class="ps-cfg-btn">Configure</a>
    {{end}}
  </div>
</div>
{{end}}{{end}}
<div class="ps-empty-filter" id="ps-empty-filter" style="display:none">No findings match this filter.</div>
</div>

<script>
function psFilter(f, btn) {
  document.querySelectorAll('.ps-filter').forEach(function(b){ b.classList.toggle('active', b===btn); });
  var visible = 0;
  document.querySelectorAll('.ps-finding').forEach(function(el){
    var sev = el.getAttribute('data-sev') || '';
    var fix = el.getAttribute('data-fixable') === '1';
    var show = false;
    if (f === 'all') show = true;
    else if (f === 'fixable') show = fix;
    else show = sev === f;
    el.style.display = show ? '' : 'none';
    if (show) visible++;
  });
  var empty = document.getElementById('ps-empty-filter');
  if (empty) empty.style.display = visible === 0 ? '' : 'none';
}
function psCopyRem(btn) {
  var code = btn.parentElement && btn.parentElement.querySelector('code');
  if (!code) return;
  var txt = code.textContent || '';
  var done = function(){
    var orig = btn.textContent;
    btn.textContent = 'Copied';
    btn.classList.add('copied');
    setTimeout(function(){ btn.textContent = orig; btn.classList.remove('copied'); }, 1400);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(txt).then(done, function(){
      var ta = document.createElement('textarea'); ta.value = txt; document.body.appendChild(ta);
      ta.select(); try { document.execCommand('copy'); done(); } catch(e){} document.body.removeChild(ta);
    });
  } else {
    var ta = document.createElement('textarea'); ta.value = txt; document.body.appendChild(ta);
    ta.select(); try { document.execCommand('copy'); done(); } catch(e){} document.body.removeChild(ta);
  }
}
</script>

` + layoutFoot))
