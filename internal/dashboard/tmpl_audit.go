package dashboard

import "html/template"

var auditTmpl = template.Must(template.New("audit").Funcs(tmplFuncs).Parse(layoutHead + `
<style>
/* ── Security Posture v2 ───────────────────────────────── */

/* Hero */
.ps-hero{display:flex;align-items:center;gap:36px;padding:32px 36px;background:linear-gradient(135deg,var(--surface) 0%,rgba(139,92,246,0.03) 100%);border:1px solid var(--border);border-radius:14px;margin-bottom:24px;position:relative;overflow:hidden}
.ps-hero::after{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--accent-light),transparent);opacity:0.4}
.ps-hero-score{display:flex;flex-direction:column;align-items:center;gap:6px;flex-shrink:0}
.ps-ring{width:110px;height:110px;border-radius:50%;background:conic-gradient(var(--clr,var(--success)) calc(var(--pct,0) * 1%),var(--surface2) 0);display:flex;align-items:center;justify-content:center;position:relative;box-shadow:0 0 24px rgba(0,0,0,0.2)}
.ps-ring::before{content:'';position:absolute;inset:8px;border-radius:50%;background:var(--surface)}
.ps-num{position:relative;font-size:2rem;font-weight:800;font-family:var(--sans);letter-spacing:-0.04em;color:var(--text)}
.ps-grade-label{font-size:0.6875rem;color:var(--text3);font-family:var(--mono);letter-spacing:0.5px;text-transform:uppercase}
.ps-hero-body{flex:1}
.ps-hero-title{font-size:1.125rem;font-weight:700;color:var(--text);margin-bottom:4px;letter-spacing:-0.02em}
.ps-hero-sub{font-size:0.8125rem;color:var(--text3);margin-bottom:6px}
.ps-hero-detail{display:flex;gap:16px;margin-bottom:16px;font-size:0.72rem;color:var(--text3)}
.ps-hero-detail span{display:flex;align-items:center;gap:4px}
.ps-hero-dot{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.ps-fix-all{padding:11px 28px;background:linear-gradient(135deg,#238636,#2ea043);border:none;border-radius:8px;color:#fff;font-size:0.8125rem;font-weight:600;cursor:pointer;transition:all 0.2s;font-family:var(--sans);letter-spacing:-0.01em;box-shadow:0 2px 8px rgba(35,134,54,0.3)}
.ps-fix-all:hover{transform:translateY(-1px);box-shadow:0 4px 16px rgba(35,134,54,0.4)}
.ps-fix-all:disabled{opacity:0.6;cursor:wait;transform:none}
.ps-resolved{font-size:0.75rem;color:var(--success);display:flex;align-items:center;gap:6px;margin-top:8px}

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
.ps-fix-btn{padding:6px 18px;background:rgba(35,134,54,0.1);border:1px solid #238636;color:#3fb950;border-radius:6px;font-size:0.72rem;font-weight:600;cursor:pointer;transition:all 0.15s;font-family:var(--sans)}
.ps-fix-btn:hover{background:rgba(35,134,54,0.2);box-shadow:0 0 8px rgba(63,185,80,0.15)}
.ps-cfg-btn{padding:6px 14px;border:1px solid var(--border);color:var(--text3);border-radius:6px;font-size:0.72rem;font-weight:500;text-decoration:none;transition:all 0.15s}
.ps-cfg-btn:hover{border-color:var(--border-hover);color:var(--text2);background:var(--surface2)}
.ps-enrich-btn{padding:7px 18px;background:rgba(139,92,246,0.06);border:1px solid var(--accent-border);color:var(--accent-light);border-radius:6px;font-size:0.75rem;font-weight:500;cursor:pointer;transition:all 0.15s;display:flex;align-items:center;gap:6px}
.ps-enrich-btn:hover{background:rgba(139,92,246,0.12);border-color:var(--accent-light)}

/* Celebration */
.ps-celebrate{text-align:center;padding:40px;background:linear-gradient(135deg,rgba(35,134,54,0.06),rgba(63,185,80,0.03));border:1px solid rgba(63,185,80,0.2);border-radius:14px;margin-bottom:24px}
.ps-celebrate-score{font-size:3rem;font-weight:800;color:var(--success);font-family:var(--sans);letter-spacing:-0.04em}
.ps-celebrate-grade{font-size:0.875rem;color:var(--text3);font-family:var(--mono);margin-top:4px}
.ps-celebrate-msg{font-size:0.8125rem;color:var(--text2);margin-top:16px}
.ps-celebrate-msg a{color:var(--accent-light);text-decoration:none}

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

@media(max-width:768px){
  .ps-hero{flex-direction:column;text-align:center;gap:20px;padding:24px}
  .ps-hero-detail{justify-content:center}
  .ps-findings .ps-finding{flex-wrap:wrap}
}
</style>

<p class="page-desc">Security posture across {{.TotalChecks}} checks. {{if gt .FixableCount 0}}{{.FixableCount}} can be auto-fixed.{{end}}</p>

{{if .Sandbox}}
<div style="display:flex;align-items:center;gap:8px;padding:10px 16px;border:1px solid var(--border);border-radius:10px;margin-bottom:20px;font-size:0.8125rem;color:var(--text3)">
  <strong style="color:var(--text2)">Sandbox</strong> &middot; Sample config with intentional security issues.
  <a href="/dashboard/audit" style="margin-left:auto;color:var(--text2);text-decoration:none;font-weight:500">Exit sandbox &rarr;</a>
</div>
{{end}}

<!-- Hero -->
<div class="ps-hero">
  <div class="ps-hero-score" id="posture-score">
    <div class="ps-ring" style="--pct:{{.Score}};--clr:{{if ge .Score 90}}var(--success){{else if ge .Score 60}}var(--warn){{else}}var(--danger){{end}}">
      <span class="ps-num">{{.Score}}</span>
    </div>
    <div class="ps-grade-label">Grade {{.Grade}}</div>
  </div>
  <div class="ps-hero-body">
    <div class="ps-hero-title">{{if ge .Score 90}}Deployment secured{{else if ge .Score 60}}Deployment needs attention{{else}}Critical security gaps detected{{end}}</div>
    <div class="ps-hero-detail">
      {{if gt .Summary.Critical 0}}<span><span class="ps-hero-dot" style="background:var(--danger)"></span>{{.Summary.Critical}} critical</span>{{end}}
      {{if gt .Summary.High 0}}<span><span class="ps-hero-dot" style="background:var(--danger)"></span>{{.Summary.High}} high</span>{{end}}
      {{if gt .Summary.Medium 0}}<span><span class="ps-hero-dot" style="background:var(--warn)"></span>{{.Summary.Medium}} medium</span>{{end}}
      {{if gt .Summary.Info 0}}<span><span class="ps-hero-dot" style="background:var(--text3)"></span>{{.Summary.Info}} info</span>{{end}}
    </div>
    {{if gt .FixableCount 0}}
    <button class="ps-fix-all"
      hx-post="/dashboard/api/audit/fix-all"
      hx-target="#posture-findings"
      hx-swap="innerHTML"
      hx-confirm="Apply {{.FixableCount}} safe fixes? This enables security features in your config.">Fix {{.FixableCount}} {{if eq .FixableCount 1}}issue{{else}}issues{{end}} automatically</button>
    {{end}}
  </div>
</div>

<!-- Status bar -->
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

<!-- Findings -->
<div class="ps-section-title">Findings</div>
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
<div class="ps-finding{{if isFixable .CheckID}} ps-fixable{{end}}" id="f-{{.CheckID}}">
  <div class="ps-f-sev"><span class="ps-sev sev-{{lower (printf "%s" .Severity)}}">{{.Severity}}</span></div>
  <div class="ps-f-body">
    <span class="ps-f-title">{{.Title}}{{if .Product}}<span class="ps-f-product">{{.Product}}</span>{{end}}</span>
    {{if .Detail}}<div class="ps-f-detail">{{.Detail}}</div>{{end}}
    {{if not (isFixable .CheckID)}}{{if .Remediation}}<div class="ps-f-rem"><code>{{.Remediation}}</code></div>{{end}}{{end}}
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
</div>

` + layoutFoot))
