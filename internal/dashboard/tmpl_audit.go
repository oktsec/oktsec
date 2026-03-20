package dashboard

import "html/template"

var auditTmpl = template.Must(template.New("audit").Funcs(tmplFuncs).Parse(layoutHead + `
<style>
/* ── Audit page ─────────────────────────────────────────── */

/* Stat strip */
.a-stats{display:grid;grid-template-columns:repeat(5,1fr);gap:1px;background:var(--border);border:1px solid var(--border);border-radius:10px;overflow:hidden;margin-bottom:24px}
.a-stat{background:var(--surface);padding:var(--sp-5) var(--sp-5);text-align:center}
.a-stat-label{font-size:var(--text-xs);text-transform:uppercase;letter-spacing:var(--ls-caps);color:var(--text3);font-weight:500;margin-bottom:var(--sp-2)}
.a-stat-val{font-family:var(--sans);font-size:1.375rem;font-weight:700;color:var(--text);letter-spacing:-0.03em}
.a-stat-val.v-crit{color:var(--danger)}
.a-stat-val.v-high{color:var(--text2)}
.a-stat-val.v-med{color:var(--text2)}
.a-stat-val.v-dim{color:var(--text2)}
.a-grade{display:block;font-size:0.6875rem;font-weight:500;color:var(--text3);font-family:var(--mono);margin-top:4px;letter-spacing:0.3px}

/* Alert strip */
.a-alert{display:flex;align-items:center;gap:10px;padding:12px 16px;border-left:3px solid var(--danger);background:rgba(248,81,73,0.04);margin-bottom:24px;font-size:0.8125rem;color:var(--text2);border-radius:0 10px 10px 0}
.a-alert strong{color:#f85149;font-weight:600}
.a-alert a{margin-left:auto;color:var(--text3);font-size:0.75rem;text-decoration:none;white-space:nowrap}
.a-alert a:hover{color:var(--text2)}

/* Sandbox strip */
.a-sandbox{display:flex;align-items:center;gap:8px;padding:10px 16px;border:1px solid var(--border);border-radius:10px;margin-bottom:20px;font-size:0.8125rem;color:var(--text3)}
.a-sandbox strong{color:var(--text2);font-weight:500}
.a-sandbox a{color:var(--text2);text-decoration:none;margin-left:auto;font-weight:500}
.a-sandbox a:hover{color:var(--text)}

/* Section */
.a-sec{margin-bottom:24px}
.a-sec-title{font-size:0.6875rem;text-transform:uppercase;letter-spacing:0.5px;color:var(--text3);font-weight:500;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid var(--border)}

/* Priority fix row */
.a-fix{display:flex;align-items:flex-start;gap:10px;padding:12px 0;border-bottom:1px solid var(--border)}
.a-fix:last-child{border-bottom:none}
.a-fix-sev{min-width:60px;flex-shrink:0;padding-top:1px;font-size:0.7rem;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;padding:3px 8px;border-radius:4px;text-align:center;display:inline-block}
.a-fix-sev.sev-critical{background:rgba(248,81,73,0.12);color:#f85149}
.a-fix-sev.sev-high{background:rgba(248,81,73,0.08);color:#fb923c}
.a-fix-sev.sev-medium{background:rgba(234,179,8,0.1);color:#d29922}
.a-fix-body{flex:1;min-width:0}
.a-fix-head{display:flex;align-items:baseline;gap:8px}
.a-fix-id{font-family:var(--mono);font-size:0.8125rem;font-weight:600;color:var(--text2)}
.a-fix-title{font-size:0.8125rem;color:var(--text);font-weight:500}
.a-fix-rem{display:flex;align-items:center;gap:6px;margin-top:6px}
.a-fix-rem code{font-family:var(--mono);font-size:0.75rem;color:var(--text2)}
.a-cp{background:transparent;border:1px solid var(--border);color:var(--text3);border-radius:4px;padding:2px 8px;font-size:0.6875rem;cursor:pointer;transition:all 0.12s;font-family:var(--mono);white-space:nowrap}
.a-cp:hover{border-color:var(--border-hover);color:var(--text2);background:var(--surface2)}

/* Product block */
.a-prod{border:1px solid var(--border);border-radius:10px;margin-bottom:16px;overflow:hidden;background:var(--surface);box-shadow:0 1px 2px rgba(0,0,0,0.2)}
.a-prod-head{padding:16px 20px;border-bottom:1px solid var(--border);display:flex;align-items:flex-start;gap:14px;flex-wrap:wrap}
.a-prod-icon{font-size:1.3rem;line-height:1;margin-top:1px}
.a-prod-name{font-size:0.875rem;font-weight:600;letter-spacing:-0.01em}
.a-prod-desc{font-size:0.75rem;color:var(--text3);margin-top:2px;line-height:1.4}
.a-prod-path{font-family:var(--mono);font-size:0.6875rem;color:var(--text3);margin-top:6px;display:flex;align-items:center;gap:6px}
.a-prod-path code{color:var(--text2)}
.a-prod-counts{display:flex;gap:12px;margin-left:auto;flex-shrink:0;align-items:center}
.a-prod-counts span{font-size:0.6875rem;font-family:var(--mono);font-weight:500}

/* Findings */
.a-fd summary{cursor:pointer;padding:10px 20px;font-size:0.8125rem;color:var(--text3);list-style:none;font-weight:500;display:flex;align-items:center;gap:5px;transition:background 0.1s;border-bottom:1px solid var(--border)}
.a-fd summary:hover{background:rgba(255,255,255,0.02)}
.a-fd summary::-webkit-details-marker{display:none}
.a-fd summary::before{content:'\203A';font-size:0.9rem;transition:transform 0.12s;font-weight:400;color:var(--text3)}
.a-fd[open] summary::before{transform:rotate(90deg)}
.a-fi{display:flex;align-items:flex-start;gap:10px;padding:12px 20px;border-bottom:1px solid var(--border)}
.a-fi:last-child{border-bottom:none}
.a-fi-sev{min-width:60px;flex-shrink:0;padding-top:1px;font-size:0.7rem;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;padding:3px 8px;border-radius:4px;text-align:center;display:inline-block}
.a-fi-sev.sev-critical{background:rgba(248,81,73,0.12);color:#f85149}
.a-fi-sev.sev-high{background:rgba(248,81,73,0.08);color:#fb923c}
.a-fi-sev.sev-medium{background:rgba(234,179,8,0.1);color:#d29922}
.a-fi-sev.sev-info,.a-fi-sev.sev-low{background:var(--surface2);color:var(--text3)}
.a-fi-body{flex:1;min-width:0}
.a-fi-head{display:flex;align-items:baseline;gap:8px}
.a-fi-id{font-family:var(--mono);font-size:0.8125rem;font-weight:600;color:var(--text2)}
.a-fi-title{font-size:0.8125rem;color:var(--text);font-weight:500}
.a-fi-detail{font-size:0.75rem;color:var(--text3);margin-top:4px;line-height:1.5}
.a-fi-fix{display:flex;align-items:center;gap:6px;margin-top:6px;flex-wrap:wrap}
.a-fi-fix code{font-family:var(--mono);font-size:0.75rem;color:var(--text2)}
.a-fi-link{font-size:0.75rem;color:#58a6ff;text-decoration:none;margin-left:4px}
.a-fi-link:hover{text-decoration:underline}

/* Footer */
.a-foot{text-align:center;padding:24px 0;color:var(--text3);font-size:0.6875rem;font-family:var(--mono)}
.a-foot a{color:var(--text2);text-decoration:none}
.a-foot a:hover{color:var(--text)}

@media(max-width:768px){
  .a-stats{grid-template-columns:repeat(2,1fr)}
  .a-prod-head{flex-direction:column}
  .a-prod-counts{margin-left:0}
}
@media(max-width:480px){
  .a-stats{grid-template-columns:1fr}
}
</style>

<p class="page-desc">Security audit of your deployment. Score based on {{.TotalChecks}} checks across oktsec and detected products.</p>

{{if .Sandbox}}
<div class="a-sandbox">
  <strong>Sandbox</strong> &middot; Sample OpenClaw config with intentional security issues.
  <a href="/dashboard/audit">Exit sandbox &rarr;</a>
</div>
{{end}}

<div class="a-stats">
  <div class="a-stat">
    <div class="a-stat-label">Posture Score</div>
    <div class="a-stat-val">{{.Score}}<span class="a-grade">Grade {{.Grade}}</span></div>
  </div>
  <div class="a-stat">
    <div class="a-stat-label">Critical</div>
    <div class="a-stat-val{{if gt .Summary.Critical 0}} v-crit{{end}}">{{.Summary.Critical}}</div>
  </div>
  <div class="a-stat">
    <div class="a-stat-label">High</div>
    <div class="a-stat-val v-high">{{.Summary.High}}</div>
  </div>
  <div class="a-stat">
    <div class="a-stat-label">Medium</div>
    <div class="a-stat-val v-med">{{.Summary.Medium}}</div>
  </div>
  <div class="a-stat">
    <div class="a-stat-label">Info</div>
    <div class="a-stat-val v-dim">{{.Summary.Info}}</div>
  </div>
</div>

{{if .ChainCount}}
<div class="a-alert" style="border-left-color:{{if .ChainValid}}var(--border){{else}}var(--danger){{end}};background:{{if .ChainValid}}transparent{{else}}rgba(248,81,73,0.04){{end}}">
  {{if .ChainValid}}&#x2713;{{else}}&#x2717;{{end}}
  <span>Audit chain: <strong style="color:{{if .ChainValid}}var(--text2){{else}}var(--danger){{end}}">{{if .ChainValid}}verified{{else}}broken{{end}}</strong> &middot; {{.ChainCount}} entries verified</span>
</div>
{{if and (not .ChainValid) .ChainReason}}
<div class="card" style="border-color:rgba(248,81,73,0.2);margin-bottom:var(--sp-6)">
  <div style="color:var(--danger);font-weight:600;margin-bottom:var(--sp-2);font-size:var(--text-md)">Chain integrity failure</div>
  <div style="color:var(--text2);font-size:var(--text-sm);line-height:1.6;margin-bottom:var(--sp-2)"><strong>Reason:</strong> {{.ChainReason}}</div>
  {{if .ChainBrokenID}}<div style="color:var(--text2);font-size:var(--text-sm)"><strong>Broken at entry:</strong> <code>{{.ChainBrokenID}}</code> (position {{.ChainBrokenAt}} of {{.ChainCount}})</div>{{end}}
  <div style="color:var(--text3);font-size:var(--text-xs);margin-top:var(--sp-2)">This typically occurs when the database is modified externally, entries are deleted, or the proxy restarts with a different signing key.</div>
</div>
{{end}}
{{end}}

{{if .LLMEnabled}}
<div style="display:flex;align-items:center;gap:12px;padding:12px 20px;background:rgba(99,102,241,0.06);border:1px solid rgba(99,102,241,0.15);border-radius:10px;margin-bottom:var(--sp-5)">
  <span style="font-size:1.1rem">&#x1F9E0;</span>
  <div style="flex:1">
    <div style="font-size:0.82rem;font-weight:600;color:var(--text)">AI-Enhanced Analysis Active</div>
    <div style="font-size:0.72rem;color:var(--text3);margin-top:2px">Messages are being analyzed by <span style="font-family:var(--mono);color:var(--accent-light)">{{.LLMModel}}</span> for threats that rules can't detect.{{if .LLMThreats}} {{.LLMThreats}} analyses completed{{if .LLMConfirmed}}, {{.LLMConfirmed}} confirmed threats{{end}}.{{end}}</div>
  </div>
  <a href="/dashboard/llm" class="btn btn-sm btn-outline" style="font-size:0.72rem;border-color:var(--accent-border);color:var(--accent-light);white-space:nowrap">View AI Analysis</a>
</div>
{{end}}

{{if .HasCritical}}
<div class="a-alert">
  <strong>{{.Summary.Critical}} critical {{if eq .Summary.Critical 1}}finding{{else}}findings{{end}}</strong> require immediate action
</div>
{{end}}

{{if .TopFixes}}
<div class="a-prod" id="remediations">
  <div class="a-prod-head" style="border-bottom:1px solid var(--border)">
    <div class="a-prod-icon">&#x1F6E1;</div>
    <div style="flex:1;min-width:0">
      <div class="a-prod-name">Priority Remediations</div>
      <div class="a-prod-desc">Top critical and high findings that need immediate attention.</div>
    </div>
    <div class="a-prod-counts"><span style="color:var(--text2)">{{len .TopFixes}} {{if eq (len .TopFixes) 1}}fix{{else}}fixes{{end}}</span></div>
  </div>
  {{range .TopFixes}}
  <div class="a-fi">
    <span class="a-fi-sev sev-{{lower (printf "%s" .Severity)}}">{{.Severity}}</span>
    <div class="a-fi-body">
      <div class="a-fi-head">
        <span class="a-fi-id">{{.CheckID}}</span>
        <span class="a-fi-title">{{.Title}}</span>
      </div>
      {{if .Remediation}}
      <div class="a-fi-fix">
        <code>{{.Remediation}}</code>
        <button class="a-cp" onclick="copyText('{{.Remediation}}',this)">copy</button>
        {{if .FixURL}}<a href="{{.FixURL}}" class="a-fi-link">Fix this &rarr;</a>{{end}}
      </div>
      {{end}}
    </div>
  </div>
  {{end}}
</div>
{{end}}

{{range .Groups}}
<div class="a-prod">
  <div class="a-prod-head">
    {{if .Info.Icon}}<div class="a-prod-icon">{{.Info.Icon}}</div>{{end}}
    <div style="flex:1;min-width:0">
      <div class="a-prod-name">{{.Info.Name}}</div>
      {{if .Info.Description}}<div class="a-prod-desc">{{.Info.Description}}</div>{{end}}
      {{if .Info.ConfigPath}}
      <div class="a-prod-path">
        Config: <code>{{.Info.ConfigPath}}</code>
        <button class="a-cp" onclick="copyText('{{.Info.ConfigPath}}',this)">copy</button>
      </div>
      {{end}}
      {{if .Info.DocsURL}}<div style="font-size:0.68rem;margin-top:3px"><a href="{{.Info.DocsURL}}" target="_blank" rel="noopener" style="color:var(--text3);text-decoration:none">{{.Info.DocsURL}}</a></div>{{end}}
    </div>
    <div class="a-prod-counts">
      {{if .Summary.Critical}}<span style="color:var(--danger)">{{.Summary.Critical}} critical</span>{{end}}
      {{if .Summary.High}}<span style="color:var(--text2)">{{.Summary.High}} high</span>{{end}}
      {{if .Summary.Medium}}<span style="color:var(--text2)">{{.Summary.Medium}} medium</span>{{end}}
      {{if .Summary.Info}}<span style="color:var(--text3)">{{.Summary.Info}} info</span>{{end}}
    </div>
  </div>

  <details class="a-fd"{{if or .Summary.Critical .Summary.High}} open{{end}}>
    <summary>{{len .Findings}} {{if eq (len .Findings) 1}}finding{{else}}findings{{end}}</summary>
    {{range .Findings}}
    <div class="a-fi">
      <span class="a-fi-sev sev-{{lower (printf "%s" .Severity)}}">{{.Severity}}</span>
      <div class="a-fi-body">
        <div class="a-fi-head">
          <span class="a-fi-id">{{.CheckID}}</span>
          <span class="a-fi-title">{{.Title}}</span>
        </div>
        <div class="a-fi-detail">{{.Detail}}</div>
        {{if .Remediation}}
        <div class="a-fi-fix">
          <code>{{.Remediation}}</code>
          <button class="a-cp" onclick="copyText('{{.Remediation}}',this)">copy</button>
          {{if .FixURL}}<a href="{{.FixURL}}" class="a-fi-link">Fix this →</a>{{end}}
        </div>
        {{end}}
      </div>
    </div>
    {{end}}
  </details>
</div>
{{end}}

<div class="a-foot">
  {{.TotalChecks}} findings &middot;
  {{.Summary.Critical}} critical &middot; {{.Summary.High}} high &middot; {{.Summary.Medium}} medium &middot; {{.Summary.Info}} info
  {{if not .Sandbox}}<br><a href="/dashboard/audit/sandbox">Try sandbox demo &rarr;</a>{{end}}
</div>

<script>
function copyText(text, btn) {
  navigator.clipboard.writeText(text).then(function() {
    var orig = btn.textContent;
    btn.textContent = 'copied';
    btn.style.color = 'var(--success)';
    setTimeout(function() { btn.textContent = orig; btn.style.color = ''; }, 1200);
  });
}
</script>
` + layoutFoot))
