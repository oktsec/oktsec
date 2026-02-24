package dashboard

import "html/template"

var auditTmpl = template.Must(template.New("audit").Funcs(tmplFuncs).Parse(layoutHead + `
<style>
/* ── Audit page ─────────────────────────────────────────── */

/* Stat strip */
.a-stats{display:grid;grid-template-columns:repeat(5,1fr);gap:1px;background:var(--border);border:1px solid var(--border);border-radius:8px;overflow:hidden;margin-bottom:24px}
.a-stat{background:var(--surface);padding:16px 18px}
.a-stat-label{font-size:0.64rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);font-weight:500;margin-bottom:6px}
.a-stat-val{font-family:var(--mono);font-size:1.5rem;font-weight:700;color:var(--text)}
.a-stat-val.v-crit{color:#ef4444}
.a-stat-val.v-high{color:#f97316}
.a-stat-val.v-med{color:var(--text2)}
.a-stat-val.v-dim{color:var(--text3)}
.a-grade{font-size:0.82rem;font-weight:600;margin-left:8px;color:var(--text3);font-family:var(--mono);vertical-align:baseline}

/* Alert strip */
.a-alert{display:flex;align-items:center;gap:10px;padding:11px 16px;border-left:3px solid #ef4444;background:rgba(239,68,68,0.04);margin-bottom:24px;font-size:0.8rem;color:var(--text2)}
.a-alert strong{color:#fca5a5;font-weight:600}
.a-alert a{margin-left:auto;color:var(--text3);font-size:0.74rem;text-decoration:none;white-space:nowrap}
.a-alert a:hover{color:var(--text2)}

/* Sandbox strip */
.a-sandbox{display:flex;align-items:center;gap:8px;padding:9px 16px;border:1px solid var(--border);border-radius:6px;margin-bottom:20px;font-size:0.76rem;color:var(--text3)}
.a-sandbox strong{color:var(--text2);font-weight:500}
.a-sandbox a{color:var(--text2);text-decoration:none;margin-left:auto;font-weight:500}
.a-sandbox a:hover{color:var(--text)}

/* Section */
.a-sec{margin-bottom:24px}
.a-sec-title{font-size:0.68rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);font-weight:500;margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid var(--border)}

/* Priority fix row */
.a-fix{display:flex;align-items:flex-start;gap:10px;padding:10px 0;border-bottom:1px solid rgba(28,28,36,0.4)}
.a-fix:last-child{border-bottom:none}
.a-fix-sev{min-width:60px;flex-shrink:0;padding-top:1px}
.a-fix-body{flex:1;min-width:0}
.a-fix-head{display:flex;align-items:baseline;gap:8px}
.a-fix-id{font-family:var(--mono);font-size:0.76rem;font-weight:600;color:var(--text2)}
.a-fix-title{font-size:0.82rem;color:var(--text);font-weight:500}
.a-fix-rem{display:flex;align-items:center;gap:6px;margin-top:5px}
.a-fix-rem code{font-family:var(--mono);font-size:0.72rem;color:var(--text2)}
.a-cp{background:none;border:1px solid var(--border);color:var(--text3);border-radius:3px;padding:1px 7px;font-size:0.62rem;cursor:pointer;transition:all 0.15s;font-family:var(--mono);white-space:nowrap}
.a-cp:hover{border-color:var(--border-hover);color:var(--text2)}

/* Product block */
.a-prod{border:1px solid var(--border);border-radius:8px;margin-bottom:16px;overflow:hidden;background:var(--surface)}
.a-prod-head{padding:16px 20px;border-bottom:1px solid var(--border);display:flex;align-items:flex-start;gap:14px;flex-wrap:wrap}
.a-prod-icon{font-size:1.3rem;line-height:1;margin-top:1px}
.a-prod-name{font-size:0.9rem;font-weight:600}
.a-prod-desc{font-size:0.72rem;color:var(--text3);margin-top:2px;line-height:1.4}
.a-prod-path{font-family:var(--mono);font-size:0.68rem;color:var(--text3);margin-top:6px;display:flex;align-items:center;gap:6px}
.a-prod-path code{color:var(--text2)}
.a-prod-counts{display:flex;gap:12px;margin-left:auto;flex-shrink:0;align-items:center}
.a-prod-counts span{font-size:0.7rem;font-family:var(--mono);font-weight:500}

/* Findings */
.a-fd summary{cursor:pointer;padding:10px 20px;font-size:0.76rem;color:var(--text3);list-style:none;font-weight:500;display:flex;align-items:center;gap:5px;transition:background 0.15s;border-bottom:1px solid rgba(28,28,36,0.3)}
.a-fd summary:hover{background:rgba(255,255,255,0.02)}
.a-fd summary::-webkit-details-marker{display:none}
.a-fd summary::before{content:'\203A';font-size:0.9rem;transition:transform 0.15s;font-weight:400;color:var(--text3)}
.a-fd[open] summary::before{transform:rotate(90deg)}
.a-fi{display:flex;align-items:flex-start;gap:10px;padding:10px 20px;border-bottom:1px solid rgba(28,28,36,0.3)}
.a-fi:last-child{border-bottom:none}
.a-fi-sev{min-width:60px;flex-shrink:0;padding-top:1px}
.a-fi-body{flex:1;min-width:0}
.a-fi-head{display:flex;align-items:baseline;gap:8px}
.a-fi-id{font-family:var(--mono);font-size:0.76rem;font-weight:600;color:var(--text2)}
.a-fi-title{font-size:0.8rem;color:var(--text);font-weight:500}
.a-fi-detail{font-size:0.72rem;color:var(--text3);margin-top:3px;line-height:1.5}
.a-fi-fix{display:flex;align-items:center;gap:6px;margin-top:5px}
.a-fi-fix code{font-family:var(--mono);font-size:0.72rem;color:var(--text2)}

/* Footer */
.a-foot{text-align:center;padding:20px 0;color:var(--text3);font-size:0.7rem;font-family:var(--mono)}
.a-foot a{color:var(--text2);text-decoration:none}
.a-foot a:hover{color:var(--text)}

@media(max-width:768px){
  .a-stats{grid-template-columns:repeat(2,1fr)}
}
</style>

<h1>Security <span>Audit</span></h1>
<p class="page-desc">Configuration posture across oktsec and detected products.</p>

{{if .Sandbox}}
<div class="a-sandbox">
  <strong>Sandbox</strong> &mdash; Sample OpenClaw config with intentional security issues.
  <a href="/dashboard/audit">Exit sandbox &rarr;</a>
</div>
{{end}}

<div class="a-stats">
  <div class="a-stat">
    <div class="a-stat-label">Posture Score</div>
    <div class="a-stat-val{{if lt .Score 40}} v-crit{{else if lt .Score 75}} v-high{{end}}">{{.Score}}<span class="a-grade">{{.Grade}}</span></div>
  </div>
  <div class="a-stat">
    <div class="a-stat-label">Critical</div>
    <div class="a-stat-val v-crit">{{.Summary.Critical}}</div>
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

{{if .HasCritical}}
<div class="a-alert">
  <strong>{{.Summary.Critical}} critical {{if eq .Summary.Critical 1}}finding{{else}}findings{{end}}</strong> require immediate action
  {{if .TopFixes}}<a href="javascript:void(0)" onclick="document.getElementById('remediations').scrollIntoView({behavior:'smooth'})">View fixes &darr;</a>{{end}}
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
      {{if .Summary.Critical}}<span style="color:#ef4444">{{.Summary.Critical}} critical</span>{{end}}
      {{if .Summary.High}}<span style="color:#f97316">{{.Summary.High}} high</span>{{end}}
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
        </div>
        {{end}}
      </div>
    </div>
    {{end}}
  </details>
</div>
{{end}}

{{if .TopFixes}}
<div class="a-sec" id="remediations">
  <div class="a-sec-title">Priority Remediations</div>
  {{range .TopFixes}}
  <div class="a-fix">
    <span class="a-fix-sev sev-{{lower (printf "%s" .Severity)}}">{{.Severity}}</span>
    <div class="a-fix-body">
      <div class="a-fix-head">
        <span class="a-fix-id">{{.CheckID}}</span>
        <span class="a-fix-title">{{.Title}}</span>
      </div>
      {{if .Remediation}}
      <div class="a-fix-rem">
        <code>{{.Remediation}}</code>
        <button class="a-cp" onclick="copyText('{{.Remediation}}',this)">copy</button>
      </div>
      {{end}}
    </div>
  </div>
  {{end}}
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
