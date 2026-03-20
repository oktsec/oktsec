package dashboard

import "html/template"

var sessionTraceTmpl = template.Must(template.New("session-trace").Funcs(tmplFuncs).Parse(layoutHead + `
<style>
/* ── Session Trace ────────────────────────────────────── */
.st-meta{font-size:var(--text-sm);color:var(--text3);margin-bottom:20px}
.st-meta span{margin-right:16px}
.st-meta .val{color:var(--text2);font-weight:500}

.st-actions{display:flex;gap:8px;margin-bottom:20px}

.st-stats{display:grid;grid-template-columns:repeat(4,1fr);margin-bottom:24px;background:var(--surface);border:1px solid var(--border);border-radius:10px;overflow:hidden}
.st-stat{padding:16px 20px}
.st-stat+.st-stat{border-left:1px solid var(--border)}
.st-stat .label{font-size:var(--text-xs);text-transform:uppercase;letter-spacing:var(--ls-caps);color:var(--text3);margin-bottom:4px}
.st-stat .value{font-size:1.2rem;font-weight:600;color:var(--text)}
.st-stat{text-align:center}
.st-stat .value.v-danger{color:var(--danger)}
.st-stat .value.v-success{color:var(--success)}

/* 2-column layout */
.st-layout{display:grid;grid-template-columns:3fr 2fr;gap:24px;align-items:start}
.st-layout.no-analysis{grid-template-columns:1fr}
@media(max-width:1100px){.st-layout{grid-template-columns:1fr}}

/* Timeline */
.st-timeline{position:relative;padding-left:32px}
.st-timeline::before{content:'';position:absolute;left:11px;top:8px;bottom:8px;width:2px;background:var(--border)}

.st-step{position:relative;margin-bottom:16px;padding:14px 18px;background:var(--surface);border:1px solid var(--border);border-radius:8px;transition:border-color 0.15s}
.st-step:hover{border-color:var(--text3)}
.st-step.s-blocked{border-left:3px solid var(--danger)}
.st-step.s-quarantined{border-left:3px solid var(--warn)}

/* Timeline dot */
.st-step::before{content:'';position:absolute;left:-25px;top:18px;width:10px;height:10px;border-radius:50%;background:var(--success);border:2px solid var(--bg)}
.st-step.s-blocked::before{background:var(--danger)}
.st-step.s-quarantined::before{background:var(--warn)}

.st-step.s-human{border-left:3px solid var(--accent)}
.st-step.s-human::before{background:var(--accent)}
.st-role{font-size:0.62rem;padding:2px 7px;border-radius:4px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px}
.st-role.r-human{color:var(--accent);background:rgba(139,124,247,0.1)}
.st-role.r-agent{color:var(--text3);background:var(--surface2)}
.st-step-header{display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap}
.st-tool{font-weight:600;color:var(--text);font-size:var(--text-sm)}
.st-verdict{font-size:var(--text-xs);padding:2px 8px;border-radius:4px;font-weight:500}
.st-verdict.v-clean{color:var(--success);background:rgba(63,185,80,0.1)}
.st-verdict.v-blocked{color:var(--danger);background:rgba(248,81,73,0.1)}
.st-verdict.v-quarantined{color:var(--warn);background:rgba(210,153,34,0.1)}
.st-time{font-size:var(--text-xs);color:var(--text3);margin-left:auto}
.st-gap{font-size:var(--text-xs);color:var(--text3);opacity:0.7}
.st-latency{font-size:var(--text-xs);color:var(--text3)}

.st-content{font-size:var(--text-xs);color:var(--text3);max-height:40px;overflow:hidden;font-family:var(--mono);word-break:break-all}

.st-reasoning{margin-top:8px;padding:10px 14px;background:var(--bg);border:1px solid var(--border);border-radius:6px;font-size:var(--text-xs);color:var(--text2);line-height:1.5}
.st-reasoning .label{font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:var(--ls-caps);font-size:0.65rem;margin-bottom:4px}
.st-plan{font-size:var(--text-xs);color:var(--accent);font-weight:500;margin-left:8px}

.st-link{font-size:var(--text-xs);color:var(--accent);text-decoration:none;margin-top:6px;display:inline-block}
.st-link:hover{text-decoration:underline}

.st-empty{padding:40px;text-align:center;color:var(--text3)}

/* AI Analysis panel */
.st-ai-panel{position:sticky;top:20px}
.st-ai-meta{display:flex;gap:12px;margin-top:12px;padding-top:12px;border-top:1px solid var(--border);font-size:0.68rem;color:var(--text3)}
.st-ai-panel h3{font-size:var(--text-sm);text-transform:uppercase;letter-spacing:var(--ls-caps);color:var(--text3);margin:0 0 12px}
.st-ai-content{padding:20px;background:var(--surface);border:1px solid var(--border);border-radius:10px;font-size:var(--text-sm);line-height:1.7;color:var(--text2)}
.st-ai-content strong{color:var(--text)}
.st-ai-content a{color:var(--accent-light)}
.st-ai-content .ai-label{display:inline-block;font-size:0.62rem;padding:2px 7px;border-radius:4px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;color:var(--accent);background:rgba(139,124,247,0.1);margin-bottom:12px}
.st-ai-actions{display:flex;gap:8px;margin-top:12px}
.ss-ai-btn{padding:6px 12px;background:var(--accent);color:#fff;border:none;border-radius:6px;font-size:var(--text-xs);cursor:pointer;font-weight:500}
.ss-ai-btn:hover{opacity:0.9}
.ss-ai-btn:disabled{opacity:0.5;cursor:not-allowed}
.ss-ai-btn.btn-outline{background:transparent;color:var(--accent);border:1px solid var(--accent)}
</style>

<div class="page-header" style="margin-bottom:8px">
  <h1 style="margin-bottom:4px">Session Trace</h1>
</div>
<p style="color:var(--text3);font-size:var(--text-sm);margin:0 0 16px">Timeline of agent tool calls within a session</p>

<div class="st-meta">
  <span>Agent: <span class="val">{{.Trace.Agent}}</span></span>
  <span>Session: <span class="val" style="font-family:var(--mono);font-size:var(--text-xs)">{{.Trace.SessionID}}</span></span>
</div>

<div class="st-actions">
  <a href="/dashboard/api/session/{{.Trace.SessionID}}/csv" class="btn btn-sm btn-outline" style="font-size:var(--text-xs)">CSV</a>
  <a href="/dashboard/api/session/{{.Trace.SessionID}}/sarif" class="btn btn-sm btn-outline" style="font-size:var(--text-xs)">SARIF</a>
  <a href="/dashboard/api/session/{{.Trace.SessionID}}/export" class="btn btn-sm btn-outline" style="font-size:var(--text-xs)">JSON</a>
  <button class="ss-ai-btn" id="ai-analyze-btn" onclick="analyzeSession('{{.Trace.SessionID}}')">{{if .SavedAnalysis}}Re-analyze{{else}}Analyze with AI{{end}}</button>
</div>

<div class="st-stats">
  <div class="st-stat">
    <div class="label">Threats</div>
    <div class="value{{if gt .Trace.Threats 0}} v-danger{{else}} v-success{{end}}">{{.Trace.Threats}}</div>
  </div>
  <div class="st-stat">
    <div class="label">Tool Calls</div>
    <div class="value">{{.Trace.ToolCount}}</div>
  </div>
  <div class="st-stat">
    <div class="label">Duration</div>
    <div class="value">{{.Trace.Duration}}</div>
  </div>
  <div class="st-stat">
    <div class="label">Started</div>
    <div class="value" data-ts="{{.Trace.StartedAt}}">{{.Trace.StartedAt}}</div>
  </div>
</div>

<div class="st-layout{{if not .SavedAnalysis}} no-analysis{{end}}" id="st-layout">
  <!-- Left: Timeline -->
  <div>
    {{if .Trace.Steps}}
    <div class="st-timeline">
      {{range .Trace.Steps}}
      <div class="st-step{{if eq .Verdict "blocked"}} s-blocked{{end}}{{if eq .Verdict "quarantined"}} s-quarantined{{end}}{{if eq .ToolName "message"}} s-human{{end}}">
        <div class="st-step-header">
          {{if eq .ToolName "message"}}<span class="st-role r-human">human</span>{{else}}<span class="st-role r-agent">agent</span>{{end}}
          <span style="font-size:var(--text-xs);color:var(--text3);font-family:var(--mono)">{{.FromAgent}}</span>
          <span class="st-tool">{{.ToolName}}</span>
          <span class="st-verdict{{if eq .Verdict "blocked"}} v-blocked{{else if eq .Verdict "quarantined"}} v-quarantined{{else}} v-clean{{end}}">{{.Verdict}}</span>
          {{if gt .PlanStep 0}}<span class="st-plan">Step {{.PlanStep}}/{{.PlanTotal}}</span>{{end}}
          <span class="st-time" data-ts="{{.Timestamp}}">{{.Timestamp}}</span>
          {{if gt .GapMs 1000}}<span class="st-gap">+{{printf "%.1f" (divf .GapMs 1000)}}s</span>{{else if gt .GapMs 0}}<span class="st-gap">+{{.GapMs}}ms</span>{{end}}
          <span class="st-latency">{{.LatencyMs}}ms</span>
        </div>
        {{if .ToolInput}}<div class="st-content">{{.ToolInput}}</div>{{end}}
        {{if .Reasoning}}
        <div class="st-reasoning">
          <div class="label">Reasoning</div>
          {{.Reasoning}}
        </div>
        {{end}}
        <a href="/dashboard/events/{{.EventID}}" class="st-link">View event detail</a>
      </div>
      {{end}}
    </div>
    {{else}}
    <div class="st-empty">No events found for this session.</div>
    {{end}}
  </div>

  <!-- Right: AI Analysis -->
  <div class="st-ai-panel">
    {{if .SavedAnalysis}}
    <div class="st-ai-content">
      {{mdToHTML .SavedAnalysis}}
      <div class="st-ai-meta">
        <span>Model: {{.AnalysisModel}}</span>
        <span>Analyzed: {{.AnalysisDate}}</span>
      </div>
    </div>
    {{end}}
  </div>
</div>

<script>
function analyzeSession(sid) {
  var btn = document.querySelector('.ss-ai-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Analyzing...'; }

  fetch('/dashboard/api/sessions/' + sid + '/analyze', {method: 'POST'})
    .then(function(r) { if (!r.ok) throw new Error(r.statusText); return r.text(); })
    .then(function() { window.location.reload(); })
    .catch(function(e) {
      if (btn) { btn.disabled = false; btn.textContent = 'Analyze with AI'; }
      var layout = document.getElementById('st-layout');
      layout.classList.remove('no-analysis');
      var panel = document.createElement('div');
      panel.className = 'st-ai-panel';
      panel.innerHTML = '<h3>AI Analysis</h3><div class="st-ai-content" style="color:var(--danger)">Analysis failed: ' + e.message + '</div>';
      layout.appendChild(panel);
    });
}
</script>

` + layoutFoot))
