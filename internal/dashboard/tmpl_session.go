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
.st-step.s-blocked{border-left:3px solid var(--danger);background:var(--danger-muted)}
.st-step.s-quarantined{border-left:3px solid var(--warn);background:var(--warn-muted)}

/* Timeline dot */
.st-step::before{content:'';position:absolute;left:-25px;top:18px;width:10px;height:10px;border-radius:50%;background:var(--success);border:2px solid var(--bg);box-shadow:0 0 6px var(--success-muted)}
.st-step.s-blocked::before{background:var(--danger);box-shadow:0 0 6px var(--danger-muted)}
.st-step.s-quarantined::before{background:var(--warn);box-shadow:0 0 6px var(--warn-muted)}

.st-step.s-human{border-left:3px solid var(--purple);background:var(--purple-muted)}
.st-step.s-human::before{background:var(--purple);box-shadow:0 0 6px var(--purple-muted)}
.st-step.s-human.s-blocked{border-left:3px solid var(--danger);background:var(--danger-muted)}
.st-role{font-size:0.62rem;padding:2px 7px;border-radius:4px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px}
.st-role.r-human{color:var(--purple);background:var(--purple-muted);border:1px solid var(--purple-border)}
.st-role.r-agent{color:var(--text3);background:var(--surface2);border:1px solid var(--border)}
.st-step-header{display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap}
.st-tool{font-weight:600;color:var(--text);font-size:var(--text-sm)}
.st-verdict{font-size:var(--text-xs);padding:2px 8px;border-radius:4px;font-weight:500}
.st-verdict.v-clean{color:var(--success);background:var(--success-muted);border:1px solid var(--success-border)}
.st-verdict.v-blocked{color:var(--danger);background:var(--danger-muted);border:1px solid var(--danger-border)}
.st-verdict.v-quarantined{color:var(--warn);background:var(--warn-muted);border:1px solid var(--warn-border)}
.st-time{font-size:var(--text-xs);color:var(--text3);margin-left:auto}
.st-gap{font-size:var(--text-xs);color:var(--text3);opacity:0.7}
.st-latency{font-size:var(--text-xs);color:var(--text3)}

.st-content{font-size:var(--text-xs);color:var(--text3);max-height:40px;overflow:hidden;font-family:var(--mono);word-break:break-all}

.st-reasoning{margin-top:8px;padding:10px 14px;background:var(--bg);border:1px solid var(--border);border-radius:6px;font-size:var(--text-xs);color:var(--text2);line-height:1.5}
.st-reasoning .label{font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:var(--ls-caps);font-size:0.65rem;margin-bottom:4px}
.st-plan{font-size:var(--text-xs);color:var(--accent);font-weight:500;margin-left:8px}

.st-link{font-size:var(--text-xs);color:var(--accent);text-decoration:none;margin-top:6px;display:inline-block}
.st-link:hover{text-decoration:underline}
.st-link:hover{text-decoration:underline}

.st-empty{padding:40px;text-align:center;color:var(--text3)}

/* Agent tree */
.st-tree{padding:16px 20px;background:var(--surface);border:1px solid var(--border);border-radius:10px;margin-bottom:20px}
.st-tree-title{font-size:var(--text-xs);text-transform:uppercase;letter-spacing:var(--ls-caps);color:var(--text3);margin-bottom:12px;font-weight:500}
.st-tree-node{display:flex;align-items:center;gap:8px;padding:4px 0;font-size:var(--text-sm)}
.st-tree-node .icon{font-size:0.9rem}
.st-tree-node .name{font-weight:500;color:var(--text);font-family:var(--mono);font-size:0.78rem}
.st-tree-node .meta{font-size:var(--text-xs);color:var(--text3)}
.st-tree-node .meta .blocks{color:var(--danger)}
.st-tree-indent{display:inline-block;width:20px;border-left:1px solid var(--border);margin-left:9px}

/* AI Analysis panel */
.st-ai-panel{position:sticky;top:20px}
.st-ai-meta{display:flex;gap:12px;margin-top:12px;padding-top:12px;border-top:1px solid var(--border);font-size:0.68rem;color:var(--text3)}
.st-ai-panel h3{font-size:var(--text-sm);text-transform:uppercase;letter-spacing:var(--ls-caps);color:var(--text3);margin:0 0 12px}
.st-ai-content{padding:20px;background:var(--surface);border:1px solid var(--border);border-radius:10px;font-size:var(--text-sm);line-height:1.7;color:var(--text2)}
.st-ai-content strong{color:var(--text)}
.st-ai-content a{color:var(--accent-light)}
.st-ai-content .ai-label{display:inline-block;font-size:0.62rem;padding:2px 7px;border-radius:4px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;color:var(--accent);background:rgba(139,124,247,0.1);margin-bottom:12px}
.st-ai-actions{display:flex;gap:8px;margin-top:12px}
.ss-ai-btn{padding:6px 16px;background:#1f6feb;color:#fff;border:1px solid var(--accent-border);border-radius:6px;font-size:var(--text-sm);cursor:pointer;font-weight:500;transition:background 0.15s}
.ss-ai-btn:hover{background:#388bfd}
.ss-ai-btn:disabled{opacity:0.5;cursor:not-allowed}
.ss-ai-btn.btn-outline{background:transparent;color:var(--accent);border:1px solid var(--accent-border)}
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

{{if .Hierarchy}}
<div class="st-tree">
  <div class="st-tree-title">Agent Tree</div>
  {{range .Hierarchy}}
  <div class="st-tree-node">
    {{range $i := (seq .Depth)}}<span class="st-tree-indent"></span>{{end}}
    <span class="icon">{{if eq .Depth 0}}&#x1F464;{{else}}&#x1F916;{{end}}</span>
    <span class="name">{{.AgentName}}</span>
    <span class="meta">{{.ToolCount}} calls{{if gt .BlockCount 0}}, <span class="blocks">{{.BlockCount}} blocked</span>{{end}}</span>
  </div>
  {{end}}
</div>
{{end}}

<div class="st-layout{{if not .SavedAnalysis}} no-analysis{{end}}" id="st-layout">
  <!-- Left: Timeline -->
  <div>
    {{if .Trace.Steps}}
    <div class="st-timeline">
      {{range .Trace.Steps}}
      <div class="st-step{{if eq .Verdict "blocked"}} s-blocked{{end}}{{if eq .Verdict "quarantined"}} s-quarantined{{end}}{{if eq .ToolName "message"}} s-human{{end}}">
        <div class="st-step-header">
          {{if eq .ToolName "message"}}<span class="st-role r-human">human</span>{{else if gt .AgentDepth 0}}<span class="st-role r-agent" style="color:var(--text3)">sub-agent</span>{{else}}<span class="st-role r-agent">agent</span>{{end}}
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

// runtimeSessionDetailTmpl renders the runtime-backed session
// page. It deliberately diverges from sessionTraceTmpl in two
// ways: (1) the timeline is built from runtime hook events, which
// carry hashes instead of raw input/output, and (2) the AI
// analysis sidebar is hidden — the session-analysis schema and
// the runtime envelope have not been reconciled yet, so showing
// audit-driven analysis next to runtime evidence would mix two
// stores. AI returns when the runtime path adopts the analysis
// pipeline.
var runtimeSessionDetailTmpl = template.Must(template.New("runtime-session-detail").Funcs(tmplFuncs).Parse(layoutHead + `
<style>
.rt-meta{font-size:var(--text-sm);color:var(--text3);margin-bottom:20px;display:flex;flex-wrap:wrap;gap:18px}
.rt-meta b{color:var(--text);font-weight:500}
.rt-meta .ss-status{display:inline-block;padding:2px 8px;border-radius:4px;font-size:var(--text-xs);font-weight:600}
.rt-meta .ss-status.s-active{background:var(--success-muted);color:var(--success);border:1px solid var(--success-border)}
.rt-meta .ss-status.s-ended{background:var(--surface2);color:var(--text2);border:1px solid var(--border)}
.rt-meta .ss-status.s-heartbeat{background:transparent;color:var(--text3);border:1px solid var(--border)}

.rt-actions{display:flex;gap:8px;margin-bottom:20px}
.rt-actions a{padding:5px 12px;font-size:var(--text-xs);border:1px solid var(--border);border-radius:5px;color:var(--text2);text-decoration:none;background:transparent}
.rt-actions a:hover{background:var(--surface2);color:var(--text)}

.rt-stats{display:grid;grid-template-columns:repeat(5,1fr);margin-bottom:24px;background:var(--surface);border:1px solid var(--border);border-radius:10px;overflow:hidden}
.rt-stat{padding:16px 20px;text-align:center}
.rt-stat+.rt-stat{border-left:1px solid var(--border)}
.rt-stat .label{font-size:var(--text-xs);text-transform:uppercase;letter-spacing:var(--ls-caps);color:var(--text3);margin-bottom:4px}
.rt-stat .value{font-size:1.2rem;font-weight:600;color:var(--text)}
.rt-stat .value.v-danger{color:var(--danger)}
@media(max-width:1100px){.rt-stats{grid-template-columns:repeat(3,1fr)}.rt-stat:nth-child(n+4){border-top:1px solid var(--border)}}

.rt-section{padding:16px 20px;background:var(--surface);border:1px solid var(--border);border-radius:10px;margin-bottom:24px}
.rt-section h3{font-size:var(--text-xs);text-transform:uppercase;letter-spacing:var(--ls-caps);color:var(--text3);margin:0 0 12px 0;font-weight:600}

.rt-actor{display:flex;align-items:center;gap:8px;padding:6px 0;font-size:var(--text-sm)}
.rt-actor .name{font-weight:500;color:var(--text);font-family:var(--mono);font-size:0.78rem}
.rt-actor .kind{font-size:0.62rem;padding:2px 7px;border-radius:4px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;background:var(--surface2);color:var(--text3);border:1px solid var(--border)}
.rt-actor .kind.k-root{color:var(--accent);border-color:var(--accent-border);background:rgba(56,139,253,0.10)}
.rt-actor .kind.k-subagent{color:var(--purple);border-color:var(--purple-border);background:var(--purple-muted)}
.rt-actor .kind.k-task{color:var(--warn);border-color:var(--warn-border);background:var(--warn-muted)}
.rt-actor .meta{font-size:var(--text-xs);color:var(--text3);margin-left:auto}
.rt-actor .meta .blocks{color:var(--danger)}
.rt-actor.indent-1{padding-left:24px}
.rt-actor.indent-2{padding-left:48px}
.rt-actor.indent-3{padding-left:72px}

.rt-timeline{position:relative;padding-left:32px}
.rt-timeline::before{content:'';position:absolute;left:11px;top:8px;bottom:8px;width:2px;background:var(--border)}
.rt-row{position:relative;margin-bottom:14px;padding:12px 16px;background:var(--surface);border:1px solid var(--border);border-radius:8px}
.rt-row::before{content:'';position:absolute;left:-25px;top:18px;width:10px;height:10px;border-radius:50%;background:var(--success);border:2px solid var(--bg);box-shadow:0 0 6px var(--success-muted)}
.rt-row.s-blocked{border-left:3px solid var(--danger);background:var(--danger-muted)}
.rt-row.s-blocked::before{background:var(--danger);box-shadow:0 0 6px var(--danger-muted)}
.rt-row.s-quarantined{border-left:3px solid var(--warn);background:var(--warn-muted)}
.rt-row.s-quarantined::before{background:var(--warn);box-shadow:0 0 6px var(--warn-muted)}
.rt-row.s-heartbeat{opacity:0.55;border-left:3px solid var(--border);background:transparent}
.rt-row.s-heartbeat::before{background:var(--text3)}

.rt-row-header{display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap}
.rt-event{font-weight:600;color:var(--text);font-size:var(--text-sm)}
.rt-actor-tag{font-size:var(--text-xs);color:var(--text3);font-family:var(--mono)}
.rt-stage{font-size:0.62rem;padding:2px 7px;border-radius:4px;text-transform:uppercase;letter-spacing:0.5px;background:var(--surface2);color:var(--text3);border:1px solid var(--border)}
.rt-status{font-size:var(--text-xs);padding:2px 8px;border-radius:4px;font-weight:500}
.rt-status.v-clean{color:var(--success);background:var(--success-muted);border:1px solid var(--success-border)}
.rt-status.v-blocked{color:var(--danger);background:var(--danger-muted);border:1px solid var(--danger-border)}
.rt-status.v-quarantined{color:var(--warn);background:var(--warn-muted);border:1px solid var(--warn-border)}
.rt-status.v-delivered,.rt-status.v-allowed{color:var(--text2);background:var(--surface2);border:1px solid var(--border)}
.rt-time{font-size:var(--text-xs);color:var(--text3);margin-left:auto;font-family:var(--mono)}
.rt-meta-line{font-size:var(--text-xs);color:var(--text3);font-family:var(--mono);word-break:break-all}
.rt-meta-line + .rt-meta-line{margin-top:4px}
.rt-link{font-size:var(--text-xs);color:var(--accent);text-decoration:none;margin-top:6px;display:inline-block}
.rt-link:hover{text-decoration:underline}
.rt-empty{padding:40px;text-align:center;color:var(--text3)}
.rt-diagnostic-banner{padding:12px 16px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;font-size:var(--text-sm);color:var(--text2);margin-bottom:20px}

/* Phase 4C — runtime AI sidebar. Distinct rt-* classes (rather
   than reusing the legacy ss-ai-* prefix) so the runtime branch
   never gets mistaken for the audit branch by a template grep
   or a copy-pinned test. */
.rt-ai-actions{display:inline-flex;gap:8px;align-items:center;margin-left:auto}
.rt-ai-analyze-btn{padding:6px 14px;background:#1f6feb;color:#fff;border:1px solid var(--accent-border);border-radius:6px;font-size:var(--text-sm);cursor:pointer;font-weight:500;transition:background 0.15s}
.rt-ai-analyze-btn:hover{background:#388bfd}
.rt-ai-analyze-btn:disabled{opacity:0.6;cursor:wait}
.rt-ai-disabled{font-size:var(--text-xs);color:var(--text3);font-style:italic}
.rt-ai-panel{margin-top:24px;padding:18px 20px;background:var(--surface);border:1px solid var(--accent-border);border-radius:10px;position:relative}
.rt-ai-panel::before{content:'';position:absolute;left:0;top:14px;bottom:14px;width:3px;background:var(--accent-light);border-radius:2px}
.rt-ai-hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;font-size:var(--text-sm);font-weight:600;color:var(--text)}
.rt-ai-model{font-size:0.65rem;color:var(--text3);font-family:var(--mono);font-weight:400;padding:2px 8px;background:var(--surface2);border-radius:4px}
.rt-ai-text{font-size:var(--text-sm);color:var(--text2);line-height:1.65;white-space:pre-wrap}
.rt-ai-meta{display:flex;gap:12px;margin-top:12px;padding-top:12px;border-top:1px solid var(--border);font-size:0.68rem;color:var(--text3)}
</style>

<div class="page-header" style="margin-bottom:8px">
  <h1 style="margin-bottom:4px">Session</h1>
</div>
<p style="color:var(--text3);font-size:var(--text-sm);margin:0 0 16px">Runtime hook events for this session</p>

<div class="rt-meta">
  <span><b>Session:</b> <span style="font-family:var(--mono);font-size:var(--text-xs)">{{.Detail.Session.SessionID}}</span></span>
  {{if .Detail.Session.PrincipalID}}<span><b>Principal:</b> <span style="font-family:var(--mono);font-size:var(--text-xs)">{{.Detail.Session.PrincipalID}}</span></span>{{end}}
  {{if .Detail.Session.ClientID}}<span><b>Client:</b> {{.Detail.Session.ClientID}}</span>{{end}}
  {{if .Detail.Session.ConnectorID}}<span><b>Connector:</b> {{.Detail.Session.ConnectorID}}</span>{{end}}
  <span><b>Status:</b> <span class="ss-status s-{{.Detail.Session.StatusClass}}">{{.Detail.Session.StatusLabel}}</span></span>
</div>

<div class="rt-actions">
  <a href="{{.Detail.JSONExportURL}}">JSON</a>
  <a href="{{.Detail.CSVExportURL}}">CSV</a>
  {{if .LLMEnabled}}
    {{if .CanAnalyze}}
    <span class="rt-ai-actions">
      <button class="rt-ai-analyze-btn" id="rt-ai-analyze-btn" onclick="rtAnalyzeSession('{{.Detail.Session.SessionID}}')">{{if .SavedAnalysis}}Re-analyze with AI{{else}}Analyze with AI{{end}}</button>
    </span>
    {{else if .AnalysisDisabledReason}}
    <span class="rt-ai-disabled">{{.AnalysisDisabledReason}}</span>
    {{end}}
  {{end}}
</div>

{{if .Detail.Session.IsHeartbeatOnly}}
<div class="rt-diagnostic-banner">
  This session id is a heartbeat keepalive. The events below are diagnostic only — no real hook activity has been recorded.
</div>
{{end}}

<div class="rt-stats">
  <div class="rt-stat">
    <div class="label">Events</div>
    <div class="value">{{.Detail.Session.EventCount}}</div>
  </div>
  <div class="rt-stat">
    <div class="label">Tool calls</div>
    <div class="value">{{.Detail.Session.ToolEventCount}}</div>
  </div>
  <div class="rt-stat">
    <div class="label">Subagents</div>
    <div class="value">{{.Detail.Session.SubagentCount}}</div>
  </div>
  <div class="rt-stat">
    <div class="label">Tasks</div>
    <div class="value">{{.Detail.Session.TaskCount}}</div>
  </div>
  <div class="rt-stat">
    <div class="label">Blocks</div>
    <div class="value{{if gt .Detail.Session.BlockCount 0}} v-danger{{end}}">{{.Detail.Session.BlockCount}}</div>
  </div>
</div>

{{if .Detail.Actors}}
<div class="rt-section">
  <h3>Actor tree</h3>
  {{range .Detail.Actors}}
  <div class="rt-actor{{if eq .Kind "subagent"}} indent-1{{else if eq .Kind "task"}} indent-2{{end}}">
    <span class="name">{{.Label}}</span>
    {{if .Kind}}<span class="kind k-{{.Kind}}">{{.Kind}}</span>{{end}}
    <span class="meta">
      {{.EventCount}} event{{if ne .EventCount 1}}s{{end}}{{if gt .ToolCount 0}} &middot; {{.ToolCount}} tool{{if ne .ToolCount 1}}s{{end}}{{end}}{{if gt .BlockCount 0}} &middot; <span class="blocks">{{.BlockCount}} blocked</span>{{end}}
    </span>
  </div>
  {{end}}
</div>
{{end}}

<div class="rt-section">
  <h3>Timeline</h3>
  {{if .Detail.Events}}
  <div class="rt-timeline">
    {{range .Detail.Events}}
    <div class="rt-row{{if .IsHeartbeat}} s-heartbeat{{end}}{{if eq .Status "blocked"}} s-blocked{{end}}{{if eq .Status "quarantined"}} s-quarantined{{end}}">
      <div class="rt-row-header">
        <span class="rt-event">{{.HookEventName}}</span>
        {{if .ActorLabel}}<span class="rt-actor-tag">{{.ActorLabel}}</span>{{end}}
        {{if .ToolName}}<span class="rt-actor-tag">tool: {{.ToolName}}</span>{{end}}
        {{if .Stage}}<span class="rt-stage">{{.Stage}}</span>{{end}}
        {{if .Status}}<span class="rt-status v-{{.Status}}">{{.Status}}</span>{{end}}
        <span class="rt-time" data-ts="{{.Timestamp}}">{{.Timestamp}}</span>
      </div>
      {{if .ToolUseID}}<div class="rt-meta-line">use_id: {{.ToolUseID}}</div>{{end}}
      {{if .ToolInputHash}}<div class="rt-meta-line">input: sha256:{{truncate .ToolInputHash 16}}</div>{{end}}
      {{if .ToolOutputHash}}<div class="rt-meta-line">output: sha256:{{truncate .ToolOutputHash 16}}</div>{{end}}
      {{if .FilePathTail}}<div class="rt-meta-line">path: {{.FilePathTail}}</div>{{end}}
      {{if .TaskSubject}}<div class="rt-meta-line">task: {{.TaskSubject}}</div>{{end}}
      {{if .CoverageMode}}<div class="rt-meta-line">coverage: {{.CoverageMode}}{{if gt .Confidence 0}} &middot; confidence {{.Confidence}}{{end}}</div>{{end}}
      {{if and (ne .PolicyDecision "") (ne .PolicyDecision .Status)}}<div class="rt-meta-line">policy: {{.PolicyDecision}}</div>{{end}}
      {{if gt .LatencyMs 0}}<div class="rt-meta-line">latency: {{.LatencyMs}}ms</div>{{end}}
      {{if .AuditEntryID}}<a href="/dashboard/events/{{.AuditEntryID}}" class="rt-link">View audit entry &rarr;</a>{{end}}
    </div>
    {{end}}
  </div>
  {{else}}
  <div class="rt-empty">No hook events recorded for this session.</div>
  {{end}}
</div>

<div id="rt-ai-panel-slot">
{{if .SavedAnalysis}}
<div class="rt-ai-panel" id="rt-ai-panel">
  <div class="rt-ai-hdr">
    <span>Runtime AI assessment</span>
    {{if .AnalysisModel}}<span class="rt-ai-model">{{.AnalysisModel}}</span>{{end}}
  </div>
  <div class="rt-ai-text">{{.SavedAnalysis}}</div>
  {{if .AnalysisDate}}
  <div class="rt-ai-meta">
    <span>Analyzed: {{.AnalysisDate}}</span>
  </div>
  {{end}}
</div>
{{end}}
</div>

<script>
function rtAnalyzeSession(sid) {
  var btn = document.getElementById('rt-ai-analyze-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Analyzing...'; }
  fetch('/dashboard/api/sessions/' + sid + '/analyze', {method: 'POST'})
    .then(function(r) {
      if (!r.ok) { return r.text().then(function(t){ throw new Error(t || r.statusText); }); }
      return r.text();
    })
    .then(function() { window.location.reload(); })
    .catch(function(e) {
      if (btn) { btn.disabled = false; btn.textContent = 'Analyze with AI'; }
      var slot = document.getElementById('rt-ai-panel-slot');
      if (slot) {
        slot.innerHTML = '<div class="rt-ai-panel" id="rt-ai-panel"><div class="rt-ai-hdr"><span>Runtime AI assessment</span></div><div class="rt-ai-text" style="color:var(--danger)">Analysis failed: ' + e.message + '</div></div>';
      }
    });
}
</script>
` + layoutFoot))
