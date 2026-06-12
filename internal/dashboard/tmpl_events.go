package dashboard

import "html/template"

var eventDetailTmpl = template.Must(template.New("event-detail").Funcs(tmplFuncs).Parse(`
<style>
.ed-hdr{display:flex;align-items:center;gap:var(--sp-3);padding:var(--sp-4) var(--sp-5);border-bottom:1px solid var(--border)}
.ed-close{background:none;border:none;color:var(--text3);font-size:1.2rem;cursor:pointer;padding:var(--sp-1) var(--sp-2);border-radius:var(--radius-sm);line-height:1}
.ed-close:hover{background:var(--surface-hover);color:var(--text)}
.ed-body{padding:0}
.ed-section{padding:var(--sp-4) var(--sp-5)}
.ed-slbl{font-size:var(--text-xs);font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:var(--ls-caps);margin-bottom:var(--sp-3)}
.ed-row{display:flex;justify-content:space-between;align-items:baseline;padding:var(--sp-2) 0;border-bottom:1px solid var(--border-subtle)}
.ed-row:last-child{border-bottom:none}
.ed-row .k{color:var(--text3);font-size:var(--text-sm)}
.ed-row .v{font-family:var(--mono);font-size:var(--text-sm);color:var(--text);text-align:right;max-width:60%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ed-row .v a{color:var(--accent-light)}
.ed-tabs{display:flex;border-bottom:1px solid var(--border);padding:0 var(--sp-5)}
.ed-tab{padding:var(--sp-3) var(--sp-4);font-size:var(--text-xs);font-weight:500;color:var(--text3);cursor:pointer;border-bottom:2px solid transparent;text-transform:uppercase;letter-spacing:0.5px;transition:color 0.15s,border-color 0.15s}
.ed-tab:hover{color:var(--text2)}
.ed-tab.active{color:var(--accent-light);border-bottom-color:var(--accent)}
.ed-tab-content{display:none}
.ed-tab-content.active{display:block}
</style>
<div class="ed-hdr">
  <div style="display:flex;align-items:center;gap:8px">
    {{if eq .Entry.Status "delivered"}}<span class="badge-delivered">delivered</span>
    {{else if eq .Entry.Status "blocked"}}<span class="badge-blocked">blocked</span>
    {{else if eq .Entry.Status "rejected"}}<span class="badge-rejected">rejected</span>
    {{else if eq .Entry.Status "quarantined"}}<span class="badge-quarantined">quarantined</span>
    {{else if eq .Entry.Status "step_up"}}<span class="badge-quarantined">awaiting approval</span>
    {{else if eq .Entry.Status "modified"}}<span class="badge-delivered">delivered (redacted)</span>
    {{else}}<span style="color:var(--text2);font-size:0.75rem">{{.Entry.Status}}</span>{{end}}
  </div>
  <span style="flex:1;font-family:var(--mono);font-size:var(--text-sm);color:var(--text2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{.Entry.FromAgent}} &rarr; {{.Entry.ToAgent}}</span>
  <a href="/dashboard/events/{{.Entry.ID}}" class="btn btn-sm btn-outline" style="font-size:var(--text-xs);white-space:nowrap;border-color:var(--accent-border);color:var(--accent-light)">Detail &rarr;</a>
  <button class="ed-close" onclick="closePanel()">&times;</button>
</div>
<div style="font-size:var(--text-sm);color:var(--text3);padding:var(--sp-2) var(--sp-5);border-bottom:1px solid var(--border);font-family:var(--mono)" data-ts="{{.Entry.Timestamp}}">{{.Entry.Timestamp}}</div>

{{if eq .Entry.Status "quarantined"}}<div style="padding:var(--sp-3) var(--sp-5);background:rgba(210,153,34,0.08);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:var(--sp-3)">
  <span style="font-size:var(--text-sm);color:var(--warn);font-weight:500">Awaiting human review</span>
  <a href="/dashboard/events?tab=quarantine" class="btn btn-sm" style="margin-left:auto;font-size:var(--text-xs);background:var(--warn);color:#000;border:none">Review Queue &rarr;</a>
</div>{{end}}
{{if eq .Entry.Status "blocked"}}<div style="padding:var(--sp-3) var(--sp-5);background:rgba(248,81,73,0.06);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:var(--sp-3)">
  <span style="font-size:var(--text-sm);color:var(--danger);font-weight:500">Blocked by security pipeline</span>
  <a href="/dashboard/events/{{.Entry.ID}}" class="btn btn-sm btn-outline" style="margin-left:auto;font-size:var(--text-xs)">Full Investigation &rarr;</a>
</div>{{end}}

<!-- Tabs -->
<div class="ed-tabs">
  <div class="ed-tab active" onclick="edSwitchTab('overview',this)">Overview</div>
  <div class="ed-tab" onclick="edSwitchTab('content',this)">Content{{if .Rules}} <span style="color:var(--warn)">({{len .Rules}})</span>{{end}}</div>
  <div class="ed-tab" onclick="edSwitchTab('forensics',this)">Forensics{{if .Reasoning}} &bull;{{end}}</div>
</div>

<div class="ed-body">

<!-- TAB: Overview -->
<div class="ed-tab-content active" data-ed-tab="overview">
  <div class="ed-section">
    <div class="ed-row"><span class="k">Agent</span><span class="v"><a href="/dashboard/agents/{{.Entry.FromAgent}}">{{.Entry.FromAgent}}</a></span></div>
    <div class="ed-row"><span class="k">Tool</span><span class="v">{{if .Entry.ToolName}}{{toolDot .Entry.ToolName}}{{else}}{{.Entry.ToAgent}}{{end}}</span></div>
    <div class="ed-row"><span class="k">Latency</span><span class="v" style="color:{{if lt .Entry.LatencyMs 100}}var(--text2){{else}}var(--warn){{end}}">{{.Entry.LatencyMs}}ms</span></div>
    {{if .Entry.SessionID}}<div class="ed-row"><span class="k">Session</span><span class="v"><a href="/dashboard/sessions/{{.Entry.SessionID}}" style="color:var(--accent);text-decoration:none;font-size:0.72rem" title="View session trace">{{truncate .Entry.SessionID 20}} &rarr;</a></span></div>{{end}}
    {{if .AgentSuspended}}<div class="ed-row"><span class="k">Status</span><span class="v"><span style="color:var(--danger);font-weight:600">Suspended</span></span></div>{{end}}
  </div>
  <div class="ed-section">
    <div class="ed-slbl">Authorization</div>
    {{if .Entry.DelegationChain}}<div class="ed-row"><span class="k">Delegation</span><span class="v" style="font-size:0.72rem;color:var(--success);font-family:var(--sans)">{{.Entry.DelegationChain}}</span></div>{{else}}<div class="ed-row"><span class="k">Delegation</span><span class="v" style="font-size:0.72rem;color:var(--text3)">Direct (no delegation)</span></div>{{end}}
    {{if .AgentCreatedBy}}<div class="ed-row"><span class="k">Registered by</span><span class="v" style="font-family:var(--sans)">{{.AgentCreatedBy}}</span></div>{{end}}
    {{if .AgentCreatedAt}}<div class="ed-row"><span class="k">Registered</span><span class="v" style="font-size:0.72rem" data-ts="{{.AgentCreatedAt}}">{{.AgentCreatedAt}}</span></div>{{end}}
  </div>
  <div class="ed-section">
    <div class="ed-slbl">Security pipeline</div>
    <div class="ed-row">
      <span class="k" style="display:flex;align-items:center;gap:6px"><span style="width:6px;height:6px;border-radius:50%;background:{{if eq .Entry.SignatureVerified 1}}var(--success){{else if eq .Entry.SignatureVerified -1}}var(--danger){{else}}var(--text3){{end}};flex-shrink:0"></span>Identity</span>
      <span class="v">{{if eq .Entry.SignatureVerified 1}}<span style="color:var(--success)">Verified</span>{{else if eq .Entry.SignatureVerified -1}}<span style="color:var(--danger)">Invalid</span>{{else}}{{if .RequireSig}}<span style="color:var(--danger)">Missing</span>{{else}}<span style="color:var(--text3)">Not required</span>{{end}}{{end}}</span>
    </div>
    <div class="ed-row">
      <span class="k" style="display:flex;align-items:center;gap:6px"><span style="width:6px;height:6px;border-radius:50%;background:{{if .Rules}}var(--warn){{else}}var(--success){{end}};flex-shrink:0"></span>Content scan</span>
      <span class="v">{{if .Rules}}<span style="color:var(--warn);font-weight:600">{{len .Rules}} triggered</span>{{else}}<span style="color:var(--success)">Clean</span>{{end}} <span style="color:var(--text3);font-size:0.62rem">({{.RuleCount}})</span></span>
    </div>
    <div class="ed-row">
      <span class="k" style="display:flex;align-items:center;gap:6px"><span style="width:6px;height:6px;border-radius:50%;background:{{if eq .Entry.Status "delivered"}}var(--success){{else if eq .Entry.Status "blocked"}}var(--danger){{else}}var(--warn){{end}};flex-shrink:0"></span>Verdict</span>
      <span class="v">{{.Decision}}</span>
    </div>
    {{if ge .LLMRiskScore 0.0}}
    <div class="ed-row">
      <span class="k" style="display:flex;align-items:center;gap:6px"><span style="width:6px;height:6px;border-radius:50%;background:{{if ge .LLMRiskScore 51.0}}var(--danger){{else if ge .LLMRiskScore 31.0}}var(--warn){{else}}var(--success){{end}};flex-shrink:0"></span>LLM</span>
      <span class="v" style="{{if ge .LLMRiskScore 76.0}}color:#f85149{{else if ge .LLMRiskScore 51.0}}color:var(--danger){{else if ge .LLMRiskScore 31.0}}color:#d29922{{else}}color:var(--success){{end}}">{{printf "%.0f" .LLMRiskScore}}/100{{if .LLMAction}} &middot; {{.LLMAction}}{{end}}</span>
    </div>
    {{end}}
  </div>
</div>

<!-- TAB: Content -->
<div class="ed-tab-content" data-ed-tab="content">
  {{if .Rules}}
  <div class="ed-section">
    <div class="ed-slbl">Rules triggered ({{len .Rules}})</div>
    {{range .Rules}}
    <div style="display:flex;align-items:center;gap:var(--sp-2);padding:var(--sp-2) 0;font-size:var(--text-sm);border-bottom:1px solid var(--border-subtle)">
      {{$s := lower .Severity}}
      {{if eq $s "critical"}}<span class="sev-critical">critical</span>
      {{else if eq $s "high"}}<span class="sev-high">high</span>
      {{else if eq $s "medium"}}<span class="sev-medium">medium</span>
      {{else if eq $s "low"}}<span class="sev-low">low</span>
      {{else}}<span class="sev-low">{{.Severity}}</span>{{end}}
      <span style="font-family:var(--mono);font-weight:600;color:var(--text);font-size:var(--text-sm)">{{.RuleID}}</span>
      <span style="color:var(--text3);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:var(--text-sm)">{{.Name}}</span>
    </div>
    {{if .Match}}<div style="font-family:var(--mono);font-size:var(--text-xs);color:var(--text3);padding:2px 0 var(--sp-1);margin-left:var(--sp-1);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;opacity:0.7" title="{{.Match}}">{{truncate .Match 80}}</div>{{end}}
    {{end}}
  </div>
  {{end}}
  {{if .Entry.Intent}}
  <div class="ed-section">
    <div class="ed-slbl">Intercepted content</div>
    <div id="ed-content-raw" style="display:none">{{.Entry.Intent}}</div>
    <pre id="ed-content-pretty" style="background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:10px 12px;font-family:var(--mono);font-size:var(--text-xs);line-height:1.6;color:var(--text2);white-space:pre-wrap;word-break:break-all;max-height:240px;overflow-y:auto;margin:0"></pre>
    <script>
    (function(){
      var raw=document.getElementById('ed-content-raw');if(!raw)return;
      var el=document.getElementById('ed-content-pretty');if(!el)return;
      var txt=raw.textContent.trim();
      try{el.innerHTML=syntaxHL(JSON.stringify(JSON.parse(txt),null,2));}catch(e){el.textContent=txt;}
      function syntaxHL(j){return j.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"([^"]*)"(\s*:)/g,'<span style="color:#79c0ff">"$1"</span>$2').replace(/"([^"]*)"/g,'<span style="color:#a5d6ff">"$1"</span>').replace(/\b(true|false|null)\b/g,'<span style="color:#ff7b72">$1</span>').replace(/\b(-?\d+\.?\d*)\b/g,'<span style="color:#d2a8ff">$1</span>');}
    })();
    </script>
  </div>
  {{else}}
  <div class="ed-section"><div style="color:var(--text3);font-size:var(--text-sm);padding:var(--sp-3) 0">No content captured</div></div>
  {{end}}
</div>

<!-- TAB: Forensics -->
<div class="ed-tab-content" data-ed-tab="forensics">
  {{if .Reasoning}}
  <div class="ed-section">
    <div class="ed-slbl">Reasoning</div>
    <div style="font-size:var(--text-sm);color:var(--text2);line-height:1.6;padding:4px 0 8px">{{.Reasoning.Reasoning}}</div>
    {{if gt .Reasoning.PlanStep 0}}<div class="ed-row"><span class="k">Plan</span><span class="v">Step {{.Reasoning.PlanStep}} of {{.Reasoning.PlanTotal}}</span></div>{{end}}
    <div class="ed-row"><span class="k">Reasoning hash</span><span class="v" style="font-size:0.68rem" title="{{.Reasoning.ReasoningHash}}">{{truncate .Reasoning.ReasoningHash 28}}</span></div>
  </div>
  {{end}}
  <div class="ed-section">
    <div class="ed-slbl">Integrity</div>
    <div class="ed-row"><span class="k">Event ID</span><span class="v" title="{{.Entry.ID}}" style="font-size:0.68rem">{{truncate .Entry.ID 28}}</span></div>
    {{if .Entry.ContentHash}}<div class="ed-row"><span class="k">Content hash</span><span class="v" title="{{.Entry.ContentHash}}" style="font-size:0.68rem">{{truncate .Entry.ContentHash 28}}</span></div>{{end}}
    {{if .Entry.EntryHash}}<div class="ed-row"><span class="k">Chain hash</span><span class="v" title="{{.Entry.EntryHash}}" style="font-size:0.68rem">{{truncate .Entry.EntryHash 28}}</span></div>{{end}}
    {{if .Entry.ProxySignature}}<div class="ed-row"><span class="k">Proxy signature</span><span class="v" style="color:var(--success);font-size:0.68rem">signed</span></div>{{end}}
    {{if .Entry.DelegationChainHash}}<div class="ed-row"><span class="k">Delegation</span><span class="v" style="font-size:0.68rem" title="{{.Entry.DelegationChainHash}}">{{truncate .Entry.DelegationChainHash 28}}</span></div>{{end}}
  </div>
</div>

</div>
<script>
function edSwitchTab(name,el){
  document.querySelectorAll('.ed-tab').forEach(function(t){t.classList.remove('active')});
  document.querySelectorAll('.ed-tab-content').forEach(function(c){c.classList.remove('active')});
  el.classList.add('active');
  var target=document.querySelector('[data-ed-tab="'+name+'"]');
  if(target)target.classList.add('active');
}
</script>
`))

// ciCSS is the shared CSS for "case investigation" style pages (Threat Intel, Event Detail).
const ciCSS = `
.ci-back{color:var(--text3);text-decoration:none;font-size:var(--text-sm);display:inline-flex;align-items:center;gap:6px;transition:color var(--ease-default);touch-action:manipulation}
.ci-back:hover{color:var(--accent-light)}
.ci-hdr{display:flex;align-items:flex-start;gap:var(--sp-5);margin-bottom:var(--sp-5)}
.ci-score{display:flex;flex-direction:column;align-items:center;justify-content:center;width:72px;height:72px;border-radius:var(--radius-xl);flex-shrink:0}
.ci-score .n{font-size:var(--text-2xl);font-weight:700;font-family:var(--sans);line-height:1;letter-spacing:0}
.ci-score .l{font-size:0.52rem;letter-spacing:0.6px;margin-top:var(--sp-1);opacity:0.7;font-weight:500}
.ci-hdr-body{flex:1;min-width:0}
.ci-title{font-size:var(--text-lg);font-weight:600;margin:0 0 var(--sp-2);line-height:1.4;color:var(--text);text-wrap:pretty}
.ci-hdr-row{display:flex;align-items:center;gap:var(--sp-2);flex-wrap:wrap;font-size:var(--text-sm);color:var(--text3)}
.ci-hdr-row .sep{color:var(--border)}
.ci-badge{display:inline-block;padding:var(--sp-1) 14px;border-radius:100px;font-size:var(--text-sm);font-weight:500;flex-shrink:0;align-self:center;letter-spacing:0.2px}
.ci-badge-blk{background:rgba(248,81,73,0.15);color:#f85149}
.ci-badge-inv{background:rgba(210,153,34,0.15);color:#d29922}
.ci-badge-qua{background:var(--danger-muted);color:var(--danger)}
.ci-badge-ok{background:var(--surface2);color:var(--text3)}
.ci-s{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-xl);padding:var(--sp-5) var(--sp-6);margin-bottom:var(--sp-5)}
.ci-s h3{font-size:var(--text-xs);font-weight:600;color:var(--text3);margin:0 0 var(--sp-4);text-transform:uppercase;letter-spacing:var(--ls-caps);display:flex;align-items:center;gap:var(--sp-2)}
.ci-s h3 .cnt{font-weight:500;font-family:var(--mono);text-transform:none}
.ci-context-row{display:grid;grid-template-columns:3fr 2fr;gap:var(--sp-5);align-items:start;margin-bottom:var(--sp-5)}
.ci-sev{display:inline-block;padding:2px var(--sp-2);border-radius:100px;font-size:0.6rem;font-weight:600;letter-spacing:0.3px}
.ci-sev-c{background:rgba(248,81,73,0.18);color:#f85149}
.ci-sev-h{background:var(--danger-muted);color:var(--danger)}
.ci-sev-m{background:rgba(210,153,34,0.18);color:#d29922}
.ci-sev-l{background:rgba(63,185,80,0.15);color:#3fb950}
.ci-thr{display:flex;align-items:flex-start;gap:var(--sp-3);padding:14px var(--sp-5);border-bottom:1px solid var(--border)}
.ci-thr:last-child{border-bottom:none}
.ci-thr-sev{flex-shrink:0;padding-top:2px}
.ci-thr-body{flex:1;min-width:0}
.ci-thr-head{display:flex;flex-direction:column;gap:var(--sp-1)}
.ci-thr-id{font-family:var(--mono);font-size:var(--text-sm);font-weight:600;color:var(--text2);text-transform:uppercase}
.ci-thr-name{font-size:var(--text-base);color:var(--text);font-weight:500;line-height:1.55}
.ci-thr-detail{font-size:var(--text-sm);color:var(--text3);margin-top:var(--sp-2);line-height:1.6}
.ci-benign{display:flex;align-items:center;gap:10px;color:var(--success);font-size:var(--text-md);padding:var(--sp-3) var(--sp-5)}
.ci-meta-row{display:flex;justify-content:space-between;align-items:baseline;padding:var(--sp-2) 0;border-bottom:1px solid var(--border-subtle);font-size:var(--text-sm)}
.ci-meta-row:last-child{border-bottom:none}
.ci-meta-row .mk{color:var(--text3);font-weight:500}
.ci-meta-row .mv{font-family:var(--mono);color:var(--text2);font-size:var(--text-sm);text-align:right;word-break:break-all}
@media(max-width:960px){.ci-context-row{grid-template-columns:1fr}.ci-hdr{flex-direction:column;gap:14px}.ci-s{padding:var(--sp-4) var(--sp-4)}}
`

var eventPageTmpl = template.Must(template.New("event-page").Funcs(tmplFuncs).Parse(layoutHead + `
<style>
.ep-back{color:var(--text3);text-decoration:none;font-size:var(--text-sm);display:inline-flex;align-items:center;gap:6px;transition:color var(--ease-default)}
.ep-back:hover{color:var(--accent-light)}
.ep-grid{display:grid;grid-template-columns:1fr 1fr;gap:var(--sp-5);align-items:start}
.ep-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;overflow:hidden;margin-bottom:var(--sp-5)}
.ep-card-hdr{display:flex;align-items:center;justify-content:space-between;padding:12px 20px;border-bottom:1px solid var(--border)}
.ep-card-hdr h3{margin:0;font-size:0.68rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);font-weight:500}
.ep-card-body{padding:16px 20px}
.ep-row{display:flex;justify-content:space-between;align-items:baseline;padding:8px 0;border-bottom:1px solid var(--border-subtle)}
.ep-row:last-child{border-bottom:none}
.ep-row .k{color:var(--text3);flex-shrink:0;font-size:var(--text-sm)}
.ep-row .v{font-family:var(--mono);font-size:var(--text-sm);color:var(--text);text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-left:var(--sp-3)}
.ep-row .v a{color:var(--accent-light)}
.ep-rule{display:flex;align-items:center;gap:8px;padding:8px 0;font-size:var(--text-sm);border-bottom:1px solid var(--border-subtle)}
.ep-rule:last-child{border-bottom:none}
.ep-content{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:16px 18px;font-family:var(--mono);font-size:0.75rem;line-height:1.8;color:var(--text2);white-space:pre-wrap;word-break:break-word;max-height:500px;overflow:auto;tab-size:2}
.ep-content .json-key{color:#79c0ff}
.ep-content .json-str{color:#a5d6ff}
.ep-content .json-bool{color:#ff7b72}
.ep-content .json-num{color:#d2a8ff}
.ep-content .json-null{color:#ff7b72;font-style:italic}
.ep-content .json-bracket{color:var(--text3)}
.ep-pipe-step{display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid var(--border-subtle)}
.ep-pipe-step:last-child{border-bottom:none}
.ep-pipe-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.ep-pipe-name{font-size:var(--text-sm);color:var(--text2);flex:1}
.ep-pipe-val{font-family:var(--mono);font-size:var(--text-sm);font-weight:600}
.ep-hash{font-family:var(--mono);font-size:0.72rem;color:var(--text2);word-break:break-all;line-height:1.5;padding:8px 12px;background:var(--bg);border:1px solid var(--border);border-radius:6px;margin-top:4px}
@media(max-width:960px){.ep-grid{grid-template-columns:1fr}}
</style>

<p style="margin-bottom:16px"><a href="/dashboard/events" class="ep-back">&larr; Event Log</a></p>

<!-- Header bar -->
<div style="display:flex;align-items:center;gap:14px;margin-bottom:var(--sp-5);padding:16px 20px;background:var(--surface);border:1px solid var(--border);border-radius:10px">
  {{if eq .Entry.Status "delivered"}}<span class="badge-delivered" style="font-size:0.82rem;padding:4px 14px">delivered</span>
  {{else if eq .Entry.Status "blocked"}}<span class="badge-blocked" style="font-size:0.82rem;padding:4px 14px">blocked</span>
  {{else if eq .Entry.Status "rejected"}}<span class="badge-rejected" style="font-size:0.82rem;padding:4px 14px">rejected</span>
  {{else if eq .Entry.Status "quarantined"}}<span class="badge-quarantined" style="font-size:0.82rem;padding:4px 14px">quarantined</span>
  {{else}}<span style="color:var(--text2)">{{.Entry.Status}}</span>{{end}}
  <div style="flex:1">
    <div style="font-family:var(--mono);font-size:0.85rem;color:var(--text);font-weight:600">{{.Entry.FromAgent}} &rarr; {{if .Entry.ToolName}}{{.Entry.ToolName}}{{else}}{{.Entry.ToAgent}}{{end}}</div>
    <div style="font-size:0.72rem;color:var(--text3);margin-top:2px">{{.Decision}}</div>
  </div>
  <div style="text-align:right">
    <div style="font-family:var(--mono);font-size:0.82rem;color:var(--text2)" data-ts="{{.Entry.Timestamp}}">{{relativeTime .Entry.Timestamp}}</div>
    <div style="font-family:var(--mono);font-size:0.72rem;color:var(--text3);margin-top:2px">{{.Entry.LatencyMs}}ms latency</div>
  </div>
</div>

<!-- Pipeline summary bar -->
<div style="display:flex;gap:1px;background:var(--border);border:1px solid var(--border);border-radius:10px;overflow:hidden;margin-bottom:var(--sp-5)">
  <div style="flex:1;background:var(--surface);padding:12px 16px;text-align:center">
    <div style="display:flex;align-items:center;justify-content:center;gap:6px">
      <span class="ep-pipe-dot" style="background:{{if eq .Entry.SignatureVerified 1}}var(--success){{else if eq .Entry.SignatureVerified -1}}var(--danger){{else}}var(--text3){{end}}"></span>
      <span style="font-size:0.72rem;color:var(--text2)">Identity</span>
    </div>
  </div>
  <div style="flex:1;background:var(--surface);padding:12px 16px;text-align:center">
    <div style="display:flex;align-items:center;justify-content:center;gap:6px">
      <span class="ep-pipe-dot" style="background:{{if .Rules}}var(--warn){{else}}var(--success){{end}}"></span>
      <span style="font-size:0.72rem;color:var(--text2)">Scan{{if .Rules}} ({{len .Rules}}){{end}}</span>
    </div>
  </div>
  <div style="flex:1;background:var(--surface);padding:12px 16px;text-align:center">
    <div style="display:flex;align-items:center;justify-content:center;gap:6px">
      <span class="ep-pipe-dot" style="background:{{if eq .Entry.Status "delivered"}}var(--success){{else if eq .Entry.Status "blocked"}}var(--danger){{else}}var(--warn){{end}}"></span>
      <span style="font-size:0.72rem;color:var(--text2)">Verdict</span>
    </div>
  </div>
  {{if ge .LLMRiskScore 0.0}}
  <div style="flex:1;background:var(--surface);padding:12px 16px;text-align:center">
    <div style="display:flex;align-items:center;justify-content:center;gap:6px">
      <span class="ep-pipe-dot" style="background:{{if ge .LLMRiskScore 51.0}}var(--danger){{else if ge .LLMRiskScore 31.0}}var(--warn){{else}}var(--success){{end}}"></span>
      <span style="font-size:0.72rem;color:var(--text2)">LLM {{printf "%.0f" .LLMRiskScore}}</span>
    </div>
  </div>
  {{end}}
  <div style="flex:1;background:var(--surface);padding:12px 16px;text-align:center">
    <div style="display:flex;align-items:center;justify-content:center;gap:6px">
      <span class="ep-pipe-dot" style="background:{{if .Entry.EntryHash}}var(--success){{else}}var(--text3){{end}}"></span>
      <span style="font-size:0.72rem;color:var(--text2)">Audit</span>
    </div>
  </div>
</div>

<div class="ep-grid">
  <!-- LEFT -->
  <div>
    <!-- Message Details -->
    <div class="ep-card">
      <div class="ep-card-hdr"><h3>Message Details</h3></div>
      <div class="ep-card-body">
        <div class="ep-row"><span class="k">From</span><span class="v"><a href="/dashboard/agents/{{.Entry.FromAgent}}">{{.Entry.FromAgent}}</a>{{if .AgentSuspended}} <span style="color:var(--danger);font-size:0.58rem;font-weight:600">SUSPENDED</span>{{end}}</span></div>
        <div class="ep-row"><span class="k">To</span><span class="v">{{if .Entry.ToolName}}{{toolDot .Entry.ToolName}}{{else}}{{.Entry.ToAgent}}{{end}}</span></div>
        <div class="ep-row"><span class="k">Latency</span><span class="v" style="color:{{if ge .Entry.LatencyMs 500}}var(--danger){{else if ge .Entry.LatencyMs 100}}var(--warn){{else}}var(--text2){{end}}">{{.Entry.LatencyMs}}ms</span></div>
        {{if .Entry.SessionID}}<div class="ep-row"><span class="k">Session</span><span class="v"><a href="/dashboard/sessions/{{.Entry.SessionID}}" style="color:var(--accent);text-decoration:none" title="View session trace">{{truncate .Entry.SessionID 24}} &rarr;</a></span></div>{{end}}
        <div class="ep-row"><span class="k">Decision</span><span class="v" style="font-family:var(--sans);color:{{if eq .Entry.Status "delivered"}}var(--success){{else if eq .Entry.Status "blocked"}}var(--danger){{else}}var(--warn){{end}}">{{.Decision}}</span></div>
      </div>
    </div>

    <!-- Security Pipeline -->
    <div class="ep-card">
      <div class="ep-card-hdr"><h3>Security Pipeline</h3><span style="font-size:0.68rem;color:var(--text3);font-family:var(--mono)">{{.RuleCount}} rules</span></div>
      <div class="ep-card-body">
        <div class="ep-pipe-step">
          <span class="ep-pipe-dot" style="background:{{if eq .Entry.SignatureVerified 1}}var(--success){{else if eq .Entry.SignatureVerified -1}}var(--danger){{else}}var(--text3){{end}}"></span>
          <span class="ep-pipe-name">Identity verification</span>
          <span class="ep-pipe-val" style="color:{{if eq .Entry.SignatureVerified 1}}var(--success){{else if eq .Entry.SignatureVerified -1}}var(--danger){{else}}var(--text3){{end}}">{{if eq .Entry.SignatureVerified 1}}Verified{{else if eq .Entry.SignatureVerified -1}}Invalid{{else}}{{if .RequireSig}}Missing{{else}}Skipped{{end}}{{end}}</span>
        </div>
        <div class="ep-pipe-step">
          <span class="ep-pipe-dot" style="background:{{if .Rules}}var(--warn){{else}}var(--success){{end}}"></span>
          <span class="ep-pipe-name">Content scan</span>
          <span class="ep-pipe-val" style="color:{{if .Rules}}var(--warn){{else}}var(--success){{end}}">{{if .Rules}}{{len .Rules}} triggered{{else}}Clean{{end}}</span>
        </div>
        <div class="ep-pipe-step">
          <span class="ep-pipe-dot" style="background:{{if eq .Entry.Status "delivered"}}var(--success){{else if eq .Entry.Status "blocked"}}var(--danger){{else}}var(--warn){{end}}"></span>
          <span class="ep-pipe-name">Final verdict</span>
          <span class="ep-pipe-val" style="color:{{if eq .Entry.Status "delivered"}}var(--success){{else if eq .Entry.Status "blocked"}}var(--danger){{else}}var(--warn){{end}}">{{if eq .Entry.Status "delivered"}}Allowed{{else if eq .Entry.Status "blocked"}}Blocked{{else if eq .Entry.Status "quarantined"}}Quarantined{{else}}Rejected{{end}}</span>
        </div>
        {{if ge .LLMRiskScore 0.0}}
        <div class="ep-pipe-step">
          <span class="ep-pipe-dot" style="background:{{if ge .LLMRiskScore 51.0}}var(--danger){{else if ge .LLMRiskScore 31.0}}var(--warn){{else}}var(--success){{end}}"></span>
          <span class="ep-pipe-name">LLM analysis</span>
          <span class="ep-pipe-val" style="color:{{if ge .LLMRiskScore 76.0}}#f85149{{else if ge .LLMRiskScore 51.0}}var(--danger){{else if ge .LLMRiskScore 31.0}}#d29922{{else}}var(--success){{end}}">{{printf "%.0f" .LLMRiskScore}}/100{{if .LLMAction}} &middot; {{.LLMAction}}{{end}}</span>
        </div>
        {{end}}
      </div>
    </div>

    <!-- Rules Triggered -->
    {{if .Rules}}
    <div class="ep-card">
      <div class="ep-card-hdr"><h3>Rules Triggered</h3><span style="font-size:0.72rem;font-family:var(--mono);color:var(--warn);font-weight:600">{{len .Rules}}</span></div>
      <div class="ep-card-body">
        {{range .Rules}}
        <div class="ep-rule">
          {{if eq .Severity "CRITICAL"}}<span class="sev-critical" style="font-size:0.58rem">critical</span>
          {{else if eq .Severity "HIGH"}}<span class="sev-high" style="font-size:0.58rem">high</span>
          {{else if eq .Severity "MEDIUM"}}<span class="sev-medium" style="font-size:0.58rem">medium</span>
          {{else}}<span class="sev-low" style="font-size:0.58rem">{{.Severity}}</span>{{end}}
          <span style="font-family:var(--mono);font-weight:600;font-size:0.78rem;color:var(--text)">{{.RuleID}}</span>
          <span style="color:var(--text3);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{.Name}}</span>
          <a href="/dashboard/rules/{{.Category}}" style="color:var(--text3);text-decoration:none;font-size:0.75rem">&rsaquo;</a>
        </div>
        {{if .Match}}<div style="font-family:var(--mono);font-size:0.68rem;color:var(--text3);padding:0 0 8px 28px;opacity:0.7;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{{.Match}}">{{truncate .Match 80}}</div>{{end}}
        {{end}}
      </div>
    </div>
    {{end}}
  </div>

  <!-- RIGHT -->
  <div>
    <!-- Intercepted content -->
    <div class="ep-card">
      <div class="ep-card-hdr"><h3>Intercepted Content</h3>{{if .Entry.ToolName}}<span style="font-size:0.68rem;color:var(--text3);font-family:var(--mono)">{{.Entry.ToolName}}</span>{{end}}</div>
      <div class="ep-card-body">
        {{if .Entry.Intent}}
        <div id="ep-content-raw" style="display:none">{{.Entry.Intent}}</div>
        <pre id="ep-content-pretty" class="ep-content" style="margin:0"></pre>
        <script>
        (function(){
          var raw=document.getElementById('ep-content-raw').textContent.trim();
          var el=document.getElementById('ep-content-pretty');
          try{
            var obj=JSON.parse(raw);
            el.innerHTML=renderJSON(obj,'');
          }catch(e){
            el.style.lineHeight='1.7';
            el.style.fontSize='0.82rem';
            el.innerHTML=fmtText(raw);
          }
          function fmtText(s){
            s=s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
            s=s.replace(/\\n/g,'\n');
            s=s.replace(/^(#{1,3})\s+(.+)$/gm,function(_,h,txt){
              var sz=h.length===1?'1.05rem':'0.92rem';
              return '<strong style="color:var(--text1);font-size:'+sz+'">'+txt+'</strong>';
            });
            s=s.replace(/\*\*([^*]+)\*\*/g,'<strong style="color:var(--text1)">$1</strong>');
            s=s.replace(/^[-*]\s+/gm,'  • ');
            return s;
          }
          function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
          function renderJSON(val,indent){
            if(val===null)return '<span class="json-null">null</span>';
            if(typeof val==='boolean')return '<span class="json-bool">'+val+'</span>';
            if(typeof val==='number')return '<span class="json-num">'+val+'</span>';
            if(typeof val==='string'){
              var s=esc(val);
              if(s.length>200){
                var id='jv'+Math.random().toString(36).substr(2,6);
                return '<span class="json-str">"<span id="'+id+'s">'+s.substring(0,120)+'<a onclick="document.getElementById(\''+id+'f\').style.display=\'inline\';document.getElementById(\''+id+'s\').style.display=\'none\'" style="color:var(--accent-light);cursor:pointer"> ...('+(s.length-120)+' more)</a></span><span id="'+id+'f" style="display:none">'+s+'</span>"</span>';
              }
              return '<span class="json-str">"'+s+'"</span>';
            }
            if(Array.isArray(val)){
              if(val.length===0)return '<span class="json-bracket">[]</span>';
              var ni=indent+'  ';
              var items=val.map(function(v){return ni+renderJSON(v,ni);});
              return '<span class="json-bracket">[</span>\n'+items.join(',\n')+'\n'+indent+'<span class="json-bracket">]</span>';
            }
            var keys=Object.keys(val);
            if(keys.length===0)return '<span class="json-bracket">{}</span>';
            var ni=indent+'  ';
            var pairs=keys.map(function(k){
              return ni+'<span class="json-key">"'+esc(k)+'"</span>: '+renderJSON(val[k],ni);
            });
            return '<span class="json-bracket">{</span>\n'+pairs.join(',\n')+'\n'+indent+'<span class="json-bracket">}</span>';
          }
        })();
        </script>
        {{else}}
        <div style="text-align:center;padding:20px 0;color:var(--text3);font-size:0.82rem">
          <div style="margin-bottom:6px">Content not stored in audit log</div>
          <div style="font-family:var(--mono);font-size:0.68rem;opacity:0.6">SHA-256: {{if .Entry.ContentHash}}{{.Entry.ContentHash}}{{else}}n/a{{end}}</div>
        </div>
        {{end}}
      </div>
    </div>

    <!-- Agent -->
    <div class="ep-card">
      <div class="ep-card-hdr"><h3>Agent</h3><a href="/dashboard/agents/{{.Entry.FromAgent}}" style="font-size:0.72rem;color:var(--accent-light);text-decoration:none">View agent &rarr;</a></div>
      <div class="ep-card-body">
        <div class="ep-row"><span class="k">Name</span><span class="v"><a href="/dashboard/agents/{{.Entry.FromAgent}}">{{.Entry.FromAgent}}</a></span></div>
        {{if .AgentDesc}}<div class="ep-row"><span class="k">Description</span><span class="v" style="font-family:var(--sans)" title="{{.AgentDesc}}">{{truncate .AgentDesc 40}}</span></div>{{end}}
        {{if .AgentLocation}}<div class="ep-row"><span class="k">Location</span><span class="v">{{.AgentLocation}}</span></div>{{end}}
        {{if .AgentCreatedBy}}<div class="ep-row"><span class="k">Origin</span><span class="v" style="font-family:var(--sans)">{{.AgentCreatedBy}}</span></div>{{end}}
        {{if .ToolConstraintCount}}<div class="ep-row"><span class="k">Constraints</span><span class="v"><span style="color:var(--warn)">{{.ToolConstraintCount}} rules</span></span></div>{{end}}
      </div>
    </div>

    <!-- Forensics / Audit Chain -->
    <div class="ep-card">
      <div class="ep-card-hdr"><h3>Audit Chain</h3>{{if .Entry.ProxySignature}}<span style="font-size:0.68rem;color:var(--success);font-weight:600">signed</span>{{end}}</div>
      <div class="ep-card-body">
        <div class="ep-row"><span class="k">Event ID</span></div>
        <div class="ep-hash">{{.Entry.ID}}</div>
        {{if .Entry.ContentHash}}
        <div class="ep-row" style="margin-top:8px"><span class="k">Content hash (SHA-256)</span></div>
        <div class="ep-hash">{{.Entry.ContentHash}}</div>
        {{end}}
        {{if .Entry.EntryHash}}
        <div class="ep-row" style="margin-top:8px"><span class="k">Chain hash</span></div>
        <div class="ep-hash">{{.Entry.EntryHash}}</div>
        {{end}}
        {{if .Entry.PrevHash}}
        <div class="ep-row" style="margin-top:8px"><span class="k">Previous hash</span></div>
        <div class="ep-hash">{{.Entry.PrevHash}}</div>
        {{end}}
        {{if .Entry.PubkeyFingerprint}}
        <div class="ep-row" style="margin-top:8px"><span class="k">Key fingerprint</span></div>
        <div class="ep-hash">{{.Entry.PubkeyFingerprint}}</div>
        {{end}}
        {{if .Entry.ProxySignature}}
        <div class="ep-row" style="margin-top:8px"><span class="k">Proxy signature (Ed25519)</span></div>
        <div class="ep-hash">{{.Entry.ProxySignature}}</div>
        {{end}}
      </div>
    </div>

    <!-- LLM Analysis -->
    {{if .LLMAnalysis}}
    <div class="ep-card">
      <div class="ep-card-hdr"><h3>LLM Analysis</h3><a href="/dashboard/llm/{{.LLMAnalysis.ID}}" style="font-size:0.72rem;color:var(--accent-light);text-decoration:none">Full analysis &rarr;</a></div>
      <div class="ep-card-body">
        <div class="ep-row"><span class="k">Risk score</span><span class="v" style="{{if ge .LLMAnalysis.RiskScore 76.0}}color:#f85149{{else if ge .LLMAnalysis.RiskScore 51.0}}color:var(--danger){{else if ge .LLMAnalysis.RiskScore 31.0}}color:#d29922{{else}}color:var(--success){{end}};font-weight:700">{{printf "%.0f" .LLMAnalysis.RiskScore}} / 100</span></div>
        <div class="ep-row"><span class="k">Confidence</span><span class="v">{{printf "%.0f" .LLMAnalysis.Confidence}}%</span></div>
        <div class="ep-row"><span class="k">Action</span><span class="v" style="font-family:var(--sans)">{{.LLMAnalysis.RecommendedAction}}</span></div>
        <div class="ep-row"><span class="k">Model</span><span class="v">{{.LLMAnalysis.Model}}</span></div>
      </div>
    </div>
    {{end}}
  </div>
</div>
` + layoutFoot))

var eventsTmpl = template.Must(template.New("events").Funcs(tmplFuncs).Parse(layoutHead + `
<p class="page-desc">Security events from the pipeline. Click a row to inspect, double-click for full detail. <span class="sse-indicator" id="sse-status"><span class="sse-dot" id="sse-dot"></span> <span id="sse-label">connecting</span></span></p>

<div class="filter-bar">
  <select id="filter-agent">
    <option value="">All Agents</option>
    {{range .AgentNames}}<option value="{{.}}" {{if eq . $.FilterAgent}}selected{{end}}>{{.}}</option>{{end}}
  </select>
  <input type="date" id="filter-since" value="{{.FilterSince}}" title="From date">
  <span class="sep">to</span>
  <input type="date" id="filter-until" value="{{.FilterUntil}}" title="Until date">
  <button class="btn btn-sm" onclick="clearEventFilters()">Clear</button>
  <span class="spacer"></span>
  <select id="export-redaction" title="Redaction level" onchange="updateExportLinks()">
    <option value="">Full (admin)</option>
    <option value="analyst">Analyst (match snippets redacted, metadata visible)</option>
    <option value="external">External (status and agents only)</option>
  </select>
  <a id="export-csv" class="btn btn-sm" download>CSV</a>
  <a id="export-json" class="btn btn-sm" download>JSON</a>
</div>
<div id="redaction-hint" style="display:none;font-size:var(--text-xs);color:var(--text3);padding:4px 0 0 0;text-align:right"></div>
<script>
function buildExportURL(format) {
  var agent = document.getElementById('filter-agent').value;
  var since = document.getElementById('filter-since').value;
  var until = document.getElementById('filter-until').value;
  var redaction = document.getElementById('export-redaction').value;
  var url = '/dashboard/api/export/' + format + '?_=1';
  if (agent) url += '&agent=' + encodeURIComponent(agent);
  if (since) url += '&since=' + encodeURIComponent(since);
  if (until) url += '&until=' + encodeURIComponent(until);
  if (redaction) url += '&redaction=' + encodeURIComponent(redaction);
  return url;
}
function updateExportLinks() {
  var csv = document.getElementById('export-csv');
  var json = document.getElementById('export-json');
  if (csv) csv.href = buildExportURL('csv');
  if (json) json.href = buildExportURL('json');
  var hint = document.getElementById('redaction-hint');
  if (hint) {
    var r = document.getElementById('export-redaction').value;
    var msgs = {analyst:'Exports include all metadata. Rule match snippets are replaced with [REDACTED].',external:'Exports include only: timestamp, agents, status, and policy decision. No content, rules, or latency.'};
    if (msgs[r]) { hint.textContent = msgs[r]; hint.style.display = ''; }
    else { hint.style.display = 'none'; }
  }
}
function applyEventFilters() {
  var agent = document.getElementById('filter-agent').value;
  var since = document.getElementById('filter-since').value;
  var until = document.getElementById('filter-until').value;
  var tab = '{{.Tab}}';
  var url = '/dashboard/events?tab=' + tab;
  if (agent) url += '&agent=' + encodeURIComponent(agent);
  if (since) url += '&since=' + encodeURIComponent(since);
  if (until) url += '&until=' + encodeURIComponent(until);
  window.location = url;
}
function clearEventFilters() {
  window.location = '/dashboard/events?tab={{.Tab}}';
}
document.getElementById('filter-agent').addEventListener('change', applyEventFilters);
document.getElementById('filter-since').addEventListener('change', applyEventFilters);
document.getElementById('filter-until').addEventListener('change', applyEventFilters);
updateExportLinks();
</script>

<div class="tabs" data-tab-group="events">
  <a href="/dashboard/events?tab=all{{if .FilterAgent}}&agent={{.FilterAgent}}{{end}}{{if .FilterSince}}&since={{.FilterSince}}{{end}}{{if .FilterUntil}}&until={{.FilterUntil}}{{end}}" class="tab {{if eq .Tab "all"}}active{{end}}">All Events</a>
  <a href="/dashboard/events?tab=quarantine{{if .FilterAgent}}&agent={{.FilterAgent}}{{end}}{{if .FilterSince}}&since={{.FilterSince}}{{end}}{{if .FilterUntil}}&until={{.FilterUntil}}{{end}}" class="tab {{if eq .Tab "quarantine"}}active{{end}}">Quarantine{{if .QPending}} <span class="pending-badge">{{.QPending}}</span>{{end}}</a>
  <a href="/dashboard/events?tab=blocked{{if .FilterAgent}}&agent={{.FilterAgent}}{{end}}{{if .FilterSince}}&since={{.FilterSince}}{{end}}{{if .FilterUntil}}&until={{.FilterUntil}}{{end}}" class="tab {{if eq .Tab "blocked"}}active{{end}}">Blocked</a>
</div>

<!-- All Events -->
<div class="tab-content {{if eq .Tab "all"}}active{{end}}" data-tab-content="events" data-tab-name="all">
  <div class="search-bar">
    <span class="search-icon">&#x1F50D;</span>
    <label for="ev-search" class="sr-only">Search events</label>
    <input type="text" id="ev-search" placeholder="Search events by agent, rule, or content hash..."
           hx-get="/dashboard/api/search" hx-trigger="keyup changed delay:300ms" hx-target="#search-results" hx-indicator="#events-search-loading" name="q">
    <span id="events-search-loading" class="htmx-indicator"><span class="loading-spinner"></span></span>
  </div>

  <div id="search-results">
  {{if .Entries}}
  <table>
    <thead><tr><th>Time</th><th>From</th><th>To</th><th>Status</th><th>Session</th><th style="text-align:right">Latency</th><th style="text-align:right">Rules</th><th></th></tr></thead>
    <tbody id="events-body">
    {{range .Entries}}
    <tr class="ev-row clickable{{if hasRules .RulesTriggered}} has-rules{{end}}" hx-get="/dashboard/api/event/{{.ID}}" hx-target="#panel-content" hx-swap="innerHTML" ondblclick="event.preventDefault();event.stopPropagation();window.location='/dashboard/events/{{.ID}}'">
      <td data-ts="{{.Timestamp}}"><a href="/dashboard/events/{{.ID}}" class="ev-ts-link" onclick="event.preventDefault();htmx.ajax('GET','/dashboard/api/event/{{.ID}}','#panel-content')">{{.Timestamp}}</a></td>
      <td>{{agentCell .FromAgent}}</td>
      <td>{{if .ToolName}}{{toolDot .ToolName}}{{else}}{{agentCell .ToAgent}}{{end}}</td>
      <td><span class="badge-{{.Status}}">{{.Status}}</span>{{if ne .PolicyDecision "allowed"}} <span style="font-family:var(--sans);font-size:var(--text-xs);color:var(--text3);margin-left:4px">{{humanDecision .PolicyDecision}}</span>{{end}}</td>
      <td style="font-size:var(--text-xs)">{{if .SessionID}}<a href="/dashboard/sessions/{{.SessionID}}" style="color:var(--accent);text-decoration:none;font-family:var(--mono)" title="{{.SessionID}}">{{truncate .SessionID 12}}</a>{{else}}<span style="color:var(--text3)">-</span>{{end}}</td>
      <td style="text-align:right;font-family:var(--mono);font-size:var(--text-xs);color:{{if ge .LatencyMs 500}}var(--danger){{else if ge .LatencyMs 100}}var(--warn){{else}}var(--text3){{end}}">{{.LatencyMs}}ms</td>
      <td style="text-align:right;font-family:var(--mono);font-size:var(--text-xs)">{{if hasRules .RulesTriggered}}<span style="color:var(--warn);font-weight:600">&#x26A0;</span>{{else}}<span style="color:var(--text3)">-</span>{{end}}</td>
      <td><a href="/dashboard/events/{{.ID}}" class="btn btn-sm btn-outline" style="font-size:0.65rem;padding:2px 8px;white-space:nowrap;border-color:var(--border);color:var(--text3)" title="Open full event detail" onclick="event.stopPropagation()">Inspect</a></td>
    </tr>
    {{end}}
    </tbody>
  </table>
  <div class="pager">
    <span id="ev-pager-info"></span>
    <div class="pager-btns">
      <button id="ev-prev" class="pager-btn" onclick="evPage(-1)" disabled>&larr; Prev</button>
      <button id="ev-next" class="pager-btn" onclick="evPage(1)">Next &rarr;</button>
    </div>
  </div>
  <script>
  var evCur=1,evSize=30;
  function evRender(){
    var rows=document.querySelectorAll('.ev-row');
    var total=rows.length;
    var start=(evCur-1)*evSize,end=Math.min(start+evSize,total);
    rows.forEach(function(r,i){r.style.display=(i>=start&&i<end)?'':'none';});
    document.getElementById('ev-pager-info').textContent=total?'Showing '+(start+1)+'–'+end+' of '+total:'';
    document.getElementById('ev-prev').disabled=evCur<=1;
    document.getElementById('ev-next').disabled=end>=total;
  }
  function evPage(d){evCur+=d;evRender();}
  evRender();
  </script>
  {{else}}
  <div class="empty">No events in this view. Use your MCP tools normally and events will appear here in real-time.</div>
  {{end}}
  </div>
</div>

<!-- Quarantine -->
<div class="tab-content {{if eq .Tab "quarantine"}}active{{end}}" data-tab-content="events" data-tab-name="quarantine">
  {{if .QStats}}
  <div class="stats grid-4" style="margin-bottom:20px">
    <div class="stat">
      <div class="label">Pending</div>
      <div class="value warn">{{.QStats.Pending}}</div>
    </div>
    <div class="stat">
      <div class="label">Approved</div>
      <div class="value success">{{.QStats.Approved}}</div>
    </div>
    <div class="stat">
      <div class="label">Rejected</div>
      <div class="value danger">{{.QStats.Rejected}}</div>
    </div>
    <div class="stat">
      <div class="label">Expired</div>
      <div class="value" style="color:var(--text3)">{{.QStats.Expired}}</div>
    </div>
  </div>
  {{end}}

  <div class="filter-bar">
    <a href="/dashboard/events?tab=quarantine&status=pending" class="toggle-btn {{if eq .QStatusFilter "pending"}}active{{end}}">Pending</a>
    <a href="/dashboard/events?tab=quarantine&status=approved" class="toggle-btn {{if eq .QStatusFilter "approved"}}active{{end}}">Approved</a>
    <a href="/dashboard/events?tab=quarantine&status=rejected" class="toggle-btn {{if eq .QStatusFilter "rejected"}}active{{end}}">Rejected</a>
    <a href="/dashboard/events?tab=quarantine&status=" class="toggle-btn {{if eq .QStatusFilter ""}}active{{end}}">All</a>
  </div>

  {{if .QItems}}
  <table>
    <thead><tr><th>Time</th><th>From</th><th>To</th><th>Content</th><th>Status</th><th>Expires</th><th>Actions</th></tr></thead>
    <tbody>
    {{range .QItems}}
    <tr id="q-row-{{.ID}}">
      <td data-ts="{{.CreatedAt}}">{{.CreatedAt}}</td>
      <td>{{agentCell .FromAgent}}</td>
      <td>{{agentCell .ToAgent}}</td>
      <td><div class="q-preview" style="cursor:pointer" hx-get="/dashboard/api/quarantine/{{.ID}}" hx-target="#panel-content" hx-swap="innerHTML">{{truncate .Content 80}}</div></td>
      <td><span class="badge-{{.Status}}">{{.Status}}</span></td>
      <td style="font-size:0.72rem;white-space:nowrap">{{if eq .Status "pending"}}<span data-expires="{{.ExpiresAt}}"></span>{{else}}&mdash;{{end}}</td>
      <td>
        {{if eq .Status "pending"}}
        <div class="q-actions">
          <button class="btn btn-sm btn-success" hx-post="/dashboard/api/quarantine/{{.ID}}/approve" hx-target="#q-row-{{.ID}}" hx-swap="outerHTML">Approve</button>
          <button class="btn btn-sm btn-danger" hx-post="/dashboard/api/quarantine/{{.ID}}/reject" hx-target="#q-row-{{.ID}}" hx-swap="outerHTML">Reject</button>
        </div>
        {{else}}
        <button class="btn btn-sm" style="padding:2px 8px;font-size:0.7rem" hx-get="/dashboard/api/quarantine/{{.ID}}" hx-target="#panel-content" hx-swap="innerHTML">view</button>
        {{end}}
      </td>
    </tr>
    {{end}}
    </tbody>
  </table>
  <script>
  function updateExpiry() {
    document.querySelectorAll('[data-expires]').forEach(function(el) {
      var exp = new Date(el.dataset.expires);
      var now = new Date();
      var diff = exp - now;
      var hours = Math.floor(diff / 3600000);
      var mins = Math.floor((diff % 3600000) / 60000);
      if (diff <= 0) { el.textContent = 'expired'; el.style.color = 'var(--danger)'; }
      else if (hours < 1) { el.textContent = mins + 'm'; el.style.color = 'var(--danger)'; }
      else if (hours < 4) { el.textContent = hours + 'h ' + mins + 'm'; el.style.color = 'var(--warn)'; }
      else { el.textContent = hours + 'h'; el.style.color = 'var(--text3)'; }
    });
  }
  setInterval(updateExpiry, 60000);
  updateExpiry();
  </script>
  {{else}}
  <div class="empty">No quarantined messages{{if .QStatusFilter}} with status "{{.QStatusFilter}}"{{end}}.{{if not .RequireSig}} In observe mode, suspicious messages are flagged in the event log but delivered normally. Switch to enforce mode in <a href="/dashboard/settings" style="color:var(--accent-light)">Settings</a> to hold them for review.{{end}}</div>
  {{end}}
</div>

<!-- Blocked -->
<div class="tab-content {{if eq .Tab "blocked"}}active{{end}}" data-tab-content="events" data-tab-name="blocked">
  {{if .BlockedEntries}}
  <table>
    <thead><tr><th>Time</th><th>From</th><th>To</th><th>Status</th><th style="text-align:right">Latency</th><th style="text-align:right">Rules</th><th></th></tr></thead>
    <tbody>
    {{range .BlockedEntries}}
    <tr class="blk-row clickable has-rules" hx-get="/dashboard/api/event/{{.ID}}" hx-target="#panel-content" hx-swap="innerHTML" ondblclick="event.preventDefault();event.stopPropagation();window.location='/dashboard/events/{{.ID}}'">
      <td data-ts="{{.Timestamp}}">{{.Timestamp}}</td>
      <td>{{agentCell .FromAgent}}</td>
      <td>{{if .ToolName}}{{toolDot .ToolName}}{{else}}{{agentCell .ToAgent}}{{end}}</td>
      <td><span class="badge-{{.Status}}">{{.Status}}</span> <span style="font-family:var(--sans);font-size:var(--text-xs);color:var(--text3);margin-left:4px">{{humanDecision .PolicyDecision}}</span></td>
      <td style="text-align:right;font-family:var(--mono);font-size:var(--text-xs);color:{{if ge .LatencyMs 500}}var(--danger){{else if ge .LatencyMs 100}}var(--warn){{else}}var(--text3){{end}}">{{.LatencyMs}}ms</td>
      <td style="text-align:right;font-family:var(--mono);font-size:var(--text-xs)"><span style="color:var(--warn);font-weight:600">&#x26A0;</span></td>
      <td><a href="/dashboard/events/{{.ID}}" class="btn btn-sm btn-outline" style="font-size:0.65rem;padding:2px 8px;white-space:nowrap;border-color:var(--border);color:var(--text3)" title="Open full event detail" onclick="event.stopPropagation()">Inspect</a></td>
    </tr>
    {{end}}
    </tbody>
  </table>
  <div class="pager">
    <span id="blk-pager-info"></span>
    <div class="pager-btns">
      <button id="blk-prev" class="pager-btn" onclick="blkPage(-1)" disabled>&larr; Prev</button>
      <button id="blk-next" class="pager-btn" onclick="blkPage(1)">Next &rarr;</button>
    </div>
  </div>
  <script>
  var blkCur=1,blkSize=30;
  function blkRender(){
    var rows=document.querySelectorAll('.blk-row');
    var total=rows.length;
    var start=(blkCur-1)*blkSize,end=Math.min(start+blkSize,total);
    rows.forEach(function(r,i){r.style.display=(i>=start&&i<end)?'':'none';});
    document.getElementById('blk-pager-info').textContent=total?'Showing '+(start+1)+'–'+end+' of '+total:'';
    document.getElementById('blk-prev').disabled=blkCur<=1;
    document.getElementById('blk-next').disabled=end>=total;
  }
  function blkPage(d){blkCur+=d;blkRender();}
  blkRender();
  </script>
  {{else}}
  <div class="empty">No blocked or rejected messages.</div>
  {{end}}
</div>

<script>
// SSE for live events
(function() {
  var src = new EventSource('/dashboard/api/events');
  var dot = document.getElementById('sse-dot');
  var label = document.getElementById('sse-label');
  src.onopen = function() { dot.classList.add('connected'); label.textContent = 'live updates connected'; };
  src.onerror = function() { dot.classList.remove('connected'); label.textContent = 'reconnecting'; };
  src.onmessage = function(e) {
    try {
      var ev = JSON.parse(e.data);
      var tbody = document.getElementById('events-body');
      if (!tbody) return;
      var toolColors = {Bash:'#d29922',Write:'#c084fc',Edit:'#58a6ff',Read:'#22d3ee',Glob:'#2dd4bf',Grep:'#2dd4bf',WebFetch:'#f472b6',WebSearch:'#f472b6',Agent:'#bc8cff'};
      var toCell;
      if (ev.tool_name) {
        var tc = toolColors[ev.tool_name] || '#6e7681';
        toCell = '<span style="display:inline-flex;align-items:center;gap:5px"><span style="width:6px;height:6px;border-radius:50%;background:'+tc+';flex-shrink:0"></span>'+_esc(ev.tool_name)+'</span>';
      } else {
        toCell = agentCellHTML(ev.to_agent||'');
      }
      var hasRules = ev.rules_triggered && ev.rules_triggered !== '[]' && ev.rules_triggered !== 'null';
      var row = document.createElement('tr');
      row.className = 'ev-row clickable new-event' + (hasRules ? ' has-rules' : '');
      row.setAttribute('hx-get', '/dashboard/api/event/' + ev.id);
      row.setAttribute('hx-target', '#panel-content');
      row.setAttribute('hx-swap', 'innerHTML');
      row.ondblclick = function(evt){evt.preventDefault();evt.stopPropagation();window.location='/dashboard/events/'+ev.id;};
      var decExtra='';
      if(ev.policy_decision&&ev.policy_decision!=='allowed'){
        var labels={'content_blocked':'Blocked — dangerous content','content_quarantined':'Quarantined','signature_required':'Rejected — unsigned','acl_denied':'Rejected — ACL denied'};
        decExtra=' <span style="font-family:var(--sans);font-size:var(--text-xs);color:var(--text3);margin-left:4px">'+_esc(labels[ev.policy_decision]||ev.policy_decision)+'</span>';
      }
      var sesCell = ev.session_id ? '<a href="/dashboard/sessions/'+_esc(ev.session_id)+'" style="color:var(--accent);text-decoration:none;font-family:var(--mono)" title="'+_esc(ev.session_id)+'">'+_esc(ev.session_id.substring(0,12))+'...</a>' : '<span style="color:var(--text3)">-</span>';
      var latColor = ev.latency_ms>=500?'var(--danger)':ev.latency_ms>=100?'var(--warn)':'var(--text3)';
      var rulesCell = hasRules ? '<span style="color:var(--warn);font-weight:600">&#x26A0;</span>' : '<span style="color:var(--text3)">-</span>';
      var inspectBtn='<a href="/dashboard/events/'+_esc(ev.id)+'" class="btn btn-sm btn-outline" style="font-size:0.65rem;padding:2px 8px;white-space:nowrap;border-color:var(--border);color:var(--text3)" title="Open full event detail" onclick="event.stopPropagation()">Inspect</a>';
      row.innerHTML = '<td data-ts="' + _esc(ev.timestamp) + '">' + _esc(ev.timestamp) + '</td><td>' + agentCellHTML(ev.from_agent||'') + '</td><td>' + toCell + '</td><td><span class="badge-' + _esc(ev.status) + '">' + _esc(ev.status) + '</span>'+decExtra+'</td><td style="font-size:var(--text-xs)">'+sesCell+'</td><td style="text-align:right;font-family:var(--mono);font-size:var(--text-xs);color:'+latColor+'">'+(ev.latency_ms||0)+'ms</td><td style="text-align:right;font-family:var(--mono);font-size:var(--text-xs)">'+rulesCell+'</td><td>'+inspectBtn+'</td>';
      tbody.insertBefore(row, tbody.firstChild);
      htmx.process(row);
      if(typeof humanizeTimestamps==='function')humanizeTimestamps();
    } catch(err) {}
  };
})();
</script>
` + layoutFoot))
