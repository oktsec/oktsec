package dashboard

import "html/template"

var agentsTmpl = template.Must(template.New("agents").Funcs(tmplFuncs).Parse(layoutHead + `
<style>
/* Auto-fit grid: a single configured agent fills the row instead of
   leaving an empty gray panel beside it (the desktop walkthrough's
   DP-SMOKE-03). With 2+ agents the grid still pours into 2 columns
   on a typical 1440px+ viewport because each card claims at least
   minmax(320px, 1fr). The gap+background trick that drew separator
   lines between cards is replaced with explicit per-card borders so
   collapsed empty tracks cannot leave a stray seam. */
.ag-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:12px}
.ag-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px 20px;cursor:pointer;transition:background var(--ease-default),border-color var(--ease-default);text-decoration:none;color:inherit;display:block}
.ag-card:hover{background:var(--surface-hover);border-color:var(--border-hover)}
.ag-card-head{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.ag-card-name{font-weight:600;font-size:0.88rem}
.ag-card-desc{color:var(--text3);font-size:0.78rem;margin-bottom:10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ag-card-stats{display:flex;gap:16px;font-size:0.75rem;color:var(--text3)}
.ag-card-stats .num{font-family:var(--mono);font-weight:600;color:var(--text2)}
</style>

<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
  <p class="page-desc" style="margin:0">Registered agents with identity keys, message history, and risk scoring.</p>
</div>

<!-- Add Agent -->
<div class="card" style="margin-bottom:20px;padding:16px 20px">
  <form method="POST" action="/dashboard/agents" class="inline-add" style="display:flex;align-items:flex-end;gap:12px;flex-wrap:wrap">
    <div class="form-group" style="min-width:180px;margin-bottom:0">
      <label>Name</label>
      <input type="text" name="name" placeholder="e.g. research-agent" required pattern="[a-zA-Z0-9][a-zA-Z0-9_-]*">
    </div>
    <div class="form-group" style="flex:2;margin-bottom:0">
      <label>Can Message (comma-separated)</label>
      <input type="text" name="can_message" placeholder="e.g. target-agent, helper-agent">
    </div>
    <button type="submit" class="btn">Add Agent</button>
  </form>
</div>

<div style="display:grid;grid-template-columns:{{if .DiscoveredAgents}}1fr 280px{{else}}1fr{{end}};gap:20px;align-items:start">
{{if .AgentRows}}
<div class="ag-grid">
  {{range .AgentRows}}
  <a href="/dashboard/agents/{{.Name}}" class="ag-card">
    <div class="ag-card-head">
      {{avatar .Name 28}}
      <span class="ag-card-name">{{kebabToTitle .Name}}</span>
      {{if .Suspended}}<span class="badge-blocked" style="font-size:0.6rem;padding:2px 6px">SUSPENDED</span>{{end}}
      {{if .HasKey}}<span title="Key registered" style="color:var(--success);font-size:0.7rem;margin-left:auto">&#x1f512;</span>{{else}}<span title="No key" style="color:var(--text3);font-size:0.7rem;margin-left:auto">&#x1f513;</span>{{end}}
    </div>
    <div class="ag-card-desc">{{if .Description}}{{.Description}}{{else}}No description{{end}}</div>
    <div class="ag-card-stats">
      <span><span class="num">{{formatNum .Total}}</span> msgs</span>
      <span title="Percentage of this agent's messages blocked by the security pipeline over its lifetime">historical block rate <span class="num" style="{{if gt .BlockedPct 20}}color:var(--danger){{else if gt .BlockedPct 5}}color:var(--warn){{end}}">{{.BlockedPct}}%</span></span>
      <span title="Based on blocked (x10), quarantined (x5), and flagged messages in the last 24h">current risk: <span class="num" style="{{if gt .RiskScore 60.0}}color:var(--danger){{else if gt .RiskScore 30.0}}color:var(--warn){{end}}">{{if ge .RiskScore 76.0}}critical{{else if ge .RiskScore 51.0}}high{{else if ge .RiskScore 31.0}}medium{{else if gt .RiskScore 0.0}}low{{else}}none{{end}}</span></span>
      {{if gt .LLMThreatCount 0}}<span style="color:var(--danger)">&#x26A0; {{.LLMThreatCount}} threats</span>{{end}}
      {{if .LastSeen}}<span style="margin-left:auto" data-ts="{{.LastSeen}}">{{.LastSeen}}</span>{{end}}
    </div>
  </a>
  {{end}}
</div>
{{else}}
<div class="card"><div class="empty">No agents configured.</div></div>
{{end}}

{{if .DiscoveredAgents}}
  <div class="card" style="padding:18px 20px">
    <div style="font-size:0.68rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--warn);font-weight:600;margin-bottom:8px">Discovered from Traffic <span style="color:var(--text3);font-weight:400">{{len .DiscoveredAgents}}</span></div>
    <p style="font-size:0.72rem;color:var(--text3);margin:0 0 12px;line-height:1.4">Identifiers seen in traffic but not registered.</p>
    {{range .DiscoveredAgents}}
    <div style="display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-top:1px solid var(--border)">
      <span style="display:flex;align-items:center;gap:8px">{{agentCell .}}</span>
      <form method="POST" action="/dashboard/agents" style="display:inline">
        <input type="hidden" name="name" value="{{.}}">
        <button type="submit" class="btn btn-sm" style="font-size:0.68rem;padding:3px 10px">Register</button>
      </form>
    </div>
    {{end}}
  </div>
{{end}}
</div>
` + layoutFoot))

var agentDetailTmpl = template.Must(template.New("agent-detail").Funcs(tmplFuncs).Parse(layoutHead + `
<style>
.ad-grid{display:grid;grid-template-columns:1fr 1fr;gap:var(--sp-5);align-items:stretch}
.ad-grid>div{min-width:0}
.ad-grid table{width:100%}
.ad-grid .fp{word-break:break-all;overflow-wrap:break-word}
.ad-tabs{display:flex;gap:0;border-bottom:2px solid var(--border);margin-bottom:var(--sp-5)}
.ad-tab{padding:10px var(--sp-5);font-size:var(--text-sm);font-weight:500;color:var(--text3);cursor:pointer;border:none;background:none;border-bottom:2px solid transparent;margin-bottom:-2px;transition:color var(--ease-default),border-color var(--ease-default)}
.ad-tab:hover{color:var(--text2)}
.ad-tab.active{color:var(--text);border-bottom-color:var(--accent);font-weight:600}
.ad-panel{display:none}
.ad-panel.active{display:block}
.ad-slbl{font-size:var(--text-xs);font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:var(--ls-caps);margin-bottom:var(--sp-3);display:flex;align-items:center;gap:var(--sp-2)}
.ad-kv{display:flex;justify-content:space-between;align-items:baseline;padding:var(--sp-2) 0;font-size:var(--text-base);border-bottom:1px solid var(--border-subtle)}
.ad-kv:last-child{border-bottom:none}
.ad-kv .k{color:var(--text3);font-size:var(--text-sm)}
.ad-kv .v{font-family:var(--mono);font-size:var(--text-sm);color:var(--text);text-align:right;max-width:60%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ad-rule{display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.04);position:relative}
.ad-rule:last-child{border-bottom:none}
.ad-rule-bar{position:absolute;left:0;top:0;bottom:0;border-radius:4px;opacity:0.07;pointer-events:none}
.ad-gauge{display:flex;gap:2px;align-items:center}
.ad-gauge span{width:4px;height:16px;border-radius:2px;background:var(--border)}
.ad-gauge span.filled{background:var(--success)}
.ad-gauge span.filled.warn{background:var(--warn)}
.ad-gauge span.filled.danger{background:var(--danger)}
.ad-tool-bar{height:10px;border-radius:5px;display:flex;overflow:hidden}
@media(max-width:960px){.ad-grid{grid-template-columns:1fr}}
</style>

<!-- Breadcrumb -->
<div class="breadcrumb">
  <a href="/dashboard/agents">AGENTS</a>
  <span class="sep">/</span>
  <span style="color:var(--accent-light)">{{.Name}}</span>
</div>

<!-- Header: avatar + name + actions -->
<div class="page-header">
  {{avatar .Name 48}}
  <div class="page-header-info">
    <h1>{{.Name}}</h1>
    <div class="subtitle">{{if .Agent.Description}}{{.Agent.Description}}{{else}}Agent detail{{end}}</div>
  </div>
  <div class="page-header-actions">
    <form method="POST" action="/dashboard/agents/{{.Name}}/keygen" style="display:inline"><button type="submit" class="btn btn-sm btn-outline success" onclick="return confirm('Generate new keypair for {{.Name}}?')">Generate Keypair</button></form>
    {{if and .KeyFP (not .KeyRevoked)}}<form method="POST" action="/dashboard/identity/revoke" style="display:inline"><input type="hidden" name="agent" value="{{.Name}}"><button type="submit" class="btn btn-sm btn-outline danger" onclick="return confirm('Revoke key for {{.Name}}? This agent will not be able to send signed messages.')">Revoke Key</button></form>{{end}}
    <form method="POST" action="/dashboard/agents/{{.Name}}/suspend" style="display:inline" onsubmit="return confirm('{{if .Suspended}}Unsuspend agent {{.Name}}? It will resume sending and receiving messages.{{else}}Suspend agent {{.Name}}? All messages to and from this agent will be blocked.{{end}}')">{{if .Suspended}}<button type="submit" class="btn btn-sm btn-outline success">Unsuspend</button>{{else}}<button type="submit" class="btn btn-sm btn-outline warn">Suspend</button>{{end}}</form>
    <button class="btn btn-sm btn-outline danger" hx-delete="/dashboard/agents/{{.Name}}" hx-confirm="Delete agent {{.Name}}? This cannot be undone." hx-swap="none">Delete</button>
  </div>
</div>

<!-- Stats -->
<div class="stats">
  <div class="stat"><div class="label">Total Messages</div><div class="value">{{formatNum .TotalMsgs}}</div></div>
  <div class="stat"><div class="label">Delivered</div><div class="value success">{{formatNum .Delivered}}</div></div>
  <div class="stat"><div class="label">Blocked</div><div class="value danger">{{formatNum .Blocked}}</div></div>
  <div class="stat"><div class="label">Quarantined</div><div class="value" style="color:var(--accent-light)">{{formatNum .Quarantined}}</div></div>
</div>

<!-- Risk Score + Tool Distribution -->
<div class="ad-grid" style="margin-bottom:20px">
  <div class="card" style="padding:16px 20px">
    <div class="ad-slbl">Current Risk <span style="font-weight:400;text-transform:none;letter-spacing:0;color:var(--text3)">(last 24h)</span></div>
    <div style="display:flex;align-items:center;gap:14px">
      <span style="font-size:1.5rem;font-weight:700;font-family:var(--mono)" class="{{if gt .RiskScore 60.0}}danger{{else if gt .RiskScore 30.0}}warn{{else}}success{{end}}">{{printf "%.0f" .RiskScore}}</span>
      <div class="ad-gauge" id="risk-gauge"></div>
      <span style="color:var(--text3);font-size:0.72rem;font-weight:600">{{if ge .RiskScore 76.0}}CRITICAL{{else if ge .RiskScore 51.0}}HIGH{{else if ge .RiskScore 31.0}}MEDIUM{{else if gt .RiskScore 0.0}}LOW{{else}}NONE{{end}}</span>
    </div>
    <div style="font-size:0.68rem;color:var(--text3);margin-top:6px">{{if and (eq (printf "%.0f" .RiskScore) "0") (gt .BlockedPct 0)}}No active anomaly right now. Historical block rate ({{.BlockedPct}}%) reflects past enforcement, not current risk.{{else}}Weighted from blocked (x10), quarantined (x5), and flagged messages in the last 24h.{{end}}</div>
    <script>
    (function(){
      var g=document.getElementById('risk-gauge');if(!g)return;
      var score={{printf "%.0f" .RiskScore}};
      var segs=20;
      for(var i=0;i<segs;i++){
        var s=document.createElement('span');
        var threshold=i*(100/segs);
        if(threshold<score){
          s.className='filled'+(score>60?' danger':(score>30?' warn':''));
        }
        g.appendChild(s);
      }
    })();
    </script>
  </div>
  <div class="card" style="padding:16px 20px">
    <div class="ad-slbl">Tool Distribution</div>
    <div class="ad-tool-bar" id="tool-dist-bar"></div>
    <div id="tool-dist-legend" style="display:flex;gap:12px;flex-wrap:wrap;margin-top:10px;font-size:0.68rem;color:var(--text3)"></div>
    <div id="tool-dist-empty" style="display:none;color:var(--text3);font-size:0.78rem;padding:6px 0">No tool calls observed yet for this agent.</div>
    <script>
    (function(){
      var partners={{if .CommPartners}}[{{range .CommPartners}}{to:"{{.To}}",total:{{.Total}}},{{end}}]{{else}}[]{{end}};
      var toolColors={'Bash':'#d29922','Read':'#22d3ee','Edit':'#58a6ff','Grep':'#f472b6','Write':'#c084fc','Glob':'#2dd4bf','Agent':'#bc8cff'};
      var tools={},total=0;
      partners.forEach(function(p){
        var parts=p.to.split('/');
        var t=parts.length>1?parts[parts.length-1]:p.to;
        if(!tools[t])tools[t]=0;
        tools[t]+=p.total;total+=p.total;
      });
      var sorted=Object.keys(tools).sort(function(a,b){return tools[b]-tools[a]});
      var bar=document.getElementById('tool-dist-bar');
      var legend=document.getElementById('tool-dist-legend');
      var empty=document.getElementById('tool-dist-empty');
      if(!total){if(empty)empty.style.display='block';return;}
      sorted.forEach(function(t){
        var pct=(tools[t]/total*100).toFixed(0);
        if(pct<1)return;
        var seg=document.createElement('div');
        seg.style.cssText='width:'+pct+'%;background:'+(toolColors[t]||'#6e7681');
        bar.appendChild(seg);
        var l=document.createElement('span');
        l.innerHTML='<span style="display:inline-block;width:8px;height:8px;border-radius:2px;background:'+(toolColors[t]||'#6e7681')+';vertical-align:middle;margin-right:3px"></span>'+_esc(t)+' '+pct+'%';
        legend.appendChild(l);
      });
    })();
    </script>
  </div>
</div>

<!-- Tabs -->
<div class="ad-tabs" role="tablist" aria-label="Agent detail tabs">
  <button class="ad-tab active" role="tab" aria-selected="true" aria-controls="ad-overview" id="tab-overview" onclick="adTab('overview',this)" tabindex="0">Overview</button>
  <button class="ad-tab" role="tab" aria-selected="false" aria-controls="ad-config" id="tab-config" onclick="adTab('config',this)" tabindex="-1">Messaging &amp; Access</button>
  <button class="ad-tab" role="tab" aria-selected="false" aria-controls="ad-policies" id="tab-policies" onclick="adTab('policies',this)" tabindex="-1">Tool Policies</button>
  <button class="ad-tab" role="tab" aria-selected="false" aria-controls="ad-egress" id="tab-egress" onclick="adTab('egress',this)" tabindex="-1">Egress</button>
</div>
<script>
function adTab(name,btn){
  document.querySelectorAll('.ad-tab').forEach(function(t){t.classList.remove('active');t.setAttribute('aria-selected','false');t.tabIndex=-1;});
  document.querySelectorAll('.ad-panel').forEach(function(p){p.classList.remove('active')});
  btn.classList.add('active');btn.setAttribute('aria-selected','true');btn.tabIndex=0;
  document.getElementById('ad-'+name).classList.add('active');
}
document.querySelector('[role="tablist"]').addEventListener('keydown',function(e){
  var tabs=Array.from(this.querySelectorAll('[role="tab"]'));
  var idx=tabs.indexOf(document.activeElement);
  if(idx<0)return;
  if(e.key==='ArrowRight'){e.preventDefault();var next=tabs[(idx+1)%tabs.length];next.focus();next.click();}
  else if(e.key==='ArrowLeft'){e.preventDefault();var prev=tabs[(idx-1+tabs.length)%tabs.length];prev.focus();prev.click();}
});
</script>

<!-- Overview Tab -->
<div id="ad-overview" class="ad-panel active" role="tabpanel" aria-labelledby="tab-overview">

  <!-- Agent hierarchy -->
  {{if or .ParentAgentName .SubAgents}}
  <div class="card" style="padding:18px 20px;margin-bottom:var(--sp-5)">
    {{if .ParentAgentName}}
    <div style="font-size:var(--text-sm);color:var(--text2);margin-bottom:8px">
      <span style="font-size:var(--text-xs);text-transform:uppercase;letter-spacing:var(--ls-caps);color:var(--text3)">Sub-agent of</span>
      <a href="/dashboard/agents/{{.ParentAgentName}}" style="color:var(--accent);text-decoration:none;margin-left:8px;font-family:var(--mono)">{{.ParentAgentName}}</a>
    </div>
    {{end}}
    {{if .SubAgents}}
    <div style="font-size:var(--text-xs);text-transform:uppercase;letter-spacing:var(--ls-caps);color:var(--text3);margin-bottom:8px">Sub-agents spawned</div>
    <div style="display:flex;gap:12px;flex-wrap:wrap">
      {{range .SubAgents}}
      <a href="/dashboard/agents/{{.AgentName}}" style="display:flex;align-items:center;gap:6px;padding:6px 14px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;text-decoration:none;color:var(--text)">
        <span style="font-family:var(--mono);font-size:var(--text-sm);font-weight:500">{{.AgentName}}</span>
        <span style="font-size:var(--text-xs);color:var(--text3)">{{.ToolCount}} calls</span>
        {{if gt .BlockCount 0}}<span style="font-size:var(--text-xs);color:var(--danger)">{{.BlockCount}} blocked</span>{{end}}
      </a>
      {{end}}
    </div>
    {{end}}
  </div>
  {{end}}

  <!-- Row 1: Sessions + Recent Messages -->
  <div class="ad-grid">
    {{if .AgentSessions}}
    <div class="card" style="padding:18px 20px">
      <div class="ad-slbl">Sessions <a href="/dashboard/sessions" style="margin-left:auto;font-size:0.68rem;color:var(--accent-light);text-decoration:none;font-weight:400;text-transform:none;letter-spacing:0">View all &rarr;</a></div>
      <table style="font-size:0.78rem">
        <thead><tr><th style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);font-weight:600">Session</th><th style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);font-weight:600">Events</th><th style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);font-weight:600">Duration</th><th style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);font-weight:600">Threats</th><th style="text-align:right;font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);font-weight:600">Risk</th></tr></thead>
        <tbody>
        {{range .AgentSessions}}
        <tr>
          <td><a href="/dashboard/sessions/{{.SessionID}}" style="color:var(--accent);text-decoration:none;font-family:var(--mono);font-size:0.75rem">{{truncate .SessionID 24}}</a></td>
          <td>{{.EventCount}}</td>
          <td>{{if .Duration}}{{.Duration}}{{else}}0s{{end}}</td>
          <td>{{if gt .Blocks 0}}<span style="color:var(--danger);font-size:0.75rem">{{.Blocks}} blocked</span>{{end}}{{if gt .Quarantines 0}} <span style="color:var(--warn);font-size:0.75rem">{{.Quarantines}} quarantined</span>{{end}}{{if and (eq .Blocks 0) (eq .Quarantines 0)}}<span style="color:var(--text3)">clean</span>{{end}}</td>
          <td style="text-align:right"><span style="padding:2px 8px;border-radius:4px;font-size:0.72rem;font-weight:600;{{if ge .RiskScore 10}}background:var(--danger-muted);color:var(--danger){{else if ge .RiskScore 5}}background:var(--warn-muted);color:#d29922{{else if gt .RiskScore 0}}background:var(--success-muted);color:var(--success){{else}}background:var(--surface2);color:var(--text3){{end}}">{{.RiskScore}}</span></td>
        </tr>
        {{end}}
        </tbody>
      </table>
    </div>
    {{end}}

    <!-- Recent Messages -->
    <div class="card" style="padding:18px 20px">
      <div class="ad-slbl">Recent Messages {{if .Entries}}<a href="/dashboard/events?agent={{.Name}}" style="margin-left:auto;font-size:0.68rem;color:var(--accent-light);text-decoration:none;font-weight:400;text-transform:none;letter-spacing:0">View all in Event Log &rarr;</a>{{end}}</div>
      {{if .Entries}}
      <table style="font-size:0.78rem">
        <thead><tr><th class="section-label">Time</th><th class="section-label">To</th><th class="section-label">Status</th><th style="text-align:right;font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);font-weight:600">Latency</th></tr></thead>
        <tbody>
        {{range .Entries}}
        <tr class="ad-msg clickable" hx-get="/dashboard/api/event/{{.ID}}" hx-target="#panel-content" hx-swap="innerHTML">
          <td data-ts="{{.Timestamp}}">{{.Timestamp}}</td>
          <td>
            {{/* Tool-call hooks are logged with from==to==agent; show the tool
                 instead of a same-name loop. If the row lacks a tool and the
                 destination matches the current agent, label it "(internal)"
                 so readers don't misread it as a bug. */}}
            {{if .ToolName}}{{toolDot .ToolName}}
            {{else if eq .ToAgent $.Name}}<span style="color:var(--text3);font-style:italic">(internal)</span>
            {{else}}{{agentCell .ToAgent}}{{end}}
          </td>
          <td>
            {{if eq .Status "delivered"}}<span class="badge-delivered">delivered</span>
            {{else if eq .Status "blocked"}}<span class="badge-blocked">blocked</span>
            {{else if eq .Status "rejected"}}<span class="badge-rejected">rejected</span>
            {{else if eq .Status "quarantined"}}<span class="badge-quarantined">quarantined</span>
            {{else}}{{.Status}}{{end}}
          </td>
          <td style="text-align:right;font-family:var(--mono);color:var(--text3)">{{.LatencyMs}}ms</td>
        </tr>
        {{end}}
        </tbody>
      </table>
      <div style="display:flex;align-items:center;justify-content:space-between;padding:12px 0;font-size:0.78rem;color:var(--text3)">
        <span id="ad-pager-info"></span>
        <div style="display:flex;gap:4px">
          <button id="ad-prev" class="pager-btn" onclick="adPage(-1)" disabled>&larr; Prev</button>
          <button id="ad-next" class="pager-btn" onclick="adPage(1)">Next &rarr;</button>
        </div>
      </div>
      <script>
      var adCur=1,adSize=10;
      function adRender(){
        var rows=document.querySelectorAll('.ad-msg');
        var total=rows.length;
        var start=(adCur-1)*adSize,end=Math.min(start+adSize,total);
        rows.forEach(function(r,i){r.style.display=(i>=start&&i<end)?'':'none';});
        document.getElementById('ad-pager-info').textContent=total?'Showing '+(start+1)+'–'+end+' of '+total:'';
        document.getElementById('ad-prev').disabled=adCur<=1;
        document.getElementById('ad-next').disabled=end>=total;
      }
      function adPage(d){adCur+=d;adRender();}
      adRender();
      </script>
      {{else}}
      <div class="empty">No messages for this agent yet.</div>
      {{end}}
    </div>
  </div>

  <!-- Row 2: Top Triggered Rules + Communication Partners -->
  <div class="ad-grid">
    <div class="card" style="padding:18px 20px">
      <div class="ad-slbl">Top triggered rules (24h) {{if .TopRules}}<a href="/dashboard/rules" style="margin-left:auto;font-size:0.68rem;color:var(--accent-light);text-decoration:none;font-weight:400;text-transform:none;letter-spacing:0">View all &rarr;</a>{{end}}</div>
      {{if .TopRules}}
      <div style="display:flex;gap:var(--sp-4);flex-wrap:wrap">
      {{range .TopRules}}
      <div class="ad-rule" style="padding-left:8px;flex:1;min-width:200px">
        <div class="ad-rule-bar" style="width:{{if $.TopRules}}{{printf "%.0f" (mulf (divf .Count (index $.TopRules 0).Count) 100)}}%{{else}}0%{{end}};background:{{if eq .Severity "critical"}}#f85149{{else if eq .Severity "high"}}var(--danger){{else}}var(--text3){{end}}"></div>
        <div style="flex:1;min-width:0;position:relative">
          <div style="font-size:0.82rem;font-weight:500;color:var(--text)">{{.Name}}</div>
          <div style="display:flex;align-items:center;gap:6px;margin-top:2px">
            <span style="font-family:var(--mono);font-size:0.68rem;color:var(--text3)">{{.RuleID}}</span>
          </div>
        </div>
        <span style="font-family:var(--mono);font-weight:700;font-size:1.05rem;color:var(--text);flex-shrink:0">{{.Count}}</span>
      </div>
      {{end}}
      </div>
      {{else}}
      <div class="empty" style="padding:20px 0">No rules triggered for this agent.</div>
      {{end}}
    </div>

    <div class="card" style="padding:18px 20px">
      <div class="ad-slbl">Communication partners (24h)</div>
      {{if .CommPartners}}
      <table style="font-size:0.78rem">
        <thead><tr><th class="section-label">Partner</th><th style="text-align:right;font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);font-weight:600">Total</th><th style="text-align:right;font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);font-weight:600">Blocked</th><th style="text-align:right;font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);font-weight:600">Rate</th></tr></thead>
        <tbody>
        {{range .CommPartners}}
        <tr style="{{if eq .Total 0}}opacity:0.4{{end}}">
          <td>{{toolDot .To}}</td>
          <td style="text-align:right;font-family:var(--mono)">{{.Total}}</td>
          <td style="text-align:right;font-family:var(--mono);color:{{if .Blocked}}var(--danger){{else}}var(--success){{end}}">{{.Blocked}}</td>
          <td style="text-align:right;font-family:var(--mono)">{{if .Total}}{{printf "%.0f" (divf (mulf .Blocked 100) .Total)}}%{{else}}0%{{end}}</td>
        </tr>
        {{end}}
        </tbody>
      </table>
      {{else}}
      <div class="empty" style="padding:20px 0">No communication partners.</div>
      {{end}}
    </div>
  </div>

  <!-- LLM Threat Intelligence (full width, only if data exists) -->
  {{if and .LLMEnabled .LLMHistory}}
  <div class="card" style="padding:0;overflow:hidden">
    <div style="display:flex;align-items:center;justify-content:space-between;padding:16px 20px;border-bottom:1px solid var(--border)">
      <div class="ad-slbl" style="margin-bottom:0">LLM Threat Intelligence</div>
      <a href="/dashboard/llm" style="font-size:0.72rem;color:var(--accent-light);text-decoration:none;font-weight:500">View all &rarr;</a>
    </div>
    <div style="overflow-x:auto">
    <table style="font-size:0.82rem;width:100%;border-collapse:collapse">
      <thead><tr>
        <th style="text-align:left;padding:10px 20px;font-size:0.68rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);font-weight:500;border-bottom:1px solid var(--border)">Time</th>
        <th style="text-align:center;padding:10px 20px;font-size:0.68rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);font-weight:500;border-bottom:1px solid var(--border)">Risk</th>
        <th style="text-align:center;padding:10px 20px;font-size:0.68rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);font-weight:500;border-bottom:1px solid var(--border)">Action</th>
        <th style="text-align:center;padding:10px 20px;font-size:0.68rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);font-weight:500;border-bottom:1px solid var(--border)">Status</th>
      </tr></thead>
      <tbody>
      {{range .LLMHistory}}
      <tr class="clickable" onclick="window.location='/dashboard/llm/case/{{.ID}}'">
        <td style="padding:10px 20px;border-bottom:1px solid var(--border)" data-ts="{{.Timestamp}}"><a href="/dashboard/llm/case/{{.ID}}" style="color:inherit;text-decoration:none">{{.Timestamp}}</a></td>
        <td style="text-align:center;padding:10px 20px;border-bottom:1px solid var(--border);font-family:var(--mono);font-weight:600;color:{{if gt .RiskScore 60.0}}var(--danger){{else if gt .RiskScore 30.0}}var(--warn){{else}}var(--success){{end}}">{{printf "%.0f" .RiskScore}}</td>
        <td style="text-align:center;padding:10px 20px;border-bottom:1px solid var(--border)">{{if eq .RecommendedAction "block"}}<span class="badge-blocked">block</span>{{else if eq .RecommendedAction "investigate"}}<span class="badge-quarantined">investigate</span>{{else}}<span class="badge-delivered">none</span>{{end}}</td>
        <td style="text-align:center;padding:10px 20px;border-bottom:1px solid var(--border)">{{if eq .ReviewedStatus "confirmed"}}<span style="color:var(--danger);font-weight:600">confirmed</span>{{else if eq .ReviewedStatus "false_positive"}}<span style="color:var(--text3)">dismissed</span>{{else}}<span style="color:var(--warn)">pending</span>{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    </div>
  </div>
  {{end}}

</div>

<!-- Messaging & Access Tab -->
<div id="ad-config" class="ad-panel" role="tabpanel" aria-labelledby="tab-config">
  <div class="ad-grid">
    <div class="card" style="padding:18px 20px">
      <div class="ad-slbl">Messaging Policy</div>
      <div class="ad-kv"><span class="k">Can message</span><span class="v">{{if not .Agent.CanMessage}}<span style="color:var(--text3)">No agents (isolated)</span>{{else}}{{$first := index .Agent.CanMessage 0}}{{if and (eq (len .Agent.CanMessage) 1) (eq $first "*")}}<span style="color:var(--success)">Any configured agent</span>{{else}}{{range $i, $t := .Agent.CanMessage}}{{if $i}} {{end}}<span class="acl-target">{{$t}}</span>{{end}}{{end}}{{end}}</span></div>
      <div class="ad-kv"><span class="k">Location</span><span class="v">{{if .Agent.Location}}<code style="background:var(--bg3);padding:2px 6px;border-radius:4px;font-size:0.72rem">{{.Agent.Location}}</code>{{else}}unknown{{end}}</span></div>
      <div class="ad-kv"><span class="k">Allowed tools</span><span class="v">{{if .Agent.AllowedTools}}{{range $i, $t := .Agent.AllowedTools}}{{if $i}} {{end}}<code style="background:var(--surface2);padding:2px 6px;border-radius:4px;font-size:0.72rem">{{$t}}</code>{{end}}{{else}}<span style="color:var(--success)">All tools allowed</span>{{end}}</span></div>
      {{if .Agent.BlockedContent}}<div class="ad-kv"><span class="k">Blocked content</span><span class="v">{{range .Agent.BlockedContent}}<code style="background:rgba(244,63,94,0.15);color:var(--danger);padding:2px 6px;border-radius:4px;font-size:0.72rem;margin-left:4px">{{.}}</code>{{end}}</span></div>{{end}}
      {{if .Agent.ToolConstraints}}<div class="ad-kv"><span class="k">Tool constraints</span><span class="v">{{range .Agent.ToolConstraints}}<code style="background:rgba(244,63,94,0.15);color:var(--danger);padding:2px 6px;border-radius:4px;font-size:0.72rem;margin-left:4px">{{.Tool}}</code>{{end}}</span></div>{{end}}
      {{if .KeyFP}}<div class="ad-kv"><span class="k">Key fingerprint</span><span class="v fp" title="{{.KeyFP}}">{{truncate .KeyFP 32}}</span></div>{{end}}
      {{if .Agent.CreatedBy}}<div class="ad-kv"><span class="k">Origin</span><span class="v" style="font-family:var(--sans)">{{.Agent.CreatedBy}}</span></div>{{end}}
      {{if .Agent.CreatedAt}}<div class="ad-kv"><span class="k">Created</span><span class="v" data-ts="{{.Agent.CreatedAt}}">{{.Agent.CreatedAt}}</span></div>{{end}}
    </div>
    <div class="card" style="padding:18px 20px">
      <div class="ad-slbl">Edit Metadata</div>
      <form method="POST" action="/dashboard/agents/{{.Name}}/edit">
        <div style="margin-bottom:12px"><label style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);display:block;margin-bottom:4px">Description</label><input type="text" name="description" value="{{.Agent.Description}}" style="width:100%;box-sizing:border-box"></div>
        <div style="margin-bottom:12px"><label style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);display:block;margin-bottom:4px">Location</label><input type="text" name="location" value="{{.Agent.Location}}" style="width:100%;box-sizing:border-box"></div>
        <div class="form-row">
          <div class="form-group"><label style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3)">Can Message (space-separated)</label><input type="text" name="can_message" value="{{range $i, $t := .Agent.CanMessage}}{{if $i}} {{end}}{{$t}}{{end}}"></div>
          <div class="form-group"><label style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3)">Tags (space-separated)</label><input type="text" name="tags" value="{{range $i, $t := .Agent.Tags}}{{if $i}} {{end}}{{$t}}{{end}}"></div>
        </div>
        <div class="form-row">
          <div class="form-group"><label style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3)">Blocked Content (space-separated categories)</label><input type="text" name="blocked_content" value="{{range $i, $c := .Agent.BlockedContent}}{{if $i}} {{end}}{{$c}}{{end}}"></div>
          <div class="form-group"><label style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3)">Allowed Tools (space-separated, empty = all)</label><input type="text" name="allowed_tools" value="{{range $i, $t := .Agent.AllowedTools}}{{if $i}} {{end}}{{$t}}{{end}}"></div>
        </div>
        <button type="submit" class="btn btn-sm btn-success">Save</button>
      </form>
    </div>
  </div>
</div>

<!-- Tool Policies Tab -->
<div id="ad-policies" class="ad-panel" role="tabpanel" aria-labelledby="tab-policies">
  <div class="card" style="padding:18px 20px">
    <div class="ad-slbl">Tool Policies</div>
    <p class="desc">Per-tool enforcement: spending limits, rate limits, and approval thresholds for MCP gateway tool calls.</p>
    {{if .Agent.ToolPolicies}}
    <table style="margin-bottom:16px">
      <thead><tr><th>Tool</th><th>Max/call</th><th>Daily limit</th><th>Approval above</th><th>Rate limit</th></tr></thead>
      <tbody>
      {{range $tool, $p := .Agent.ToolPolicies}}
      <tr>
        <td style="font-weight:600;font-family:var(--mono);font-size:0.82rem">{{$tool}}</td>
        <td style="font-family:var(--mono);font-size:0.82rem">{{if $p.MaxAmount}}{{printf "$%.0f" $p.MaxAmount}}{{else}}<span style="color:var(--text3)">-</span>{{end}}</td>
        <td style="font-family:var(--mono);font-size:0.82rem">{{if $p.DailyLimit}}{{printf "$%.0f" $p.DailyLimit}}{{else}}<span style="color:var(--text3)">-</span>{{end}}</td>
        <td style="font-family:var(--mono);font-size:0.82rem">{{if $p.RequireApprovalAbove}}{{printf "$%.0f" $p.RequireApprovalAbove}} <span style="color:var(--warn);font-size:0.68rem">quarantine</span>{{else}}<span style="color:var(--text3)">-</span>{{end}}</td>
        <td style="font-family:var(--mono);font-size:0.82rem">{{if $p.RateLimit}}{{$p.RateLimit}}/hr{{else}}<span style="color:var(--text3)">-</span>{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}
    <div class="empty" style="margin-bottom:16px">No tool policies configured.<br><span style="font-size:0.75rem;color:var(--text3)">Add policies below to enforce spending limits, rate limits, or approval thresholds.</span></div>
    {{end}}
    <div style="border-top:1px solid var(--border);padding-top:16px;margin-top:8px">
      <div class="ad-slbl">Add Tool Policy</div>
      <form method="POST" action="/dashboard/agents/{{.Name}}/edit">
        <input type="hidden" name="description" value="{{.Agent.Description}}">
        <input type="hidden" name="location" value="{{.Agent.Location}}">
        <input type="hidden" name="can_message" value="{{range $i, $t := .Agent.CanMessage}}{{if $i}} {{end}}{{$t}}{{end}}">
        <input type="hidden" name="tags" value="{{range $i, $t := .Agent.Tags}}{{if $i}} {{end}}{{$t}}{{end}}">
        <input type="hidden" name="blocked_content" value="{{range $i, $c := .Agent.BlockedContent}}{{if $i}} {{end}}{{$c}}{{end}}">
        <input type="hidden" name="allowed_tools" value="{{range $i, $t := .Agent.AllowedTools}}{{if $i}} {{end}}{{$t}}{{end}}">
        {{range $tool, $p := .Agent.ToolPolicies}}
        <input type="hidden" name="tp_{{$tool}}_max_amount" value="{{printf "%.0f" $p.MaxAmount}}">
        <input type="hidden" name="tp_{{$tool}}_daily_limit" value="{{printf "%.0f" $p.DailyLimit}}">
        <input type="hidden" name="tp_{{$tool}}_require_approval" value="{{printf "%.0f" $p.RequireApprovalAbove}}">
        <input type="hidden" name="tp_{{$tool}}_rate_limit" value="{{$p.RateLimit}}">
        {{end}}
        <input type="hidden" name="policy_tools" id="tp-policy-tools" value="{{range $tool, $p := .Agent.ToolPolicies}}{{$tool}} {{end}}">
        <div class="form-row" style="align-items:flex-end">
          <div class="form-group" style="flex:1.5"><label style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3)">Tool name</label><input type="text" id="tp-tool-name" placeholder="e.g. create_" required></div>
          <div class="form-group"><label style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3)">Max/call ($)</label><input type="number" id="tp-max" min="0" step="1" placeholder="100"></div>
          <div class="form-group"><label style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3)">Daily limit ($)</label><input type="number" id="tp-daily" min="0" step="1" placeholder="500"></div>
          <div class="form-group"><label style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3)">Approval above ($)</label><input type="number" id="tp-approval" min="0" step="1" placeholder="50"></div>
          <div class="form-group" style="flex:0.7"><label style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3)">Rate (/hr)</label><input type="number" id="tp-rate" min="0" step="1" placeholder="10"></div>
          <button type="submit" class="btn btn-sm" style="background:var(--success);margin-bottom:12px" onclick="return stagePolicy()">Save Policy</button>
        </div>
      </form>
    </div>
  </div>
</div>
<script>
function stagePolicy() {
  var name = document.getElementById('tp-tool-name').value.trim();
  if (!name) return false;
  var form = document.getElementById('tp-tool-name').closest('form');
  var prefix = 'tp_' + name + '_';
  form.querySelectorAll('[name^="' + prefix + '"]').forEach(function(el) { el.remove(); });
  var fields = {max_amount: 'tp-max', daily_limit: 'tp-daily', require_approval: 'tp-approval', rate_limit: 'tp-rate'};
  for (var k in fields) {
    var inp = document.createElement('input');
    inp.type = 'hidden'; inp.name = prefix + k; inp.value = document.getElementById(fields[k]).value || '0';
    form.appendChild(inp);
  }
  var toolsInput = document.getElementById('tp-policy-tools');
  var tools = toolsInput.value.trim().split(/\s+/).filter(Boolean);
  if (tools.indexOf(name) === -1) tools.push(name);
  toolsInput.value = tools.join(' ');
  return true;
}
</script>

<!-- Egress Tab -->
<div id="ad-egress" class="ad-panel" role="tabpanel" aria-labelledby="tab-egress">
  <div class="card" style="padding:18px 20px">
    <div class="ad-slbl">Egress Policy {{if .Agent.Egress}}<span style="font-weight:400;text-transform:none;letter-spacing:0;font-size:0.68rem;color:var(--accent-light);margin-left:6px">per-agent override</span>{{else}}<span style="font-weight:400;text-transform:none;letter-spacing:0;font-size:0.68rem;color:var(--text3);margin-left:6px">using global defaults</span>{{end}}</div>
    <p class="desc">{{if .Agent.Egress}}This agent has a custom egress policy. Changes here override global proxy settings.{{else}}No per-agent egress policy configured. This agent falls back to global proxy settings. Configure domains below to create an override.{{end}}</p>

    <form method="POST" action="/dashboard/agents/{{.Name}}/egress">

    <!-- Integration Presets -->
    <div style="margin-bottom:20px">
      <div style="font-size:0.68rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);margin-bottom:10px">Integration Presets</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        {{range .Presets}}
        <label style="display:flex;align-items:center;gap:5px;padding:5px 12px;background:var(--surface2);border-radius:6px;cursor:pointer;font-size:0.78rem;color:var(--text2);transition:background 0.1s" title="{{.Description}}">
          <input type="checkbox" name="integrations" value="{{.Name}}" {{if $.Agent.Egress}}{{if listContains $.Agent.Egress.Integrations .Name}}checked{{end}}{{end}} style="accent-color:var(--accent)">
          {{.Name}}
        </label>
        {{end}}
      </div>
    </div>

    <!-- Allowed Domains -->
    <div style="margin-bottom:16px">
      <div class="form-group">
        <label style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3)">Allowed Domains (space or comma separated)</label>
        <input type="text" name="allowed_domains" value="{{if .Agent.Egress}}{{range $i, $d := .Agent.Egress.AllowedDomains}}{{if $i}} {{end}}{{$d}}{{end}}{{end}}" placeholder="api.github.com api.slack.com">
      </div>
    </div>

    <!-- Blocked Domains -->
    <div style="margin-bottom:16px">
      <div class="form-group">
        <label style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3)">Blocked Domains (space or comma separated)</label>
        <input type="text" name="blocked_domains" value="{{if .Agent.Egress}}{{range $i, $d := .Agent.Egress.BlockedDomains}}{{if $i}} {{end}}{{$d}}{{end}}{{end}}" placeholder="evil.com malicious.io">
      </div>
    </div>

    <!-- Per-Tool Restrictions -->
    <div style="margin-bottom:16px">
      <div style="font-size:0.68rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);margin-bottom:10px">Per-Tool Restrictions</div>
      {{if .Agent.Egress}}{{if .Agent.Egress.ToolRestrictions}}
      {{range $tool, $domains := .Agent.Egress.ToolRestrictions}}
      <div class="form-row" style="margin-bottom:8px;align-items:center">
        <div style="min-width:120px;font-family:var(--mono);font-size:0.82rem;font-weight:600">{{$tool}}</div>
        <div class="form-group" style="flex:1;margin-bottom:0">
          <input type="text" name="tr_{{$tool}}" value="{{range $i, $d := $domains}}{{if $i}} {{end}}{{$d}}{{end}}" placeholder="Domains (empty = block all egress)">
        </div>
      </div>
      {{end}}
      {{end}}{{end}}
      <div class="form-row" style="align-items:flex-end;margin-top:8px">
        <div class="form-group" style="flex:1">
          <label style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3)">Tool Name</label>
          <input type="text" id="eg-new-tool" placeholder="e.g. Bash, WebFetch">
        </div>
        <div class="form-group" style="flex:2">
          <label style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3)">Allowed Domains (empty = block all egress for tool)</label>
          <input type="text" id="eg-new-domains" placeholder="api.github.com arxiv.org">
        </div>
        <button type="button" class="btn btn-sm" style="background:var(--surface2);color:var(--text2);margin-bottom:12px" onclick="addToolRestriction()">Add</button>
      </div>
      <input type="hidden" name="tool_restriction_tools" id="eg-tr-tools" value="{{if .Agent.Egress}}{{if .Agent.Egress.ToolRestrictions}}{{range $tool, $_ := .Agent.Egress.ToolRestrictions}}{{$tool}} {{end}}{{end}}{{end}}">
    </div>

    <button type="submit" class="btn btn-sm" style="background:var(--success)">Save Egress Policy</button>
    </form>
  </div>
</div>
<script>
function addToolRestriction() {
  var tool = document.getElementById('eg-new-tool').value.trim();
  if (!tool) return;
  var domains = document.getElementById('eg-new-domains').value.trim();
  var form = document.getElementById('eg-new-tool').closest('form');
  var existing = form.querySelector('[name="tr_' + tool + '"]');
  if (!existing) {
    var row = document.createElement('div');
    row.className = 'form-row';
    row.style.marginBottom = '8px';
    row.style.alignItems = 'center';
    row.innerHTML = '<div style="min-width:120px;font-family:var(--mono);font-size:0.82rem;font-weight:600">' + _esc(tool) + '</div><div class="form-group" style="flex:1;margin-bottom:0"><input type="text" name="tr_' + _esc(tool) + '" value="' + _esc(domains) + '" placeholder="Domains"></div>';
    document.getElementById('eg-new-tool').closest('.form-row').before(row);
  }
  var toolsInput = document.getElementById('eg-tr-tools');
  var tools = toolsInput.value.trim().split(/\s+/).filter(Boolean);
  if (tools.indexOf(tool) === -1) tools.push(tool);
  toolsInput.value = tools.join(' ');
  document.getElementById('eg-new-tool').value = '';
  document.getElementById('eg-new-domains').value = '';
}</script>

` + layoutFoot))
