package dashboard

import "html/template"

var llmTmpl = template.Must(template.New("llm").Funcs(tmplFuncs).Parse(layoutHead + `
<style>
/* ── Triage bar ── */
.tq-bar{display:flex;align-items:center;gap:0;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-xl);padding:var(--sp-5) var(--sp-6);margin-bottom:var(--sp-6)}
.tq-seg{display:flex;align-items:center;gap:10px;flex:1;min-width:0}
.tq-num{font-size:var(--text-2xl);font-weight:700;font-family:var(--sans);line-height:1;letter-spacing:var(--ls-tight);font-variant-numeric:tabular-nums;color:var(--text)}
.tq-label{font-size:var(--text-sm);color:var(--text3);font-weight:500;white-space:nowrap}
.tq-pill{font-size:0.62rem;padding:2px 8px;border-radius:100px;font-weight:500;white-space:nowrap}
.tq-pill-c{background:rgba(248,81,73,0.1);color:#f85149}
.tq-pill-m{background:rgba(210,153,34,0.08);color:#d29922}
.tq-div{width:1px;height:36px;background:var(--border);margin:0 20px;flex-shrink:0}

/* ── Triage table ── */
.tq-filters{display:flex;gap:var(--sp-2);margin-bottom:var(--sp-3);flex-wrap:wrap;align-items:center}
.tq-filters select,.tq-filters input{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:var(--radius-md);font-size:var(--text-sm);font-family:var(--sans)}
.tq-table{width:100%;border-collapse:collapse}
.tq-table th{font-size:var(--text-xs);text-transform:uppercase;letter-spacing:var(--ls-caps);color:var(--text3);font-weight:500;text-align:left;padding:var(--sp-2) var(--sp-3);border-bottom:2px solid var(--border)}
.tq-table td{padding:10px var(--sp-3);border-bottom:1px solid var(--border);font-size:var(--text-sm);font-family:var(--sans)}
.tq-table tr.tq-row{cursor:pointer;transition:background 0.1s}
.tq-table tr.tq-row:hover{background:var(--surface-hover)}
.tq-table tr.tq-dismissed{opacity:0.5}
.tq-table tr.tq-dismissed:hover{opacity:0.8}
.tq-risk{display:inline-flex;align-items:center;justify-content:center;width:36px;height:28px;border-radius:var(--radius-md);font-family:var(--sans);font-weight:700;font-size:var(--text-sm)}
.tq-pager{display:flex;align-items:center;justify-content:space-between;padding:12px 0;font-size:0.78rem;color:var(--text3)}
.tq-pager button{background:var(--bg);border:1px solid var(--border);color:var(--text2);padding:var(--sp-1) var(--sp-3);border-radius:var(--radius-md);cursor:pointer;font-size:var(--text-sm);font-family:var(--sans);transition:background var(--ease-smooth)}
.tq-pager button:hover:not(:disabled){background:var(--surface-hover)}
.tq-pager button:disabled{opacity:0.3;cursor:default}
.tq-action{padding:3px 10px;border-radius:100px;font-size:var(--text-xs);font-weight:600;text-transform:uppercase;letter-spacing:0.3px}
.tq-action.block{background:rgba(248,81,73,0.12);color:#f85149}
.tq-action.investigate{background:rgba(210,153,34,0.12);color:#d29922}
.tq-action.quarantine{background:var(--danger-muted);color:var(--danger)}
.tq-action.monitor,.tq-action.allow{background:var(--surface2);color:var(--text3)}
.tq-status{padding:3px 10px;border-radius:100px;font-size:var(--text-xs);font-weight:600;text-transform:uppercase;letter-spacing:0.3px}
.tq-status.new{background:rgba(56,139,253,0.12);color:var(--accent-light)}
.tq-status.dismissed{background:rgba(63,185,80,0.08);color:#3fb950}
.tq-status.confirmed{background:rgba(248,81,73,0.08);color:#f85149}
@media(max-width:768px){.tq-bar{flex-direction:column;gap:12px;align-items:flex-start}.tq-div{width:100%;height:1px;margin:0}}
.llm-grid{display:grid;grid-template-columns:1fr 1fr;gap:var(--sp-4);margin-bottom:var(--sp-4)}
.llm-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-xl);padding:var(--sp-5)}
.llm-card h3{font-size:var(--text-xs);letter-spacing:var(--ls-caps);color:var(--text3);margin-bottom:var(--sp-4);font-weight:600;text-transform:uppercase}
.llm-row{display:flex;justify-content:space-between;align-items:baseline;padding:var(--sp-2) 0;border-bottom:1px solid var(--border)}
.llm-row:last-child{border-bottom:none}
.llm-row .k{font-size:var(--text-base);color:var(--text2)}
.llm-row .v{font-family:var(--mono);font-weight:600;font-size:var(--text-md)}
.prov-opt{position:relative;flex:1;padding:16px;border-radius:8px;border:2px solid var(--border);cursor:pointer;transition:border-color 0.15s,background 0.15s;text-align:center}
.prov-opt:hover{border-color:var(--text3)}
.prov-opt:focus-within{outline:2px solid var(--accent);outline-offset:2px}
.prov-opt.sel{border-color:var(--accent);background:rgba(56,139,253,0.06)}
.prov-opt .pname{font-weight:600;font-size:0.88rem;margin-bottom:2px}
.prov-opt .pdesc{font-size:0.7rem;color:var(--text3);line-height:1.4}
.fw-step{display:flex;align-items:center;gap:6px;font-size:0.78rem;color:var(--text2)}
.fw-step .num{width:20px;height:20px;border-radius:50%;background:var(--accent);color:#fff;display:flex;align-items:center;justify-content:center;font-size:0.65rem;font-weight:700;flex-shrink:0}
.fw-arrow{color:var(--text3);font-size:0.7rem;flex-shrink:0}
.llm-tabs{display:flex;gap:0;border-bottom:2px solid var(--border);margin-bottom:var(--sp-5)}
.llm-tab{padding:10px var(--sp-5);font-size:var(--text-sm);font-weight:500;color:var(--text3);cursor:pointer;border:none;background:none;border-bottom:2px solid transparent;margin-bottom:-2px;transition:color var(--ease-default),border-color var(--ease-default)}
.llm-tab:hover{color:var(--text2)}
.llm-tab:focus-visible{outline:2px solid var(--accent);outline-offset:-2px;border-radius:2px}
.llm-tab.active{color:var(--text);border-bottom-color:var(--accent);font-weight:600}
.llm-tab-panel{display:none}
.llm-tab-panel.active{display:block}
.llm-status-bar{display:flex;align-items:center;gap:var(--sp-4);padding:var(--sp-3) var(--sp-5);background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-xl);margin-bottom:var(--sp-5);font-size:var(--text-sm);flex-wrap:wrap}
.llm-status-bar .dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.llm-conn-adv{display:none}
.llm-conn-adv.open{display:block}
.llm-adv-btn{display:flex;align-items:center;gap:6px;cursor:pointer;padding:10px 0 0 0;font-size:0.75rem;color:var(--text3);border:none;background:none;font-weight:500}
.llm-adv-btn:hover{color:var(--text2)}
.llm-adv-btn:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
.llm-adv-btn .arr{transition:transform 0.15s;font-size:0.6rem}
.llm-adv-btn .arr.open{transform:rotate(90deg)}
@media(max-width:768px){.llm-hero{grid-template-columns:repeat(2,1fr)}.llm-grid{grid-template-columns:1fr}}
</style>

<p class="page-desc">AI-powered threat analysis catches what rules alone can't see. Runs async, never blocks message delivery.</p>

{{if not .Enabled}}
<!-- Setup state -->
<div class="card">
  <h2 style="font-size:1rem;margin-bottom:12px">Enable AI-Powered Detection</h2>
  <p style="color:var(--text2);font-size:0.82rem;line-height:1.6;margin-bottom:8px">
    oktsec's 230 rules catch known threats instantly. Add an AI layer to detect what patterns miss:
  </p>
  <ul style="color:var(--text2);font-size:0.82rem;line-height:1.8;margin:0 0 20px 18px;padding:0">
    <li>Semantic data exfiltration disguised as normal messages</li>
    <li>Social engineering between agents</li>
    <li>Intent drift (agent doing something it shouldn't)</li>
    <li>Auto-generates new detection rules from findings</li>
  </ul>

  <form method="POST" action="/dashboard/settings/llm">
    <input type="hidden" name="enabled" value="true">

    <label style="font-size:0.72rem;text-transform:uppercase;letter-spacing:0.5px;color:var(--text3);font-weight:500;display:block;margin-bottom:10px">Provider</label>
    <div style="display:flex;gap:10px;margin-bottom:20px">
      <label class="prov-opt sel" onclick="selectProvider('openai',this)">
        <input type="radio" name="provider" value="openai" checked style="position:absolute;opacity:0">
        <div class="pname">OpenAI-Compatible</div>
        <div class="pdesc">OpenAI, Ollama, vLLM, Groq, Azure, LM Studio</div>
      </label>
      <label class="prov-opt" onclick="selectProvider('claude',this)">
        <input type="radio" name="provider" value="claude" style="position:absolute;opacity:0">
        <div class="pname">Claude</div>
        <div class="pdesc">Anthropic API</div>
      </label>
      <label class="prov-opt" onclick="selectProvider('webhook',this)">
        <input type="radio" name="provider" value="webhook" style="position:absolute;opacity:0">
        <div class="pname">Webhook</div>
        <div class="pdesc">Custom endpoint</div>
      </label>
    </div>

    <div class="form-row" style="margin-bottom:12px" id="llm-fields-row">
      <div class="form-group" style="flex:1" id="llm-model-group">
        <label id="llm-model-label">Model</label>
        <input type="text" name="model" id="llm-model" placeholder="gpt-4o">
      </div>
      <div class="form-group" style="flex:1" id="llm-key-group">
        <label id="llm-key-label">API key env variable</label>
        <input type="text" name="api_key_env" id="llm-key" placeholder="OPENAI_API_KEY">
      </div>
    </div>
    <div class="form-row" style="margin-bottom:20px">
      <div class="form-group" style="flex:1">
        <label id="llm-url-label">Base URL <span style="color:var(--text3);font-size:0.72rem">(leave empty for provider defaults)</span></label>
        <input type="text" name="base_url" id="llm-url" placeholder="http://localhost:11434/v1">
      </div>
    </div>
    <script>
    var provCfg={openai:{model:'gpt-4o, qwen3.5:latest, llama3',modelLabel:'Model',key:'Optional for local models (Ollama, LM Studio)',keyLabel:'API key env variable <span style="color:var(--text3);font-size:0.72rem">(optional for local)</span>',url:'http://localhost:11434/v1',urlLabel:'Base URL <span style="color:var(--text3);font-size:0.72rem">(required for non-OpenAI)</span>',showModel:true,showKey:true},claude:{model:'claude-sonnet-4-6',modelLabel:'Model',key:'ANTHROPIC_API_KEY',keyLabel:'API key env variable',url:'https://api.anthropic.com',urlLabel:'Base URL <span style="color:var(--text3);font-size:0.72rem">(optional)</span>',showModel:true,showKey:true},webhook:{model:'',modelLabel:'',key:'',keyLabel:'',url:'https://your-endpoint.example.com/analyze',urlLabel:'Webhook URL',showModel:false,showKey:false}};
    function selectProvider(p,el){el.parentNode.querySelectorAll('.prov-opt').forEach(function(c){c.classList.remove('sel')});el.classList.add('sel');var c=provCfg[p];document.getElementById('llm-model').placeholder=c.model;document.getElementById('llm-key').placeholder=c.key;document.getElementById('llm-key-label').innerHTML=c.keyLabel;document.getElementById('llm-url').placeholder=c.url;document.getElementById('llm-url-label').innerHTML=c.urlLabel;document.getElementById('llm-model-group').style.display=c.showModel?'':'none';document.getElementById('llm-key-group').style.display=c.showKey?'':'none';if(!c.showModel)document.getElementById('llm-model').value='';if(!c.showKey)document.getElementById('llm-key').value=''}
    </script>
    <button type="submit" class="btn">Enable AI Analysis</button>
  </form>
</div>

{{else}}
<!-- Active state: tabs -->

<!-- Status bar (always visible above tabs) -->
<div class="llm-status-bar" style="margin-bottom:var(--sp-5)">
  <div style="display:flex;align-items:center;gap:8px">
    <div class="dot" style="background:var(--success)"></div>
    <span style="font-weight:500">{{.Cfg.Model}}</span>
  </div>
  {{if .BudgetStatus}}
  <div style="margin-left:auto;display:flex;gap:16px;align-items:center">
    {{if gt .BudgetStatus.DailyLimit 0.0}}
    <div style="display:flex;align-items:center;gap:6px">
      <span style="color:var(--text3)">Today:</span>
      <span style="font-family:var(--mono);font-weight:600;font-variant-numeric:tabular-nums;{{if .BudgetStatus.DailyExhausted}}color:var(--danger){{else if .BudgetStatus.DailyWarning}}color:var(--warn){{end}}">${{printf "%.2f" .BudgetStatus.DailySpent}} / ${{printf "%.2f" .BudgetStatus.DailyLimit}}</span>
    </div>
    {{end}}
    {{if gt .BudgetStatus.MonthlyLimit 0.0}}
    <div style="display:flex;align-items:center;gap:6px">
      <span style="color:var(--text3)">Month:</span>
      <span style="font-family:var(--mono);font-weight:600;font-variant-numeric:tabular-nums;{{if .BudgetStatus.MonthlyExhaust}}color:var(--danger){{else if .BudgetStatus.MonthlyWarning}}color:var(--warn){{end}}">${{printf "%.2f" .BudgetStatus.MonthlySpent}} / ${{printf "%.2f" .BudgetStatus.MonthlyLimit}}</span>
    </div>
    {{end}}
    {{if gt .BudgetStatus.DroppedBudget 0}}<span style="color:var(--danger);font-weight:500">{{.BudgetStatus.DroppedBudget}} dropped</span>{{end}}
  </div>
  {{end}}
  <div id="llm-toggle-wrap" style="margin-left:{{if not .BudgetStatus}}auto{{else}}0{{end}}">
    <button class="btn btn-sm" style="background:var(--surface2);color:var(--text2);font-size:0.72rem;padding:4px 12px" hx-post="/dashboard/api/llm/toggle" hx-swap="innerHTML" hx-target="#llm-toggle-wrap" hx-confirm="Disable AI analysis? Threat detection will rely on rules only.">Disable</button>
  </div>
</div>

<!-- Tabs -->
<div class="llm-tabs" role="tablist">
  <button class="llm-tab active" role="tab" aria-selected="true" aria-controls="llm-panel-monitor" onclick="llmSwitchTab('monitor')">Queue{{if .Triage}}{{if gt .Triage.NeedsReview 0}} <span style="font-size:0.68rem;color:var(--accent-light)">({{.Triage.NeedsReview}})</span>{{end}}{{end}}</button>
  <button class="llm-tab" role="tab" aria-selected="false" aria-controls="llm-panel-config" onclick="llmSwitchTab('config')">Configuration</button>
</div>
<script>
function llmSwitchTab(name){
  document.querySelectorAll('.llm-tab').forEach(function(t){t.classList.remove('active');t.setAttribute('aria-selected','false')});
  document.querySelectorAll('.llm-tab-panel').forEach(function(p){p.classList.remove('active')});
  var idx=name==='config'?1:0;
  document.querySelectorAll('.llm-tab')[idx].classList.add('active');
  document.querySelectorAll('.llm-tab')[idx].setAttribute('aria-selected','true');
  document.getElementById('llm-panel-'+name).classList.add('active');
}
</script>

<!-- TAB 1: Monitoring -->
<div id="llm-panel-monitor" class="llm-tab-panel active" role="tabpanel">

<!-- Triage summary -->
<div class="tq-bar">
  <div class="tq-seg">
    <div class="tq-num {{if gt .Triage.NeedsReview 0}}danger{{end}}">{{.Triage.NeedsReview}}</div>
    <div class="tq-label">Needs review</div>
    {{if gt .Triage.HighSeverity 0}}<span class="tq-pill tq-pill-c">{{.Triage.HighSeverity}} high</span>{{end}}
    {{if gt .Triage.MediumSeverity 0}}<span class="tq-pill tq-pill-m">{{.Triage.MediumSeverity}} med</span>{{end}}
  </div>
  <div class="tq-div"></div>
  <div class="tq-seg">
    <div class="tq-num" style="color:var(--success)">{{.Stats.TotalThreats}}</div>
    <div class="tq-label">Threats caught</div>
  </div>
  <div class="tq-div"></div>
  <div class="tq-seg">
    <div class="tq-num" style="color:var(--accent-light)">{{.Stats.RulesGenerated}}</div>
    <div class="tq-label">Rules generated</div>
  </div>
  <div class="tq-div"></div>
  <div class="tq-seg">
    <div class="tq-num" style="color:var(--text3)">{{.Triage.Resolved}}</div>
    <div class="tq-label">Resolved</div>
  </div>
</div>

{{if .Analyses}}
<!-- Filters -->
<div class="tq-filters">
  <select id="tq-risk-filter" onchange="tqApply()">
    <option value="">All risk levels</option>
    <option value="76">Critical (76+)</option>
    <option value="51">High (51+)</option>
    <option value="31">Medium (31+)</option>
  </select>
  <select id="tq-status-filter" onchange="tqApply()">
    <option value="">All statuses</option>
    <option value="new">New</option>
    <option value="false_positive">Dismissed</option>
    <option value="confirmed">Confirmed</option>
  </select>
  <input type="text" id="tq-agent-filter" placeholder="Filter by agent..." oninput="tqApply()" style="width:160px">
  <span id="tq-count" style="margin-left:auto;font-size:0.78rem;color:var(--text3)"></span>
</div>

<!-- Table -->
<div style="overflow-x:auto">
<table class="tq-table">
  <thead>
    <tr>
      <th style="width:50px">Risk</th>
      <th style="white-space:nowrap">Flow</th>
      <th>Threat</th>
      <th style="width:100px">Action</th>
      <th style="width:90px">Status</th>
      <th style="width:80px">Time</th>
    </tr>
  </thead>
  <tbody id="tq-tbody">
  {{range .Analyses}}
    <tr class="tq-row{{if eq .ReviewedStatus "false_positive"}} tq-dismissed{{end}}" data-risk="{{printf "%.0f" .RiskScore}}" data-status="{{.ReviewedStatus}}" data-agent="{{.FromAgent}} {{.ToAgent}}">
      <td><a href="/dashboard/llm/case/{{.ID}}" style="text-decoration:none"><span class="tq-risk" style="{{if ge .RiskScore 76.0}}background:rgba(239,68,68,0.08);color:#f85149{{else if ge .RiskScore 51.0}}background:var(--danger-muted);color:var(--danger){{else if ge .RiskScore 31.0}}background:rgba(210,153,34,0.07);color:#d29922{{else if gt .RiskScore 0.0}}background:rgba(34,197,94,0.06);color:#3fb950{{else}}background:var(--surface2);color:var(--text3){{end}}">{{printf "%.0f" .RiskScore}}</span></a></td>
      <td style="font-size:0.8rem;white-space:nowrap">{{.FromAgent}} <span style="color:var(--text3)">&rarr;</span> {{.ToAgent}}</td>
      <td style="font-size:0.8rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{firstThreatSummary .ThreatsJSON .RiskScore}}</td>
      <td><span class="tq-action {{.RecommendedAction}}">{{.RecommendedAction}}</span></td>
      <td>{{if eq .ReviewedStatus "false_positive"}}<span class="tq-status dismissed">dismissed</span>{{else if eq .ReviewedStatus "confirmed"}}<span class="tq-status confirmed">confirmed</span>{{else if ge .RiskScore 30.0}}<span class="tq-status new">new</span>{{else}}<span style="color:var(--text3);font-size:0.72rem">&#8212;</span>{{end}}</td>
      <td style="font-size:0.72rem;color:var(--text3);font-family:var(--mono)">{{relativeTime .Timestamp}}</td>
    </tr>
  {{end}}
  </tbody>
</table>
</div>

<!-- Pagination -->
<div class="tq-pager" id="tq-pager">
  <span id="tq-pager-info"></span>
  <div style="display:flex;gap:4px">
    <button id="tq-prev" onclick="tqNav(-1)" disabled>&larr; Prev</button>
    <button id="tq-next" onclick="tqNav(1)">Next &rarr;</button>
  </div>
</div>

<script>
var tqCurPage=1,tqSize=20;
function tqApply(){
  var rMin=parseInt(document.getElementById('tq-risk-filter').value)||0;
  var st=document.getElementById('tq-status-filter').value;
  var ag=document.getElementById('tq-agent-filter').value.toLowerCase();
  document.querySelectorAll('.tq-row').forEach(function(r){
    var risk=parseInt(r.dataset.risk)||0;
    var rs=r.dataset.status;
    var a=r.dataset.agent.toLowerCase();
    var ok=true;
    if(rMin&&risk<rMin)ok=false;
    if(st==='new'&&rs!=='')ok=false;
    if(st&&st!=='new'&&rs!==st)ok=false;
    if(ag&&a.indexOf(ag)===-1)ok=false;
    r.dataset.vis=ok?'1':'0';
  });
  tqCurPage=1;tqRender();
}
function tqRender(){
  var rows=document.querySelectorAll('.tq-row');
  var vis=[];
  rows.forEach(function(r){if(r.dataset.vis!=='0')vis.push(r);});
  var total=vis.length;
  var start=(tqCurPage-1)*tqSize;
  var end=Math.min(start+tqSize,total);
  rows.forEach(function(r){r.style.display='none';});
  for(var i=start;i<end;i++)vis[i].style.display='';
  document.getElementById('tq-pager-info').textContent=total?'Showing '+(start+1)+'–'+end+' of '+total:'No results';
  document.getElementById('tq-prev').disabled=tqCurPage<=1;
  document.getElementById('tq-next').disabled=end>=total;
  document.getElementById('tq-count').textContent=total+' analyses';
}
function tqNav(d){tqCurPage+=d;tqRender();}
tqApply();
</script>

{{else}}
<div class="card" style="text-align:center;padding:48px;color:var(--text3)">
  <div style="font-size:0.88rem;font-weight:500;color:var(--text2);margin-bottom:4px">LLM analysis active, waiting for messages</div>
  <div style="font-size:0.78rem">Analyses will appear here when messages match your trigger conditions</div>
</div>
{{end}}
</div>

<!-- TAB 2: Configuration -->
<div id="llm-panel-config" class="llm-tab-panel" role="tabpanel">
<form method="POST" action="/dashboard/settings/llm" id="llm-config-form">
<input type="hidden" name="enabled" value="true">

<div class="llm-grid">
  <div class="llm-card">
    <h3 style="display:flex;align-items:center;gap:10px">Connection <span id="cfg-svc-badge" style="font-size:0.7rem;padding:2px 8px;border-radius:4px;font-weight:500;letter-spacing:0.3px"></span></h3>
    <input type="hidden" name="provider" id="cfg-provider" value="{{.Cfg.Provider}}">
    <div class="form-group" style="margin-bottom:14px">
      <label>Service</label>
      <div id="cfg-presets" style="display:flex;gap:6px;flex-wrap:wrap"></div>
    </div>
    <div class="form-group" style="margin-bottom:12px" id="cfg-url-group">
      <label id="cfg-url-label">Base URL</label>
      <input type="text" name="base_url" id="cfg-url" value="{{.Cfg.BaseURL}}" oninput="llmDetectAndRefresh()">
    </div>
    <div class="form-group" style="margin-bottom:12px" id="cfg-model-group">
      <label>Model</label>
      <input type="text" name="model" id="cfg-model" value="{{.Cfg.Model}}">
      <div id="cfg-model-hints" style="display:flex;gap:6px;margin-top:6px;flex-wrap:wrap"></div>
    </div>
    <div class="form-group" style="margin-bottom:8px" id="cfg-key-group">
      <label id="cfg-key-label">API Key</label>
      <div style="position:relative">
        <input type="password" name="api_key" id="cfg-key" value="" autocomplete="off" style="padding-right:40px" placeholder="{{if .Cfg.APIKey}}•••• (stored — leave blank to keep){{else}}sk-...{{end}}">
      </div>
      {{if .Cfg.APIKey}}<div style="font-size:0.7rem;color:var(--text3);margin-top:4px">API key is stored (masked). Type a new one to replace it, or leave blank to keep the current key.</div>{{end}}
    </div>
    <div class="form-group" style="margin-bottom:0" id="cfg-keyenv-group">
      <label>API Key Env Variable</label>
      <input type="text" name="api_key_env" id="cfg-keyenv" value="{{.Cfg.APIKeyEnv}}" autocomplete="off" placeholder="OPENROUTER_API_KEY">
      <div id="cfg-key-hint" style="font-size:0.7rem;color:var(--text3);margin-top:4px">Direct key takes precedence over env variable</div>
    </div>
    <button type="button" class="llm-adv-btn" aria-expanded="false" aria-controls="conn-advanced" onclick="var s=document.getElementById('conn-advanced');var a=this.querySelector('.arr');var open=s.classList.toggle('open');a.classList.toggle('open');this.setAttribute('aria-expanded',open)">
      <span class="arr">&#9654;</span> Advanced
    </button>
    <div id="conn-advanced" class="llm-conn-adv">
      <div class="form-row" style="margin-top:10px;margin-bottom:8px">
        <div class="form-group" style="flex:1">
          <label>Timeout</label>
          <input type="text" name="timeout" value="{{.Cfg.Timeout}}" placeholder="30s">
        </div>
        <div class="form-group" style="flex:1">
          <label>Max Concurrent</label>
          <input type="number" name="max_concurrent" value="{{if .Cfg.MaxConcurrent}}{{.Cfg.MaxConcurrent}}{{else}}3{{end}}" min="1" max="20" style="width:100%">
        </div>
      </div>
      <div class="form-row" style="margin-bottom:0">
        <div class="form-group" style="flex:1">
          <label>Max Tokens</label>
          <input type="number" name="max_tokens" value="{{if .Cfg.MaxTokens}}{{.Cfg.MaxTokens}}{{else}}1024{{end}}" min="1" style="width:100%">
        </div>
        <div class="form-group" style="flex:1">
          <label>Temperature</label>
          <input type="number" name="temperature" value="{{printf "%.1f" .Cfg.Temperature}}" min="0" max="2" step="0.1" style="width:100%">
        </div>
      </div>
    </div>
    <div style="margin-top:14px;padding-top:14px;border-top:1px solid var(--border)">
      <div style="display:flex;align-items:center;gap:10px">
        <button type="button" class="btn btn-sm btn-outline" id="llm-test-btn" onclick="llmTest()">Test Connection</button>
        <span id="llm-test-result" style="font-size:0.72rem;font-family:var(--mono);line-height:1.4;flex:1;overflow:hidden;text-overflow:ellipsis"></span>
      </div>
    </div>
    <script>
    function llmTest(){
      var btn=document.getElementById('llm-test-btn');
      var res=document.getElementById('llm-test-result');
      btn.disabled=true;btn.textContent='Testing...';
      res.textContent='';res.style.color='var(--text3)';
      fetch('/dashboard/api/llm/test',{method:'POST',credentials:'same-origin'})
        .then(function(r){return r.json()})
        .then(function(d){
          if(d.ok){
            res.style.color='var(--success)';
            res.textContent='Connected — '+d.model+' ('+d.latency+'ms)';
          }else{
            res.style.color='var(--danger)';
            var msg=d.error||'Unknown error';
            if(msg.length>120) msg=msg.substring(0,120)+'...';
            res.textContent='Failed: '+msg;
          }
        })
        .catch(function(e){res.style.color='var(--danger)';res.textContent='Error: '+e.message;})
        .finally(function(){btn.disabled=false;btn.textContent='Test Connection';});
    }
    </script>
    <input type="hidden" name="queue_size" value="{{if .Cfg.QueueSize}}{{.Cfg.QueueSize}}{{else}}100{{end}}">
    <input type="hidden" name="max_daily" value="{{.Cfg.MaxDailyReqs}}">
    <script>
    var llmSvc={
      openrouter:{label:'OpenRouter',provider:'openai',url:'https://openrouter.ai/api/v1',bg:'rgba(168,85,247,0.15)',fg:'#a855f7',keyHint:'Set OPENROUTER_API_KEY in your environment',keyPh:'OPENROUTER_API_KEY',models:['deepseek/deepseek-chat-v3-0324','google/gemini-2.5-flash-preview','google/gemini-2.5-flash','anthropic/claude-sonnet-4','x-ai/grok-4-fast']},
      ollama:{label:'Ollama',provider:'openai',url:'http://localhost:11434/v1',bg:'rgba(34,197,94,0.15)',fg:'#3fb950',keyHint:'No API key needed for local Ollama',keyPh:'',models:['qwen3.5:latest','llama3:latest','mistral:latest','deepseek-r1:latest']},
      lmstudio:{label:'LM Studio',provider:'openai',url:'http://localhost:1234/v1',bg:'var(--accent-muted)',fg:'var(--accent)',keyHint:'No API key needed for local LM Studio',keyPh:'',models:['loaded-model']},
      openai:{label:'OpenAI',provider:'openai',url:'https://api.openai.com/v1',bg:'rgba(168,162,158,0.15)',fg:'#a8a29e',keyHint:'Set OPENAI_API_KEY in your environment',keyPh:'OPENAI_API_KEY',models:['gpt-4o','gpt-4o-mini','gpt-4-turbo']},
      groq:{label:'Groq',provider:'openai',url:'https://api.groq.com/openai/v1',bg:'rgba(210,153,34,0.15)',fg:'#d29922',keyHint:'Set GROQ_API_KEY in your environment',keyPh:'GROQ_API_KEY',models:['llama-3.3-70b-versatile','mixtral-8x7b-32768']},
      azure:{label:'Azure',provider:'openai',url:'https://YOUR-RESOURCE.openai.azure.com/openai/deployments/YOUR-DEPLOYMENT',bg:'var(--accent-muted)',fg:'var(--accent)',keyHint:'Set AZURE_OPENAI_API_KEY in your environment',keyPh:'AZURE_OPENAI_API_KEY',models:['gpt-4o']},
      vllm:{label:'vLLM',provider:'openai',url:'http://localhost:8000/v1',bg:'rgba(34,197,94,0.15)',fg:'#3fb950',keyHint:'No API key needed for local vLLM',keyPh:'',models:[]},
      claude:{label:'Claude',provider:'claude',url:'https://api.anthropic.com',bg:'rgba(217,119,87,0.15)',fg:'#d97756',keyHint:'Set ANTHROPIC_API_KEY in your environment',keyPh:'ANTHROPIC_API_KEY',models:['claude-sonnet-4-6','claude-haiku-4-5-20251001','claude-opus-4-6']},
      webhook:{label:'Webhook',provider:'webhook',url:'',bg:'rgba(168,162,158,0.15)',fg:'#a8a29e',keyHint:'',keyPh:'',models:[]}
    };
    function llmDetectCurrent(){
      var u=(document.getElementById('cfg-url').value||'').toLowerCase();
      var p=document.getElementById('cfg-provider').value;
      if(p==='claude') return 'claude';
      if(p==='webhook') return 'webhook';
      var m=(document.getElementById('cfg-model').value||'').toLowerCase();
      if(u.indexOf('openrouter')!==-1) return 'openrouter';
      if(m.indexOf('/')!==-1&&m.indexOf('/')<m.lastIndexOf('/') || (m.indexOf('/')!==-1&&(m.indexOf('google/')===0||m.indexOf('anthropic/')===0||m.indexOf('meta-llama/')===0||m.indexOf('mistralai/')===0||m.indexOf('deepseek/')===0))) return 'openrouter';
      if(u.indexOf(':11434')!==-1) return 'ollama';
      if(u.indexOf('lmstudio')!==-1||u.indexOf(':1234')!==-1) return 'lmstudio';
      if(u.indexOf('groq')!==-1) return 'groq';
      if(u.indexOf('azure')!==-1) return 'azure';
      if(u.indexOf(':8000')!==-1) return 'vllm';
      if(u.indexOf('openai.com')!==-1) return 'openai';
      if(u.indexOf('localhost')!==-1||u.indexOf('127.0.0.1')!==-1) return 'ollama';
      if(u==='') return 'ollama';
      return 'openai'
    }
    function llmApply(key){
      var s=llmSvc[key];if(!s) return;
      document.getElementById('cfg-provider').value=s.provider;
      document.getElementById('cfg-url').value=s.url;
      document.getElementById('cfg-key').value=s.keyPh;
      if(s.models.length>0) document.getElementById('cfg-model').value=s.models[0];
      else document.getElementById('cfg-model').value='';
      llmRefresh()
    }
    function llmDetectAndRefresh(){
      var cur=llmDetectCurrent();
      var s=llmSvc[cur];
      if(s) document.getElementById('cfg-provider').value=s.provider;
      llmRefresh()
    }
    function llmRefresh(){
      var cur=llmDetectCurrent(),s=llmSvc[cur],b=document.getElementById('cfg-svc-badge');
      var mg=document.getElementById('cfg-model-group'),kg=document.getElementById('cfg-key-group'),ug=document.getElementById('cfg-url-group');
      var hintBox=document.getElementById('cfg-model-hints'),keyHint=document.getElementById('cfg-key-hint'),presetBox=document.getElementById('cfg-presets');
      b.textContent=s?s.label:'';b.style.background=s?s.bg:'';b.style.color=s?s.fg:'';
      hintBox.innerHTML='';keyHint.textContent='';presetBox.innerHTML='';
      if(cur==='webhook'){
        mg.style.display='none';kg.style.display='none';
        document.getElementById('cfg-url-label').textContent='Webhook URL';
        document.getElementById('cfg-url').placeholder='https://your-endpoint.example.com/analyze';
      }else{
        mg.style.display='';kg.style.display='';
        document.getElementById('cfg-url-label').textContent='Base URL';
        if(s){
          document.getElementById('cfg-url').placeholder=s.url;
          document.getElementById('cfg-key').placeholder=s.keyPh||'Not required';
          keyHint.textContent=s.keyHint||'';
          document.getElementById('cfg-model').placeholder=s.models.length>0?s.models[0]:'model-name';
          s.models.forEach(function(m){
            var c=document.createElement('button');c.type='button';c.textContent=m;
            c.style.cssText='font-size:0.68rem;padding:2px 8px;border-radius:4px;border:1px solid var(--border);background:var(--surface2);color:var(--text3);cursor:pointer';
            c.onclick=function(){document.getElementById('cfg-model').value=m};
            hintBox.appendChild(c)
          })
        }
      }
      Object.keys(llmSvc).forEach(function(k){
        var sv=llmSvc[k];
        var btn=document.createElement('button');btn.type='button';btn.textContent=sv.label;
        var active=k===cur;
        btn.style.cssText='font-size:0.7rem;padding:4px 12px;border-radius:5px;cursor:pointer;font-weight:'+(active?'600':'400')+';border:1px solid '+(active?sv.fg:'var(--border)')+';background:'+(active?sv.bg:'transparent')+';color:'+(active?sv.fg:'var(--text3)');
        btn.onclick=function(){llmApply(k)};
        presetBox.appendChild(btn)
      })
    }
    document.addEventListener('DOMContentLoaded', llmRefresh);
    </script>
  </div>

  <div class="llm-card">
    <h3>Spending limits</h3>
    <div class="form-row" style="margin-bottom:10px">
      <div class="form-group" style="flex:1">
        <label>Daily limit (USD)</label>
        <input type="number" name="budget_daily" value="{{printf "%.2f" .Cfg.Budget.DailyLimitUSD}}" min="0" step="0.01" style="width:100%" placeholder="0 = no limit">
      </div>
      <div class="form-group" style="flex:1">
        <label>Monthly limit (USD)</label>
        <input type="number" name="budget_monthly" value="{{printf "%.2f" .Cfg.Budget.MonthlyLimitUSD}}" min="0" step="0.01" style="width:100%" placeholder="0 = no limit">
      </div>
    </div>
    <div class="form-group" style="margin-bottom:0">
      <label>When limit reached</label>
      <select name="budget_on_limit" style="width:100%;padding:8px 12px;border-radius:6px;border:1px solid var(--border);background:var(--surface2);color:var(--text);font-size:0.85rem">
        <option value="skip" {{if or (eq .Cfg.Budget.OnLimit "skip") (eq .Cfg.Budget.OnLimit "")}}selected{{end}}>Continue without LLM (deterministic only)</option>
        <option value="block" {{if eq .Cfg.Budget.OnLimit "block"}}selected{{end}}>Pause all analysis until reset</option>
      </select>
    </div>
    <input type="hidden" name="budget_warn" value="{{if gt .Cfg.Budget.WarnThreshold 0.0}}{{printf "%.0f" (divf .Cfg.Budget.WarnThreshold 0.01)}}{{else}}80{{end}}">

    <h3 style="margin-top:20px">Analysis triggers</h3>
    <p style="color:var(--text3);font-size:0.78rem;margin-bottom:10px">Which verdicts get sent to the LLM?</p>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
      <label style="display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:6px;border:1px solid {{if .Cfg.Analyze.Clean}}var(--success){{else}}var(--border){{end}};cursor:pointer;{{if .Cfg.Analyze.Clean}}background:rgba(34,197,94,0.06){{end}}">
        <span class="toggle"><input type="checkbox" name="analyze_clean" value="true" {{if .Cfg.Analyze.Clean}}checked{{end}}><span class="toggle-slider"></span></span>
        <div><div style="font-size:0.82rem;font-weight:500">Clean</div></div>
      </label>
      <label style="display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:6px;border:1px solid {{if .Cfg.Analyze.Flagged}}var(--warn){{else}}var(--border){{end}};cursor:pointer;{{if .Cfg.Analyze.Flagged}}background:rgba(210,153,34,0.06){{end}}">
        <span class="toggle"><input type="checkbox" name="analyze_flagged" value="true" {{if .Cfg.Analyze.Flagged}}checked{{end}}><span class="toggle-slider"></span></span>
        <div><div style="font-size:0.82rem;font-weight:500">Flagged</div></div>
      </label>
      <label style="display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:6px;border:1px solid {{if .Cfg.Analyze.Quarantined}}var(--danger){{else}}var(--border){{end}};cursor:pointer;{{if .Cfg.Analyze.Quarantined}}background:var(--danger-muted){{end}}">
        <span class="toggle"><input type="checkbox" name="analyze_quarantined" value="true" {{if .Cfg.Analyze.Quarantined}}checked{{end}}><span class="toggle-slider"></span></span>
        <div><div style="font-size:0.82rem;font-weight:500">Quarantined</div></div>
      </label>
      <label style="display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:6px;border:1px solid {{if .Cfg.Analyze.Blocked}}var(--danger){{else}}var(--border){{end}};cursor:pointer;{{if .Cfg.Analyze.Blocked}}background:rgba(239,68,68,0.06){{end}}">
        <span class="toggle"><input type="checkbox" name="analyze_blocked" value="true" {{if .Cfg.Analyze.Blocked}}checked{{end}}><span class="toggle-slider"></span></span>
        <div><div style="font-size:0.82rem;font-weight:500">Blocked</div></div>
      </label>
    </div>
    <div style="margin-top:14px">
      <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
        <span class="toggle"><input type="checkbox" name="two_stage" value="true" {{if .Cfg.TwoStage}}checked{{end}}><span class="toggle-slider"></span></span>
        <span style="font-size:0.85rem;color:var(--text2)">Two-stage classification (fast filter before full analysis)</span>
      </label>
    </div>
  </div>
</div>

<div class="llm-card" style="margin-bottom:16px">
  <h3>Auto-generate rules</h3>
  <div style="display:flex;gap:20px;margin-bottom:14px;flex-wrap:wrap">
    <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
      <span class="toggle"><input type="checkbox" name="rulegen_enabled" value="true" {{if .Cfg.RuleGen.Enabled}}checked{{end}}><span class="toggle-slider"></span></span>
      <span style="font-size:0.85rem;color:var(--text2)">Enable rule generation</span>
    </label>
    <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
      <span class="toggle"><input type="checkbox" name="rulegen_approval" value="true" {{if .Cfg.RuleGen.RequireApproval}}checked{{end}}><span class="toggle-slider"></span></span>
      <span style="font-size:0.85rem;color:var(--text2)">Require human approval</span>
    </label>
  </div>
  <div class="form-row" style="margin-bottom:0">
    <div class="form-group" style="flex:2">
      <label>Output directory</label>
      <input type="text" name="rulegen_dir" value="{{.Cfg.RuleGen.OutputDir}}" placeholder="./rules/generated">
    </div>
    <div class="form-group" style="flex:1">
      <label>Min confidence</label>
      <input type="number" name="rulegen_confidence" value="{{printf "%.1f" .Cfg.RuleGen.MinConfidence}}" min="0" max="1" step="0.1" placeholder="0.8">
    </div>
  </div>
</div>

<div style="display:flex;justify-content:space-between;align-items:center;padding-top:4px;padding-bottom:16px">
  <button type="submit" class="btn">Save Configuration</button>
  <button type="submit" form="llm-disable-form" class="btn btn-sm btn-outline" style="font-size:0.75rem" onclick="return confirm('Disable AI analysis? Threat detection will rely on rules only.')">Disable AI Analysis</button>
</div>
</form>
<form method="POST" action="/dashboard/settings/llm" id="llm-disable-form" style="display:none">
  <input type="hidden" name="enabled" value="false">
  <input type="hidden" name="provider" value="{{.Cfg.Provider}}">
  <input type="hidden" name="model" value="{{.Cfg.Model}}">
</form>
</div>

{{end}}
` + layoutFoot))

var llmDetailTmpl = template.Must(template.New("llm-detail").Funcs(tmplFuncs).Parse(`
<div class="panel-header">
  <h3 style="font-size:0.95rem;font-weight:600">LLM Analysis Detail</h3>
  <button onclick="closePanel()" style="background:none;border:none;color:var(--text3);cursor:pointer;font-size:1.2rem">&times;</button>
</div>
<div style="padding:20px;font-size:0.85rem">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px">
    <span style="display:inline-block;min-width:48px;padding:6px 12px;border-radius:6px;font-family:var(--mono);font-weight:800;font-size:1.4rem;text-align:center;{{if ge .RiskScore 80.0}}background:rgba(239,68,68,0.15);color:var(--danger){{else if ge .RiskScore 50.0}}background:rgba(210,153,34,0.15);color:var(--warn){{else if gt .RiskScore 0.0}}background:rgba(34,197,94,0.1);color:var(--success){{else}}background:var(--surface2);color:var(--text3){{end}}">{{printf "%.0f" .RiskScore}}</span>
    <div>
      <div style="font-weight:600;margin-bottom:2px">Risk Score</div>
      <div style="color:var(--text3);font-size:0.78rem">Confidence: {{printf "%.0f" .Confidence}}%{{if lt .Confidence 30.0}} <span title="Risk score comes from deterministic rule matches. Low confidence means the LLM had limited session context." style="cursor:help;color:var(--warn)">&#9432;</span>{{end}}</div>
    </div>
    <span style="margin-left:auto;padding:4px 12px;border-radius:4px;font-size:0.78rem;font-weight:500;{{if eq .RecommendedAction "block"}}background:rgba(239,68,68,0.15);color:var(--danger){{else if eq .RecommendedAction "investigate"}}background:rgba(210,153,34,0.15);color:var(--warn){{else if eq .RecommendedAction "quarantine"}}background:var(--danger-muted);color:var(--danger){{else}}background:var(--surface2);color:var(--text3){{end}}">{{.RecommendedAction}}</span>
  </div>

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px">
    <div style="background:var(--surface2);border-radius:8px;padding:12px">
      <div style="color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px">Flow</div>
      <div><span style="color:var(--accent-light);font-weight:600">{{.FromAgent}}</span> <span style="color:var(--text3)">→</span> <span style="font-weight:500">{{.ToAgent}}</span></div>
    </div>
    <div style="background:var(--surface2);border-radius:8px;padding:12px">
      <div style="color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px">Model</div>
      <div style="font-family:var(--mono);font-size:0.82rem">{{.Model}}</div>
    </div>
    <div style="background:var(--surface2);border-radius:8px;padding:12px">
      <div style="color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px">Latency</div>
      <div style="font-family:var(--mono)">{{latencySec .LatencyMs}}s</div>
    </div>
    <div style="background:var(--surface2);border-radius:8px;padding:12px">
      <div style="color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px">Tokens</div>
      <div style="font-family:var(--mono)">{{.TokensUsed}}</div>
    </div>
  </div>

  <div style="margin-bottom:16px">
    <div style="color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px">Threats ({{countJSONArray .ThreatsJSON}})</div>
    {{$threats := parseJSONArray .ThreatsJSON}}
    {{if $threats}}
    <div style="padding:4px 0">{{range $threats}}<span style="display:inline-block;padding:3px 10px;border-radius:5px;font-size:0.75rem;font-weight:500;margin:2px 4px 2px 0;background:rgba(239,68,68,0.1);color:var(--danger);border:1px solid rgba(239,68,68,0.2)">{{.}}</span>{{end}}</div>
    {{else}}
    <div style="color:var(--text3);font-size:0.82rem">None</div>
    {{end}}
  </div>

  <div style="margin-bottom:16px">
    <div style="color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px">Intent</div>
    {{$intent := parseJSONMap .IntentJSON}}
    {{if $intent}}
    {{range $k, $v := $intent}}
    <div style="padding:6px 0;border-bottom:1px solid var(--border);font-size:0.82rem">
      <span style="color:var(--text3);text-transform:capitalize">{{$k}}:</span>
      <span style="color:var(--text)">{{$v}}</span>
    </div>
    {{end}}
    {{else}}
    <div style="color:var(--text3);font-size:0.82rem">No intent data</div>
    {{end}}
  </div>

  <div style="border-top:1px solid var(--border);padding-top:12px;margin-top:8px">
    <a href="/dashboard/llm/case/{{.ID}}" style="color:var(--accent);text-decoration:none;font-size:0.82rem;font-weight:500">View Full Case &rarr;</a>
  </div>
  </div>
</div>
`))

var llmCaseTmpl = template.Must(template.New("llm-case").Funcs(tmplFuncs).Parse(layoutHead + `
<style>` + ciCSS + `
/* Case page overrides */
.cs-layout{display:grid;grid-template-columns:1fr 340px;gap:24px;align-items:start}
.cs-main{min-width:0}
.cs-side{display:flex;flex-direction:column;gap:16px}

/* Verdict banner */
.cs-banner{display:flex;align-items:stretch;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-xl);overflow:hidden;margin-bottom:var(--sp-6)}
.cs-banner-score{display:flex;flex-direction:column;align-items:center;justify-content:center;min-width:90px;padding:20px 16px;flex-shrink:0}
.cs-banner-score .n{font-size:2rem;font-weight:700;font-family:var(--mono);line-height:1;letter-spacing:-0.03em}
.cs-banner-score .l{font-size:0.56rem;letter-spacing:0.8px;margin-top:5px;font-weight:600;text-transform:uppercase}
.cs-banner-body{flex:1;padding:18px 22px;display:flex;flex-direction:column;justify-content:center;border-left:1px solid var(--border);min-width:0}
.cs-banner-title{font-size:1rem;font-weight:600;margin:0 0 8px;line-height:1.45;color:var(--text);text-wrap:pretty}
.cs-banner-meta{display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:0.75rem;color:var(--text3)}
.cs-banner-meta .sep{color:var(--border)}
.cs-banner-action{display:flex;align-items:center;padding:0 22px;flex-shrink:0;border-left:1px solid var(--border)}

/* Action buttons */
.cs-actions{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:20px}
.cs-abtn{display:inline-flex;align-items:center;gap:6px;padding:8px 18px;border-radius:8px;font-size:0.78rem;font-weight:500;cursor:pointer;border:1px solid;transition:background 0.15s,border-color 0.15s;text-decoration:none}
.cs-abtn-danger{background:rgba(239,68,68,0.08);color:#f85149;border-color:rgba(239,68,68,0.2)}
.cs-abtn-danger:hover{background:rgba(239,68,68,0.15);border-color:#f85149}
.cs-abtn-ghost{background:transparent;color:var(--text2);border-color:var(--border)}
.cs-abtn-ghost:hover{background:var(--surface2);border-color:var(--text3)}
.cs-abtn svg{width:14px;height:14px}
.cs-reviewed{display:inline-flex;align-items:center;gap:6px;padding:8px 18px;border-radius:8px;font-size:0.78rem;font-weight:600}
.cs-reviewed-ok{background:rgba(34,197,94,0.08);color:#3fb950}
.cs-reviewed-bad{background:rgba(239,68,68,0.08);color:#f85149}

/* Side panel cards */
.cs-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-xl);overflow:hidden}
.cs-card-hdr{padding:12px 16px;border-bottom:1px solid var(--border);font-size:0.68rem;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:0.6px}
.cs-card-body{padding:14px 16px}
.cs-row{display:flex;justify-content:space-between;align-items:baseline;padding:7px 0;border-bottom:1px solid rgba(255,255,255,0.04);font-size:0.78rem}
.cs-row:last-child{border-bottom:none}
.cs-row .k{color:var(--text3);font-size:0.75rem}
.cs-row .v{font-family:var(--mono);font-size:0.72rem;color:var(--text2);text-align:right}
.cs-conf-bar{height:4px;background:var(--surface2);border-radius:2px;margin-top:4px}
.cs-conf-fill{height:100%;border-radius:2px;transition:width 0.3s}

/* History pills in sidebar */
.cs-hist-grid{display:flex;flex-wrap:wrap;gap:4px;padding:4px 0}
.cs-hist-pill{display:inline-flex;align-items:center;gap:4px;padding:4px 10px;border-radius:6px;font-size:0.68rem;text-decoration:none;color:var(--text3);background:var(--surface2);transition:background 0.12s,color 0.12s}
.cs-hist-pill:hover{color:var(--text);background:var(--bg3)}
.cs-hist-score{font-family:var(--mono);font-weight:700;font-size:0.65rem}

/* Threat cards */
.cs-thr-card{border:1px solid var(--border);border-radius:10px;overflow:hidden;margin-bottom:12px}
.cs-thr-card:last-child{margin-bottom:0}
.cs-thr-top{display:flex;align-items:flex-start;gap:12px;padding:14px 18px}
.cs-thr-num{width:26px;height:26px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:0.68rem;font-weight:700;font-family:var(--mono);flex-shrink:0;margin-top:1px}
.cs-thr-num-c{background:var(--danger-muted);color:#f85149}
.cs-thr-num-h{background:var(--danger-muted);color:var(--danger)}
.cs-thr-num-m{background:rgba(210,153,34,0.1);color:#d29922}
.cs-thr-num-l{background:rgba(34,197,94,0.08);color:#3fb950}
.cs-thr-info{flex:1;min-width:0}
.cs-thr-type{font-family:var(--mono);font-size:0.72rem;font-weight:600;color:var(--text2);text-transform:uppercase;margin-bottom:3px}
.cs-thr-desc{font-size:0.82rem;color:var(--text);font-weight:500;line-height:1.5}
.cs-thr-ev{padding:var(--sp-3) var(--sp-5) var(--sp-4);background:rgba(255,255,255,0.015);border-top:1px solid var(--border);font-size:var(--text-sm);color:var(--text3);line-height:1.6;font-family:var(--mono)}
.cs-thr-rule{padding:var(--sp-2) var(--sp-5) var(--sp-3);border-top:1px solid var(--border);font-size:var(--text-sm);display:flex;align-items:center;gap:var(--sp-2);flex-wrap:wrap}

/* Intent diff */
.cs-intent{display:grid;grid-template-columns:1fr 1fr;gap:0;border:1px solid var(--border);border-radius:10px;overflow:hidden}
.cs-intent-side{padding:14px 18px}
.cs-intent-decl{border-right:1px solid var(--border)}
.cs-intent-act.cs-intent-warn{background:rgba(239,68,68,0.03)}
.cs-intent-lbl{font-size:0.58rem;font-weight:600;letter-spacing:0.6px;text-transform:uppercase;color:var(--text3);margin-bottom:8px;display:flex;align-items:center;gap:6px}
.cs-intent-lbl-warn{color:#f85149}
.cs-intent-txt{font-size:0.82rem;line-height:1.55;color:var(--text)}
.cs-intent-act .cs-intent-txt{font-weight:500}
.cs-intent-act.cs-intent-warn .cs-intent-txt{color:#f85149}

/* Evidence block */
.cs-evidence{background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:16px 18px;font-family:var(--mono);font-size:0.72rem;line-height:1.7;color:var(--text);white-space:pre-wrap;word-break:break-all;max-height:280px;overflow-y:auto}

/* Generated rule */
.cs-rule-block{background:var(--surface2);border:1px solid rgba(56,139,253,0.15);border-radius:10px;padding:14px 18px;font-family:var(--mono);font-size:0.72rem;line-height:1.7;color:var(--accent-light);white-space:pre-wrap}

@media(max-width:960px){.cs-layout{grid-template-columns:1fr}.cs-banner{flex-direction:column}.cs-banner-score{min-width:unset;padding:14px}.cs-banner-body{border-left:none;border-top:1px solid var(--border)}.cs-banner-action{border-left:none;border-top:1px solid var(--border);padding:14px 22px}.cs-intent{grid-template-columns:1fr}.cs-intent-decl{border-right:none;border-bottom:1px solid var(--border)}}
</style>

<p style="margin-bottom:18px"><a href="/dashboard/llm" class="ci-back">&larr; Threat Intel</a></p>

{{with .Analysis}}
<!-- Verdict banner -->
<div class="cs-banner">
  <div class="cs-banner-score" style="{{if ge .RiskScore 76.0}}background:rgba(239,68,68,0.08);color:#f85149{{else if ge .RiskScore 51.0}}background:var(--danger-muted);color:var(--danger){{else if ge .RiskScore 31.0}}background:rgba(210,153,34,0.06);color:#d29922{{else if gt .RiskScore 10.0}}background:rgba(34,197,94,0.06);color:#3fb950{{else}}background:var(--surface2);color:var(--text3){{end}}">
    <div class="n">{{printf "%.0f" .RiskScore}}</div>
    <div class="l">{{if ge .RiskScore 76.0}}CRITICAL{{else if ge .RiskScore 51.0}}HIGH{{else if ge .RiskScore 31.0}}MEDIUM{{else if gt .RiskScore 10.0}}LOW{{else}}BENIGN{{end}}</div>
  </div>
  <div class="cs-banner-body">
    <h2 class="cs-banner-title">{{firstThreatSummary .ThreatsJSON .RiskScore}}{{if and (gt .Confidence 0.0) (lt .Confidence 30.0)}} <span title="The LLM had limited context for this analysis. Risk score is based on deterministic rule matches, not LLM certainty." style="font-size:var(--text-xs);color:var(--warn);font-weight:500;cursor:help">&#9888; Low confidence (limited context)</span>{{end}}</h2>
    <div class="cs-banner-meta">
      {{if .FromAgent}}<a href="/dashboard/agents/{{.FromAgent}}" style="color:var(--accent-light);text-decoration:none;font-weight:500">{{.FromAgent}}</a> <span style="opacity:0.5">&rarr;</span> <a href="/dashboard/agents/{{.ToAgent}}" style="color:var(--text2);text-decoration:none">{{.ToAgent}}</a><span class="sep">&middot;</span>{{end}}
      <span>{{relativeTime .Timestamp}}</span>
      <span class="sep">&middot;</span>
      <span>{{printf "%.0f" .Confidence}}% confidence</span>
    </div>
  </div>
  <div class="cs-banner-action">
    <span class="ci-badge {{if eq .RecommendedAction "block"}}ci-badge-blk{{else if eq .RecommendedAction "investigate"}}ci-badge-inv{{else if eq .RecommendedAction "quarantine"}}ci-badge-qua{{else}}ci-badge-ok{{end}}" style="font-size:0.75rem;padding:6px 18px">{{.RecommendedAction}}</span>
  </div>
</div>

<!-- Action buttons -->
<div class="cs-actions">
  {{if or (eq .ReviewedStatus "false_positive") (eq .ReviewedStatus "confirmed")}}
    {{if eq .ReviewedStatus "false_positive"}}<span class="cs-reviewed cs-reviewed-ok">&#10003; Dismissed as false positive</span>
    {{else}}<span class="cs-reviewed cs-reviewed-bad">&#10003; Confirmed as real threat</span>{{end}}
  {{else}}
    <button class="cs-abtn cs-abtn-danger" hx-post="/dashboard/api/llm/{{.ID}}/confirm" hx-target="closest .cs-actions" hx-swap="innerHTML" hx-confirm="Confirm this as a real threat?"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg> Confirm threat</button>
    <button class="cs-abtn cs-abtn-ghost" hx-post="/dashboard/api/llm/{{.ID}}/dismiss" hx-target="closest .cs-actions" hx-swap="innerHTML" hx-confirm="Dismiss as false positive?">False positive</button>
    {{if and .FromAgent (not $.AgentSuspended)}}<form method="POST" action="/dashboard/agents/{{.FromAgent}}/suspend" style="display:contents"><button type="submit" class="cs-abtn cs-abtn-ghost" style="color:#f85149;border-color:rgba(239,68,68,0.2)" onclick="return confirm('Suspend agent {{.FromAgent}}?')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg> Suspend agent</button></form>{{end}}
    {{if $.AgentSuspended}}<span class="cs-abtn" style="color:#f85149;cursor:default;border-color:rgba(239,68,68,0.2)">Agent suspended</span>{{end}}
  {{end}}
</div>

<!-- Two-column layout -->
<div class="cs-layout">
  <!-- LEFT: Main content -->
  <div class="cs-main">

    <!-- Findings -->
    {{$threats := parseJSONArray .ThreatsJSON}}
    <div class="ci-s">
      <h3>Findings <span class="cnt">({{countJSONArray .ThreatsJSON}})</span></h3>
      {{if $threats}}
        {{range $i, $t := $threats}}
          {{$m := toMap $t}}
          {{if $m}}
          <div class="cs-thr-card">
            <div class="cs-thr-top">
              <span class="cs-thr-num {{with index $m "severity"}}cs-thr-num-{{if eq (toString .) "critical"}}c{{else if eq (toString .) "high"}}h{{else if eq (toString .) "medium"}}m{{else}}l{{end}}{{end}}">{{inc $i}}</span>
              <div class="cs-thr-info">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
                  <span class="cs-thr-type">{{with index $m "type"}}{{upper (toString .)}}{{else}}THREAT-{{inc $i}}{{end}}</span>
                  {{with index $m "severity"}}<span class="ci-sev ci-sev-{{if eq (toString .) "critical"}}c{{else if eq (toString .) "high"}}h{{else if eq (toString .) "medium"}}m{{else}}l{{end}}">{{upper (toString .)}}</span>{{end}}
                </div>
                <div class="cs-thr-desc">{{with index $m "description"}}{{.}}{{end}}</div>
              </div>
            </div>
            {{with index $m "evidence"}}<div class="cs-thr-ev">{{.}}</div>{{end}}
            {{with index $m "suggestion"}}{{$s := toMap .}}{{if $s}}
            <div class="cs-thr-rule">
              <span style="color:var(--text3);font-size:var(--text-xs)">Suggested rule:</span>
              <code>{{with index $s "name"}}{{.}}{{end}}</code>
              {{with index $s "pattern"}}<code style="color:var(--text3);font-size:var(--text-xs)">{{.}}</code>{{end}}
              <button class="a-cp" onclick="ciCopyText(this.closest('.cs-thr-rule').querySelector('code').textContent,this)">copy</button>
            </div>
            {{end}}{{end}}
          </div>
          {{else}}
          <div class="cs-thr-card"><div class="cs-thr-top"><span class="cs-thr-num cs-thr-num-m">{{inc $i}}</span><div class="cs-thr-info"><div class="cs-thr-desc">{{$t}}</div></div></div></div>
          {{end}}
        {{end}}
      {{else}}
      <div class="ci-benign">
        <svg aria-hidden="true" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
        No threats detected - message assessed as benign.
      </div>
      {{end}}
    </div>

    <!-- Intent Analysis -->
    {{$intent := parseJSONMap .IntentJSON}}
    {{if $intent}}
    <div class="ci-s">
      <h3>Intent Analysis {{with index $intent "alignment"}}{{$a := toString .}}<span style="display:inline-flex;align-items:center;gap:4px;font-family:var(--mono);font-size:0.72rem;font-weight:600;padding:2px 10px;border-radius:100px;{{if lt $a "0.5"}}background:rgba(239,68,68,0.1);color:#f85149{{else}}background:rgba(34,197,94,0.1);color:#3fb950{{end}}">{{if lt $a "0.5"}}&#10007;{{else}}&#10003;{{end}} {{$a}}</span>{{end}}</h3>
      <div class="cs-intent">
        <div class="cs-intent-side cs-intent-decl">
          <div class="cs-intent-lbl">Declared intent</div>
          <div class="cs-intent-txt">{{with index $intent "declared_intent"}}{{.}}{{else}}-{{end}}</div>
        </div>
        <div class="cs-intent-side cs-intent-act{{if ge $.Analysis.RiskScore 50.0}} cs-intent-warn{{end}}">
          <div class="cs-intent-lbl{{if ge $.Analysis.RiskScore 50.0}} cs-intent-lbl-warn{{end}}">Actual behavior</div>
          <div class="cs-intent-txt">{{with index $intent "actual_intent"}}{{.}}{{else}}-{{end}}</div>
        </div>
      </div>
      {{with index $intent "reason"}}
      <p style="font-size:0.75rem;line-height:1.55;color:var(--text3);margin-top:10px">{{.}}</p>
      {{end}}
    </div>
    {{end}}

    <!-- Intercepted content -->
    {{if $.ToolArgs}}
    <div class="ci-s">
      <h3>Intercepted Content</h3>
      <div class="cs-evidence">{{$.ToolArgs}}</div>
    </div>
    {{end}}

    <!-- Generated Rule -->
    {{if .RuleGenerated}}
    <div class="ci-s" style="border-color:rgba(56,139,253,0.15)">
      <h3 style="color:var(--accent-light)">Generated Rule</h3>
      <p style="font-size:0.78rem;color:var(--text2);margin-bottom:10px">Deterministic rule created from this analysis. Catches future matches in &lt;1ms.</p>
      <div class="cs-rule-block">{{.RuleGenerated}}</div>
    </div>
    {{end}}

  </div>

  <!-- RIGHT: Sidebar -->
  <div class="cs-side">

    <!-- Assessment card -->
    <div class="cs-card">
      <div class="cs-card-hdr">Assessment</div>
      <div class="cs-card-body">
        <div class="cs-row"><span class="k">Risk score</span><span class="v" style="font-weight:700;font-size:0.82rem;{{if ge .RiskScore 76.0}}color:#f85149{{else if ge .RiskScore 51.0}}color:var(--danger){{else if ge .RiskScore 31.0}}color:#d29922{{else}}color:#3fb950{{end}}">{{printf "%.0f" .RiskScore}}</span></div>
        <div class="cs-row">
          <span class="k">Confidence</span>
          <span class="v">{{printf "%.0f" .Confidence}}%</span>
        </div>
        <div class="cs-conf-bar"><div class="cs-conf-fill" style="width:{{printf "%.0f" .Confidence}}%;background:{{if ge .Confidence 80.0}}#3fb950{{else if ge .Confidence 50.0}}#d29922{{else}}#f85149{{end}}"></div></div>
        {{if lt .Confidence 30.0}}<div style="font-size:0.68rem;color:var(--text3);margin-top:4px">Risk score is from rule matches. Low confidence means the LLM had limited context.</div>{{end}}
        <div class="cs-row" style="margin-top:6px"><span class="k">Latency</span><span class="v">{{latencySec .LatencyMs}}s</span></div>
        <div class="cs-row"><span class="k">Model</span><span class="v" style="font-size:0.68rem">{{.Model}}</span></div>
        <div class="cs-row"><span class="k">Tokens</span><span class="v">{{.TokensUsed}}</span></div>
      </div>
    </div>

    <!-- Quick links -->
    <div class="cs-card">
      <div class="cs-card-hdr">Related</div>
      <div class="cs-card-body" style="display:flex;flex-direction:column;gap:2px">
        {{if .FromAgent}}<a href="/dashboard/agents/{{.FromAgent}}" class="cs-row" style="text-decoration:none;color:inherit;border-radius:6px;padding:8px 10px;margin:-4px -10px;transition:background 0.1s"><span class="k">Agent</span><span class="v" style="color:var(--accent-light)">{{.FromAgent}}</span></a>{{end}}
        <a href="/dashboard/events?q={{.MessageID}}" class="cs-row" style="text-decoration:none;color:inherit;border-radius:6px;padding:8px 10px;margin:-4px -10px;transition:background 0.1s"><span class="k">Event</span><span class="v" style="color:var(--accent-light)">View &rarr;</span></a>
        <div class="cs-row"><span class="k">Message ID</span><span class="v" style="font-size:0.58rem;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{{.MessageID}}">{{.MessageID}}</span></div>
      </div>
    </div>

    <!-- Agent history -->
    {{if $.AgentHistory}}
    <div class="cs-card">
      <div class="cs-card-hdr">Agent History ({{.FromAgent}})</div>
      <div class="cs-card-body">
        <div class="cs-hist-grid">
          {{range $.AgentHistory}}
          <a href="/dashboard/llm/case/{{.ID}}" class="cs-hist-pill">
            <span class="cs-hist-score" style="{{if ge .RiskScore 76.0}}color:#f85149{{else if ge .RiskScore 51.0}}color:var(--danger){{else if ge .RiskScore 31.0}}color:#d29922{{else}}color:var(--text3){{end}}">{{printf "%.0f" .RiskScore}}</span>
            <span>{{relativeTime .Timestamp}}</span>
          </a>
          {{end}}
        </div>
      </div>
    </div>
    {{end}}

  </div>
</div>

<script>
function ciCopyText(text, btn) {
  navigator.clipboard.writeText(text).then(function() {
    var orig = btn.textContent;
    btn.textContent = 'copied';
    btn.style.color = 'var(--success)';
    setTimeout(function() { btn.textContent = orig; btn.style.color = ''; }, 1200);
  });
}
</script>
{{end}}
` + layoutFoot))
