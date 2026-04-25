package dashboard

import "html/template"

var graphTmpl = template.Must(template.New("graph").Funcs(tmplFuncs).Parse(layoutHead + `
<p class="page-desc">Visual map of how your AI agents communicate and which tools they use. Red nodes indicate high risk. Dashed lines are unmonitored routes.</p>

<div style="display:flex;gap:8px;margin-bottom:16px">
  {{range $v := .Ranges}}<a href="/dashboard/graph?range={{$v}}" class="btn btn-sm{{if eq $v $.Range}} active{{end}}" style="{{if eq $v $.Range}}background:#1F6FEB;color:#fff;border:none{{else}}background:transparent;color:#8B949E;border:1px solid #30363D{{end}}">{{$v}}</a>{{end}}
</div>

<div class="stats">
  <div class="stat"><div class="label">Agents</div><div class="value">{{.Graph.TotalNodes}}</div></div>
  <div class="stat"><div class="label" data-tooltip="Connections with observed traffic between agents">Active Connections</div><div class="value">{{.Graph.TotalEdges}}</div></div>
  <div class="stat"><div class="label" data-tooltip="Traffic between agents not covered by any security rule">Unmonitored Routes</div><div class="value{{if .Graph.ShadowEdges}} warn{{end}}">{{len .Graph.ShadowEdges}}</div></div>
  <div class="stat"><div class="label" data-tooltip="Security rules with no observed traffic — consider tightening permissions">Unused Rules</div><div class="value{{if .Graph.UnusedACL}} warn{{end}}">{{len .Graph.UnusedACL}}</div></div>
</div>

{{if and .Graph.ShadowEdges .RequireSig}}
<div class="alert-banner warn">
  <strong>{{len .Graph.ShadowEdges}} connection{{if gt (len .Graph.ShadowEdges) 1}}s{{end}} are not covered by any security rule.</strong> <a href="/dashboard/agents" style="color:inherit;text-decoration:underline">Review agents &rarr;</a>
</div>
{{end}}

<div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap">
  <button class="btn btn-sm active" id="gf-all" onclick="gfApply('all')" style="font-size:0.72rem">All routes</button>
  <button class="btn btn-sm" id="gf-risky" onclick="gfApply('risky')" style="font-size:0.72rem;background:transparent;border:1px solid var(--border);color:var(--text3)">Risky routes</button>
  <button class="btn btn-sm" id="gf-blocked" onclick="gfApply('blocked')" style="font-size:0.72rem;background:transparent;border:1px solid var(--border);color:var(--text3)">Blocked routes</button>
  <button class="btn btn-sm" id="gf-unmonitored" onclick="gfApply('unmonitored')" style="font-size:0.72rem;background:transparent;border:1px solid var(--border);color:var(--text3)">Unmonitored</button>
</div>

<div class="card" style="padding:0;overflow:hidden">
  <div style="display:flex;min-height:560px;height:calc(100vh - 340px)">
    <div style="flex:1;position:relative;overflow:hidden">
      <div id="graph-container" style="width:100%;height:100%;background:var(--bg);position:relative;overflow:hidden"><p style="color:var(--text3);text-align:center;padding-top:200px">Loading graph&#8230;</p></div>
      <div style="position:absolute;bottom:12px;left:16px;display:flex;gap:16px;font-size:0.7rem;color:var(--text3);align-items:center">
        <span><svg width="18" height="10"><line x1="0" y1="5" x2="18" y2="5" stroke="#5eead4" stroke-width="2"/></svg> Orchestration</span>
        <span><svg width="18" height="10"><line x1="0" y1="5" x2="18" y2="5" stroke="#bc8cff" stroke-width="1" stroke-dasharray="3 3" stroke-opacity="0.5"/></svg> Tool call</span>
        <button id="graph-sidebar-expand" onclick="toggleGraphSidebar()" style="display:none;background:var(--surface2);border:1px solid var(--border);border-radius:4px;color:var(--text3);cursor:pointer;padding:2px 8px;font-size:0.7rem;margin-left:auto">Overview ›</button>
      </div>
    </div>
    <div id="graph-sidebar" style="width:340px;border-left:1px solid var(--border);background:var(--surface2);flex-shrink:0;overflow-y:auto;font-size:0.8rem;transition:width 0.2s,opacity 0.2s">
      <div style="padding:16px 20px;border-bottom:1px solid var(--border)">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <h3 style="font-size:0.95rem;font-weight:700;margin:0">Overview</h3>
          <button onclick="toggleGraphSidebar()" style="background:none;border:1px solid var(--border);border-radius:4px;color:var(--text3);cursor:pointer;padding:2px 6px;font-size:0.7rem" title="Collapse panel">✕</button>
        </div>
        <div id="gw-stats">
          <div style="display:flex;justify-content:space-between;padding:7px 10px;border:1px solid var(--border);border-radius:6px;margin-bottom:4px"><span style="color:var(--text3)">Agents</span><span id="gs-agents" style="font-weight:700;font-family:var(--mono)">--</span></div>
          <div style="display:flex;justify-content:space-between;padding:7px 10px;border:1px solid var(--border);border-radius:6px;margin-bottom:4px"><span style="color:var(--text3)">Tools</span><span id="gs-tools" style="font-weight:700;font-family:var(--mono)">--</span></div>
          <div style="display:flex;justify-content:space-between;padding:7px 10px;border:1px solid var(--border);border-radius:6px;margin-bottom:4px"><span style="color:var(--text3)">Messages scanned</span><span id="gs-messages" style="font-weight:700;font-family:var(--mono)">--</span></div>
          <div style="display:flex;justify-content:space-between;padding:7px 10px;border:1px solid var(--border);border-radius:6px;margin-bottom:4px"><span style="color:var(--text3)">Policy blocks</span><span id="gs-blocks" style="font-weight:700;font-family:var(--mono);color:#f85149">--</span></div>
        </div>
      </div>
      <div style="padding:16px 20px;border-bottom:1px solid var(--border)">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
          <h3 style="font-size:0.85rem;font-weight:700;margin:0">Events</h3>
          <span id="gw-event-count" style="font-size:0.7rem;color:var(--text3)"></span>
        </div>
        <div id="gw-events" style="font-size:0.75rem;font-family:var(--mono)"></div>
      </div>
      {{if .RiskyRoutes}}
      <div style="padding:16px 20px;border-bottom:1px solid var(--border)">
        <h3 style="font-size:0.85rem;font-weight:700;margin:0 0 10px 0;color:var(--warn)">Top Risky Routes</h3>
        {{range .RiskyRoutes}}
        <div style="display:flex;justify-content:space-between;align-items:center;padding:6px 10px;border:1px solid var(--border);border-radius:6px;margin-bottom:4px">
          <span style="font-size:0.72rem;font-family:var(--mono)">{{.From}} &rarr; {{.To}}</span>
          <span style="font-size:0.72rem;font-weight:700;font-family:var(--mono);color:{{if lt .HealthScore 40.0}}var(--danger){{else}}var(--warn){{end}}">{{printf "%.0f" .HealthScore}}%</span>
        </div>
        {{end}}
      </div>
      {{end}}
    </div>
  </div>
</div>

<h3 style="font-size:0.95rem;font-weight:700;margin:24px 0 16px 0;color:var(--text)">Agent &amp; Connection Details</h3>
<div id="graph-tables">
<div class="grid-2" style="gap:20px">
  <div class="card">
    <h2>Agent Risk Scores</h2>
    <p style="color:var(--text3);font-size:0.78rem;margin-bottom:4px">Higher scores mean more blocked or quarantined messages originating from this agent.</p>
    <div style="font-size:0.68rem;color:var(--text3);margin-bottom:12px">Scale 0&ndash;100. <span style="color:var(--success)">&#9679;</span> Low &middot; <span style="color:var(--warn)">&#9679;</span> Medium &middot; <span style="color:var(--danger)">&#9679;</span> High</div>
    {{if .Graph.Nodes}}
    <table>
      <thead><tr><th>Agent</th><th data-tooltip="Score based on ratio of blocked and quarantined messages">Risk</th><th>Sent</th><th data-tooltip="Messages received by this agent">Received</th><th data-tooltip="Agent's role in the communication network based on traffic patterns">Role</th></tr></thead>
      <tbody>
      {{range .Graph.Nodes}}
      <tr class="clickable" onclick="location.href='/dashboard/agents/{{.Name}}'">
        <td style="font-weight:600"><a href="/dashboard/agents/{{.Name}}" style="color:inherit;text-decoration:none">{{agentCell .Name}}</a></td>
        <td>
          <div style="display:flex;align-items:center;gap:8px">
            <div class="risk-bar" style="width:60px">
              <div class="risk-bar-fill {{if gt .ThreatScore 60.0}}risk-high{{else if gt .ThreatScore 30.0}}risk-med{{else}}risk-low{{end}}" style="width:{{printf "%.0f" .ThreatScore}}%"></div>
            </div>
            <span>{{printf "%.1f" .ThreatScore}}</span>
          </div>
        </td>
        <td>{{.TotalSent}}</td>
        <td>{{.TotalRecv}}</td>
        <td style="color:var(--text3)">{{if eq .Betweenness -1.0}}—{{else if gt .Betweenness 0.3}}Hub{{else if and (gt .TotalSent 0) (eq .TotalRecv 0)}}Sender{{else if and (eq .TotalSent 0) (gt .TotalRecv 0)}}Receiver{{else}}Peer{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">No agents detected in this time range</p>{{end}}
  </div>

  <div class="card">
    <h2>Connection Health</h2>
    <p style="color:var(--text3);font-size:0.78rem;margin-bottom:12px">Percentage of messages successfully delivered on each route.</p>
    {{if .Graph.Edges}}
    <table>
      <thead><tr><th>From</th><th>To</th><th data-tooltip="Ratio of delivered messages to total — lower scores indicate more blocked or quarantined traffic">Health</th></tr></thead>
      <tbody>
      {{range .Graph.Edges}}
      <tr class="clickable ch-row" data-health="{{printf "%.0f" .HealthScore}}" data-blocked="{{.Blocked}}" data-quarantined="{{.Quarantined}}" hx-get="/dashboard/api/graph/edge?from={{.From}}&amp;to={{.To}}&amp;range={{$.Range}}" hx-target="#panel-content" hx-swap="innerHTML">
        <td>{{.From}}</td>
        <td>{{.To}}</td>
        <td>
          <div style="display:flex;align-items:center;gap:8px">
            <div class="risk-bar" style="width:60px">
              <div class="risk-bar-fill {{if lt .HealthScore 40.0}}risk-high{{else if lt .HealthScore 70.0}}risk-med{{else}}risk-low{{end}}" style="width:{{printf "%.0f" .HealthScore}}%"></div>
            </div>
            <span>{{printf "%.0f" .HealthScore}}%</span>
          </div>
        </td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">No traffic in this time range</p>{{end}}
  </div>
</div>

{{if .Graph.ShadowEdges}}
<div class="card" id="unmonitored-section">
  <h2 style="color:var(--warn)">Unmonitored Routes</h2>
  <p style="color:var(--text2);font-size:0.82rem;margin-bottom:12px">Traffic between agents not covered by any security rule.</p>
  <table>
    <thead><tr><th>From</th><th>To</th><th>Messages</th><th></th></tr></thead>
    <tbody>
    {{range .Graph.ShadowEdges}}
    <tr><td>{{.From}}</td><td>{{.To}}</td><td>{{.Total}}</td><td style="text-align:right"><a href="/dashboard/agents" style="color:var(--accent-light);font-size:0.75rem;text-decoration:none">Add rule &rarr;</a></td></tr>
    {{end}}
    </tbody>
  </table>
</div>
{{end}}

{{if .Graph.UnusedACL}}
<div class="card">
  <h2>Unused ACL Permissions</h2>
  <p style="color:var(--text2);font-size:0.82rem;margin-bottom:12px">ACL entries with no observed traffic. Consider tightening permissions.</p>
  <table>
    <thead><tr><th>From</th><th>To</th><th>Status</th></tr></thead>
    <tbody id="acl-tbody">
    {{range .Graph.UnusedACL}}
    <tr class="acl-row"><td>{{.From}}</td><td>{{.To}}</td><td><span style="color:var(--text3)">no traffic</span></td></tr>
    {{end}}
    </tbody>
  </table>
  {{if gt (len .Graph.UnusedACL) 10}}
  <button id="acl-toggle" onclick="(function(){var rows=document.querySelectorAll('.acl-row');var btn=document.getElementById('acl-toggle');if(btn.dataset.open==='1'){rows.forEach(function(r,i){r.style.display=i>=10?'none':''});btn.textContent='Show all ('+rows.length+')';btn.dataset.open='0'}else{rows.forEach(function(r){r.style.display=''});btn.textContent='Show less';btn.dataset.open='1'}})()" data-open="0" style="margin-top:8px;background:none;border:1px solid var(--border);color:var(--accent-light);padding:6px 16px;border-radius:6px;cursor:pointer;font-size:0.78rem">Show all ({{len .Graph.UnusedACL}})</button>
  <script>document.querySelectorAll('.acl-row').forEach(function(r,i){if(i>=10)r.style.display='none'});</script>
  {{end}}
</div>
{{end}}
</div><!-- end graph-tables -->

<script>
var _graphFilter='all';
function gfApply(f){
  _graphFilter=f;
  document.querySelectorAll('[id^="gf-"]').forEach(function(btn){
    var id=btn.id.replace('gf-','');
    if(id===f){btn.classList.add('active');btn.style.background='';btn.style.border='';btn.style.color='';}
    else{btn.classList.remove('active');btn.style.background='transparent';btn.style.border='1px solid var(--border)';btn.style.color='var(--text3)';}
  });
  _applyGraphFilter();
}
function _applyGraphFilter(){
  document.querySelectorAll('.ch-row').forEach(function(row){
    var health=parseFloat(row.getAttribute('data-health')||'100');
    var blocked=parseInt(row.getAttribute('data-blocked')||'0',10);
    var quarantined=parseInt(row.getAttribute('data-quarantined')||'0',10);
    var show=true;
    if(_graphFilter==='risky') show=health<70||blocked>0||quarantined>0;
    else if(_graphFilter==='blocked') show=blocked>0;
    else if(_graphFilter==='unmonitored') show=false;
    row.style.display=show?'':'none';
  });
  var unm=document.getElementById('unmonitored-section');
  if(unm) unm.style.display=(_graphFilter==='blocked'||_graphFilter==='risky')?'none':'';
}
</script>
<script>
function toggleGraphSidebar() {
  var sb = document.getElementById('graph-sidebar');
  var btn = document.getElementById('graph-sidebar-expand');
  if (sb.style.display === 'none') {
    sb.style.display = '';
    btn.style.display = 'none';
  } else {
    sb.style.display = 'none';
    btn.style.display = '';
  }
}
(function() {
  var container = document.getElementById('graph-container');
  if (!container) return;

  fetch('/dashboard/api/graph?range={{.Range}}',{credentials:'same-origin',cache:'no-store'})
    .then(function(r){
      if(!r.ok) throw new Error('HTTP '+r.status);
      return r.json();
    })
    .then(function(data) { renderGraph(container, data); })
    .catch(function(err){
      console.error('graph fetch failed:',err);
      container.innerHTML='<p style="color:var(--text3);text-align:center;padding-top:200px">Failed to load graph data</p>';
    });

  function renderGraph(el, data) {
    if (!data || !data.nodes || data.nodes.length === 0) {
      el.innerHTML = '<p style="color:var(--text3);text-align:center;padding-top:200px">No traffic in selected range</p>';
      return;
    }

    var W = el.clientWidth, H = el.clientHeight;
    var NR = 22, OR = 30, TR = 12, PAD = 50;
    var cx = W / 2, cy = H / 2;
    // 3-column layout: ORCHESTRATOR | AGENTS | TOOLS
    // Agent sub-columns expand when there are many agents
    var agentCols = 1;
    var totalAgents = (data.nodes||[]).filter(function(n){return !n.is_tool && !n.is_orch && n.name!=='gateway';}).length;
    if (totalAgents > 12) agentCols = 3;
    else if (totalAgents > 6) agentCols = 2;

    var COL1 = W * 0.10; // orchestrator
    var COL_GW = W * 0.22; // gateway checkpoint
    var agentZoneStart = W * 0.36;
    var agentZoneEnd = W * 0.68;
    var COL2 = (agentZoneStart + agentZoneEnd) / 2; // center (used for header)
    var COL3 = W * 0.82; // tools
    var NS = 'http://www.w3.org/2000/svg';

    // ── Build edge latency map from raw data ──
    var latencyMap = {};
    (data.edges || []).forEach(function(e) {
      latencyMap[e.from+'>'+e.to] = e.avg_latency_ms || 0;
    });

    // ── Build node + link arrays ──
    var nodes = data.nodes.map(function(n) {
      return {name:n.name, isTool:false, isOrch:n.name==='claude-code', threat:n.threat_score, sent:n.total_sent||0, recv:n.total_recv||0, betweenness:n.betweenness!=null?n.betweenness:-1, x:cx, y:cy, _g:null};
    });
    var nodeIdx = {};
    nodes.forEach(function(n,i){ nodeIdx[n.name]=i; });

    var links = (data.edges||[]).filter(function(e){
      return nodeIdx[e.from]!==undefined && nodeIdx[e.to]!==undefined;
    }).map(function(e){
      return {from:nodeIdx[e.from], to:nodeIdx[e.to], health:e.health_score, total:e.total, latency:e.avg_latency_ms||0, fromName:e.from, toName:e.to, isTool:false};
    });

    (data.tool_nodes||[]).forEach(function(tn){
      nodeIdx[tn.name]=nodes.length;
      nodes.push({name:tn.name, isTool:true, isOrch:false, toolTotal:tn.total, threat:0, sent:0, recv:0, betweenness:-1, x:cx, y:cy, _g:null});
    });
    (data.tool_edges||[]).forEach(function(te){
      var ai=nodeIdx[te.agent], ti=nodeIdx[te.tool];
      if(ai!==undefined&&ti!==undefined) links.push({from:ai, to:ti, health:100, total:te.total, latency:0, fromName:te.agent, toName:te.tool, isTool:true});
    });

    // ── Columnar layout: ORCHESTRATOR → AGENTS → TOOLS ──
    // Separate agents from gateway
    var agentNodes=[], gwIdx=-1;
    nodes.forEach(function(n,i){
      if(n.isOrch) return;
      if(n.isTool) return;
      if(n.name==='gateway'){ gwIdx=i; return; }
      agentNodes.push(i);
    });

    // Position orchestrator (column 1)
    if(nodeIdx['claude-code']!==undefined){
      nodes[nodeIdx['claude-code']].x=COL1;
      nodes[nodeIdx['claude-code']].y=H*0.50;
    }
    // Position gateway checkpoint (between col 1 and col 2)
    if(gwIdx>=0){
      nodes[gwIdx].x=COL_GW;
      nodes[gwIdx].y=H*0.50;
    }
    // Position agents in sub-columns (1, 2, or 3 cols depending on count)
    var perCol=Math.ceil(agentNodes.length/agentCols);
    var subColWidth=(agentZoneEnd-agentZoneStart)/(agentCols);
    agentNodes.forEach(function(idx,i){
      var col=Math.floor(i/perCol);
      var row=i%perCol;
      var colCount=Math.min(perCol, agentNodes.length-col*perCol);
      var spacing=Math.min(90, (H-PAD*2)/(colCount+1));
      var startY=(H-(colCount-1)*spacing)/2;
      nodes[idx].x=agentZoneStart+subColWidth*(col+0.5);
      nodes[idx].y=startY+row*spacing;
    });
    // Position tool nodes vertically in column 3
    var toolNodes=[];
    nodes.forEach(function(n,i){ if(n.isTool) toolNodes.push(i); });
    var toolSpacing=Math.min(60, (H-PAD*2)/(toolNodes.length+1));
    var toolStartY=(H-(toolNodes.length-1)*toolSpacing)/2;
    toolNodes.forEach(function(idx,i){
      nodes[idx].x=COL3;
      nodes[idx].y=toolStartY+i*toolSpacing;
    });
    function nodeRadius(n){return n.isTool?TR+4:(n.isOrch?OR+4:NR+4);}

    // ── SVG setup ──
    var svg=document.createElementNS(NS,'svg');
    svg.setAttribute('width',W); svg.setAttribute('height',H);
    svg.setAttribute('viewBox','0 0 '+W+' '+H);
    svg.style.width='100%'; svg.style.height='100%';

    var defs=document.createElementNS(NS,'defs');
    var edgeColors={ok:'#5eead4',warn:'#d29922',bad:'#f85149'};
    ['ok','warn','bad'].forEach(function(k){
      var m=document.createElementNS(NS,'marker');
      m.setAttribute('id','arr-'+k); m.setAttribute('viewBox','0 0 8 6');
      m.setAttribute('refX','8'); m.setAttribute('refY','3');
      m.setAttribute('markerWidth','6'); m.setAttribute('markerHeight','5');
      m.setAttribute('orient','auto');
      var p=document.createElementNS(NS,'path');
      p.setAttribute('d','M0,0.5 L7,3 L0,5.5'); p.setAttribute('fill',edgeColors[k]);
      m.appendChild(p); defs.appendChild(m);
    });
    // Glow filter
    var glow=document.createElementNS(NS,'filter');
    glow.setAttribute('id','glow'); glow.setAttribute('x','-50%'); glow.setAttribute('y','-50%');
    glow.setAttribute('width','200%'); glow.setAttribute('height','200%');
    var gb=document.createElementNS(NS,'feGaussianBlur'); gb.setAttribute('stdDeviation','4'); gb.setAttribute('result','blur');
    glow.appendChild(gb);
    var fm=document.createElementNS(NS,'feMerge');
    var mn1=document.createElementNS(NS,'feMergeNode'); mn1.setAttribute('in','blur');
    var mn2=document.createElementNS(NS,'feMergeNode'); mn2.setAttribute('in','SourceGraphic');
    fm.appendChild(mn1); fm.appendChild(mn2); glow.appendChild(fm); defs.appendChild(glow);
    // Orchestrator gradient
    var orchGrad=document.createElementNS(NS,'radialGradient'); orchGrad.setAttribute('id','orchFill');
    var s1=document.createElementNS(NS,'stop'); s1.setAttribute('offset','0%'); s1.setAttribute('stop-color','#bc8cff'); s1.setAttribute('stop-opacity','0.25');
    var s2=document.createElementNS(NS,'stop'); s2.setAttribute('offset','100%'); s2.setAttribute('stop-color','#8b5cf6'); s2.setAttribute('stop-opacity','0.08');
    orchGrad.appendChild(s1); orchGrad.appendChild(s2); defs.appendChild(orchGrad);
    svg.appendChild(defs);

    var style=document.createElementNS(NS,'style');
    style.textContent='@keyframes orchPulse{0%,100%{opacity:0.7}50%{opacity:1}}.orch-hex{animation:orchPulse 3s ease-in-out infinite}.graph-dim{opacity:0.18!important;transition:opacity 0.3s}.graph-bright{opacity:1!important;transition:opacity 0.3s}';
    svg.appendChild(style);

    // Column headers
    var headerFont='font-size:9px;fill:#52525b;font-family:ui-monospace,SFMono-Regular,monospace;letter-spacing:0.08em';
    ['SOURCE','AGENTS','TOOLS'].forEach(function(label,ci){
      var hx=[COL1,COL2,COL3][ci];
      var ht=document.createElementNS(NS,'text');
      ht.setAttribute('x',hx); ht.setAttribute('y',24);
      ht.setAttribute('text-anchor','middle');
      ht.setAttribute('style',headerFont);
      ht.textContent=label;
      svg.appendChild(ht);
    });

    // Column separator lines
    [COL_GW+(agentZoneStart-COL_GW)*0.5, agentZoneEnd+(COL3-agentZoneEnd)*0.5].forEach(function(sx){
      var sep=document.createElementNS(NS,'line');
      sep.setAttribute('x1',sx); sep.setAttribute('y1',38);
      sep.setAttribute('x2',sx); sep.setAttribute('y2',H-10);
      sep.setAttribute('stroke','#2a2a2e'); sep.setAttribute('stroke-width','1');
      sep.setAttribute('stroke-dasharray','2 4');
      svg.appendChild(sep);
    });

    // ── Edges ──
    var lineEls=[], particles=[];
    var edgePairs={};
    links.forEach(function(e){ var key=Math.min(e.from,e.to)+'-'+Math.max(e.from,e.to); edgePairs[key]=(edgePairs[key]||0)+1; });
    var edgePairCount={};
    var maxTotal=1;
    links.forEach(function(e){ if(!e.isTool&&e.total>maxTotal) maxTotal=e.total; });

    links.forEach(function(e){
      var hk, strokeColor, baseW, co=0;

      if(e.isTool){
        // Tool edges: dashed purple lines
        hk='ok'; strokeColor='#bc8cff'; baseW=1.2;
      } else {
        hk=e.health>=70?'ok':(e.health>=40?'warn':'bad');
        strokeColor=edgeColors[hk];
        var key=Math.min(e.from,e.to)+'-'+Math.max(e.from,e.to);
        var pairTotal=edgePairs[key]||1;
        edgePairCount[key]=(edgePairCount[key]||0)+1;
        if(pairTotal>1) co=(edgePairCount[key]%2===0?1:-1)*18;
        baseW=Math.min(3,0.8+(e.total/maxTotal)*2.2);
      }

      var lineEl;
      if(co!==0){ lineEl=document.createElementNS(NS,'path'); lineEl.setAttribute('fill','none'); }
      else { lineEl=document.createElementNS(NS,'line'); }
      lineEl.setAttribute('stroke',strokeColor);
      lineEl.setAttribute('stroke-width',baseW);
      lineEl.setAttribute('stroke-opacity',e.isTool?'0.5':'0.4');
      if(e.isTool) lineEl.setAttribute('stroke-dasharray','4 3');
      if(!e.isTool) lineEl.setAttribute('marker-end','url(#arr-'+hk+')');
      lineEl.style.cursor='pointer';
      lineEl.setAttribute('data-edge','1');
      lineEl.setAttribute('data-from',e.fromName);
      lineEl.setAttribute('data-to',e.toName);
      svg.appendChild(lineEl);

      // Latency info available on hover/sidebar — no inline labels to keep graph clean

      // Particles
      var numP=e.isTool?1:Math.min(3,Math.max(1,Math.ceil(e.total/maxTotal*3)));
      for(var pi=0;pi<numP;pi++){
        var dot=document.createElementNS(NS,'circle');
        dot.setAttribute('r',e.isTool?'1.8':'2.5');
        dot.setAttribute('fill',strokeColor);
        dot.setAttribute('opacity',e.isTool?'0.5':'0.6');
        dot.setAttribute('data-edge','1');
        dot.setAttribute('data-from',e.fromName);
        dot.setAttribute('data-to',e.toName);
        svg.appendChild(dot);
        particles.push({dot:dot, link:e, co:co, t:pi/numP, speed:e.isTool?0.001+Math.random()*0.001:0.0015+Math.random()*0.002});
      }
      lineEls.push({el:lineEl, link:e, curved:co!==0, co:co, baseW:baseW, hk:hk, isTool:e.isTool});
    });

    function edgeEndpoints(le){
      var s=nodes[le.link.from],t=nodes[le.link.to];
      var dx=t.x-s.x, dy=t.y-s.y, d=Math.sqrt(dx*dx+dy*dy)||1;
      var tr=nodeRadius(t);
      return {sx:s.x,sy:s.y,ex:t.x-(dx/d)*tr,ey:t.y-(dy/d)*tr,dx:dx,dy:dy,d:d};
    }

    function updateEdges(){
      lineEls.forEach(function(le){
        var ep=edgeEndpoints(le);
        if(le.curved){
          var mx=(ep.sx+ep.ex)/2+(-ep.dy/ep.d)*le.co;
          var my=(ep.sy+ep.ey)/2+(ep.dx/ep.d)*le.co;
          le.el.setAttribute('d','M'+ep.sx+','+ep.sy+' Q'+mx+','+my+' '+ep.ex+','+ep.ey);
        } else {
          le.el.setAttribute('x1',ep.sx); le.el.setAttribute('y1',ep.sy);
          le.el.setAttribute('x2',ep.ex); le.el.setAttribute('y2',ep.ey);
        }
      });
    }
    updateEdges();

    // Particle animation (pauses when tab hidden to save CPU)
    var tabVisible=true, animId=null;
    document.addEventListener('visibilitychange',function(){
      tabVisible=!document.hidden;
      if(tabVisible&&!animId) animId=requestAnimationFrame(animParticles);
    });
    function animParticles(){
      if(!tabVisible){animId=null;return;}
      particles.forEach(function(p){
        p.t+=p.speed; if(p.t>1) p.t-=1;
        var s=nodes[p.link.from],t=nodes[p.link.to];
        var dx=t.x-s.x,dy=t.y-s.y,d=Math.sqrt(dx*dx+dy*dy)||1;
        var tr=nodeRadius(t);
        var ex=t.x-(dx/d)*tr, ey=t.y-(dy/d)*tr;
        var tt=p.t, x, y;
        if(p.co!==0){
          var mx=(s.x+ex)/2+(-dy/d)*p.co, my=(s.y+ey)/2+(dx/d)*p.co;
          var u=1-tt;
          x=u*u*s.x+2*u*tt*mx+tt*tt*ex; y=u*u*s.y+2*u*tt*my+tt*tt*ey;
        } else { x=s.x+(ex-s.x)*tt; y=s.y+(ey-s.y)*tt; }
        p.dot.setAttribute('cx',x); p.dot.setAttribute('cy',y);
      });
      animId=requestAnimationFrame(animParticles);
    }
    animId=requestAnimationFrame(animParticles);

    // ── Focus/Dim state ──
    var focusedNode=null;

    function getConnectedNames(nodeName){
      var connected={};
      connected[nodeName]=true;
      // Upstream: trace back from clicked node to orchestrator
      var upstream={};upstream[nodeName]=true;
      var ch=true;
      while(ch){ ch=false; links.forEach(function(l){
        if(!l.isTool&&upstream[l.toName]&&!upstream[l.fromName]){ upstream[l.fromName]=true;connected[l.fromName]=true;ch=true; }
      });}
      // Downstream: trace forward from clicked node to tools
      ch=true;
      var downstream={};downstream[nodeName]=true;
      while(ch){ ch=false; links.forEach(function(l){
        if(downstream[l.fromName]&&!downstream[l.toName]){ downstream[l.toName]=true;connected[l.toName]=true;ch=true; }
      });}
      return connected;
    }

    function focusNode(n){
      if(focusedNode===n.name){ unfocus(); return; }
      focusedNode=n.name;
      var connected=getConnectedNames(n.name);
      nodes.forEach(function(nd){
        if(nd._g){
          if(connected[nd.name]) nd._g.classList.remove('graph-dim'), nd._g.classList.add('graph-bright');
          else nd._g.classList.add('graph-dim'), nd._g.classList.remove('graph-bright');
        }
      });
      svg.querySelectorAll('[data-edge]').forEach(function(el2){
        var ef=el2.getAttribute('data-from'), et=el2.getAttribute('data-to');
        if(connected[ef]&&connected[et]) el2.classList.remove('graph-dim'), el2.classList.add('graph-bright');
        else el2.classList.add('graph-dim'), el2.classList.remove('graph-bright');
      });
    }

    function unfocus(){
      focusedNode=null;
      nodes.forEach(function(nd){ if(nd._g){ nd._g.classList.remove('graph-dim','graph-bright'); }});
      svg.querySelectorAll('[data-edge]').forEach(function(el2){ el2.classList.remove('graph-dim','graph-bright'); });
    }

    // polling moved to separate script block below

    // Click background to unfocus
    svg.addEventListener('click',function(ev){ if(ev.target===svg) unfocus(); });

    // ── Nodes ──
    var nodeLayer=document.createElementNS(NS,'g');
    function hexPts(hx,hy,r){
      var pts=[];
      for(var hi=0;hi<6;hi++){var a=Math.PI/6+(Math.PI/3)*hi; pts.push((hx+r*Math.cos(a)).toFixed(1)+','+(hy+r*Math.sin(a)).toFixed(1));}
      return pts.join(' ');
    }

    nodes.forEach(function(n,i){
      var g=document.createElementNS(NS,'g');
      g.style.cursor='pointer';
      n._g=g;

      var shape, fo, labelY, textLen;
      var nameLen=Math.min(n.name.length,22);

      if(n.isTool){
        shape=document.createElementNS(NS,'rect');
        shape.setAttribute('x',n.x-TR-2); shape.setAttribute('y',n.y-TR-2);
        shape.setAttribute('width',(TR+2)*2); shape.setAttribute('height',(TR+2)*2);
        shape.setAttribute('rx','4');
        shape.setAttribute('fill','rgba(139,92,246,0.06)');
        shape.setAttribute('stroke','#8b5cf6'); shape.setAttribute('stroke-width','1');
        shape.setAttribute('stroke-opacity','0.5');
        fo=document.createElementNS(NS,'foreignObject');
        fo.setAttribute('x',n.x-TR); fo.setAttribute('y',n.y-TR);
        fo.setAttribute('width',TR*2); fo.setAttribute('height',TR*2);
        var toolDiv=document.createElement('div');
        toolDiv.style.cssText='width:100%;height:100%;display:flex;align-items:center;justify-content:center;color:#bc8cff;font-family:ui-monospace,SFMono-Regular,monospace;font-size:10px;font-weight:600';
        toolDiv.textContent=n.name.charAt(0).toUpperCase();
        fo.appendChild(toolDiv);
        labelY=n.y+TR+13; textLen=nameLen*5.5+8;

      } else if(n.isOrch){
        shape=document.createElementNS(NS,'polygon');
        shape.setAttribute('points',hexPts(n.x,n.y,OR+3));
        shape.setAttribute('fill','url(#orchFill)');
        shape.setAttribute('stroke','#bc8cff'); shape.setAttribute('stroke-width','2.5');
        shape.setAttribute('filter','url(#glow)');
        shape.classList.add('orch-hex');
        var innerHex=document.createElementNS(NS,'polygon');
        innerHex.setAttribute('points',hexPts(n.x,n.y,OR-5));
        innerHex.setAttribute('fill','rgba(139,92,246,0.15)');
        innerHex.setAttribute('stroke','#c4b5fd'); innerHex.setAttribute('stroke-width','1');
        innerHex.setAttribute('stroke-opacity','0.4');
        fo=document.createElementNS(NS,'foreignObject');
        fo.setAttribute('x',n.x-14); fo.setAttribute('y',n.y-14);
        fo.setAttribute('width',28); fo.setAttribute('height',28);
        var orchIcon=document.createElement('div');
        orchIcon.style.cssText='width:100%;height:100%;display:flex;align-items:center;justify-content:center;color:#c4b5fd;font-size:16px;font-weight:700;font-family:ui-monospace,SFMono-Regular,monospace';
        orchIcon.textContent='⬡';
        fo.appendChild(orchIcon);
        n._innerHex=innerHex;
        labelY=n.y+OR+18; textLen=nameLen*6.5+12;

      } else {
        var ringColor=n.threat>60?'#f85149':(n.threat>30?'#d29922':'#3fb950');
        shape=document.createElementNS(NS,'circle');
        shape.setAttribute('cx',n.x); shape.setAttribute('cy',n.y); shape.setAttribute('r',NR+2);
        shape.setAttribute('fill','none');
        shape.setAttribute('stroke',ringColor); shape.setAttribute('stroke-width','1.5');
        shape.setAttribute('stroke-opacity','0.6');
        fo=document.createElementNS(NS,'foreignObject');
        fo.setAttribute('x',n.x-NR); fo.setAttribute('y',n.y-NR);
        fo.setAttribute('width',NR*2); fo.setAttribute('height',NR*2);
        var avDiv=document.createElement('div');
        avDiv.innerHTML=agentAvatar(n.name,NR*2);
        fo.appendChild(avDiv);
        labelY=n.y+NR+16; textLen=nameLen*6.5+12;

        // Status dot (small indicator at top-right of node)
        var statusDot=document.createElementNS(NS,'circle');
        statusDot.setAttribute('cx',n.x+NR-2); statusDot.setAttribute('cy',n.y-NR+2);
        statusDot.setAttribute('r','4');
        statusDot.setAttribute('fill',ringColor);
        statusDot.setAttribute('stroke','#0d1117'); statusDot.setAttribute('stroke-width','1.5');
        n._statusDot=statusDot;
      }

      // Label
      var labelBg=document.createElementNS(NS,'rect');
      labelBg.setAttribute('x',n.x-textLen/2); labelBg.setAttribute('y',labelY-9);
      labelBg.setAttribute('width',textLen); labelBg.setAttribute('height',n.isOrch?28:16);
      labelBg.setAttribute('rx','3');
      labelBg.setAttribute('fill','#0d1117'); labelBg.setAttribute('fill-opacity','0.9');

      var label=document.createElementNS(NS,'text');
      label.setAttribute('x',n.x); label.setAttribute('y',labelY);
      label.setAttribute('text-anchor','middle');
      label.setAttribute('fill',n.isTool?'#bc8cff':'#e4e4e7');
      label.setAttribute('font-size',n.isTool?'10':(n.isOrch?'13':'11'));
      label.setAttribute('font-weight',n.isOrch?'600':'500');
      label.setAttribute('font-family','ui-monospace,SFMono-Regular,SF Mono,Menlo,monospace');
      var maxLen=n.isOrch?24:20;
      var displayName=n.name==='gateway'?'oktsec':(n.name.length>maxLen?n.name.substring(0,maxLen-1)+'…':n.name);
      label.textContent=displayName;

      // Orchestrator subtitle
      var subLabel=null;
      if(n.isOrch){
        subLabel=document.createElementNS(NS,'text');
        subLabel.setAttribute('x',n.x); subLabel.setAttribute('y',labelY+13);
        subLabel.setAttribute('text-anchor','middle');
        subLabel.setAttribute('fill','#848d97');
        subLabel.setAttribute('font-size','10');
        subLabel.setAttribute('font-family','ui-monospace,SFMono-Regular,SF Mono,Menlo,monospace');
        subLabel.textContent='orchestrator';
      }

      g.appendChild(shape);
      if(n._innerHex) g.appendChild(n._innerHex);
      g.appendChild(fo); g.appendChild(labelBg); g.appendChild(label);
      if(subLabel) g.appendChild(subLabel);
      if(n._statusDot) g.appendChild(n._statusDot);
      n._ring=shape; n._fo=fo; n._label=label; n._labelBg=labelBg; n._subLabel=subLabel;

      var didDrag=false;
      g.addEventListener('click',function(ev){
        ev.stopPropagation();
        if(didDrag){didDrag=false;return;}
        if(n.isTool) return;
        focusNode(n);
      });

      // Drag support
      var dragging=false;
      fo.addEventListener('mousedown',function(ev){dragging=true;ev.preventDefault();});
      svg.addEventListener('mousemove',function(ev){
        if(!dragging)return;
        didDrag=true;
        var rect=svg.getBoundingClientRect();
        n.x=Math.max(PAD,Math.min(W-PAD,ev.clientX-rect.left));
        n.y=Math.max(PAD,Math.min(H-PAD,ev.clientY-rect.top));
        if(n.isTool){
          shape.setAttribute('x',n.x-TR-2); shape.setAttribute('y',n.y-TR-2);
          fo.setAttribute('x',n.x-TR); fo.setAttribute('y',n.y-TR);
        } else if(n.isOrch){
          shape.setAttribute('points',hexPts(n.x,n.y,OR+3));
          if(n._innerHex) n._innerHex.setAttribute('points',hexPts(n.x,n.y,OR-5));
          fo.setAttribute('x',n.x-14); fo.setAttribute('y',n.y-14);
        } else {
          shape.setAttribute('cx',n.x); shape.setAttribute('cy',n.y);
          fo.setAttribute('x',n.x-NR); fo.setAttribute('y',n.y-NR);
          if(n._statusDot){ n._statusDot.setAttribute('cx',n.x+NR-2); n._statusDot.setAttribute('cy',n.y-NR+2); }
        }
        var ly=n.isTool?n.y+TR+11:(n.isOrch?n.y+OR+16:n.y+NR+14);
        label.setAttribute('x',n.x); label.setAttribute('y',ly);
        labelBg.setAttribute('x',n.x-textLen/2); labelBg.setAttribute('y',ly-9);
        if(n._subLabel){ n._subLabel.setAttribute('x',n.x); n._subLabel.setAttribute('y',ly+12); }
        updateEdges();
      });
      svg.addEventListener('mouseup',function(){
        if(dragging&&!didDrag) didDrag=false;
        dragging=false;
      });

      nodeLayer.appendChild(g);
    });
    svg.appendChild(nodeLayer);
    el.appendChild(svg);
  }
})();
</script>
<script>
(function(){
  var _prevEv='',_prevTb='';
  function _nc(){return '_t='+Date.now();}
  function pollGraph(){
    fetch('/dashboard/api/graph/stats?'+_nc(),{credentials:'same-origin',cache:'no-store'}).then(function(r){return r.json()}).then(function(d){
      var g=function(id){return document.getElementById(id)};
      if(g('gs-agents'))g('gs-agents').textContent=d.agents;
      if(g('gs-tools'))g('gs-tools').textContent=d.tools;
      if(g('gs-messages'))g('gs-messages').textContent=d.messages.toLocaleString();
      if(g('gs-blocks'))g('gs-blocks').textContent=d.blocks;
      if(g('gs-audit'))g('gs-audit').textContent=d.messages.toLocaleString();
      var ec=document.getElementById('gw-event-count');
      if(ec)ec.textContent=d.messages.toLocaleString()+' EVENTS';
    }).catch(function(){});
    fetch('/dashboard/api/graph/events?'+_nc(),{credentials:'same-origin',cache:'no-store'}).then(function(r){return r.text()}).then(function(h){
      var t=h.trim();
      if(t!==_prevEv){_prevEv=t;var el=document.getElementById('gw-events');if(el){el.innerHTML=t;el.querySelectorAll('[data-ts]').forEach(function(e){var ts=e.getAttribute('data-ts');if(ts&&typeof _relTime==='function')e.textContent=_relTime(ts);});}}
    }).catch(function(){});
    fetch('/dashboard/api/graph/tables?range={{.Range}}&'+_nc(),{credentials:'same-origin',cache:'no-store'}).then(function(r){return r.text()}).then(function(h){
      var t=h.trim();
      if(t!==_prevTb){_prevTb=t;var el=document.getElementById('graph-tables');if(el){el.innerHTML=t;if(typeof _applyGraphFilter==='function')_applyGraphFilter();}}
    }).catch(function(){});
  }
  pollGraph();
  function schedulePoll(){
    setTimeout(function(){
      if(!document.hidden) pollGraph();
      schedulePoll();
    },15000);
  }
  schedulePoll();
  document.addEventListener('visibilitychange',function(){
    if(!document.hidden) pollGraph();
  });
})();
</script>
` + layoutFoot))

var edgeDetailTmpl = template.Must(template.New("edge-detail").Funcs(tmplFuncs).Parse(`
<div class="panel-header">
  <h3><span class="agent-cell">{{avatar .From 20}} {{.From}}</span> &rarr; <span class="agent-cell">{{avatar .To 20}} {{.To}}</span></h3>
  <button class="panel-close" onclick="closePanel()" aria-label="Close panel">&times;</button>
</div>
<div class="panel-body">
  {{if .Rules}}
  <div class="field">
    <div class="field-label">Top Triggered Rules</div>
    <table style="margin-top:8px">
      <thead><tr><th>Rule</th><th>Severity</th><th>Count</th></tr></thead>
      <tbody>
      {{range .Rules}}
      <tr>
        <td><span style="font-weight:600">{{.RuleID}}</span><br><span style="color:var(--text3);font-size:0.72rem">{{.Name}}</span></td>
        <td><span class="sev-{{.Severity}}">{{.Severity}}</span></td>
        <td>{{.Count}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
  </div>
  {{else}}
  <div class="field">
    <div class="field-label">Rules</div>
    <p style="color:var(--text3);font-size:0.82rem">No rules triggered on this edge</p>
  </div>
  {{end}}

  {{if .Entries}}
  <div class="field" style="margin-top:20px">
    <div class="field-label">Recent Messages</div>
    <table style="margin-top:8px">
      <thead><tr><th>Time</th><th>Status</th></tr></thead>
      <tbody>
      {{range .Entries}}
      <tr>
        <td data-ts="{{.Timestamp}}">{{.Timestamp}}</td>
        <td><span class="badge-{{.Status}}">{{.Status}}</span></td>
      </tr>
      {{end}}
      </tbody>
    </table>
  </div>
  {{end}}
</div>
`))
