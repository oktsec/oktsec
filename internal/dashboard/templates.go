package dashboard

import "html/template"

var loginTmpl = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>oktsec — dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#0a0a0f;--surface:#12121a;--surface2:#1a1a26;--border:#2a2a3a;
  --text:#e0e0ee;--text2:#8888aa;--text3:#555570;
  --accent:#6366f1;--accent-light:#818cf8;--accent-dim:#4f46e5;
  --danger:#ef4444;--success:#22c55e;--warn:#f59e0b;
  --mono:'SF Mono','Fira Code','JetBrains Mono',monospace;
  --sans:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
}
body{font-family:var(--sans);background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center}
.login-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:48px 40px;max-width:400px;width:100%;text-align:center}
.logo{font-family:var(--mono);font-size:1.5rem;font-weight:700;letter-spacing:-0.5px;margin-bottom:8px}
.logo span{color:var(--accent-light)}
.subtitle{color:var(--text2);font-size:0.85rem;margin-bottom:32px}
.lock-icon{font-size:2.5rem;margin-bottom:16px;opacity:0.6}
.help{color:var(--text3);font-size:0.78rem;margin-bottom:24px;line-height:1.6}
.help code{background:var(--surface2);padding:2px 6px;border-radius:4px;font-family:var(--mono);font-size:0.75rem;color:var(--accent-light)}
input[type=text]{
  width:100%;padding:14px 16px;background:var(--bg);border:1px solid var(--border);
  border-radius:8px;color:var(--text);font-family:var(--mono);font-size:1.2rem;
  text-align:center;letter-spacing:4px;outline:none;transition:border-color 0.2s;
}
input[type=text]:focus{border-color:var(--accent)}
input[type=text]::placeholder{letter-spacing:0;font-size:0.85rem;color:var(--text3)}
button{
  width:100%;padding:12px;margin-top:16px;background:var(--accent);color:#fff;
  border:none;border-radius:8px;font-size:0.9rem;font-weight:600;cursor:pointer;
  transition:background 0.2s;
}
button:hover{background:var(--accent-dim)}
.error{color:var(--danger);font-size:0.82rem;margin-top:12px}
.footer{margin-top:32px;color:var(--text3);font-size:0.72rem}
</style>
</head>
<body>
<div class="login-card">
  <div class="lock-icon">&#x1f512;</div>
  <div class="logo">okt<span>sec</span></div>
  <div class="subtitle">Dashboard Access</div>
  <p class="help">Enter the access code shown in your terminal.<br>Run <code>oktsec serve</code> to get a code.</p>
  <form method="POST" action="/dashboard/login" autocomplete="off">
    <input type="text" name="code" placeholder="00000000" maxlength="8" pattern="\d{8}" inputmode="numeric" autofocus required>
    <button type="submit">Authenticate</button>
  </form>
  {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
  <p class="footer">Local access only &middot; 127.0.0.1</p>
</div>
</body>
</html>`))

const layoutHead = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>oktsec — {{.Active}}</title>
<script src="https://unpkg.com/htmx.org@2.0.4" integrity="sha384-HGfztofotfshcF7+8n44JQL2oJmowVChPTg48S+jvZoztPfvwD79OC/LTtG6dMp+" crossorigin="anonymous"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#0a0a0f;--surface:#12121a;--surface2:#1a1a26;--border:#2a2a3a;
  --text:#e0e0ee;--text2:#8888aa;--text3:#555570;
  --accent:#6366f1;--accent-light:#818cf8;--accent-dim:#4f46e5;
  --danger:#ef4444;--success:#22c55e;--warn:#f59e0b;
  --mono:'SF Mono','Fira Code','JetBrains Mono',monospace;
  --sans:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
}
body{font-family:var(--sans);background:var(--bg);color:var(--text);min-height:100vh}

/* Nav */
nav{background:var(--surface);border-bottom:1px solid var(--border);padding:0 24px;display:flex;align-items:center;height:52px;position:sticky;top:0;z-index:100}
nav .logo{font-family:var(--mono);font-size:1.1rem;font-weight:700;letter-spacing:-0.5px;margin-right:32px;text-decoration:none;color:var(--text)}
nav .logo span{color:var(--accent-light)}
nav a{color:var(--text2);text-decoration:none;font-size:0.82rem;padding:16px 12px;transition:color 0.2s;border-bottom:2px solid transparent}
nav a:hover{color:var(--text)}
nav a.active{color:var(--accent-light);border-bottom-color:var(--accent-light)}
nav .spacer{flex:1}
nav .badge{background:var(--surface2);color:var(--text3);font-size:0.7rem;padding:4px 10px;border-radius:12px;font-family:var(--mono)}

/* Main */
main{max-width:1100px;margin:0 auto;padding:32px 24px}
h1{font-size:1.4rem;font-weight:600;margin-bottom:8px}
h1 span{color:var(--accent-light)}
.page-desc{color:var(--text2);font-size:0.85rem;margin-bottom:28px}

/* Stats */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:32px}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px}
.stat .label{color:var(--text3);font-size:0.72rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px}
.stat .value{font-family:var(--mono);font-size:1.8rem;font-weight:700}
.stat .value.success{color:var(--success)}
.stat .value.danger{color:var(--danger)}
.stat .value.warn{color:var(--warn)}

/* Card */
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px;margin-bottom:20px}
.card h2{font-size:0.95rem;font-weight:600;margin-bottom:16px;display:flex;align-items:center;gap:8px}
.card h2 .dot{width:6px;height:6px;border-radius:50%;background:var(--success);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}

/* Table */
table{width:100%;border-collapse:collapse;font-size:0.82rem}
th{text-align:left;color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;padding:8px 12px;border-bottom:1px solid var(--border)}
td{padding:10px 12px;border-bottom:1px solid var(--border);color:var(--text2);font-family:var(--mono);font-size:0.78rem}
tr:hover td{background:var(--surface2)}

/* Badges */
.badge-delivered{background:#22c55e20;color:var(--success);padding:3px 8px;border-radius:4px;font-size:0.7rem;font-weight:600}
.badge-blocked{background:#ef444420;color:var(--danger);padding:3px 8px;border-radius:4px;font-size:0.7rem;font-weight:600}
.badge-rejected{background:#f59e0b20;color:var(--warn);padding:3px 8px;border-radius:4px;font-size:0.7rem;font-weight:600}
.badge-quarantined{background:#6366f120;color:var(--accent-light);padding:3px 8px;border-radius:4px;font-size:0.7rem;font-weight:600}
.badge-verified{color:var(--success)}
.badge-unsigned{color:var(--text3)}
.badge-invalid{color:var(--danger)}

/* Agent list */
.agent-row{display:flex;align-items:center;gap:12px;padding:12px 0;border-bottom:1px solid var(--border)}
.agent-row:last-child{border-bottom:none}
.agent-name{font-family:var(--mono);font-weight:600;min-width:160px}
.agent-name a{color:var(--text);text-decoration:none;transition:color 0.2s}
.agent-name a:hover{color:var(--accent-light)}
.agent-targets{color:var(--text3);font-size:0.78rem}

/* Severity badges */
.sev-critical{background:#ef444420;color:var(--danger);padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:700;text-transform:uppercase}
.sev-high{background:#f59e0b20;color:var(--warn);padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:600;text-transform:uppercase}
.sev-medium{background:#6366f120;color:var(--accent-light);padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:600;text-transform:uppercase}
.sev-low{background:var(--surface2);color:var(--text3);padding:2px 8px;border-radius:4px;font-size:0.7rem;text-transform:uppercase}
.sev-info{background:var(--surface2);color:var(--text3);padding:2px 8px;border-radius:4px;font-size:0.7rem;text-transform:uppercase}

/* Action badges */
.act-block{background:#ef444420;color:var(--danger);padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:600}
.act-quarantine{background:#6366f120;color:var(--accent-light);padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:600}
.act-allow-and-flag{background:#f59e0b20;color:var(--warn);padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:600}
.act-ignore{background:var(--surface2);color:var(--text3);padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:600}

/* Chart */
.chart{display:flex;align-items:flex-end;gap:3px;height:80px;padding:8px 0}
.chart-bar{flex:1;background:var(--accent);border-radius:2px 2px 0 0;min-width:4px;transition:background 0.2s;position:relative}
.chart-bar:hover{background:var(--accent-light)}
.chart-labels{display:flex;justify-content:space-between;color:var(--text3);font-size:0.65rem;font-family:var(--mono);padding-top:4px}

/* Toggle */
.toggle-btn{display:inline-block;padding:6px 14px;background:var(--surface2);color:var(--text2);border:1px solid var(--border);border-radius:6px;font-size:0.78rem;cursor:pointer;text-decoration:none;transition:all 0.2s}
.toggle-btn:hover{background:var(--accent-dim);color:#fff;border-color:var(--accent)}

/* Key table */
.fp{color:var(--text3);font-size:0.72rem}

/* Empty state */
.empty{color:var(--text3);text-align:center;padding:40px 0;font-size:0.85rem}

/* Search bar */
.search-bar{position:relative;margin-bottom:16px}
.search-bar input{
  width:100%;padding:10px 16px 10px 36px;background:var(--bg);border:1px solid var(--border);
  border-radius:8px;color:var(--text);font-family:var(--mono);font-size:0.82rem;outline:none;transition:border-color 0.2s;
}
.search-bar input:focus{border-color:var(--accent)}
.search-bar input::placeholder{color:var(--text3)}
.search-bar .search-icon{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--text3);font-size:0.82rem;pointer-events:none}

/* Slide-in panel */
.panel-overlay{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.4);z-index:199;opacity:0;pointer-events:none;transition:opacity 0.3s ease}
.panel-overlay.open{opacity:1;pointer-events:auto}
.panel{position:fixed;top:0;right:0;width:480px;max-width:90vw;height:100%;background:var(--surface);border-left:1px solid var(--border);z-index:200;transform:translateX(100%);transition:transform 0.3s ease;overflow-y:auto;padding:0}
.panel.open{transform:translateX(0)}
.panel-header{display:flex;align-items:center;justify-content:space-between;padding:20px 24px;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--surface);z-index:1}
.panel-header h3{font-size:0.95rem;font-weight:600}
.panel-close{background:none;border:none;color:var(--text3);font-size:1.2rem;cursor:pointer;padding:4px 8px;border-radius:4px;transition:all 0.2s;width:auto;margin:0}
.panel-close:hover{color:var(--text);background:var(--surface2)}
.panel-body{padding:24px}
.panel-body .field{margin-bottom:16px}
.panel-body .field-label{color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px}
.panel-body .field-value{font-family:var(--mono);font-size:0.82rem;color:var(--text);word-break:break-all}
.panel-body .field-value.hash{font-size:0.72rem;color:var(--text2)}

/* Tabs */
.tabs{display:flex;gap:0;margin-bottom:20px;border-bottom:1px solid var(--border)}
.tab{padding:10px 20px;color:var(--text3);font-size:0.82rem;cursor:pointer;border-bottom:2px solid transparent;transition:all 0.2s;background:none;border-top:none;border-left:none;border-right:none;width:auto}
.tab:hover{color:var(--text)}
.tab.active{color:var(--accent-light);border-bottom-color:var(--accent-light)}
.tab-content{display:none}
.tab-content.active{display:block}

/* Form elements */
.form-row{display:flex;gap:12px;margin-bottom:12px;align-items:flex-end}
.form-group{flex:1}
.form-group label{display:block;color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px}
.form-group input,.form-group select,.form-group textarea{
  width:100%;padding:8px 12px;background:var(--bg);border:1px solid var(--border);
  border-radius:6px;color:var(--text);font-family:var(--mono);font-size:0.82rem;outline:none;transition:border-color 0.2s;
}
.form-group input:focus,.form-group select:focus,.form-group textarea:focus{border-color:var(--accent)}
.form-group select{cursor:pointer;-webkit-appearance:none;appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%23555570' d='M6 8L1 3h10z'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 10px center;padding-right:28px}
.form-group textarea{resize:vertical;min-height:80px}
.btn{display:inline-block;padding:8px 16px;background:var(--accent);color:#fff;border:none;border-radius:6px;font-size:0.82rem;font-weight:600;cursor:pointer;transition:background 0.2s;width:auto;margin:0}
.btn:hover{background:var(--accent-dim)}
.btn-sm{padding:4px 10px;font-size:0.72rem}
.btn-danger{background:var(--danger)}
.btn-danger:hover{background:#dc2626}

/* Clickable rows */
tr.clickable{cursor:pointer}
tr.clickable:hover td{background:var(--surface2)}

/* Rule card in list */
.rule-list-item{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--border);cursor:pointer;transition:background 0.2s}
.rule-list-item:last-child{border-bottom:none}
.rule-list-item:hover{background:var(--surface2);margin:0 -20px;padding:10px 20px}
.rule-id-col{font-family:var(--mono);font-weight:600;min-width:200px;font-size:0.78rem;color:var(--text)}
.rule-name-col{flex:1;color:var(--text2);font-size:0.78rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rule-cat-col{color:var(--text3);font-size:0.72rem;min-width:100px}

/* SSE indicator */
.sse-indicator{display:inline-flex;align-items:center;gap:6px;font-size:0.72rem;color:var(--text3)}
.sse-dot{width:6px;height:6px;border-radius:50%;background:var(--text3)}
.sse-dot.connected{background:var(--success);animation:pulse 2s infinite}

/* Pattern display */
.pattern-item{font-family:var(--mono);font-size:0.72rem;color:var(--text2);background:var(--bg);padding:6px 10px;border-radius:4px;margin-bottom:4px;word-break:break-all}

/* Responsive */
@media(max-width:768px){
  .stats{grid-template-columns:repeat(2,1fr)}
  .panel{width:100%;max-width:100%}
  .form-row{flex-direction:column}
}
</style>
</head>
<body>
<nav>
  <a href="/dashboard" class="logo">okt<span>sec</span></a>
  <a href="/dashboard" class="{{if eq .Active "overview"}}active{{end}}">Overview</a>
  <a href="/dashboard/agents" class="{{if eq .Active "agents"}}active{{end}}">Agents</a>
  <a href="/dashboard/logs" class="{{if eq .Active "logs"}}active{{end}}">Audit Log</a>
  <a href="/dashboard/rules" class="{{if eq .Active "rules"}}active{{end}}">Rules</a>
  <a href="/dashboard/identity" class="{{if eq .Active "identity"}}active{{end}}">Identity</a>
  <div class="spacer"></div>
  <span class="badge">{{if .RequireSig}}enforce{{else}}observe{{end}}</span>
</nav>
<main>`

const layoutFoot = `</main>

<!-- Slide-in panel -->
<div class="panel-overlay" id="panel-overlay" onclick="closePanel()"></div>
<div class="panel" id="detail-panel">
  <div id="panel-content"></div>
</div>

<script>
function openPanel(html) {
  document.getElementById('panel-content').innerHTML = html;
  document.getElementById('detail-panel').classList.add('open');
  document.getElementById('panel-overlay').classList.add('open');
}
function closePanel() {
  document.getElementById('detail-panel').classList.remove('open');
  document.getElementById('panel-overlay').classList.remove('open');
}
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') closePanel();
});

// HTMX: when a panel response arrives, open the panel
document.body.addEventListener('htmx:afterSwap', function(e) {
  if (e.detail.target.id === 'panel-content') {
    document.getElementById('detail-panel').classList.add('open');
    document.getElementById('panel-overlay').classList.add('open');
  }
});

// Tabs
function switchTab(group, tabName) {
  document.querySelectorAll('[data-tab-group="'+group+'"] .tab').forEach(function(t) {
    t.classList.toggle('active', t.dataset.tab === tabName);
  });
  document.querySelectorAll('[data-tab-content="'+group+'"]').forEach(function(c) {
    c.classList.toggle('active', c.dataset.tabName === tabName);
  });
}
</script>
</body>
</html>`

var overviewTmpl = template.Must(template.New("overview").Parse(layoutHead + `
<h1>Dashboard <span>Overview</span></h1>
<p class="page-desc">Real-time view of agent communication and security events. <span class="sse-indicator" id="sse-status"><span class="sse-dot" id="sse-dot"></span> <span id="sse-label">connecting</span></span></p>

<div class="stats" hx-get="/dashboard/api/stats" hx-trigger="every 5s" hx-swap="none">
  <div class="stat">
    <div class="label">Total Messages</div>
    <div class="value" id="stat-total">{{.Stats.TotalMessages}}</div>
  </div>
  <div class="stat">
    <div class="label">Delivered</div>
    <div class="value success" id="stat-delivered">{{.Stats.Delivered}}</div>
  </div>
  <div class="stat">
    <div class="label">Blocked</div>
    <div class="value danger" id="stat-blocked">{{.Stats.Blocked}}</div>
  </div>
  <div class="stat">
    <div class="label">Rejected</div>
    <div class="value warn" id="stat-rejected">{{.Stats.Rejected}}</div>
  </div>
</div>

{{if .Chart}}
<div class="card">
  <h2>24h Activity</h2>
  <div class="chart">
    {{range .Chart}}<div class="chart-bar" style="height:{{.Percent}}%" title="{{.Label}}: {{.Count}} msgs"></div>{{end}}
  </div>
  <div class="chart-labels">
    <span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>23:00</span>
  </div>
</div>
{{end}}

<div class="card">
  <h2><span class="dot"></span> Recent Events</h2>
  <div class="search-bar">
    <span class="search-icon">&#x1f50d;</span>
    <input type="text" placeholder="Search events..." hx-get="/dashboard/api/search" hx-trigger="input changed delay:300ms" hx-target="#search-results" name="q">
  </div>
  <div id="search-results" style="display:none"></div>
  <div id="recent-events">
    {{if .Recent}}
    <table>
      <thead><tr><th>Time</th><th>From</th><th>To</th><th>Status</th><th>Decision</th><th>Verified</th></tr></thead>
      <tbody id="events-tbody">
      {{range .Recent}}
      <tr class="clickable" hx-get="/dashboard/api/event/{{.ID}}" hx-target="#panel-content" hx-swap="innerHTML">
        <td>{{.Timestamp}}</td>
        <td>{{.FromAgent}}</td>
        <td>{{.ToAgent}}</td>
        <td>
          {{if eq .Status "delivered"}}<span class="badge-delivered">delivered</span>
          {{else if eq .Status "blocked"}}<span class="badge-blocked">blocked</span>
          {{else if eq .Status "rejected"}}<span class="badge-rejected">rejected</span>
          {{else if eq .Status "quarantined"}}<span class="badge-quarantined">quarantined</span>
          {{else}}{{.Status}}{{end}}
        </td>
        <td>{{.PolicyDecision}}</td>
        <td>
          {{if eq .SignatureVerified 1}}<span class="badge-verified">&#10003;</span>
          {{else if eq .SignatureVerified -1}}<span class="badge-invalid">&#10007;</span>
          {{else}}<span class="badge-unsigned">&mdash;</span>{{end}}
        </td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}
    <div class="empty" id="empty-msg">No events yet. Send a message through the proxy to see activity.</div>
    {{end}}
  </div>
</div>

<div class="card">
  <h2>Configuration</h2>
  <table>
    <tr>
      <td style="color:var(--text3)">Mode</td>
      <td>
        {{if .RequireSig}}<span class="badge-blocked">enforce</span>{{else}}<span class="badge-quarantined">observe</span>{{end}}
        <form method="POST" action="/dashboard/mode/toggle" style="display:inline;margin-left:12px"><button type="submit" class="toggle-btn">switch to {{if .RequireSig}}observe{{else}}enforce{{end}}</button></form>
      </td>
    </tr>
    <tr><td style="color:var(--text3)">Agents</td><td>{{.AgentCount}} configured</td></tr>
    <tr><td style="color:var(--text3)">Signatures</td><td>{{if .RequireSig}}required{{else}}optional{{end}}</td></tr>
  </table>
</div>

<script>
(function() {
  var dot = document.getElementById('sse-dot');
  var label = document.getElementById('sse-label');
  var searchInput = document.querySelector('.search-bar input');
  var searchResults = document.getElementById('search-results');
  var recentEvents = document.getElementById('recent-events');

  // Show/hide search results
  if (searchInput) {
    searchInput.addEventListener('input', function() {
      if (this.value.trim()) {
        searchResults.style.display = 'block';
        recentEvents.style.display = 'none';
      } else {
        searchResults.style.display = 'none';
        recentEvents.style.display = 'block';
      }
    });
  }

  // SSE connection
  var evtSource = new EventSource('/dashboard/api/events');
  evtSource.onopen = function() {
    dot.classList.add('connected');
    label.textContent = 'live';
  };
  evtSource.onerror = function() {
    dot.classList.remove('connected');
    label.textContent = 'reconnecting';
  };
  evtSource.onmessage = function(e) {
    try {
      var entry = JSON.parse(e.data);
      var tbody = document.getElementById('events-tbody');
      var empty = document.getElementById('empty-msg');
      if (empty) empty.remove();

      // If table doesn't exist yet, create it
      if (!tbody) {
        var recentDiv = document.getElementById('recent-events');
        recentDiv.innerHTML = '<table><thead><tr><th>Time</th><th>From</th><th>To</th><th>Status</th><th>Decision</th><th>Verified</th></tr></thead><tbody id="events-tbody"></tbody></table>';
        tbody = document.getElementById('events-tbody');
      }

      var statusBadge = '';
      switch(entry.status) {
        case 'delivered': statusBadge = '<span class="badge-delivered">delivered</span>'; break;
        case 'blocked': statusBadge = '<span class="badge-blocked">blocked</span>'; break;
        case 'rejected': statusBadge = '<span class="badge-rejected">rejected</span>'; break;
        case 'quarantined': statusBadge = '<span class="badge-quarantined">quarantined</span>'; break;
        default: statusBadge = entry.status;
      }

      var verifiedBadge = '<span class="badge-unsigned">&mdash;</span>';
      if (entry.signature_verified === 1) verifiedBadge = '<span class="badge-verified">&#10003;</span>';
      else if (entry.signature_verified === -1) verifiedBadge = '<span class="badge-invalid">&#10007;</span>';

      var row = document.createElement('tr');
      row.className = 'clickable';
      row.setAttribute('hx-get', '/dashboard/api/event/' + entry.id);
      row.setAttribute('hx-target', '#panel-content');
      row.setAttribute('hx-swap', 'innerHTML');
      row.innerHTML = '<td>' + entry.timestamp + '</td><td>' + entry.from_agent + '</td><td>' + entry.to_agent + '</td><td>' + statusBadge + '</td><td>' + entry.policy_decision + '</td><td>' + verifiedBadge + '</td>';
      tbody.insertBefore(row, tbody.firstChild);
      htmx.process(row);

      // Keep only 20 rows
      while (tbody.children.length > 20) tbody.removeChild(tbody.lastChild);
    } catch(err) {}
  };
})();
</script>
` + layoutFoot))

var recentPartialTmpl = template.Must(template.New("recent").Parse(`
{{if .}}
<table>
  <thead><tr><th>Time</th><th>From</th><th>To</th><th>Status</th><th>Decision</th><th>Verified</th></tr></thead>
  <tbody>
  {{range .}}
  <tr class="clickable" hx-get="/dashboard/api/event/{{.ID}}" hx-target="#panel-content" hx-swap="innerHTML">
    <td>{{.Timestamp}}</td>
    <td>{{.FromAgent}}</td>
    <td>{{.ToAgent}}</td>
    <td>
      {{if eq .Status "delivered"}}<span class="badge-delivered">delivered</span>
      {{else if eq .Status "blocked"}}<span class="badge-blocked">blocked</span>
      {{else if eq .Status "rejected"}}<span class="badge-rejected">rejected</span>
      {{else if eq .Status "quarantined"}}<span class="badge-quarantined">quarantined</span>
      {{else}}{{.Status}}{{end}}
    </td>
    <td>{{.PolicyDecision}}</td>
    <td>
      {{if eq .SignatureVerified 1}}<span class="badge-verified">&#10003;</span>
      {{else if eq .SignatureVerified -1}}<span class="badge-invalid">&#10007;</span>
      {{else}}<span class="badge-unsigned">&mdash;</span>{{end}}
    </td>
  </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<div class="empty">No events yet.</div>
{{end}}`))

var searchResultsTmpl = template.Must(template.New("search-results").Parse(`
{{if .}}
<table>
  <thead><tr><th>Time</th><th>From</th><th>To</th><th>Status</th><th>Decision</th><th>Latency</th></tr></thead>
  <tbody>
  {{range .}}
  <tr class="clickable" hx-get="/dashboard/api/event/{{.ID}}" hx-target="#panel-content" hx-swap="innerHTML">
    <td>{{.Timestamp}}</td>
    <td>{{.FromAgent}}</td>
    <td>{{.ToAgent}}</td>
    <td>
      {{if eq .Status "delivered"}}<span class="badge-delivered">delivered</span>
      {{else if eq .Status "blocked"}}<span class="badge-blocked">blocked</span>
      {{else if eq .Status "rejected"}}<span class="badge-rejected">rejected</span>
      {{else if eq .Status "quarantined"}}<span class="badge-quarantined">quarantined</span>
      {{else}}{{.Status}}{{end}}
    </td>
    <td>{{.PolicyDecision}}</td>
    <td>{{.LatencyMs}}ms</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<div class="empty">No results found.</div>
{{end}}`))

var logsTmpl = template.Must(template.New("logs").Parse(layoutHead + `
<h1>Audit <span>Log</span></h1>
<p class="page-desc">Complete record of all inter-agent communication.</p>

<div class="card">
  <div class="search-bar">
    <span class="search-icon">&#x1f50d;</span>
    <input type="text" placeholder="Search by agent, status, or rule..." hx-get="/dashboard/api/search" hx-trigger="input changed delay:300ms" hx-target="#log-search-results" name="q" id="log-search-input">
  </div>
  <div id="log-search-results" style="display:none"></div>
  <div id="log-entries">
  {{if .Entries}}
  <table>
    <thead><tr><th>Time</th><th>From</th><th>To</th><th>Status</th><th>Decision</th><th>Verified</th><th>Latency</th></tr></thead>
    <tbody>
    {{range .Entries}}
    <tr class="clickable" hx-get="/dashboard/api/event/{{.ID}}" hx-target="#panel-content" hx-swap="innerHTML">
      <td>{{.Timestamp}}</td>
      <td>{{.FromAgent}}</td>
      <td>{{.ToAgent}}</td>
      <td>
        {{if eq .Status "delivered"}}<span class="badge-delivered">delivered</span>
        {{else if eq .Status "blocked"}}<span class="badge-blocked">blocked</span>
        {{else if eq .Status "rejected"}}<span class="badge-rejected">rejected</span>
        {{else if eq .Status "quarantined"}}<span class="badge-quarantined">quarantined</span>
        {{else}}{{.Status}}{{end}}
      </td>
      <td>{{.PolicyDecision}}</td>
      <td>
        {{if eq .SignatureVerified 1}}<span class="badge-verified">&#10003;</span>
        {{else if eq .SignatureVerified -1}}<span class="badge-invalid">&#10007;</span>
        {{else}}<span class="badge-unsigned">&mdash;</span>{{end}}
      </td>
      <td>{{.LatencyMs}}ms</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}
  <div class="empty">No audit entries yet. Send a message through the proxy to see activity.</div>
  {{end}}
  </div>
</div>

<script>
(function() {
  var input = document.getElementById('log-search-input');
  var results = document.getElementById('log-search-results');
  var entries = document.getElementById('log-entries');
  if (input) {
    input.addEventListener('input', function() {
      if (this.value.trim()) {
        results.style.display = 'block';
        entries.style.display = 'none';
      } else {
        results.style.display = 'none';
        entries.style.display = 'block';
      }
    });
  }
})();
</script>
` + layoutFoot))

var agentsTmpl = template.Must(template.New("agents").Parse(layoutHead + `
<h1>Registered <span>Agents</span></h1>
<p class="page-desc">Agents configured in oktsec.yaml with their access control rules.</p>

<div class="card">
  {{if .Agents}}
  {{range $name, $agent := .Agents}}
  <div class="agent-row">
    <div class="agent-name"><a href="/dashboard/agents/{{$name}}">{{$name}}</a></div>
    <div class="agent-targets">
      {{if $agent.CanMessage}}can message: {{range $i, $t := $agent.CanMessage}}{{if $i}}, {{end}}{{$t}}{{end}}
      {{else}}<span style="color:var(--text3)">no restrictions</span>{{end}}
    </div>
  </div>
  {{end}}
  {{else}}
  <div class="empty">No agents configured. Add agents to your oktsec.yaml.</div>
  {{end}}
</div>
` + layoutFoot))

var agentDetailTmpl = template.Must(template.New("agent-detail").Parse(layoutHead + `
<h1>Agent: <span>{{.Name}}</span></h1>
<p class="page-desc">Detail view for agent {{.Name}}.</p>

<div class="stats">
  <div class="stat">
    <div class="label">Total Messages</div>
    <div class="value">{{.TotalMsgs}}</div>
  </div>
  <div class="stat">
    <div class="label">Delivered</div>
    <div class="value success">{{.Delivered}}</div>
  </div>
  <div class="stat">
    <div class="label">Blocked</div>
    <div class="value danger">{{.Blocked}}</div>
  </div>
  <div class="stat">
    <div class="label">Rejected</div>
    <div class="value warn">{{.Rejected}}</div>
  </div>
</div>

<div class="card">
  <h2>Access Control</h2>
  <table>
    <tr><td style="color:var(--text3)">Can message</td><td>{{range $i, $t := .Agent.CanMessage}}{{if $i}}, {{end}}{{$t}}{{end}}{{if not .Agent.CanMessage}}<span style="color:var(--text3)">no restrictions</span>{{end}}</td></tr>
    {{if .Agent.BlockedContent}}<tr><td style="color:var(--text3)">Blocked content</td><td>{{range $i, $c := .Agent.BlockedContent}}{{if $i}}, {{end}}{{$c}}{{end}}</td></tr>{{end}}
    {{if .KeyFP}}<tr><td style="color:var(--text3)">Key fingerprint</td><td class="fp">{{.KeyFP}}</td></tr>{{end}}
  </table>
</div>

<div class="card">
  <h2>Recent Messages</h2>
  {{if .Entries}}
  <table>
    <thead><tr><th>Time</th><th>From</th><th>To</th><th>Status</th><th>Decision</th><th>Verified</th><th>Latency</th></tr></thead>
    <tbody>
    {{range .Entries}}
    <tr class="clickable" hx-get="/dashboard/api/event/{{.ID}}" hx-target="#panel-content" hx-swap="innerHTML">
      <td>{{.Timestamp}}</td>
      <td>{{.FromAgent}}</td>
      <td>{{.ToAgent}}</td>
      <td>
        {{if eq .Status "delivered"}}<span class="badge-delivered">delivered</span>
        {{else if eq .Status "blocked"}}<span class="badge-blocked">blocked</span>
        {{else if eq .Status "rejected"}}<span class="badge-rejected">rejected</span>
        {{else if eq .Status "quarantined"}}<span class="badge-quarantined">quarantined</span>
        {{else}}{{.Status}}{{end}}
      </td>
      <td>{{.PolicyDecision}}</td>
      <td>
        {{if eq .SignatureVerified 1}}<span class="badge-verified">&#10003;</span>
        {{else if eq .SignatureVerified -1}}<span class="badge-invalid">&#10007;</span>
        {{else}}<span class="badge-unsigned">&mdash;</span>{{end}}
      </td>
      <td>{{.LatencyMs}}ms</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}
  <div class="empty">No messages for this agent yet.</div>
  {{end}}
</div>
` + layoutFoot))

var rulesTmpl = template.Must(template.New("rules").Parse(layoutHead + `
<h1>Detection <span>Rules</span></h1>
<p class="page-desc">{{.RuleCount}} built-in + custom rules for content inspection and enforcement.</p>

<div class="tabs" data-tab-group="rules">
  <button class="tab active" data-tab="all-rules" onclick="switchTab('rules','all-rules')">All Rules</button>
  <button class="tab" data-tab="enforcement" onclick="switchTab('rules','enforcement')">Enforcement Overrides</button>
  <button class="tab" data-tab="custom" onclick="switchTab('rules','custom')">Custom Rules</button>
</div>

<!-- Tab 1: All Rules -->
<div class="tab-content active" data-tab-content="rules" data-tab-name="all-rules">
  <div class="card">
    <div class="search-bar">
      <span class="search-icon">&#x1f50d;</span>
      <input type="text" placeholder="Filter rules by ID, name, or category..." id="rules-filter" oninput="filterRules(this.value)">
    </div>
    <div id="rules-list">
    {{if .AllRules}}
      {{range .AllRules}}
      <div class="rule-list-item" data-rule-id="{{.ID}}" data-rule-name="{{.Name}}" data-rule-cat="{{.Category}}" hx-get="/dashboard/api/rule/{{.ID}}" hx-target="#panel-content" hx-swap="innerHTML">
        <div class="rule-id-col">{{.ID}}</div>
        <div class="rule-name-col">{{.Name}}</div>
        <div>
          {{if eq .Severity "critical"}}<span class="sev-critical">critical</span>
          {{else if eq .Severity "high"}}<span class="sev-high">high</span>
          {{else if eq .Severity "medium"}}<span class="sev-medium">medium</span>
          {{else if eq .Severity "low"}}<span class="sev-low">low</span>
          {{else}}<span class="sev-info">{{.Severity}}</span>{{end}}
        </div>
        <div class="rule-cat-col">{{.Category}}</div>
      </div>
      {{end}}
    {{else}}
      <div class="empty">No rules loaded.</div>
    {{end}}
    </div>
  </div>
</div>

<!-- Tab 2: Enforcement Overrides -->
<div class="tab-content" data-tab-content="rules" data-tab-name="enforcement">
  <div class="card">
    <h2>Active Overrides</h2>
    {{if .Overrides}}
    <table>
      <thead><tr><th>Rule ID</th><th>Severity</th><th>Action</th><th></th></tr></thead>
      <tbody>
      {{range .Overrides}}
      <tr>
        <td>{{.ID}}</td>
        <td>
          {{if eq .Severity "critical"}}<span class="sev-critical">critical</span>
          {{else if eq .Severity "high"}}<span class="sev-high">high</span>
          {{else if eq .Severity "medium"}}<span class="sev-medium">medium</span>
          {{else}}<span class="sev-low">{{.Severity}}</span>{{end}}
        </td>
        <td>
          {{if eq .Action "block"}}<span class="act-block">block</span>
          {{else if eq .Action "quarantine"}}<span class="act-quarantine">quarantine</span>
          {{else if eq .Action "allow-and-flag"}}<span class="act-allow-and-flag">allow-and-flag</span>
          {{else if eq .Action "ignore"}}<span class="act-ignore">ignore</span>
          {{else}}{{.Action}}{{end}}
        </td>
        <td><button class="btn btn-sm btn-danger" hx-delete="/dashboard/rules/enforcement/{{.ID}}" hx-confirm="Remove override for {{.ID}}?" hx-target="closest tr" hx-swap="outerHTML">remove</button></td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}
    <div class="empty" style="padding:20px 0">No overrides configured. All rules use default actions.</div>
    {{end}}
  </div>

  <div class="card">
    <h2>Add Override</h2>
    <form method="POST" action="/dashboard/rules/enforcement">
      <div class="form-row">
        <div class="form-group">
          <label>Rule ID</label>
          <input type="text" name="rule_id" placeholder="e.g. PROMPT-001" required>
        </div>
        <div class="form-group">
          <label>Severity</label>
          <select name="severity">
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium" selected>Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
        <div class="form-group">
          <label>Action</label>
          <select name="action">
            <option value="block">Block</option>
            <option value="quarantine">Quarantine</option>
            <option value="allow-and-flag">Allow & Flag</option>
            <option value="ignore">Ignore</option>
          </select>
        </div>
      </div>
      <button type="submit" class="btn">Add Override</button>
    </form>
  </div>
</div>

<!-- Tab 3: Custom Rules -->
<div class="tab-content" data-tab-content="rules" data-tab-name="custom">
  <div class="card" hx-get="/dashboard/rules/custom" hx-trigger="load" hx-target="this" hx-swap="innerHTML">
    <div class="empty">Loading custom rules...</div>
  </div>

  <div class="card">
    <h2>Create Custom Rule</h2>
    <form method="POST" action="/dashboard/rules/custom">
      <div class="form-row">
        <div class="form-group">
          <label>Rule ID</label>
          <input type="text" name="rule_id" placeholder="e.g. CUSTOM-001" required>
        </div>
        <div class="form-group">
          <label>Name</label>
          <input type="text" name="name" placeholder="e.g. Block internal secrets" required>
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label>Severity</label>
          <select name="severity">
            <option value="critical">Critical</option>
            <option value="high" selected>High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
        <div class="form-group">
          <label>Category</label>
          <input type="text" name="category" placeholder="e.g. data-exfiltration" value="custom">
        </div>
      </div>
      <div class="form-group" style="margin-bottom:12px">
        <label>Patterns (one per line)</label>
        <textarea name="patterns" placeholder="password&#10;secret_key&#10;api_token"></textarea>
      </div>
      <button type="submit" class="btn">Create Rule</button>
    </form>
  </div>
</div>

<script>
function filterRules(query) {
  var q = query.toLowerCase();
  document.querySelectorAll('.rule-list-item').forEach(function(item) {
    var id = (item.dataset.ruleId || '').toLowerCase();
    var name = (item.dataset.ruleName || '').toLowerCase();
    var cat = (item.dataset.ruleCat || '').toLowerCase();
    item.style.display = (!q || id.includes(q) || name.includes(q) || cat.includes(q)) ? '' : 'none';
  });
}
</script>
` + layoutFoot))

var eventDetailTmpl = template.Must(template.New("event-detail").Parse(`
<div class="panel-header">
  <h3>Event Detail</h3>
  <button class="panel-close" onclick="closePanel()">&times;</button>
</div>
<div class="panel-body">
  <div class="field">
    <div class="field-label">Timestamp</div>
    <div class="field-value">{{.Entry.Timestamp}}</div>
  </div>
  <div class="field">
    <div class="field-label">From</div>
    <div class="field-value">{{.Entry.FromAgent}}</div>
  </div>
  <div class="field">
    <div class="field-label">To</div>
    <div class="field-value">{{.Entry.ToAgent}}</div>
  </div>
  <div class="field">
    <div class="field-label">Status</div>
    <div class="field-value">
      {{if eq .Entry.Status "delivered"}}<span class="badge-delivered">delivered</span>
      {{else if eq .Entry.Status "blocked"}}<span class="badge-blocked">blocked</span>
      {{else if eq .Entry.Status "rejected"}}<span class="badge-rejected">rejected</span>
      {{else if eq .Entry.Status "quarantined"}}<span class="badge-quarantined">quarantined</span>
      {{else}}{{.Entry.Status}}{{end}}
    </div>
  </div>
  <div class="field">
    <div class="field-label">Decision</div>
    <div class="field-value">{{.Entry.PolicyDecision}}</div>
  </div>
  <div class="field">
    <div class="field-label">Signature Verified</div>
    <div class="field-value">
      {{if eq .Entry.SignatureVerified 1}}<span class="badge-verified">verified</span>
      {{else if eq .Entry.SignatureVerified -1}}<span class="badge-invalid">invalid</span>
      {{else}}<span class="badge-unsigned">unsigned</span>{{end}}
    </div>
  </div>
  {{if .Entry.PubkeyFingerprint}}
  <div class="field">
    <div class="field-label">Fingerprint</div>
    <div class="field-value hash">{{.Entry.PubkeyFingerprint}}</div>
  </div>
  {{end}}
  <div class="field">
    <div class="field-label">Content Hash</div>
    <div class="field-value hash">{{.Entry.ContentHash}}</div>
  </div>
  <div class="field">
    <div class="field-label">Latency</div>
    <div class="field-value">{{.Entry.LatencyMs}}ms</div>
  </div>
  {{if .Rules}}
  <div class="field">
    <div class="field-label">Rules Triggered</div>
    {{range .Rules}}
    <div style="margin-bottom:4px">
      <a href="#" class="field-value" style="color:var(--accent-light);text-decoration:none;font-size:0.78rem" hx-get="/dashboard/api/rule/{{.}}" hx-target="#panel-content" hx-swap="innerHTML">{{.}}</a>
    </div>
    {{end}}
  </div>
  {{end}}
</div>`))

var ruleDetailTmpl = template.Must(template.New("rule-detail").Parse(`
<div class="panel-header">
  <h3>Rule Detail</h3>
  <button class="panel-close" onclick="closePanel()">&times;</button>
</div>
<div class="panel-body">
  <div class="field">
    <div class="field-label">ID</div>
    <div class="field-value">{{.ID}}</div>
  </div>
  <div class="field">
    <div class="field-label">Name</div>
    <div class="field-value" style="font-family:var(--sans)">{{.Name}}</div>
  </div>
  <div class="field">
    <div class="field-label">Severity</div>
    <div class="field-value">
      {{if eq .Severity "critical"}}<span class="sev-critical">critical</span>
      {{else if eq .Severity "high"}}<span class="sev-high">high</span>
      {{else if eq .Severity "medium"}}<span class="sev-medium">medium</span>
      {{else if eq .Severity "low"}}<span class="sev-low">low</span>
      {{else}}<span class="sev-info">{{.Severity}}</span>{{end}}
    </div>
  </div>
  <div class="field">
    <div class="field-label">Category</div>
    <div class="field-value">{{.Category}}</div>
  </div>
  {{if .Description}}
  <div class="field">
    <div class="field-label">Description</div>
    <div class="field-value" style="font-family:var(--sans);font-size:0.82rem;line-height:1.5">{{.Description}}</div>
  </div>
  {{end}}
  {{if .Patterns}}
  <div class="field">
    <div class="field-label">Patterns</div>
    {{range .Patterns}}
    <div class="pattern-item">{{.}}</div>
    {{end}}
  </div>
  {{end}}
  {{if .TruePositives}}
  <div class="field">
    <div class="field-label">True Positive Examples</div>
    {{range .TruePositives}}
    <div class="pattern-item" style="border-left:2px solid var(--danger)">{{.}}</div>
    {{end}}
  </div>
  {{end}}
  {{if .FalsePositives}}
  <div class="field">
    <div class="field-label">False Positive Examples</div>
    {{range .FalsePositives}}
    <div class="pattern-item" style="border-left:2px solid var(--success)">{{.}}</div>
    {{end}}
  </div>
  {{end}}
</div>`))

var enforcementTmpl = template.Must(template.New("enforcement").Parse(`
{{if .Overrides}}
<h2 style="font-size:0.95rem;font-weight:600;margin-bottom:16px">Active Overrides</h2>
<table>
  <thead><tr><th>Rule ID</th><th>Severity</th><th>Action</th><th></th></tr></thead>
  <tbody>
  {{range .Overrides}}
  <tr>
    <td>{{.ID}}</td>
    <td>{{.Severity}}</td>
    <td>{{.Action}}</td>
    <td><button class="btn btn-sm btn-danger" hx-delete="/dashboard/rules/enforcement/{{.ID}}" hx-confirm="Remove?" hx-target="closest tr" hx-swap="outerHTML">remove</button></td>
  </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<div class="empty" style="padding:20px 0">No overrides configured.</div>
{{end}}`))

var customRulesTmpl = template.Must(template.New("custom-rules").Parse(`
{{if .CustomFiles}}
<h2 style="font-size:0.95rem;font-weight:600;margin-bottom:16px">Custom Rules</h2>
<table>
  <thead><tr><th>Rule ID</th><th>File</th><th></th></tr></thead>
  <tbody>
  {{range .CustomFiles}}
  <tr>
    <td>{{.ID}}</td>
    <td style="color:var(--text3)">{{.Filename}}</td>
    <td><button class="btn btn-sm btn-danger" hx-delete="/dashboard/rules/custom/{{.ID}}" hx-confirm="Delete custom rule {{.ID}}?" hx-target="closest tr" hx-swap="outerHTML">delete</button></td>
  </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<div class="empty" style="padding:20px 0">
  {{if .CustomRulesDir}}No custom rules in {{.CustomRulesDir}}.{{else}}Set <code style="background:var(--surface2);padding:2px 6px;border-radius:4px;font-family:var(--mono);font-size:0.75rem;color:var(--accent-light)">custom_rules_dir</code> in oktsec.yaml to enable custom rules.{{end}}
</div>
{{end}}`))

var identityTmpl = template.Must(template.New("identity").Parse(layoutHead + `
<h1>Agent <span>Identity</span></h1>
<p class="page-desc">Ed25519 public keys and revocation status.</p>

<div class="card">
  <h2>Active Keys</h2>
  {{if .Keys}}
  <table>
    <thead><tr><th>Agent</th><th>Fingerprint</th><th>Actions</th></tr></thead>
    <tbody>
    {{range .Keys}}
    <tr>
      <td>{{.Name}}</td>
      <td class="fp">{{.Fingerprint}}</td>
      <td>
        <form method="POST" action="/dashboard/identity/revoke" style="display:inline">
          <input type="hidden" name="agent" value="{{.Name}}">
          <button type="submit" class="btn btn-sm btn-danger" onclick="return confirm('Revoke key for {{.Name}}?')">revoke</button>
        </form>
      </td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}
  <div class="empty">No keys loaded.{{if .KeysDir}} Keys directory: {{.KeysDir}}{{end}}</div>
  {{end}}
</div>

{{if .Revoked}}
<div class="card">
  <h2>Revoked Keys</h2>
  <table>
    <thead><tr><th>Agent</th><th>Fingerprint</th><th>Revoked At</th><th>Reason</th></tr></thead>
    <tbody>
    {{range .Revoked}}
    <tr>
      <td>{{.AgentName}}</td>
      <td class="fp">{{.Fingerprint}}</td>
      <td>{{.RevokedAt}}</td>
      <td style="color:var(--text3)">{{.Reason}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
</div>
{{end}}

<div class="card">
  <h2>Mode</h2>
  <table>
    <tr>
      <td style="color:var(--text3)">Current mode</td>
      <td>
        {{if .RequireSig}}<span class="badge-blocked">enforce</span>{{else}}<span class="badge-quarantined">observe</span>{{end}}
        <form method="POST" action="/dashboard/mode/toggle" style="display:inline;margin-left:12px"><button type="submit" class="toggle-btn">switch to {{if .RequireSig}}observe{{else}}enforce{{end}}</button></form>
      </td>
    </tr>
    <tr><td style="color:var(--text3)">Signatures</td><td>{{if .RequireSig}}required — unsigned messages are rejected{{else}}optional — unsigned messages are allowed{{end}}</td></tr>
  </table>
</div>
` + layoutFoot))
