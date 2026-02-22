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

/* Quarantine */
.q-preview{font-family:var(--mono);font-size:0.75rem;color:var(--text2);background:var(--bg);padding:8px 12px;border-radius:6px;max-height:60px;overflow:hidden;white-space:pre-wrap;word-break:break-all}
.q-content{font-family:var(--mono);font-size:0.78rem;color:var(--text);background:var(--bg);padding:12px 16px;border-radius:6px;white-space:pre-wrap;word-break:break-all;max-height:300px;overflow-y:auto;border:1px solid var(--border)}
.q-actions{display:flex;gap:8px;margin-top:8px}
.pending-badge{background:var(--warn);color:#000;font-size:0.65rem;font-weight:700;padding:2px 6px;border-radius:8px;margin-left:6px}
.badge-pending{background:#f59e0b20;color:var(--warn);padding:3px 8px;border-radius:4px;font-size:0.7rem;font-weight:600}
.badge-approved{background:#22c55e20;color:var(--success);padding:3px 8px;border-radius:4px;font-size:0.7rem;font-weight:600}
.badge-expired{background:var(--surface2);color:var(--text3);padding:3px 8px;border-radius:4px;font-size:0.7rem;font-weight:600}

/* Risk bar */
.risk-bar{height:8px;border-radius:4px;background:var(--surface2);position:relative;min-width:60px}
.risk-bar-fill{height:100%;border-radius:4px;transition:width 0.3s}
.risk-low{background:var(--success)}
.risk-med{background:var(--warn)}
.risk-high{background:var(--danger)}

/* Horizontal bar chart */
.hbar{display:flex;align-items:center;gap:8px;margin-bottom:6px}
.hbar-label{min-width:80px;font-family:var(--mono);font-size:0.75rem;color:var(--text2);text-align:right}
.hbar-track{flex:1;height:20px;background:var(--surface2);border-radius:4px;overflow:hidden}
.hbar-fill{height:100%;border-radius:4px;transition:width 0.3s}
.hbar-count{min-width:40px;font-family:var(--mono);font-size:0.75rem;color:var(--text3)}

/* Alert banner */
.alert-banner{padding:14px 20px;border-radius:10px;margin-bottom:20px;display:flex;align-items:center;gap:12px;font-size:0.88rem}
.alert-banner.warn{background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.3);color:var(--warn)}
.alert-banner strong{font-weight:600}
.alert-banner .btn{margin-left:auto;white-space:nowrap}

/* Rule categories accordion */
.rule-category{border-bottom:1px solid var(--border)}
.rule-category:last-child{border-bottom:none}
.rule-cat-header{display:flex;align-items:center;gap:12px;padding:14px 4px;cursor:pointer;list-style:none;user-select:none;transition:background 0.15s}
.rule-cat-header:hover{background:var(--surface2)}
.rule-cat-header::-webkit-details-marker{display:none}
.rule-cat-header::before{content:'\25B8';color:var(--text3);font-size:0.75rem;transition:transform 0.2s;width:14px;text-align:center}
details[open] > .rule-cat-header::before{transform:rotate(90deg)}
.rule-cat-name{font-weight:600;font-size:0.85rem;min-width:180px}
.rule-cat-count{color:var(--text3);font-size:0.72rem;font-family:var(--mono)}
.rule-cat-badges{display:flex;gap:4px;margin-left:auto}
.rule-cat-body{padding:0 0 8px 26px}

/* Toggle switch */
.toggle{position:relative;display:inline-block;width:36px;height:20px;flex-shrink:0}
.toggle input{opacity:0;width:0;height:0}
.toggle-slider{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background:var(--surface2);border:1px solid var(--border);border-radius:20px;transition:all 0.2s}
.toggle-slider::before{content:'';position:absolute;height:14px;width:14px;left:2px;bottom:2px;background:var(--text3);border-radius:50%;transition:all 0.2s}
input:checked + .toggle-slider{background:var(--accent-dim);border-color:var(--accent)}
input:checked + .toggle-slider::before{transform:translateX(16px);background:var(--accent-light)}

/* Rule row with toggle */
.rule-list-item{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--border);transition:background 0.2s}
.rule-list-item:last-child{border-bottom:none}
.rule-list-item:hover{background:var(--surface2);margin:0 -20px;padding:10px 20px}
.rule-list-item.disabled{opacity:0.45}
.rule-desc{color:var(--text3);font-size:0.72rem;font-family:var(--sans);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:350px}
.rule-info{flex:1;min-width:0;cursor:pointer}
.rule-info .rule-id-col{font-family:var(--mono);font-weight:600;font-size:0.78rem;color:var(--text)}
.rule-info .rule-name-col{color:var(--text2);font-size:0.75rem;font-family:var(--sans);margin-top:1px}

/* Category header with toggle */
.rule-cat-header{display:flex;align-items:center;gap:12px;padding:16px 4px;cursor:pointer;list-style:none;user-select:none;transition:background 0.15s}
.rule-cat-desc{color:var(--text3);font-size:0.72rem;font-family:var(--sans);margin-top:2px}
.cat-disabled-label{color:var(--text3);font-size:0.7rem;font-style:italic}

/* Inline add form */
.inline-add{display:flex;gap:8px;align-items:flex-end;padding:16px 0;border-top:1px solid var(--border);margin-top:8px}
.inline-add .form-group{margin:0}
.inline-add .form-group label{margin-bottom:2px}

/* Responsive */
@media(max-width:768px){
  .stats{grid-template-columns:repeat(2,1fr)}
  .panel{width:100%;max-width:100%}
  .form-row{flex-direction:column}
  .inline-add{flex-direction:column;align-items:stretch}
}
</style>
</head>
<body>
<nav>
  <a href="/dashboard" class="logo">okt<span>sec</span></a>
  <a href="/dashboard" class="{{if eq .Active "overview"}}active{{end}}">Overview</a>
  <a href="/dashboard/agents" class="{{if eq .Active "agents"}}active{{end}}">Agents</a>
  <a href="/dashboard/events" class="{{if eq .Active "events"}}active{{end}}">Events</a>
  <a href="/dashboard/rules" class="{{if eq .Active "rules"}}active{{end}}">Rules</a>
  <a href="/dashboard/settings" class="{{if eq .Active "settings"}}active{{end}}">Settings</a>
  <div class="spacer"></div>
  <span class="badge">{{if .RequireSig}}enforce{{else}}observe{{end}}</span>
  <form method="POST" action="/dashboard/logout" style="margin-left:8px;display:inline"><button type="submit" style="background:none;border:1px solid var(--border);color:var(--text3);padding:4px 10px;border-radius:6px;font-size:0.72rem;cursor:pointer;font-family:var(--sans);transition:all 0.2s" onmouseover="this.style.color='var(--danger)';this.style.borderColor='var(--danger)'" onmouseout="this.style.color='var(--text3)';this.style.borderColor='var(--border)'">Logout</button></form>
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

{{if .PendingReview}}
<div class="alert-banner warn">
  <strong>{{.PendingReview}} message{{if gt .PendingReview 1}}s{{end}} pending review</strong>
  <span style="color:var(--text2);font-size:0.78rem">Quarantined content awaiting human decision</span>
  <a href="/dashboard/quarantine" class="btn btn-sm" style="background:var(--warn);color:#000">Review Now</a>
</div>
{{end}}

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

var agentsTmpl = template.Must(template.New("agents").Parse(layoutHead + `
<h1>Registered <span>Agents</span></h1>
<p class="page-desc">Agents configured in oktsec.yaml with their access control rules.</p>

<div class="card">
  {{if .Agents}}
  <table>
    <thead><tr><th>Name</th><th>Description</th><th>Can Message</th><th>Tags</th></tr></thead>
    <tbody>
    {{range $name, $agent := .Agents}}
    <tr class="clickable" onclick="window.location='/dashboard/agents/{{$name}}'">
      <td style="font-weight:600">{{$name}}</td>
      <td style="color:var(--text2);font-family:var(--sans)">{{$agent.Description}}</td>
      <td>{{if $agent.CanMessage}}{{range $i, $t := $agent.CanMessage}}{{if $i}}, {{end}}{{$t}}{{end}}{{else}}<span style="color:var(--text3)">no restrictions</span>{{end}}</td>
      <td>{{range $i, $tag := $agent.Tags}}{{if $i}} {{end}}<span style="background:var(--surface2);padding:2px 6px;border-radius:4px;font-size:0.7rem">{{$tag}}</span>{{end}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}
  <div class="empty">No agents configured.</div>
  {{end}}
</div>

<div class="card">
  <h2>Add Agent</h2>
  <form method="POST" action="/dashboard/agents" class="inline-add">
    <div class="form-group" style="min-width:180px">
      <label>Name</label>
      <input type="text" name="name" placeholder="e.g. research-agent" required pattern="[a-zA-Z0-9][a-zA-Z0-9_-]*">
    </div>
    <div class="form-group" style="flex:2">
      <label>Can Message (comma-separated)</label>
      <input type="text" name="can_message" placeholder="e.g. target-agent, helper-agent">
    </div>
    <button type="submit" class="btn">Add</button>
  </form>
  <p style="color:var(--text3);font-size:0.72rem;margin-top:8px">Add description, tags, and other metadata from the agent detail page.</p>
</div>
` + layoutFoot))

var agentDetailTmpl = template.Must(template.New("agent-detail").Parse(layoutHead + `
<h1>Agent: <span>{{.Name}}</span></h1>
<p class="page-desc">{{if .Agent.Description}}{{.Agent.Description}}{{else}}Detail view for agent {{.Name}}.{{end}}</p>

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
    <div class="label">Quarantined</div>
    <div class="value" style="color:var(--accent-light)">{{.Quarantined}}</div>
  </div>
</div>

<div class="card">
  <h2>Configuration</h2>
  <table>
    <tr><td style="color:var(--text3)">Can message</td><td>{{range $i, $t := .Agent.CanMessage}}{{if $i}}, {{end}}{{$t}}{{end}}{{if not .Agent.CanMessage}}<span style="color:var(--text3)">no restrictions</span>{{end}}</td></tr>
    {{if .Agent.BlockedContent}}<tr><td style="color:var(--text3)">Blocked content</td><td>{{range $i, $c := .Agent.BlockedContent}}{{if $i}}, {{end}}{{$c}}{{end}}</td></tr>{{end}}
    {{if .Agent.Location}}<tr><td style="color:var(--text3)">Location</td><td>{{.Agent.Location}}</td></tr>{{end}}
    {{if .Agent.Tags}}<tr><td style="color:var(--text3)">Tags</td><td>{{range $i, $tag := .Agent.Tags}}{{if $i}} {{end}}<span style="background:var(--surface2);padding:2px 6px;border-radius:4px;font-size:0.72rem">{{$tag}}</span>{{end}}</td></tr>{{end}}
    {{if .Agent.CreatedBy}}<tr><td style="color:var(--text3)">Created by</td><td>{{.Agent.CreatedBy}}</td></tr>{{end}}
    {{if .Agent.CreatedAt}}<tr><td style="color:var(--text3)">Created at</td><td>{{.Agent.CreatedAt}}</td></tr>{{end}}
    {{if .KeyFP}}<tr><td style="color:var(--text3)">Key fingerprint</td><td class="fp">{{.KeyFP}}</td></tr>{{end}}
  </table>
  <div style="margin-top:16px;display:flex;gap:8px">
    <form method="POST" action="/dashboard/agents/{{.Name}}/keygen" style="display:inline"><button type="submit" class="btn btn-sm" onclick="return confirm('Generate new keypair for {{.Name}}? Existing key will be overwritten.')">Generate Keypair</button></form>
    <button class="btn btn-sm btn-danger" hx-delete="/dashboard/agents/{{.Name}}" hx-confirm="Delete agent {{.Name}}? This cannot be undone." hx-swap="none" onclick="setTimeout(function(){window.location='/dashboard/agents'},300)">Delete Agent</button>
  </div>
</div>

<div class="card">
  <h2>Edit Metadata</h2>
  <form method="POST" action="/dashboard/agents/{{.Name}}/edit">
    <div class="form-row">
      <div class="form-group">
        <label>Description</label>
        <input type="text" name="description" value="{{.Agent.Description}}">
      </div>
      <div class="form-group">
        <label>Location</label>
        <input type="text" name="location" value="{{.Agent.Location}}">
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>Can Message (space-separated)</label>
        <input type="text" name="can_message" value="{{range $i, $t := .Agent.CanMessage}}{{if $i}} {{end}}{{$t}}{{end}}">
      </div>
      <div class="form-group">
        <label>Tags (space-separated)</label>
        <input type="text" name="tags" value="{{range $i, $t := .Agent.Tags}}{{if $i}} {{end}}{{$t}}{{end}}">
      </div>
    </div>
    <button type="submit" class="btn btn-sm">Save</button>
  </form>
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
<p class="page-desc">{{.RuleCount}} rules across {{.CatCount}} categories. Click a category to manage its rules.</p>

<style>
.cat-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:16px;margin-bottom:24px}
@media(max-width:768px){.cat-grid{grid-template-columns:1fr}}
.cat-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px;cursor:pointer;transition:all 0.2s;position:relative;text-decoration:none;color:inherit;display:block}
.cat-card:hover{border-color:var(--accent);background:var(--surface2)}
.cat-card-head{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:10px}
.cat-card-name{font-weight:600;font-size:0.92rem}
.cat-card-count{color:var(--text3);font-size:0.72rem;font-family:var(--mono);white-space:nowrap}
.cat-card-desc{color:var(--text3);font-size:0.78rem;line-height:1.5;margin-bottom:14px}
.cat-card-footer{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.cat-card-sev{display:inline-flex;align-items:center;gap:4px;font-size:0.68rem;font-family:var(--mono);padding:3px 8px;border-radius:4px}
.cat-card-sev.critical{background:#ef444420;color:var(--danger)}
.cat-card-sev.high{background:#f59e0b20;color:var(--warn)}
.cat-card-sev.medium{background:#6366f120;color:var(--accent-light)}
.cat-card-sev.low{background:var(--surface2);color:var(--text3)}
.cat-card-status{margin-left:auto;font-size:0.72rem;font-weight:600}
.cat-card-status.all-on{color:var(--success)}
.cat-card-status.some-off{color:var(--warn)}
.cat-card-status.all-off{color:var(--text3)}
</style>

{{if .Categories}}
<div class="cat-grid">
  {{range .Categories}}
  <a href="/dashboard/rules/{{.Name}}" class="cat-card">
    <div class="cat-card-head">
      <span class="cat-card-name">{{.Name}}</span>
      <span class="cat-card-count">{{.Total}} rules</span>
    </div>
    {{if .Description}}<div class="cat-card-desc">{{.Description}}</div>{{end}}
    <div class="cat-card-footer">
      {{if .Critical}}<span class="cat-card-sev critical">{{.Critical}} critical</span>{{end}}
      {{if .High}}<span class="cat-card-sev high">{{.High}} high</span>{{end}}
      {{if .Medium}}<span class="cat-card-sev medium">{{.Medium}} medium</span>{{end}}
      {{if .Low}}<span class="cat-card-sev low">{{.Low}} low</span>{{end}}
      {{if eq .Disabled 0}}<span class="cat-card-status all-on">All enabled</span>
      {{else if eq .Disabled .Total}}<span class="cat-card-status all-off">All disabled</span>
      {{else}}<span class="cat-card-status some-off">{{.Disabled}}/{{.Total}} disabled</span>{{end}}
    </div>
  </a>
  {{end}}
</div>
{{else}}
<div class="empty">No rules loaded.</div>
{{end}}

{{if .CustomRulesDir}}
<div class="card">
  <h2>Custom Rules</h2>
  <p style="color:var(--text2);font-size:0.82rem;margin-bottom:16px">
    Add your own detection patterns. Custom rules are stored in <code style="background:var(--bg);padding:2px 6px;border-radius:4px;font-family:var(--mono);font-size:0.75rem;color:var(--accent-light)">{{.CustomRulesDir}}</code>
  </p>
  <div hx-get="/dashboard/rules/custom" hx-trigger="load" hx-target="this" hx-swap="innerHTML">
    <div class="empty">Loading...</div>
  </div>
  <form method="POST" action="/dashboard/rules/custom" style="border-top:1px solid var(--border);padding-top:16px;margin-top:16px">
    <div class="form-row">
      <div class="form-group" style="flex:1">
        <label>Rule name</label>
        <input type="text" name="name" placeholder="e.g. Block internal secrets" required>
      </div>
      <div class="form-group" style="max-width:120px">
        <label>Severity</label>
        <select name="severity">
          <option value="critical">Critical</option>
          <option value="high" selected>High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>
    </div>
    <div class="form-group" style="margin-bottom:12px">
      <label>Patterns (one per line)</label>
      <textarea name="patterns" placeholder="password&#10;secret_key&#10;api_token" style="min-height:60px"></textarea>
    </div>
    <input type="hidden" name="rule_id" value="">
    <input type="hidden" name="category" value="custom">
    <button type="submit" class="btn">Create Rule</button>
  </form>
</div>
{{end}}
` + layoutFoot))

// --- Category detail page ---

var categoryDetailTmpl = template.Must(template.New("category-detail").Parse(layoutHead + `
<style>
.breadcrumb{display:flex;align-items:center;gap:8px;margin-bottom:20px;font-size:0.82rem}
.breadcrumb a{color:var(--accent-light);text-decoration:none}
.breadcrumb a:hover{text-decoration:underline}
.breadcrumb .sep{color:var(--text3)}
.cat-header{display:flex;align-items:center;gap:16px;margin-bottom:8px}
.cat-header h1{margin:0}
.cat-toggle{margin-left:auto;display:flex;align-items:center;gap:8px;font-size:0.78rem;color:var(--text2)}
.rule-table{width:100%;border-collapse:collapse;table-layout:fixed}
.rule-table th{text-align:left;color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;padding:10px 12px;border-bottom:1px solid var(--border)}
.rule-table td{padding:12px;border-bottom:1px solid var(--border);font-size:0.82rem;vertical-align:top}
.rule-table tr:hover td{background:var(--surface2)}
.rule-table .rule-name{font-weight:600;font-family:var(--mono);font-size:0.78rem;color:var(--text);cursor:pointer;display:inline}
.rule-table .rule-name:hover{color:var(--accent-light)}
.rule-table .rule-desc{color:var(--text3);font-size:0.75rem;display:inline;margin-left:6px}
</style>

<div class="breadcrumb">
  <a href="/dashboard/rules">Rules</a>
  <span class="sep">/</span>
  <span>{{.Category.Name}}</span>
</div>

<div class="cat-header">
  <h1>{{.Category.Name}}</h1>
  <div class="cat-toggle">
    <span>{{.EnabledCount}} of {{.Category.Total}} enabled</span>
    <label class="toggle" title="Toggle all rules in this category">
      <input type="checkbox" {{if lt .Category.Disabled .Category.Total}}checked{{end}}
             hx-post="/dashboard/api/category/{{.Category.Name}}/toggle" hx-swap="none"
             onchange="setTimeout(function(){window.location.reload()},300)">
      <span class="toggle-slider"></span>
    </label>
  </div>
</div>
{{if .Category.Description}}<p class="page-desc">{{.Category.Description}}</p>{{end}}

<div class="card" style="padding:0;overflow:hidden">
  {{if .Category.Rules}}
  <table class="rule-table">
    <thead>
      <tr>
        <th style="width:52px">On</th>
        <th>Rule</th>
        <th style="width:80px;text-align:right">Severity</th>
      </tr>
    </thead>
    <tbody>
    {{range .Category.Rules}}
    <tr class="{{if .Disabled}}disabled{{end}}" style="{{if .Disabled}}opacity:0.5{{end}}">
      <td>
        <span id="toggle-{{.ID}}">
          <label class="toggle" title="{{if .Disabled}}Enable{{else}}Disable{{end}} this rule">
            <input type="checkbox" {{if not .Disabled}}checked{{end}} hx-post="/dashboard/api/rule/{{.ID}}/toggle" hx-target="#toggle-{{.ID}}" hx-swap="outerHTML">
            <span class="toggle-slider"></span>
          </label>
        </span>
      </td>
      <td>
        <span class="rule-name" hx-get="/dashboard/api/rule/{{.ID}}" hx-target="#panel-content" hx-swap="innerHTML">{{.ID}}</span>
        <span class="rule-desc">{{.Name}}{{if .Description}} — {{.Description}}{{end}}</span>
      </td>
      <td style="text-align:right">
        {{if eq .Severity "critical"}}<span class="sev-critical">critical</span>
        {{else if eq .Severity "high"}}<span class="sev-high">high</span>
        {{else if eq .Severity "medium"}}<span class="sev-medium">medium</span>
        {{else if eq .Severity "low"}}<span class="sev-low">low</span>
        {{else}}<span class="sev-info">{{.Severity}}</span>{{end}}
      </td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}
  <div class="empty">No rules in this category.</div>
  {{end}}
</div>
` + layoutFoot))

var eventDetailTmpl = template.Must(template.New("event-detail").Parse(`
<div class="panel-header">
  <h3>Event Detail</h3>
  <button class="panel-close" onclick="closePanel()">&times;</button>
</div>
<div class="panel-body">

  <!-- Status banner -->
  <div style="padding:12px 16px;border-radius:8px;margin-bottom:20px;font-size:0.85rem;line-height:1.5;
    {{if eq .Entry.Status "delivered"}}background:rgba(34,197,94,0.08);border:1px solid rgba(34,197,94,0.2);color:var(--success)
    {{else if eq .Entry.Status "blocked"}}background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.2);color:var(--danger)
    {{else if eq .Entry.Status "quarantined"}}background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.2);color:var(--warn)
    {{else if eq .Entry.Status "rejected"}}background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.2);color:var(--warn)
    {{else}}background:var(--surface2);border:1px solid var(--border);color:var(--text2){{end}}">
    {{.Decision}}
  </div>

  <!-- Message flow -->
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:20px;padding:12px 16px;background:var(--surface2);border-radius:8px">
    <span style="font-family:var(--mono);font-weight:600;font-size:0.85rem">{{.Entry.FromAgent}}</span>
    <span style="color:var(--text3);font-size:0.82rem">&rarr;</span>
    <span style="font-family:var(--mono);font-weight:600;font-size:0.85rem">{{.Entry.ToAgent}}</span>
    <span style="margin-left:auto;color:var(--text3);font-size:0.72rem;font-family:var(--mono)">{{.Entry.LatencyMs}}ms</span>
  </div>

  {{if .Rules}}
  <!-- Triggered rules — clickable, link to category page -->
  <div style="margin-bottom:20px">
    <div style="color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px">Rules triggered</div>
    {{range .Rules}}
    <a href="/dashboard/rules/{{.Category}}" style="display:flex;align-items:center;gap:10px;padding:10px 14px;background:var(--bg);border:1px solid var(--border);border-radius:8px;margin-bottom:6px;text-decoration:none;color:inherit;transition:border-color 0.2s"
       onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'">
      <div style="flex:1;min-width:0">
        <div style="font-family:var(--mono);font-weight:600;font-size:0.78rem;color:var(--text)">{{.RuleID}}</div>
        <div style="font-size:0.75rem;color:var(--text2);margin-top:2px">{{.Name}}</div>
        {{if .Match}}<div style="font-family:var(--mono);font-size:0.72rem;color:var(--text3);margin-top:4px;background:var(--surface2);padding:3px 8px;border-radius:4px;display:inline-block">matched: {{.Match}}</div>{{end}}
      </div>
      <div>
        {{if eq .Severity "CRITICAL"}}<span class="sev-critical">critical</span>
        {{else if eq .Severity "HIGH"}}<span class="sev-high">high</span>
        {{else if eq .Severity "MEDIUM"}}<span class="sev-medium">medium</span>
        {{else}}<span class="sev-low">{{.Severity}}</span>{{end}}
      </div>
      <span style="color:var(--text3);font-size:0.82rem">&rsaquo;</span>
    </a>
    {{end}}
    <div style="font-size:0.72rem;color:var(--text3);margin-top:6px">Click a rule to view its category and enable/disable it.</div>
  </div>
  {{end}}

  <!-- Details -->
  <div style="color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px">Details</div>
  <table style="width:100%;font-size:0.78rem;border-collapse:collapse">
    <tr><td style="color:var(--text3);padding:6px 0;width:120px">Time</td><td style="font-family:var(--mono);padding:6px 0">{{.Entry.Timestamp}}</td></tr>
    <tr><td style="color:var(--text3);padding:6px 0">Status</td><td style="padding:6px 0">
      {{if eq .Entry.Status "delivered"}}<span class="badge-delivered">delivered</span>
      {{else if eq .Entry.Status "blocked"}}<span class="badge-blocked">blocked</span>
      {{else if eq .Entry.Status "rejected"}}<span class="badge-rejected">rejected</span>
      {{else if eq .Entry.Status "quarantined"}}<span class="badge-quarantined">quarantined</span>
      {{else}}{{.Entry.Status}}{{end}}
    </td></tr>
    <tr><td style="color:var(--text3);padding:6px 0">Signature</td><td style="padding:6px 0">
      {{if eq .Entry.SignatureVerified 1}}<span style="color:var(--success)">Verified</span>
      {{else if eq .Entry.SignatureVerified -1}}<span style="color:var(--danger)">Invalid</span>
      {{else}}<span style="color:var(--text3)">Not signed</span>{{end}}
    </td></tr>
    {{if .Entry.PubkeyFingerprint}}<tr><td style="color:var(--text3);padding:6px 0">Key</td><td style="font-family:var(--mono);font-size:0.7rem;color:var(--text2);padding:6px 0;word-break:break-all">{{.Entry.PubkeyFingerprint}}</td></tr>{{end}}
    <tr><td style="color:var(--text3);padding:6px 0">Content hash</td><td style="font-family:var(--mono);font-size:0.7rem;color:var(--text2);padding:6px 0;word-break:break-all">{{.Entry.ContentHash}}</td></tr>
  </table>
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

// --- Quarantine templates ---

var quarantineDetailTmpl = template.Must(template.New("quarantine-detail").Parse(`
<div class="panel-header">
  <h3>Quarantined Message</h3>
  <button class="panel-close" onclick="closePanel()">&times;</button>
</div>
<div class="panel-body">

  <!-- Status banner -->
  <div style="padding:12px 16px;border-radius:8px;margin-bottom:20px;font-size:0.85rem;line-height:1.5;
    {{if eq .Item.Status "pending"}}background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.2);color:var(--warn)
    {{else if eq .Item.Status "approved"}}background:rgba(34,197,94,0.08);border:1px solid rgba(34,197,94,0.2);color:var(--success)
    {{else if eq .Item.Status "rejected"}}background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.2);color:var(--danger)
    {{else}}background:var(--surface2);border:1px solid var(--border);color:var(--text3){{end}}">
    {{if eq .Item.Status "pending"}}This message is held for review. Approve to deliver or reject to discard.
    {{else if eq .Item.Status "approved"}}Approved by {{.Item.ReviewedBy}} — message was delivered.
    {{else if eq .Item.Status "rejected"}}Rejected by {{.Item.ReviewedBy}} — message was not delivered.
    {{else if eq .Item.Status "expired"}}Expired without review — message was not delivered.
    {{else}}{{.Item.Status}}{{end}}
  </div>

  <!-- Message flow -->
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:20px;padding:12px 16px;background:var(--surface2);border-radius:8px">
    <span style="font-family:var(--mono);font-weight:600;font-size:0.85rem">{{.Item.FromAgent}}</span>
    <span style="color:var(--text3);font-size:0.82rem">&rarr;</span>
    <span style="font-family:var(--mono);font-weight:600;font-size:0.85rem">{{.Item.ToAgent}}</span>
  </div>

  <!-- Message content -->
  <div style="margin-bottom:20px">
    <div style="color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Message content</div>
    <div class="q-content">{{.Item.Content}}</div>
  </div>

  {{if .Rules}}
  <!-- Triggered rules — clickable, link to category page -->
  <div style="margin-bottom:20px">
    <div style="color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px">Why it was quarantined</div>
    {{range .Rules}}
    <a href="/dashboard/rules/{{.Category}}" style="display:flex;align-items:center;gap:10px;padding:10px 14px;background:var(--bg);border:1px solid var(--border);border-radius:8px;margin-bottom:6px;text-decoration:none;color:inherit;transition:border-color 0.2s"
       onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'">
      <div style="flex:1;min-width:0">
        <div style="font-family:var(--mono);font-weight:600;font-size:0.78rem;color:var(--text)">{{.RuleID}}</div>
        <div style="font-size:0.75rem;color:var(--text2);margin-top:2px">{{.Name}}</div>
        {{if .Match}}<div style="font-family:var(--mono);font-size:0.72rem;color:var(--text3);margin-top:4px;background:var(--surface2);padding:3px 8px;border-radius:4px;display:inline-block">matched: {{.Match}}</div>{{end}}
      </div>
      <div>
        {{if eq .Severity "CRITICAL"}}<span class="sev-critical">critical</span>
        {{else if eq .Severity "HIGH"}}<span class="sev-high">high</span>
        {{else if eq .Severity "MEDIUM"}}<span class="sev-medium">medium</span>
        {{else}}<span class="sev-low">{{.Severity}}</span>{{end}}
      </div>
      <span style="color:var(--text3);font-size:0.82rem">&rsaquo;</span>
    </a>
    {{end}}
    <div style="font-size:0.72rem;color:var(--text3);margin-top:6px">Click a rule to view its category and enable/disable it.</div>
  </div>
  {{end}}

  <!-- Details -->
  <div style="color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Details</div>
  <table style="width:100%;font-size:0.78rem;border-collapse:collapse">
    <tr><td style="color:var(--text3);padding:6px 0;width:100px">Created</td><td style="font-family:var(--mono);padding:6px 0">{{.Item.CreatedAt}}</td></tr>
    <tr><td style="color:var(--text3);padding:6px 0">Expires</td><td style="font-family:var(--mono);padding:6px 0">{{.Item.ExpiresAt}}</td></tr>
    {{if .Item.ReviewedBy}}<tr><td style="color:var(--text3);padding:6px 0">Reviewed</td><td style="padding:6px 0">{{.Item.ReviewedBy}} at {{.Item.ReviewedAt}}</td></tr>{{end}}
  </table>

  {{if eq .Item.Status "pending"}}
  <div class="q-actions" style="margin-top:20px">
    <button class="btn" style="background:var(--success)" hx-post="/dashboard/api/quarantine/{{.Item.ID}}/approve" hx-target="#q-row-{{.Item.ID}}" hx-swap="outerHTML" onclick="closePanel()">Approve &amp; Deliver</button>
    <button class="btn btn-danger" hx-post="/dashboard/api/quarantine/{{.Item.ID}}/reject" hx-target="#q-row-{{.Item.ID}}" hx-swap="outerHTML" onclick="closePanel()">Reject</button>
  </div>
  {{end}}
</div>`))

var quarantineRowTmpl = template.Must(template.New("quarantine-row").Funcs(template.FuncMap{
	"truncate": func(s string, n int) string {
		if len(s) <= n {
			return s
		}
		return s[:n] + "..."
	},
}).Parse(`<tr id="q-row-{{.Item.ID}}">
  <td>{{.Item.CreatedAt}}</td>
  <td>{{.Item.FromAgent}}</td>
  <td>{{.Item.ToAgent}}</td>
  <td><div class="q-preview">{{truncate .Item.Content 80}}</div></td>
  <td>
    {{if eq .Item.Status "pending"}}<span class="badge-pending">pending</span>
    {{else if eq .Item.Status "approved"}}<span class="badge-approved">approved</span>
    {{else if eq .Item.Status "rejected"}}<span class="badge-blocked">rejected</span>
    {{else if eq .Item.Status "expired"}}<span class="badge-expired">expired</span>
    {{else}}{{.Item.Status}}{{end}}
  </td>
  <td style="font-size:0.72rem">{{.Item.ExpiresAt}}</td>
  <td>
    <div style="display:flex;gap:4px;align-items:center">
      <button class="btn btn-sm" style="padding:2px 8px;font-size:0.7rem" hx-get="/dashboard/api/quarantine/{{.Item.ID}}" hx-target="#panel-content" hx-swap="innerHTML">view</button>
    </div>
  </td>
</tr>`))

// --- Rule toggle partial ---

var ruleToggleTmpl = template.Must(template.New("rule-toggle").Parse(`<span id="toggle-{{.ID}}">
  <label class="toggle" title="{{if .Enabled}}Disable{{else}}Enable{{end}} this rule">
    <input type="checkbox" {{if .Enabled}}checked{{end}} hx-post="/dashboard/api/rule/{{.ID}}/toggle" hx-target="#toggle-{{.ID}}" hx-swap="outerHTML">
    <span class="toggle-slider"></span>
  </label>
</span>`))

// --- Settings page ---

var settingsTmpl = template.Must(template.New("settings").Parse(layoutHead + `
<h1>Settings</h1>
<p class="page-desc">Configure security mode, agent identity, quarantine behavior, and server options.</p>

<div class="card">
  <h2>Security Mode</h2>
  <p style="color:var(--text2);font-size:0.82rem;margin-bottom:16px;line-height:1.6">
    Controls how oktsec handles message signatures. This is the most important setting — it determines whether agents can communicate without proving their identity.
  </p>
  <div style="display:flex;gap:16px;margin-bottom:16px">
    <div style="flex:1;padding:16px;border-radius:8px;border:1px solid {{if .RequireSig}}var(--accent){{else}}var(--border){{end}};background:{{if .RequireSig}}rgba(99,102,241,0.06){{else}}var(--surface){{end}}">
      <div style="font-weight:600;font-size:0.88rem;margin-bottom:6px;color:{{if .RequireSig}}var(--accent-light){{else}}var(--text2){{end}}">
        {{if .RequireSig}}&#x2713; {{end}}Enforce Mode
      </div>
      <p style="color:var(--text3);font-size:0.78rem;line-height:1.5">
        Every message must include a valid Ed25519 signature. Unsigned or tampered messages are <strong style="color:var(--danger)">rejected</strong>. Use this in production.
      </p>
    </div>
    <div style="flex:1;padding:16px;border-radius:8px;border:1px solid {{if not .RequireSig}}var(--warn){{else}}var(--border){{end}};background:{{if not .RequireSig}}rgba(245,158,11,0.06){{else}}var(--surface){{end}}">
      <div style="font-weight:600;font-size:0.88rem;margin-bottom:6px;color:{{if not .RequireSig}}var(--warn){{else}}var(--text2){{end}}">
        {{if not .RequireSig}}&#x2713; {{end}}Observe Mode
      </div>
      <p style="color:var(--text3);font-size:0.78rem;line-height:1.5">
        Messages are scanned for threats but signatures are <strong style="color:var(--warn)">not required</strong>. Useful for onboarding agents gradually.
      </p>
    </div>
  </div>
  <form method="POST" action="/dashboard/mode/toggle">
    <button type="submit" class="btn" style="background:{{if .RequireSig}}var(--warn){{else}}var(--accent){{end}}">
      Switch to {{if .RequireSig}}Observe{{else}}Enforce{{end}} Mode
    </button>
  </form>
</div>

<div class="card">
  <h2>Agent Identity &amp; Keys</h2>
  <p style="color:var(--text2);font-size:0.82rem;margin-bottom:16px;line-height:1.6">
    Each agent has an Ed25519 keypair. The public key is stored here; the agent holds the private key. Keys are used to sign and verify messages between agents.
  </p>
  <div style="color:var(--text3);font-size:0.78rem;margin-bottom:12px">
    <strong>Keys directory:</strong> <code style="background:var(--bg);padding:2px 8px;border-radius:4px;font-family:var(--mono);font-size:0.75rem;color:var(--accent-light)">{{.KeysDir}}</code>
  </div>
  {{if .Keys}}
  <table>
    <thead><tr><th>Agent</th><th>Fingerprint</th><th>Status</th><th></th></tr></thead>
    <tbody>
    {{range .Keys}}
    <tr>
      <td style="font-weight:600">{{.Name}}</td>
      <td class="fp">{{.Fingerprint}}</td>
      <td>{{if index $.RevokedFPs .Fingerprint}}<span class="sev-high">revoked</span>{{else}}<span style="color:var(--success);font-size:0.75rem">active</span>{{end}}</td>
      <td>
        {{if not (index $.RevokedFPs .Fingerprint)}}
        <form method="POST" action="/dashboard/identity/revoke" style="display:inline">
          <input type="hidden" name="agent" value="{{.Name}}">
          <button type="submit" class="btn btn-sm btn-danger" onclick="return confirm('Revoke key for {{.Name}}? This agent will not be able to send signed messages.')">Revoke</button>
        </form>
        {{end}}
      </td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}
  <div class="empty">No agent keys found. Generate keys from the <a href="/dashboard/agents" style="color:var(--accent-light)">Agents</a> page.</div>
  {{end}}

  {{if .Revoked}}
  <div style="margin-top:16px">
    <h3 style="font-size:0.82rem;color:var(--text3);margin-bottom:8px">Revoked Keys</h3>
    <table>
      <thead><tr><th>Agent</th><th>Fingerprint</th><th>Revoked</th></tr></thead>
      <tbody>
      {{range .Revoked}}
      <tr>
        <td>{{.AgentName}}</td>
        <td class="fp">{{.Fingerprint}}</td>
        <td style="color:var(--text3)">{{.RevokedAt}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
  </div>
  {{end}}
</div>

<div class="card">
  <h2>Quarantine Queue</h2>
  <p style="color:var(--text2);font-size:0.82rem;margin-bottom:16px;line-height:1.6">
    When a message triggers high-severity rules, it's held in quarantine instead of being delivered. A human must approve or reject it before the content reaches the destination agent.
  </p>
  <div style="display:flex;gap:24px;margin-bottom:16px">
    <div>
      <span style="color:var(--text3);font-size:0.72rem;text-transform:uppercase;letter-spacing:1px">Status</span>
      <div style="font-size:1rem;font-weight:600;margin-top:4px;color:{{if .QEnabled}}var(--success){{else}}var(--danger){{end}}">
        {{if .QEnabled}}Enabled{{else}}Disabled{{end}}
      </div>
    </div>
    <div>
      <span style="color:var(--text3);font-size:0.72rem;text-transform:uppercase;letter-spacing:1px">Auto-Expiry</span>
      <div style="font-size:1rem;font-weight:600;margin-top:4px">{{.QExpiryHours}}h</div>
    </div>
    <div>
      <span style="color:var(--text3);font-size:0.72rem;text-transform:uppercase;letter-spacing:1px">Pending</span>
      <div style="font-size:1rem;font-weight:600;margin-top:4px;color:{{if .QPending}}var(--warn){{else}}var(--success){{end}}">{{.QPending}}</div>
    </div>
  </div>
  <p style="color:var(--text3);font-size:0.78rem;line-height:1.5">
    Quarantined messages expire after <strong>{{.QExpiryHours}} hours</strong> if not reviewed.
    Expired messages are preserved for audit but the content is not delivered.
    Edit <code style="background:var(--bg);padding:2px 6px;border-radius:4px;font-size:0.72rem;font-family:var(--mono);color:var(--accent-light)">quarantine.expiry_hours</code> in the config file to change this.
  </p>
</div>

<div class="card">
  <h2>Server</h2>
  <p style="color:var(--text2);font-size:0.82rem;margin-bottom:16px;line-height:1.6">
    Core proxy settings. These require a server restart to take effect.
  </p>
  <table>
    <tbody>
    <tr><td style="color:var(--text3);font-weight:600;width:160px">Port</td><td>{{.ServerPort}}</td></tr>
    <tr><td style="color:var(--text3);font-weight:600">Bind Address</td><td>{{.ServerBind}}</td></tr>
    <tr><td style="color:var(--text3);font-weight:600">Log Level</td><td>{{.LogLevel}}</td></tr>
    <tr><td style="color:var(--text3);font-weight:600">Custom Rules Dir</td><td>{{if .CustomRulesDir}}{{.CustomRulesDir}}{{else}}<span style="color:var(--text3)">not set</span>{{end}}</td></tr>
    <tr><td style="color:var(--text3);font-weight:600">Webhooks</td><td>{{.WebhookCount}} configured</td></tr>
    </tbody>
  </table>
</div>
` + layoutFoot))

// --- Events page (merged audit log + quarantine) ---

var eventsTmpl = template.Must(template.New("events").Funcs(template.FuncMap{
	"truncate": func(s string, n int) string {
		if len(s) <= n { return s }
		return s[:n] + "..."
	},
}).Parse(layoutHead + `
<h1>Events</h1>
<p class="page-desc">All security events, quarantine decisions, and message audit trail. <span class="sse-indicator" id="sse-status"><span class="sse-dot" id="sse-dot"></span> <span id="sse-label">connecting</span></span></p>

<div class="tabs" data-tab-group="events">
  <button class="tab {{if eq .Tab "all"}}active{{end}}" data-tab="all" onclick="switchTab('events','all')">All Events</button>
  <button class="tab {{if eq .Tab "quarantine"}}active{{end}}" data-tab="quarantine" onclick="switchTab('events','quarantine')">Quarantine{{if .QPending}} <span class="pending-badge">{{.QPending}}</span>{{end}}</button>
  <button class="tab {{if eq .Tab "blocked"}}active{{end}}" data-tab="blocked" onclick="switchTab('events','blocked')">Blocked</button>
</div>

<!-- All Events -->
<div class="tab-content {{if eq .Tab "all"}}active{{end}}" data-tab-content="events" data-tab-name="all">
  <div class="search-bar">
    <span class="search-icon">&#x1F50D;</span>
    <input type="text" placeholder="Search events by agent, rule, or content hash..."
           hx-get="/dashboard/api/search" hx-trigger="keyup changed delay:300ms" hx-target="#search-results" name="q">
  </div>

  <div id="search-results">
  {{if .Entries}}
  <table>
    <thead><tr><th>Time</th><th>From</th><th>To</th><th>Status</th><th>Signature</th></tr></thead>
    <tbody id="events-body">
    {{range .Entries}}
    <tr class="clickable" hx-get="/dashboard/api/event/{{.ID}}" hx-target="#panel-content" hx-swap="innerHTML">
      <td>{{.Timestamp}}</td>
      <td>{{.FromAgent}}</td>
      <td>{{.ToAgent}}</td>
      <td><span class="badge-{{.Status}}">{{.Status}}</span></td>
      <td>
        {{if eq .SigStatus "verified"}}<span class="badge-verified" title="Signature verified">&#x2714;</span>
        {{else if eq .SigStatus "unsigned"}}<span class="badge-unsigned" title="No signature">&#x2014;</span>
        {{else if eq .SigStatus "invalid"}}<span class="badge-invalid" title="Invalid signature">&#x2718;</span>
        {{else}}{{.SigStatus}}{{end}}
      </td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}
  <div class="empty">No events yet. Send a message through the proxy to see activity here.</div>
  {{end}}
  </div>
</div>

<!-- Quarantine -->
<div class="tab-content {{if eq .Tab "quarantine"}}active{{end}}" data-tab-content="events" data-tab-name="quarantine">
  {{if .QStats}}
  <div class="stats" style="grid-template-columns:repeat(4,1fr);margin-bottom:20px">
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

  <div style="display:flex;gap:8px;margin-bottom:16px">
    <a href="/dashboard/events?tab=quarantine&status=pending" class="toggle-btn {{if eq .QStatusFilter "pending"}}active{{end}}" style="{{if eq .QStatusFilter "pending"}}background:var(--accent-dim);color:#fff;border-color:var(--accent){{end}}">Pending</a>
    <a href="/dashboard/events?tab=quarantine&status=approved" class="toggle-btn {{if eq .QStatusFilter "approved"}}active{{end}}" style="{{if eq .QStatusFilter "approved"}}background:var(--accent-dim);color:#fff;border-color:var(--accent){{end}}">Approved</a>
    <a href="/dashboard/events?tab=quarantine&status=rejected" class="toggle-btn {{if eq .QStatusFilter "rejected"}}active{{end}}" style="{{if eq .QStatusFilter "rejected"}}background:var(--accent-dim);color:#fff;border-color:var(--accent){{end}}">Rejected</a>
    <a href="/dashboard/events?tab=quarantine&status=" class="toggle-btn {{if eq .QStatusFilter ""}}active{{end}}" style="{{if eq .QStatusFilter ""}}background:var(--accent-dim);color:#fff;border-color:var(--accent){{end}}">All</a>
  </div>

  {{if .QItems}}
  <table>
    <thead><tr><th>Time</th><th>From</th><th>To</th><th>Content</th><th>Status</th><th>Actions</th></tr></thead>
    <tbody>
    {{range .QItems}}
    <tr id="q-row-{{.ID}}">
      <td>{{.CreatedAt}}</td>
      <td>{{.FromAgent}}</td>
      <td>{{.ToAgent}}</td>
      <td><div class="q-preview">{{truncate .Content 80}}</div></td>
      <td><span class="badge-{{.Status}}">{{.Status}}</span></td>
      <td>
        {{if eq .Status "pending"}}
        <div class="q-actions">
          <button class="btn btn-sm" style="background:var(--success)" hx-post="/dashboard/api/quarantine/{{.ID}}/approve" hx-target="#q-row-{{.ID}}" hx-swap="outerHTML">Approve</button>
          <button class="btn btn-sm btn-danger" hx-post="/dashboard/api/quarantine/{{.ID}}/reject" hx-target="#q-row-{{.ID}}" hx-swap="outerHTML">Reject</button>
        </div>
        {{end}}
      </td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}
  <div class="empty">No quarantined messages{{if .QStatusFilter}} with status "{{.QStatusFilter}}"{{end}}.</div>
  {{end}}
</div>

<!-- Blocked -->
<div class="tab-content {{if eq .Tab "blocked"}}active{{end}}" data-tab-content="events" data-tab-name="blocked">
  {{if .BlockedEntries}}
  <table>
    <thead><tr><th>Time</th><th>From</th><th>To</th><th>Status</th><th>Rules</th></tr></thead>
    <tbody>
    {{range .BlockedEntries}}
    <tr class="clickable" hx-get="/dashboard/api/event/{{.ID}}" hx-target="#panel-content" hx-swap="innerHTML">
      <td>{{.Timestamp}}</td>
      <td>{{.FromAgent}}</td>
      <td>{{.ToAgent}}</td>
      <td><span class="badge-{{.Status}}">{{.Status}}</span></td>
      <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{.RulesTriggered}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
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
  src.onopen = function() { dot.classList.add('connected'); label.textContent = 'live'; };
  src.onerror = function() { dot.classList.remove('connected'); label.textContent = 'reconnecting'; };
  src.onmessage = function(e) {
    try {
      var ev = JSON.parse(e.data);
      var tbody = document.getElementById('events-body');
      if (!tbody) return;
      var row = document.createElement('tr');
      row.className = 'clickable';
      row.setAttribute('hx-get', '/dashboard/api/event/' + ev.id);
      row.setAttribute('hx-target', '#panel-content');
      row.setAttribute('hx-swap', 'innerHTML');
      row.innerHTML = '<td>' + ev.timestamp + '</td><td>' + (ev.from_agent||'') + '</td><td>' + (ev.to_agent||'') + '</td><td><span class="badge-' + ev.status + '">' + ev.status + '</span></td><td></td>';
      tbody.insertBefore(row, tbody.firstChild);
      htmx.process(row);
    } catch(err) {}
  };
})();
</script>
` + layoutFoot))
