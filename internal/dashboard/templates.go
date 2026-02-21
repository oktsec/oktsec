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
.agent-targets{color:var(--text3);font-size:0.78rem}

/* Rule list */
.rule-row{display:flex;align-items:center;gap:12px;padding:12px 0;border-bottom:1px solid var(--border)}
.rule-row:last-child{border-bottom:none}
.rule-id{font-family:var(--mono);font-weight:600;min-width:200px;font-size:0.82rem}
.severity-critical{color:var(--danger);font-weight:700}
.severity-high{color:var(--warn);font-weight:600}
.severity-medium{color:var(--accent-light)}
.severity-low{color:var(--text3)}

/* Empty state */
.empty{color:var(--text3);text-align:center;padding:40px 0;font-size:0.85rem}

/* Responsive */
@media(max-width:768px){.stats{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>
<nav>
  <a href="/dashboard" class="logo">okt<span>sec</span></a>
  <a href="/dashboard" class="{{if eq .Active "overview"}}active{{end}}">Overview</a>
  <a href="/dashboard/agents" class="{{if eq .Active "agents"}}active{{end}}">Agents</a>
  <a href="/dashboard/logs" class="{{if eq .Active "logs"}}active{{end}}">Audit Log</a>
  <a href="/dashboard/rules" class="{{if eq .Active "rules"}}active{{end}}">Rules</a>
  <div class="spacer"></div>
  <span class="badge">{{if .RequireSig}}enforce{{else}}observe{{end}}</span>
</nav>
<main>`

const layoutFoot = `</main>
</body>
</html>`

var overviewTmpl = template.Must(template.New("overview").Parse(layoutHead + `
<h1>Dashboard <span>Overview</span></h1>
<p class="page-desc">Real-time view of agent communication and security events.</p>

<div class="stats" hx-get="/dashboard/api/stats" hx-trigger="every 5s" hx-swap="none">
  <div class="stat">
    <div class="label">Total Messages</div>
    <div class="value">{{.Stats.TotalMessages}}</div>
  </div>
  <div class="stat">
    <div class="label">Delivered</div>
    <div class="value success">{{.Stats.Delivered}}</div>
  </div>
  <div class="stat">
    <div class="label">Blocked</div>
    <div class="value danger">{{.Stats.Blocked}}</div>
  </div>
  <div class="stat">
    <div class="label">Rejected</div>
    <div class="value warn">{{.Stats.Rejected}}</div>
  </div>
</div>

<div class="card">
  <h2><span class="dot"></span> Recent Events</h2>
  <div id="recent-events" hx-get="/dashboard/api/recent" hx-trigger="every 5s" hx-swap="innerHTML">
    {{if .Recent}}
    <table>
      <thead><tr><th>Time</th><th>From</th><th>To</th><th>Status</th><th>Decision</th><th>Verified</th></tr></thead>
      <tbody>
      {{range .Recent}}
      <tr>
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
    <div class="empty">No events yet. Send a message through the proxy to see activity.</div>
    {{end}}
  </div>
</div>

<div class="card">
  <h2>Configuration</h2>
  <table>
    <tr><td style="color:var(--text3)">Mode</td><td>{{if .RequireSig}}<span class="badge-blocked">enforce</span>{{else}}<span class="badge-quarantined">observe</span>{{end}}</td></tr>
    <tr><td style="color:var(--text3)">Agents</td><td>{{.AgentCount}} configured</td></tr>
    <tr><td style="color:var(--text3)">Signatures</td><td>{{if .RequireSig}}required{{else}}optional{{end}}</td></tr>
  </table>
</div>
` + layoutFoot))

var recentPartialTmpl = template.Must(template.New("recent").Parse(`
{{if .}}
<table>
  <thead><tr><th>Time</th><th>From</th><th>To</th><th>Status</th><th>Decision</th><th>Verified</th></tr></thead>
  <tbody>
  {{range .}}
  <tr>
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

var logsTmpl = template.Must(template.New("logs").Parse(layoutHead + `
<h1>Audit <span>Log</span></h1>
<p class="page-desc">Complete record of all inter-agent communication.</p>

<div class="card">
  {{if .Entries}}
  <table>
    <thead><tr><th>Time</th><th>From</th><th>To</th><th>Status</th><th>Decision</th><th>Verified</th><th>Latency</th></tr></thead>
    <tbody>
    {{range .Entries}}
    <tr>
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
` + layoutFoot))

var agentsTmpl = template.Must(template.New("agents").Parse(layoutHead + `
<h1>Registered <span>Agents</span></h1>
<p class="page-desc">Agents configured in oktsec.yaml with their access control rules.</p>

<div class="card">
  {{if .Agents}}
  {{range $name, $agent := .Agents}}
  <div class="agent-row">
    <div class="agent-name">{{$name}}</div>
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

var rulesTmpl = template.Must(template.New("rules").Parse(layoutHead + `
<h1>Active <span>Rules</span></h1>
<p class="page-desc">Policy rules configured for content inspection and enforcement.</p>

<div class="card">
  {{if .Rules}}
  {{range .Rules}}
  <div class="rule-row">
    <div class="rule-id">{{.ID}}</div>
    <div>
      {{if eq .Severity "critical"}}<span class="severity-critical">CRITICAL</span>
      {{else if eq .Severity "high"}}<span class="severity-high">HIGH</span>
      {{else if eq .Severity "medium"}}<span class="severity-medium">MEDIUM</span>
      {{else}}<span class="severity-low">{{.Severity}}</span>{{end}}
    </div>
    <div style="color:var(--text2);font-size:0.82rem">{{.Action}}</div>
  </div>
  {{end}}
  {{else}}
  <div class="empty">No custom rules configured. Oktsec uses 144 built-in detection rules by default.</div>
  {{end}}
</div>
` + layoutFoot))
