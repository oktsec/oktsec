package dashboard

import "html/template"

var alertsTmpl = template.Must(template.New("alerts").Funcs(tmplFuncs).Parse(layoutHead + `
<style>
.alert-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--border);border:1px solid var(--border);border-radius:12px;overflow:hidden;margin-bottom:24px}
.alert-stat{background:var(--surface);padding:var(--sp-5) var(--sp-5);text-align:center}
.alert-stat .num{font-size:var(--text-3xl);font-weight:800;letter-spacing:-0.04em;font-family:var(--sans);line-height:1;color:var(--text)}
.alert-stat .lbl{font-size:var(--text-xs);text-transform:uppercase;letter-spacing:var(--ls-caps);color:var(--text3);margin-top:var(--sp-2);font-weight:500}
.alert-config{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px;margin-bottom:24px}
.alert-config h3{font-size:0.72rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);margin-bottom:14px;font-weight:500}
.config-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px}
.config-item{display:flex;align-items:center;gap:10px;padding:10px 14px;background:var(--bg);border:1px solid var(--border);border-radius:8px}
.config-item .dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.config-item .dot.on{background:var(--success)}
.config-item .dot.off{background:var(--text3);opacity:0.3}
.config-item .name{font-size:0.82rem;font-weight:500}
.config-item .val{font-size:0.72rem;color:var(--text3);margin-left:auto;font-family:var(--mono)}
.alert-table{width:100%;border-collapse:collapse;font-size:0.82rem}
.alert-table th{text-align:left;font-size:0.68rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);font-weight:500;padding:10px 12px;border-bottom:1px solid var(--border)}
.alert-table td{padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:middle}
.alert-table tr:last-child td{border-bottom:none}
.alert-table tr:hover td{background:var(--surface2)}
.event-badge{display:inline-flex;align-items:center;gap:5px;padding:3px 8px;border-radius:5px;font-size:0.72rem;font-weight:600;font-family:var(--mono)}
.event-badge.blocked{background:rgba(248,81,73,0.12);color:#f85149}
.event-badge.quarantined{background:rgba(210,153,34,0.12);color:#d29922}
.event-badge.llm_threat{background:rgba(137,87,229,0.12);color:#8957e5}
.event-badge.anomaly,.event-badge.agent_risk_elevated{background:rgba(210,153,34,0.12);color:#d29922}
.event-badge.agent_suspended{background:rgba(248,81,73,0.15);color:#f85149}
.event-badge.rule_triggered{background:rgba(56,139,253,0.12);color:var(--accent-light)}
.sev-dot{width:7px;height:7px;border-radius:50%;display:inline-block}
.sev-dot.critical{background:#f85149}
.sev-dot.high{background:#db6d28}
.sev-dot.medium{background:#d29922}
.sev-dot.low{background:#3fb950}
.sev-dot.info{background:var(--text3)}
.status-pill{font-size:0.68rem;padding:2px 7px;border-radius:4px;font-weight:600;font-family:var(--mono)}
.status-pill.sent{background:rgba(63,185,80,0.12);color:#3fb950}
.status-pill.failed{background:rgba(248,81,73,0.12);color:#f85149}
.empty-state{text-align:center;padding:60px 24px;color:var(--text3)}
.empty-state svg{width:48px;height:48px;stroke:var(--text3);opacity:0.3;margin-bottom:12px}
.empty-state p{font-size:0.88rem;margin:0}
.channel-mono{font-family:var(--mono);font-size:0.72rem;color:var(--text3);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.by-event-grid{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
@media(max-width:768px){.alert-stats{grid-template-columns:repeat(2,1fr)}.alert-table{font-size:0.75rem}}
</style>

<p class="page-desc">Notification channels and alert history for security events.</p>

<!-- Stats -->
<div class="alert-stats">
  <div class="alert-stat">
    <div class="num">{{.Stats.Total}}</div>
    <div class="lbl">Total Alerts</div>
  </div>
  <div class="alert-stat">
    <div class="num">{{.Stats.Last24h}}</div>
    <div class="lbl">Last 24h</div>
  </div>
  <div class="alert-stat">
    <div class="num">{{.WebhookCount}}</div>
    <div class="lbl">Channels</div>
  </div>
  <div class="alert-stat">
    <div class="num">{{.EventTypeCount}}</div>
    <div class="lbl">Event Types</div>
  </div>
</div>

<!-- Config summary -->
<div class="alert-config">
  <h3>Alert Configuration</h3>
  <div class="config-grid">
    <div class="config-item">
      <span class="dot {{if gt .WebhookCount 0}}on{{else}}off{{end}}"></span>
      <span class="name">Webhooks</span>
      <span class="val">{{.WebhookCount}} channel{{if ne .WebhookCount 1}}s{{end}}</span>
    </div>
    <div class="config-item">
      <span class="dot {{if .Cooldown}}on{{else}}off{{end}}"></span>
      <span class="name">Cooldown</span>
      <span class="val">{{if .Cooldown}}{{.Cooldown}}{{else}}off{{end}}</span>
    </div>
    <div class="config-item">
      <span class="dot {{if .LLMThreats}}on{{else}}off{{end}}"></span>
      <span class="name">LLM Threats</span>
      <span class="val">{{if .LLMThreats}}on{{else}}off{{end}}</span>
    </div>
    <div class="config-item">
      <span class="dot {{if .Suspensions}}on{{else}}off{{end}}"></span>
      <span class="name">Suspensions</span>
      <span class="val">{{if .Suspensions}}on{{else}}off{{end}}</span>
    </div>
  </div>
  {{if .Stats.ByEvent}}
  <div class="by-event-grid" style="margin-top:14px">
    {{range $event, $count := .Stats.ByEvent}}
    <span class="event-badge {{$event}}">{{$event}}: {{$count}}</span>
    {{end}}
  </div>
  {{end}}
</div>

<!-- Webhook channels -->
<div class="card" style="margin-bottom:24px">
  <h3 style="font-size:0.82rem;font-weight:600;margin-bottom:14px">Webhook Channels</h3>
  <p class="desc" style="margin-bottom:16px">Add webhook URLs for Slack, email, or any HTTP endpoint to receive alerts when oktsec blocks or quarantines a message.</p>
  <form method="POST" action="/dashboard/settings/webhooks" style="margin-bottom:16px">
    <div class="form-row">
      <div class="form-group" style="flex:1;min-width:140px">
        <label>Channel name</label>
        <input type="text" name="name" placeholder="e.g. slack-security" required pattern="[a-zA-Z0-9][a-zA-Z0-9_-]*">
      </div>
      <div class="form-group" style="flex:3">
        <label>Webhook URL</label>
        <input type="url" name="url" placeholder="https://hooks.slack.com/services/..." required>
      </div>
      <div class="form-group" style="align-self:flex-end">
        <button type="submit" class="btn">Add Channel</button>
      </div>
    </div>
  </form>
  {{if .WebhookChannels}}
  <table>
    <thead><tr><th>Channel</th><th>URL</th><th></th></tr></thead>
    <tbody>
    {{range .WebhookChannels}}
    <tr id="wh-row-{{.Name}}">
      <td style="font-weight:600;font-family:var(--mono);font-size:0.82rem">{{.Name}}</td>
      <td style="font-family:var(--mono);font-size:0.75rem;color:var(--text3);max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{.URL}}</td>
      <td>{{if .Name}}<button class="btn btn-sm btn-danger" hx-delete="/dashboard/settings/webhooks/{{.Name}}" hx-confirm="Delete channel {{.Name}}?" hx-target="#wh-row-{{.Name}}" hx-swap="outerHTML swap:200ms">delete</button>{{end}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}
  <div class="empty">No webhook channels configured. Add one above to start receiving alerts.</div>
  {{end}}
</div>

<!-- Alert history table -->
<div class="card" style="padding:0;overflow:hidden">
  <div style="padding:16px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between">
    <h3 style="margin:0;font-size:0.82rem;font-weight:600">Alert History</h3>
  </div>
  {{if .Alerts}}
  <div style="overflow-x:auto">
  <table class="alert-table">
    <thead>
      <tr>
        <th>Time</th>
        <th>Event</th>
        <th>Severity</th>
        <th>Agent</th>
        <th>Detail</th>
        <th>Channel</th>
        <th>Status</th>
      </tr>
    </thead>
    <tbody>
      {{range .Alerts}}
      <tr>
        <td style="white-space:nowrap;font-family:var(--mono);font-size:0.72rem;color:var(--text3)">{{.Timestamp | truncTS}}</td>
        <td><span class="event-badge {{.Event}}">{{.Event}}</span></td>
        <td><span class="sev-dot {{.Severity}}"></span> {{.Severity}}</td>
        <td>{{if .Agent}}<span style="font-family:var(--mono);font-size:0.78rem">{{.Agent}}</span>{{else}}<span style="color:var(--text3)">-</span>{{end}}</td>
        <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{if .Detail}}{{.Detail}}{{else if .MessageID}}msg:{{truncate .MessageID 8}}{{else}}-{{end}}</td>
        <td><span class="channel-mono" title="{{.Channel}}">{{truncate .Channel 24}}</span></td>
        <td><span class="status-pill {{.Status}}">{{.Status}}</span></td>
      </tr>
      {{end}}
    </tbody>
  </table>
  </div>
  {{else}}
  <div class="empty-state">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
    <p>No alerts yet</p>
    <p style="font-size:0.75rem;color:var(--text3);margin-top:6px">Add a webhook channel above to start receiving alerts</p>
  </div>
  {{end}}
</div>
` + layoutFoot))
