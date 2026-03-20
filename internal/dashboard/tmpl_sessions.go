package dashboard

import "html/template"

var sessionsPageTmpl = template.Must(template.New("sessions").Funcs(tmplFuncs).Parse(layoutHead + `
<style>
.ss-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
.ss-filters{display:flex;gap:8px;align-items:center}
.ss-filters select,.ss-filters input{padding:6px 10px;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:var(--text-sm)}
.ss-stats{display:flex;gap:24px;margin-bottom:24px;padding:16px 20px;background:var(--surface);border:1px solid var(--border);border-radius:10px}
.ss-stat .label{font-size:var(--text-xs);text-transform:uppercase;letter-spacing:var(--ls-caps);color:var(--text3);margin-bottom:2px}
.ss-stat .value{font-size:1.1rem;font-weight:600;color:var(--text)}
.ss-stat .value.v-danger{color:var(--danger)}
.ss-stat .value.v-warn{color:var(--warning)}

.ss-table{width:100%;border-collapse:collapse;table-layout:fixed}
.ss-table th{text-align:left;padding:10px 12px;font-size:var(--text-xs);text-transform:uppercase;letter-spacing:var(--ls-caps);color:var(--text3);border-bottom:1px solid var(--border)}
.ss-table td{padding:12px 12px;border-bottom:1px solid var(--border);font-size:var(--text-sm);color:var(--text2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ss-table tr:hover{background:var(--surface)}
.ss-table a{color:var(--accent);text-decoration:none}
.ss-table a:hover{text-decoration:underline}
.ss-table .col-session{width:14%}
.ss-table .col-started{width:16%}
.ss-table .col-duration{width:10%}
.ss-table .col-agents{width:22%}
.ss-table .col-events{width:8%;text-align:right}
.ss-table .col-threats{width:22%}
.ss-table .col-risk{width:8%;text-align:right}

.ss-risk{display:inline-block;padding:2px 8px;border-radius:4px;font-size:var(--text-xs);font-weight:600}
.ss-risk.r-high{background:rgba(239,68,68,0.12);color:var(--danger)}
.ss-risk.r-medium{background:rgba(234,179,8,0.12);color:var(--warning)}
.ss-risk.r-low{background:rgba(34,197,94,0.12);color:var(--success)}
.ss-risk.r-none{background:var(--surface2);color:var(--text3)}

.ss-agents{font-family:var(--mono);font-size:var(--text-xs);color:var(--text3)}
.ss-id{font-family:var(--mono);font-size:var(--text-xs)}
.ss-threats{display:flex;gap:6px;font-size:var(--text-xs)}
.ss-threats .badge{padding:1px 6px;border-radius:3px;font-weight:500}
.ss-threats .b-block{background:rgba(239,68,68,0.12);color:var(--danger)}
.ss-threats .b-quar{background:rgba(234,179,8,0.12);color:var(--warning)}
.ss-threats .b-flag{background:rgba(96,165,250,0.12);color:var(--info)}

.ss-empty{text-align:center;padding:40px;color:var(--text3)}

.ss-export{display:flex;gap:8px}
.ss-export a{padding:4px 10px;font-size:var(--text-xs);border:1px solid var(--border);border-radius:5px;color:var(--text2);text-decoration:none}
.ss-export a:hover{background:var(--surface2)}

.ss-ai-btn{padding:6px 12px;background:var(--accent);color:#fff;border:none;border-radius:6px;font-size:var(--text-sm);cursor:pointer;font-weight:500}
.ss-ai-btn:hover{opacity:0.9}
.ss-ai-btn:disabled{opacity:0.5;cursor:not-allowed}

.ss-ai-result{margin-top:16px;padding:16px;background:var(--surface);border:1px solid var(--border);border-radius:8px;font-size:var(--text-sm);line-height:1.6;color:var(--text2);white-space:pre-wrap}
</style>
` + sessionsBodyTmpl + layoutFoot))

const sessionsBodyTmpl = `
<div class="ss-header">
  <h1>Sessions</h1>
  <div class="ss-filters">
    <select id="ss-range" onchange="window.location='/dashboard/sessions?range='+this.value">
      <option value="24h"{{if eq .Range "24h"}} selected{{end}}>Last 24 hours</option>
      <option value="7d"{{if eq .Range "7d"}} selected{{end}}>Last 7 days</option>
      <option value="30d"{{if eq .Range "30d"}} selected{{end}}>Last 30 days</option>
    </select>
    <div class="ss-export">
      <a href="/dashboard/api/sessions/export?format=json&range={{.Range}}">JSON</a>
      <a href="/dashboard/api/sessions/export?format=csv&range={{.Range}}">CSV</a>
    </div>
  </div>
</div>

<div class="ss-stats">
  <div class="ss-stat">
    <div class="label">Sessions</div>
    <div class="value">{{.TotalSessions}}</div>
  </div>
  <div class="ss-stat">
    <div class="label">With threats</div>
    <div class="value{{if gt .ThreatSessions 0}} v-danger{{end}}">{{.ThreatSessions}}</div>
  </div>
  <div class="ss-stat">
    <div class="label">Avg duration</div>
    <div class="value">{{.AvgDuration}}</div>
  </div>
  <div class="ss-stat">
    <div class="label">Total events</div>
    <div class="value">{{.TotalEvents}}</div>
  </div>
</div>

{{if .Sessions}}
<table class="ss-table">
  <thead>
    <tr>
      <th class="col-session">Session</th>
      <th class="col-started">Started</th>
      <th class="col-duration">Duration</th>
      <th class="col-agents">Agents</th>
      <th class="col-events">Events</th>
      <th class="col-threats">Threats</th>
      <th class="col-risk">Risk</th>
    </tr>
  </thead>
  <tbody>
    {{range .Sessions}}
    <tr>
      <td class="ss-id"><a href="/dashboard/sessions/{{.SessionID}}" title="{{.SessionID}}">{{truncate .SessionID 16}}</a></td>
      <td title="{{.StartedAt}}">{{truncate .StartedAt 16}}</td>
      <td>{{if .Duration}}{{.Duration}}{{else}}&mdash;{{end}}</td>
      <td class="ss-agents" title="{{.Agents}}">{{.Agents}}</td>
      <td style="text-align:right">{{.EventCount}}</td>
      <td>
        <div class="ss-threats">
          {{if gt .Blocks 0}}<span class="badge b-block">{{.Blocks}} blocked</span>{{end}}
          {{if gt .Quarantines 0}}<span class="badge b-quar">{{.Quarantines}} quarantined</span>{{end}}
          {{if gt .Flags 0}}<span class="badge b-flag">{{.Flags}} flagged</span>{{end}}
          {{if and (eq .Blocks 0) (eq .Quarantines 0) (eq .Flags 0)}}<span style="color:var(--text3)">&mdash;</span>{{end}}
        </div>
      </td>
      <td style="text-align:right">
        <span class="ss-risk{{if ge .RiskScore 10}} r-high{{else if ge .RiskScore 5}} r-medium{{else if gt .RiskScore 0}} r-low{{else}} r-none{{end}}">{{.RiskScore}}</span>
      </td>
    </tr>
    {{end}}
  </tbody>
</table>
{{else}}
<div class="ss-empty">No sessions found in this time range.</div>
{{end}}
`
