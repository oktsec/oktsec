package dashboard

import "html/template"

var sessionsPageTmpl = template.Must(template.New("sessions").Funcs(tmplFuncs).Parse(layoutHead + `
<style>
.ss-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
.ss-filters{display:flex;gap:8px;align-items:center}
.ss-filters select{padding:6px 10px;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:var(--text-sm)}
.ss-stats{display:flex;gap:24px;margin-bottom:20px;padding:16px 20px;background:var(--surface);border:1px solid var(--border);border-radius:10px}
.ss-stat .label{font-size:var(--text-xs);text-transform:uppercase;letter-spacing:var(--ls-caps);color:var(--text3);margin-bottom:2px}
.ss-stat .value{font-size:1.1rem;font-weight:600;color:var(--text)}
.ss-stat .value.v-danger{color:var(--danger)}

.ss-search{margin-bottom:16px;position:relative}
.ss-search input{width:100%;padding:10px 14px 10px 36px;background:var(--surface);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:var(--text-sm)}
.ss-search input::placeholder{color:var(--text3)}
.ss-search svg{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--text3);width:14px;height:14px}

.ss-table{width:100%;border-collapse:collapse}
.ss-table th{text-align:left;padding:10px 12px;font-size:var(--text-xs);text-transform:uppercase;letter-spacing:var(--ls-caps);color:var(--text3);border-bottom:1px solid var(--border)}
.ss-table td{padding:14px 12px;border-bottom:1px solid var(--border);font-size:var(--text-sm);color:var(--text2);vertical-align:middle}
.ss-table tr:hover{background:var(--surface)}
.ss-table tr.ss-hidden{display:none}
.ss-table a{color:var(--accent);text-decoration:none}
.ss-table a:hover{text-decoration:underline}
.ss-table .r{text-align:right}

.ss-risk{display:inline-block;padding:2px 8px;border-radius:4px;font-size:var(--text-xs);font-weight:600}
.ss-risk.r-high{background:rgba(239,68,68,0.12);color:var(--danger)}
.ss-risk.r-medium{background:rgba(234,179,8,0.12);color:var(--warning)}
.ss-risk.r-low{background:rgba(34,197,94,0.12);color:var(--success)}
.ss-risk.r-none{background:var(--surface2);color:var(--text3)}

.ss-agents .pill{display:inline-block;padding:2px 7px;background:var(--surface2);border-radius:4px;margin:1px 2px;font-family:var(--mono);font-size:0.68rem;color:var(--text2)}
.ss-session{font-family:var(--mono);font-size:var(--text-xs);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block}
.ss-threats{display:flex;gap:4px;flex-wrap:wrap}
.ss-threats .badge{padding:2px 7px;border-radius:4px;font-weight:500;font-size:var(--text-xs);white-space:nowrap}
.ss-threats .b-block{background:rgba(239,68,68,0.12);color:var(--danger)}
.ss-threats .b-quar{background:rgba(234,179,8,0.12);color:var(--warning)}
.ss-threats .b-flag{background:rgba(96,165,250,0.12);color:var(--info)}

.ss-empty{text-align:center;padding:40px;color:var(--text3)}
.ss-export{display:flex;gap:8px}
.ss-export a{padding:4px 10px;font-size:var(--text-xs);border:1px solid var(--border);border-radius:5px;color:var(--text2);text-decoration:none}
.ss-export a:hover{background:var(--surface2)}
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

<div class="ss-search">
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
  <input type="text" id="ss-filter" placeholder="Search by session, agent, or status..." oninput="filterSessions(this.value)">
</div>

{{if .Sessions}}
<table class="ss-table" id="ss-table">
  <thead>
    <tr>
      <th style="width:22%">Session</th>
      <th style="width:12%">Duration</th>
      <th style="width:24%">Agents</th>
      <th style="width:7%" class="r">Events</th>
      <th style="width:25%">Threats</th>
      <th style="width:10%" class="r">Risk</th>
    </tr>
  </thead>
  <tbody>
    {{range .Sessions}}
    <tr data-search="{{.SessionID}} {{.Agents}} {{if gt .Blocks 0}}blocked{{end}} {{if gt .Quarantines 0}}quarantined{{end}}">
      <td>
        <a href="/dashboard/sessions/{{.SessionID}}" class="ss-session" title="{{.SessionID}}">{{.SessionID}}</a>
        <div style="font-size:0.65rem;color:var(--text3);margin-top:2px">{{truncate .StartedAt 19}}{{if .Duration}} &middot; {{.Duration}}{{end}}</div>
      </td>
      <td>{{if .Duration}}{{.Duration}}{{else}}&mdash;{{end}}</td>
      <td class="ss-agents">{{range $i, $a := split .Agents ","}}{{if $i}} {{end}}<span class="pill">{{$a}}</span>{{end}}</td>
      <td class="r">{{.EventCount}}</td>
      <td>
        <div class="ss-threats">
          {{if gt .Blocks 0}}<span class="badge b-block">{{.Blocks}} blocked</span>{{end}}
          {{if gt .Quarantines 0}}<span class="badge b-quar">{{.Quarantines}} quarantined</span>{{end}}
          {{if gt .Flags 0}}<span class="badge b-flag">{{.Flags}} flagged</span>{{end}}
          {{if and (eq .Blocks 0) (eq .Quarantines 0) (eq .Flags 0)}}<span style="color:var(--text3)">&mdash;</span>{{end}}
        </div>
      </td>
      <td class="r">
        <span class="ss-risk{{if ge .RiskScore 10}} r-high{{else if ge .RiskScore 5}} r-medium{{else if gt .RiskScore 0}} r-low{{else}} r-none{{end}}">{{.RiskScore}}</span>
      </td>
    </tr>
    {{end}}
  </tbody>
</table>
<script>
function filterSessions(q) {
  q = q.toLowerCase();
  document.querySelectorAll('#ss-table tbody tr').forEach(function(row) {
    var text = (row.getAttribute('data-search') || '').toLowerCase();
    row.classList.toggle('ss-hidden', q !== '' && text.indexOf(q) === -1);
  });
}
</script>
{{else}}
<div class="ss-empty">No sessions found in this time range.</div>
{{end}}
`
