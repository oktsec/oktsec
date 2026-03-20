package dashboard

import "html/template"

var sessionsPageTmpl = template.Must(template.New("sessions").Funcs(tmplFuncs).Parse(layoutHead + `
<style>
.ss-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
.ss-filters{display:flex;gap:8px;align-items:center}
.ss-filters select{padding:6px 10px;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:var(--text-sm)}
.ss-stats{display:grid;grid-template-columns:repeat(4,1fr);margin-bottom:20px;background:var(--surface);border:1px solid var(--border);border-radius:10px;overflow:hidden}
.ss-stat{padding:16px 20px;text-align:center}
.ss-stat+.ss-stat{border-left:1px solid var(--border)}
.ss-stat .label{font-size:var(--text-xs);text-transform:uppercase;letter-spacing:var(--ls-caps);color:var(--text3);margin-bottom:4px}
.ss-stat .value{font-size:1.2rem;font-weight:600;color:var(--text)}
.ss-stat .value.v-danger{color:var(--danger)}

.ss-search{margin-bottom:16px;position:relative}
.ss-search input{width:100%;padding:10px 14px 10px 36px;background:var(--surface);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:var(--text-sm)}
.ss-search input::placeholder{color:var(--text3)}
.ss-search svg{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--text3);width:14px;height:14px}

.ss-table{width:100%;border-collapse:collapse}
.ss-table th{text-align:left;padding:10px 14px;font-size:var(--text-xs);text-transform:uppercase;letter-spacing:var(--ls-caps);color:var(--text3);border-bottom:1px solid var(--border)}
.ss-table td{padding:14px;border-bottom:1px solid var(--border);font-size:var(--text-sm);color:var(--text2);vertical-align:top}
.ss-table tr:hover{background:var(--surface)}
.ss-table tr.ss-hidden{display:none}
.ss-table a{color:var(--accent);text-decoration:none}
.ss-table a:hover{text-decoration:underline}
.ss-table .r{text-align:right}
.ss-session-name{font-weight:500;color:var(--accent);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:block;max-width:220px}

.ss-risk{display:inline-block;padding:2px 8px;border-radius:4px;font-size:var(--text-xs);font-weight:600}
.ss-risk.r-high{background:var(--danger-muted);color:var(--danger);border:1px solid var(--danger-border)}
.ss-risk.r-medium{background:var(--warn-muted);color:var(--warn);border:1px solid var(--warn-border)}
.ss-risk.r-low{background:var(--success-muted);color:var(--success);border:1px solid var(--success-border)}
.ss-risk.r-none{background:var(--surface2);color:var(--text3);border:1px solid var(--border)}

.ss-agents .pill{display:inline-block;padding:2px 7px;background:var(--surface2);border-radius:4px;margin:1px 2px;font-family:var(--mono);font-size:0.68rem;color:var(--text2)}
.ss-session{font-family:var(--mono);font-size:var(--text-xs);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block}
.ss-threats{display:flex;gap:4px;flex-wrap:wrap}
.ss-threats .badge{padding:2px 7px;border-radius:4px;font-weight:500;font-size:var(--text-xs);white-space:nowrap}
.ss-threats .b-block{background:var(--danger-muted);color:var(--danger);border:1px solid var(--danger-border)}
.ss-threats .b-quar{background:var(--warn-muted);color:var(--warn);border:1px solid var(--warn-border)}
.ss-threats .b-flag{background:rgba(56,139,253,0.15);color:var(--accent);border:1px solid var(--accent-border)}

.ss-filter-btn{padding:5px 12px;font-size:var(--text-xs);background:var(--surface);border:1px solid var(--border);border-radius:5px;color:var(--text3);cursor:pointer;white-space:nowrap}
.ss-filter-btn:hover{background:var(--surface2)}
.ss-filter-btn.active{background:var(--accent);color:#fff;border-color:var(--accent)}
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
    <div class="label">With threats</div>
    <div class="value{{if gt .ThreatSessions 0}} v-danger{{end}}">{{.ThreatSessions}}</div>
  </div>
  <div class="ss-stat">
    <div class="label">Sessions</div>
    <div class="value">{{.TotalSessions}}</div>
  </div>
  <div class="ss-stat">
    <div class="label">Total events</div>
    <div class="value">{{.TotalEvents}}</div>
  </div>
  <div class="ss-stat">
    <div class="label">Avg duration</div>
    <div class="value">{{.AvgDuration}}</div>
  </div>
</div>

<div style="display:flex;gap:12px;align-items:center;margin-bottom:16px">
  <div class="ss-search" style="flex:1;margin-bottom:0">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
    <input type="text" id="ss-filter" placeholder="Search by session, agent, or status..." oninput="filterSessions(this.value)">
  </div>
  <div style="display:flex;gap:4px">
    <button class="ss-filter-btn active" onclick="filterThreats('all',this)">All</button>
    <button class="ss-filter-btn" onclick="filterThreats('threats',this)">With threats</button>
    <button class="ss-filter-btn" onclick="filterThreats('clean',this)">Clean</button>
  </div>
</div>

{{if .Sessions}}
<table class="ss-table" id="ss-table">
  <thead>
    <tr>
      <th style="width:18%">Session</th>
      <th style="width:20%">Agents</th>
      <th style="width:20%">Threats</th>
      <th style="width:7%" class="r">Events</th>
      <th style="width:8%" class="r">Risk</th>
      <th style="width:9%">Duration</th>
      <th style="width:12%">Date</th>
    </tr>
  </thead>
  <tbody>
    {{range .Sessions}}
    <tr data-search="{{.SessionID}} {{.Agents}} {{if gt .Blocks 0}}blocked{{end}} {{if gt .Quarantines 0}}quarantined{{end}}" data-threats="{{if or (gt .Blocks 0) (gt .Quarantines 0) (gt .Flags 0)}}yes{{else}}no{{end}}">
      <td><a href="/dashboard/sessions/{{.SessionID}}" class="ss-session-name" title="{{.SessionID}}">{{truncate .SessionID 24}}</a></td>
      <td class="ss-agents">{{range $i, $a := split .Agents ","}}{{if $i}} {{end}}<span class="pill">{{$a}}</span>{{end}}</td>
      <td>
        <div class="ss-threats">
          {{if gt .Blocks 0}}<span class="badge b-block">{{.Blocks}} blocked</span>{{end}}
          {{if gt .Quarantines 0}}<span class="badge b-quar">{{.Quarantines}} quarantined</span>{{end}}
          {{if gt .Flags 0}}<span class="badge b-flag">{{.Flags}} flagged</span>{{end}}
          {{if and (eq .Blocks 0) (eq .Quarantines 0) (eq .Flags 0)}}<span style="color:var(--text3)">&mdash;</span>{{end}}
        </div>
      </td>
      <td class="r">{{.EventCount}}</td>
      <td class="r">
        <span class="ss-risk{{if ge .RiskScore 10}} r-high{{else if ge .RiskScore 5}} r-medium{{else if gt .RiskScore 0}} r-low{{else}} r-none{{end}}">{{.RiskScore}}</span>
      </td>
      <td>{{if .Duration}}{{.Duration}}{{else}}0s{{end}}</td>
      <td style="font-size:var(--text-xs);color:var(--text2);white-space:nowrap">{{fmtDate .StartedAt}}</td>
    </tr>
    {{end}}
  </tbody>
</table>
<script>
var currentThreatFilter = 'all';
function filterSessions(q) {
  q = q.toLowerCase();
  document.querySelectorAll('#ss-table tbody tr').forEach(function(row) {
    var text = (row.getAttribute('data-search') || '').toLowerCase();
    var matchSearch = q === '' || text.indexOf(q) !== -1;
    var threats = row.getAttribute('data-threats');
    var matchThreat = currentThreatFilter === 'all' || (currentThreatFilter === 'threats' && threats === 'yes') || (currentThreatFilter === 'clean' && threats === 'no');
    row.classList.toggle('ss-hidden', !matchSearch || !matchThreat);
  });
}
function filterThreats(mode, btn) {
  currentThreatFilter = mode;
  document.querySelectorAll('.ss-filter-btn').forEach(function(b) { b.classList.remove('active'); });
  btn.classList.add('active');
  filterSessions(document.getElementById('ss-filter').value);
}
</script>
{{else}}
<div class="ss-empty">No sessions found in this time range.</div>
{{end}}
`
