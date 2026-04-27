package dashboard

import "html/template"

var overviewTmpl = template.Must(template.New("overview").Funcs(tmplFuncs).Parse(layoutHead + `
<style>
.hero-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--border);border:1px solid var(--border);border-radius:var(--radius-xl);overflow:hidden;margin-bottom:var(--sp-6)}
.hero-stat{background:var(--surface2);padding:var(--sp-6) var(--sp-5);text-align:center;transition:background var(--ease-smooth);position:relative;display:flex;flex-direction:column;align-items:center;justify-content:center}
.hero-stat::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--accent-dim),var(--accent-light));opacity:0;transition:opacity var(--ease-smooth)}
.hero-stat:hover{background:var(--surface2)}
.hero-stat:hover::before{opacity:1}
.hero-stat .num{font-size:var(--text-3xl);font-weight:800;letter-spacing:0;font-family:var(--sans);line-height:1}
.hero-stat .lbl{font-size:var(--text-xs);text-transform:uppercase;letter-spacing:var(--ls-caps);color:var(--text3);margin-top:var(--sp-2);font-weight:500}
.ov-grid{display:grid;grid-template-columns:1fr 1fr;gap:var(--sp-4);margin-bottom:var(--sp-4)}
.ov-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-xl);padding:var(--sp-5);transition:border-color var(--ease-smooth),box-shadow var(--ease-smooth)}
.ov-card:hover{border-color:var(--border-hover);box-shadow:var(--shadow-md)}
.ov-card h3{font-size:var(--text-xs);text-transform:uppercase;letter-spacing:var(--ls-caps);color:var(--text3);margin-bottom:14px;font-weight:500}
.ov-metric{display:flex;justify-content:space-between;align-items:baseline;padding:7px 0;border-bottom:1px solid var(--border)}
.ov-metric:last-child{border-bottom:none}
.ov-metric .k{font-size:var(--text-base);color:var(--text2)}
.ov-metric .v{font-family:var(--mono);font-weight:600;font-size:var(--text-md)}
a.ov-metric{display:flex;border-radius:var(--radius-sm);margin:0 -6px;padding:7px 6px;transition:background var(--ease-default);text-decoration:none;color:inherit}
a.ov-metric:hover{background:var(--surface2)}
.ov-feed-hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--sp-3)}
.ov-feed-hdr h2{font-size:var(--text-base);margin:0;border:none;padding:0}
.ov-feed-hdr a{font-size:var(--text-sm);color:var(--accent-light);text-decoration:none;font-weight:500}
.ov-feed-hdr a:hover{text-decoration:underline}
.pipeline-stages{display:flex;gap:var(--sp-3);margin-bottom:var(--sp-4);overflow-x:auto}
.pipeline-stage{display:flex;align-items:center;gap:5px;font-size:0.72rem;color:var(--text2);white-space:nowrap}
.pipeline-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
/* At narrower desktop widths the Pipeline Health summary
   (rules / mode / chain / latency) was sharing the same row as
   the 11 stage labels and pushed the last stage ("Guard") into
   an overflow-x clip mid-word. DP-SMOKE-04 fix: under 1600px the
   summary wraps to its own row beneath the stages so every label
   stays readable. 1920px keeps the inline single-row layout. */
@media(max-width:1599px){.pipeline-meta{flex-basis:100%;margin-left:0 !important;padding-top:var(--sp-3);border-top:1px solid var(--border-subtle);text-align:left;white-space:normal !important}}
.pipeline-dot.active{background:var(--success)}
.pipeline-dot.inactive{background:var(--text3);opacity:0.4}
.pipeline-summary{font-size:var(--text-sm);color:var(--text3);padding-top:var(--sp-3);border-top:1px solid var(--border)}
.sparkline-wrap{padding:var(--sp-2) 0}
.sparkline-chart{display:flex;align-items:flex-end;gap:2px;height:48px}
.sparkline-bar{flex:1;background:var(--accent);border-radius:1px 1px 0 0;min-width:3px;transition:background var(--ease-smooth)}
.sparkline-bar:hover{background:var(--accent-light)}
.empty-state{text-align:center;padding:60px var(--sp-6) var(--sp-16)}
.empty-state svg.empty-icon{width:72px;height:72px;color:var(--accent-light);margin-bottom:var(--sp-6);filter:drop-shadow(0 0 24px rgba(139,92,246,0.4))}
.empty-state h2{font-size:1.75rem;font-weight:700;margin-bottom:var(--sp-3);letter-spacing:var(--ls-tight);color:#fff}
.empty-state .tagline{color:var(--accent-light);font-size:var(--text-md);margin-bottom:var(--sp-2);font-weight:500}
.empty-state p{color:var(--text3);font-size:0.9rem;margin-bottom:48px;max-width:440px;margin-left:auto;margin-right:auto;line-height:1.7}
.empty-steps{display:flex;flex-direction:column;gap:var(--sp-4);max-width:440px;margin:0 auto}
.empty-step{display:flex;align-items:center;gap:var(--sp-4);padding:16px 20px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-lg);font-size:0.9rem;color:var(--text1);text-align:left;transition:border-color 0.2s,background 0.2s}
.empty-step:hover{border-color:var(--accent-border);background:var(--surface3,var(--surface2))}
.empty-step .step-num{width:32px;height:32px;border-radius:50%;background:var(--accent-glow);border:1.5px solid var(--accent-border);color:var(--accent-light);font-size:0.8rem;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.empty-step .step-done{width:32px;height:32px;border-radius:50%;background:rgba(63,185,80,0.15);border:1.5px solid rgba(63,185,80,0.4);color:var(--success);font-size:1rem;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.empty-step code{background:var(--bg);padding:3px 10px;border-radius:var(--radius-sm);font-family:var(--mono);font-size:var(--text-xs);color:var(--accent-light);border:1px solid var(--border)}
.empty-step .step-desc{color:var(--text3);font-size:0.78rem;margin-top:2px}
.score-ring{position:relative;display:inline-flex;align-items:center;justify-content:center}
.score-ring svg{display:block}
.score-ring-fill{transition:stroke-dashoffset 0.8s ease-out}
.score-ring-fill.success{stroke:var(--success)}
.score-ring-fill.warn{stroke:var(--warn)}
.score-ring-fill.danger{stroke:var(--danger)}
.score-ring-val{position:absolute;font-size:var(--text-md);font-weight:700;font-family:var(--sans);letter-spacing:0}
.score-ring-val.success{color:var(--success)}
.score-ring-val.warn{color:var(--warn)}
.score-ring-val.danger{color:var(--danger)}
@media(max-width:768px){.hero-stats{grid-template-columns:repeat(2,1fr)}.ov-grid{grid-template-columns:1fr}}
</style>

<p class="page-desc">Real-time security overview for agents and tools routed through Oktsec. <span class="sse-indicator" id="sse-status"><span class="sse-dot" id="sse-dot"></span> <span id="sse-label">connecting</span></span></p>
<noscript><div style="padding:8px 12px;background:rgba(210,153,34,0.08);border:1px solid rgba(210,153,34,0.2);border-radius:var(--radius-md);font-size:var(--text-sm);color:var(--warn);margin-bottom:var(--sp-4)">Live updates require JavaScript.</div></noscript>

{{if and (eq .Stats.TotalMessages 0) (eq .AgentCount 0)}}
<div class="empty-state">
  <svg class="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
  <h2>Welcome to oktsec</h2>
  <div class="tagline">Real-time visibility into the tool calls your AI agents route through Oktsec</div>
  <p>Real-time monitoring for every tool call routed through Oktsec. Your pipeline is running. Start using your tools and activity will appear here.</p>
  <div class="empty-steps">
    <div class="empty-step">
      <span class="step-done">&#10003;</span>
      <div><strong>Pipeline ready</strong> <code>oktsec run</code><div class="step-desc">{{.RuleCount}} detection rules loaded, hooks configured</div></div>
    </div>
    <div class="empty-step">
      <span class="step-num">2</span>
      <div><strong>Use your AI tools</strong><div class="step-desc">Claude Code, Cursor, Codex, or any connected tool</div></div>
    </div>
    <div class="empty-step">
      <span class="step-num">3</span>
      <div><strong>Monitor in real time</strong><div class="step-desc">Routed tool calls scanned, threats flagged, audit trail built</div></div>
    </div>
  </div>
</div>
{{else}}

<!-- Hero: the 4 numbers that tell the story -->
<div style="display:flex;align-items:baseline;gap:var(--sp-2);margin-bottom:var(--sp-2)">
  <span style="font-size:var(--text-xs);color:var(--text3);text-transform:uppercase;letter-spacing:var(--ls-caps);font-weight:500">All time</span>
</div>
<div class="hero-stats" id="hero-stats">
  <a href="/dashboard/events" class="hero-stat">
    <div class="num success" id="stat-total">{{formatNum .Stats.TotalMessages}}</div>
    <div class="lbl">Messages Protected</div>
  </a>
  <a href="/dashboard/events?tab=blocked" class="hero-stat">
    <div class="num danger" id="stat-blocked">{{formatNum (add .Stats.Blocked .Stats.Rejected)}}</div>
    <div class="lbl">Threats Blocked</div>
  </a>
  <a href="/dashboard/agents" class="hero-stat">
    <div class="num" style="color:var(--accent-light)" id="stat-agents">{{.AgentCount}}</div>
    <div class="lbl">Agents Observed</div>
  </a>
  <a href="/dashboard/audit" class="hero-stat">
    <div class="score-ring" id="score-ring">
      <svg viewBox="0 0 48 48" width="48" height="48">
        <circle cx="24" cy="24" r="20" fill="none" stroke="var(--border)" stroke-width="3"/>
        <circle id="score-ring-arc" cx="24" cy="24" r="20" fill="none" stroke-width="3" stroke-linecap="round"
          class="score-ring-fill {{gradeColor .Grade}}"
          stroke-dasharray="125.66" stroke-dashoffset="125.66"
          transform="rotate(-90 24 24)"/>
      </svg>
      <span class="score-ring-val {{gradeColor .Grade}}">{{.Score}}</span>
    </div>
    <script>
    (function(){var arc=document.getElementById('score-ring-arc');if(!arc)return;var score={{.Score}};var offset=125.66*(1-score/100);setTimeout(function(){arc.style.strokeDashoffset=offset},50)})();
    </script>
    <div class="lbl">Posture Score</div>
  </a>
</div>

{{if .PendingReview}}
<div class="alert-banner warn">
  <strong>{{.PendingReview}} message{{if gt .PendingReview 1}}s{{end}} pending review</strong>
  <span style="color:var(--text2);font-size:var(--text-sm)">Quarantined content awaiting human decision</span>
  <a href="/dashboard/events?tab=quarantine" class="btn btn-sm" style="background:var(--warn);color:#000">Review Now</a>
</div>
{{end}}

<!-- Pipeline Health (horizontal bar) -->
<div class="ov-card" style="margin-bottom:var(--sp-4)">
  <div style="display:flex;align-items:center;gap:var(--sp-5);flex-wrap:wrap">
    <h3 style="margin:0;white-space:nowrap">Pipeline Health</h3>
    <div class="pipeline-stages" style="margin-bottom:0;flex:1">
      {{range .PipelineStages}}
      <div class="pipeline-stage">
        <span class="pipeline-dot {{if .Active}}active{{else}}inactive{{end}}"></span>
        {{.Name}}
      </div>
      {{end}}
    </div>
    <div class="pipeline-meta" style="font-size:var(--text-sm);color:var(--text3);white-space:nowrap;margin-left:auto">
      {{.RuleCount}} rules &middot; {{if .RequireSig}}enforce{{else}}observe{{end}} mode &middot; chain {{if .ChainValid}}verified{{else}}broken{{end}} ({{formatNum .ChainCount}})
      {{if .AvgLatency}}&middot; <span style="color:var(--text2);font-weight:600">{{.AvgLatency}}ms</span> median{{end}}
    </div>
  </div>
</div>

<!-- Coverage matrix: per-principal, per-surface protection state. -->
<style>
.cov-scroll{overflow-x:auto;margin:0 -4px}
.cov-table{width:100%;min-width:760px;border-collapse:collapse;font-size:var(--text-sm)}
.cov-table th{text-align:left;font-weight:600;color:var(--text3);font-size:var(--text-xs);text-transform:uppercase;letter-spacing:var(--ls-wide);padding:8px 12px;border-bottom:1px solid var(--border);white-space:nowrap}
.cov-table td{padding:10px 12px;border-bottom:1px solid var(--border-subtle);vertical-align:top;white-space:nowrap}
.cov-table tr:last-child td{border-bottom:none}
.cov-principal{font-weight:600;color:var(--text);font-family:var(--mono)}
.cov-connector{font-size:var(--text-xs);color:var(--text3)}
.cov-badge{display:inline-block;padding:2px 8px;border-radius:var(--radius-sm);font-size:var(--text-xs);font-weight:600;letter-spacing:0.02em}
.cov-badge.protected{background:rgba(63,185,80,0.12);color:var(--success);border:1px solid rgba(63,185,80,0.30)}
.cov-badge.observed{background:rgba(88,166,255,0.10);color:var(--accent);border:1px solid rgba(88,166,255,0.25)}
.cov-badge.blind{background:transparent;color:var(--text3);border:1px solid var(--border)}
.cov-short{display:block;font-size:var(--text-xs);color:var(--text3);margin-top:3px;line-height:1.3;cursor:help}
.cov-identity{font-size:var(--text-xs);color:var(--text2)}
.cov-lastseen{font-size:var(--text-xs);color:var(--text2);font-family:var(--mono)}
.cov-empty{padding:24px;text-align:center;color:var(--text3);font-size:var(--text-sm)}
.cov-empty a{color:var(--accent);text-decoration:none}
.cov-empty a:hover{text-decoration:underline}
.cov-cell{padding:0;vertical-align:top;white-space:nowrap}
.cov-cell-btn{width:100%;min-height:52px;display:flex;flex-direction:column;align-items:flex-start;gap:4px;padding:10px 12px;background:transparent;border:0;color:inherit;font:inherit;text-align:left;cursor:pointer;border-radius:var(--radius-sm);transition:background 0.12s ease}
.cov-cell-btn:hover{background:rgba(88,166,255,0.06)}
.cov-cell-btn:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
</style>
<div class="ov-card" style="margin-bottom:var(--sp-4)">
  <div style="display:flex;align-items:center;gap:var(--sp-3);margin-bottom:var(--sp-3)">
    <h3 style="margin:0">Coverage matrix</h3>
    <span style="font-size:var(--text-xs);color:var(--text3)">Per-principal, per-surface protection state</span>
  </div>
  {{if .CoverageRows}}
  <div class="cov-scroll">
  <table class="cov-table" aria-label="Coverage matrix by principal and surface">
    <thead>
      <tr>
        <th>Principal</th>
        <th>Connector</th>
        <th>MCP Gateway</th>
        <th>Egress Proxy</th>
        <th>Hooks</th>
        <th>Identity</th>
        <th>Last seen</th>
      </tr>
    </thead>
    <tbody>
      {{range .CoverageRows}}
      <tr>
        <td><span class="cov-principal">{{.PrincipalID}}</span></td>
        <td><span class="cov-connector">{{.ConnectorLabel}}</span></td>
        {{$pid := .PrincipalID}}
        {{with index .Cells "mcp_http"}}
        <td class="cov-cell">
          <button type="button" class="cov-cell-btn"
                  aria-label="Show activity for {{$pid}} on MCP Gateway"
                  hx-get="/dashboard/api/coverage/cell?principal_id={{$pid}}&surface=mcp_http"
                  hx-trigger="click"
                  hx-target="#panel-content" hx-swap="innerHTML">
            <span class="cov-badge {{.Coverage}}" title="{{.Limitation}}">{{covLabel (printf "%s" .Coverage)}}</span>
            {{$short := covShort .}}{{if $short}}<span class="cov-short" title="{{.Limitation}}">{{$short}}</span>{{end}}
          </button>
        </td>
        {{else}}<td><span class="cov-badge blind">Blind</span></td>{{end}}
        {{with index .Cells "http_egress_proxy"}}
        <td class="cov-cell">
          <button type="button" class="cov-cell-btn"
                  aria-label="Show activity for {{$pid}} on Egress Proxy"
                  hx-get="/dashboard/api/coverage/cell?principal_id={{$pid}}&surface=http_egress_proxy"
                  hx-trigger="click"
                  hx-target="#panel-content" hx-swap="innerHTML">
            <span class="cov-badge {{.Coverage}}" title="{{.Limitation}}">{{covLabel (printf "%s" .Coverage)}}</span>
            {{$short := covShort .}}{{if $short}}<span class="cov-short" title="{{.Limitation}}">{{$short}}</span>{{end}}
          </button>
        </td>
        {{else}}<td><span class="cov-badge blind">Blind</span></td>{{end}}
        {{with index .Cells "hooks"}}
        <td class="cov-cell">
          <button type="button" class="cov-cell-btn"
                  aria-label="Show activity for {{$pid}} on Hooks"
                  hx-get="/dashboard/api/coverage/cell?principal_id={{$pid}}&surface=hooks"
                  hx-trigger="click"
                  hx-target="#panel-content" hx-swap="innerHTML">
            <span class="cov-badge {{.Coverage}}" title="{{.Limitation}}">{{covLabel (printf "%s" .Coverage)}}</span>
            {{$short := covShort .}}{{if $short}}<span class="cov-short" title="{{.Limitation}}">{{$short}}</span>{{end}}
          </button>
        </td>
        {{else}}<td><span class="cov-badge blind">Blind</span></td>{{end}}
        <td><span class="cov-identity">{{.IdentityList}}</span></td>
        <td>{{if .LastSeen}}<span class="cov-lastseen" data-ts="{{.LastSeen}}">{{.LastSeen}}</span>{{else}}<span class="cov-lastseen" style="color:var(--text3)">No activity yet</span>{{end}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
  </div>
  {{else}}
  <div class="cov-empty">
    No principals configured yet.
    <a href="https://oktsec.com/docs/guides/mcp-http-bearer-client/">Issue a bearer token</a>
    to start populating the matrix.
  </div>
  {{end}}
</div>

<!-- Live Feed + Security Status -->
<div class="ov-grid">
  <div class="card" style="margin-bottom:0">
    <div class="ov-feed-hdr">
      <h2><span class="dot"></span> Live Feed</h2>
      <a href="/dashboard/events">View all &rarr;</a>
    </div>
    <div id="recent-events">
      {{if .Recent}}
      <table>
        <thead><tr><th>Time</th><th>From</th><th>To</th><th>Status</th></tr></thead>
        <tbody id="events-tbody">
        {{range .Recent}}
        <tr class="clickable" hx-get="/dashboard/api/event/{{.ID}}" hx-target="#panel-content" hx-swap="innerHTML">
          <td data-ts="{{.Timestamp}}">{{.Timestamp}}</td>
          <td>{{agentCell .FromAgent}}</td>
          <td>{{agentCell .ToAgent}}</td>
          <td>
            {{if eq .Status "delivered"}}<span class="badge-delivered">delivered</span>
            {{else if eq .Status "blocked"}}<span class="badge-blocked">blocked</span>
            {{else if eq .Status "rejected"}}<span class="badge-rejected">rejected</span>
            {{else if eq .Status "quarantined"}}<span class="badge-quarantined">quarantined</span>
            {{else}}{{.Status}}{{end}}
          </td>
        </tr>
        {{end}}
        </tbody>
      </table>
      {{else}}
      <div class="empty" id="empty-msg">Waiting for agent traffic...</div>
      {{end}}
    </div>
  </div>
  <div class="ov-card">
    <h3>Security Status</h3>
    <a href="/dashboard/events?tab=blocked" class="ov-metric">
      <span class="k">Threat rate</span>
      <span class="v {{if gt .DetectionRate 20}}danger{{else if gt .DetectionRate 5}}warn{{end}}">{{if gt .DetectionRate 0}}{{.DetectionRate}}%{{else}}<span style="color:var(--success)">&lt; 1%</span>{{end}}</span>
    </a>
    <div class="ov-metric">
      <span class="k">Scan latency</span>
      <span class="v" style="color:var(--text2)">{{.AvgLatency}}ms</span>
    </div>
    <a href="/dashboard/settings" class="ov-metric">
      <span class="k">Identity mode</span>
      <span class="v">{{if .RequireSig}}<span style="color:var(--success)">enforced</span>{{else}}<span style="color:var(--text2)">observe</span>{{end}}</span>
    </a>
    <a href="/dashboard/events?tab=quarantine" class="ov-metric">
      <span class="k">Quarantine</span>
      <span class="v">{{if .PendingReview}}<span style="color:var(--warn)">{{.PendingReview}} pending</span>{{else}}<span style="color:var(--success)">clear</span>{{end}}</span>
    </a>
    <a href="/dashboard/events" class="ov-metric">
      <span class="k">Memory poisoning</span>
      <span class="v">{{if gt .MemPoisonCount 0}}<span style="color:var(--danger)">{{.MemPoisonCount}} detected</span>{{else}}<span style="color:var(--success)">clear</span>{{end}}</span>
    </a>
    <div class="ov-metric">
      <span class="k">File guard</span>
      <span class="v">{{if .GuardEnabled}}{{if gt .GuardAlerts 0}}<span style="color:var(--danger)">{{.GuardAlerts}} alerts</span>{{else}}<span style="color:var(--success)">watching</span>{{end}}{{else}}<span style="color:var(--text3)">off</span>{{end}}</span>
    </div>
    {{if .LLMEnabled}}
    <a href="/dashboard/llm" class="ov-metric">
      <span class="k">AI analysis</span>
      <span class="v {{if gt .LLMThreats 5}}warn{{else if gt .LLMThreats 0}}text-secondary{{end}}">{{.LLMThreats}} <span style="color:var(--text3);font-size:var(--text-xs);font-weight:400">findings</span></span>
    </a>
    {{if .LLMTwoStage}}<div class="ov-metric"><span class="k">Stage 1 savings</span><span class="v"><span style="color:var(--success)">{{.LLMStage1Clean}}</span> skipped full analysis</span></div>{{end}}
    {{end}}
  </div>
</div>

{{if .Chart}}
<!-- Activity sparkline. Wrapped in an ov-card with a heading so
     the bar strip carries visible context. The chart itself is
     suppressed by handlers.go when no hour bucket has traffic, so
     reaching this template path means there is data to show. -->
<div class="ov-card" style="margin-bottom:var(--sp-4)">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:var(--sp-3)">
    <h3 style="margin:0">Hourly activity (last 24h)</h3>
    <span style="font-size:var(--text-xs);color:var(--text3)">Routed tool calls per hour</span>
  </div>
  <div class="sparkline-wrap">
    <div class="sparkline-chart">
      {{range .Chart}}<div class="sparkline-bar" style="height:{{.Percent}}%" title="{{.Label}}: {{.Count}} msgs"></div>{{end}}
    </div>
  </div>
</div>
{{end}}

<!-- Top Threats + Agent Risk -->
<div class="ov-grid">
  {{if .TopRules}}
  <div class="ov-card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px"><h3 style="margin:0">Top Threats (24h)</h3><a href="/dashboard/rules" style="font-size:var(--text-sm);color:var(--accent-light);text-decoration:none;font-weight:500">View all &rarr;</a></div>
    {{range .TopRules}}
    <div class="ov-metric clickable" style="cursor:pointer" hx-get="/dashboard/api/rule/{{.RuleID}}" hx-target="#panel-content" hx-swap="innerHTML">
      <span class="k">{{.Name}}<br><span style="color:var(--text3);font-size:var(--text-xs);font-family:var(--mono)">{{.RuleID}}</span></span>
      <span class="v">{{if eq .Severity "critical"}}<span style="color:var(--danger)">{{.Count}}</span>{{else if eq .Severity "high"}}<span style="color:var(--danger)">{{.Count}}</span>{{else}}<span>{{.Count}}</span>{{end}}</span>
    </div>
    {{end}}
  </div>
  {{end}}

  {{if .AgentRisks}}
  <div class="ov-card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px"><h3 style="margin:0" data-tooltip="Risk score based on blocked and flagged messages per agent in the last 24 hours">Agent Risk (24h)</h3><a href="/dashboard/agents" style="font-size:var(--text-sm);color:var(--accent-light);text-decoration:none;font-weight:500">View all &rarr;</a></div>
    <div id="ar-list">
    {{range $i, $a := .AgentRisks}}{{if not (contains $a.Agent ":")}}
    <a href="/dashboard/agents/{{$a.Agent}}" class="ov-metric clickable ar-item" style="cursor:pointer;text-decoration:none;color:inherit">
      <span class="k">{{if eq $a.Agent "unknown"}}<span style="color:var(--text3)">Unidentified</span>{{else}}{{$a.Agent}}{{end}}<br><span style="color:var(--text3);font-size:var(--text-xs);font-family:var(--mono)">{{$a.Total}} msgs</span></span>
      <span class="v">
        <div class="risk-bar" style="width:60px;display:inline-block;vertical-align:middle;margin-right:6px"><div class="risk-bar-fill {{if gt $a.RiskScore 60.0}}risk-high{{else if gt $a.RiskScore 30.0}}risk-med{{else}}risk-low{{end}}" style="width:{{printf "%.0f" $a.RiskScore}}%"></div></div>
        <span style="font-size:var(--text-sm)">{{printf "%.0f" $a.RiskScore}}</span>
      </span>
    </a>
    {{end}}{{end}}
    <div id="ar-pager" style="display:none;padding-top:10px;border-top:1px solid var(--border);margin-top:var(--sp-1)">
      <div style="display:flex;align-items:center;justify-content:space-between">
        <span id="ar-info" style="font-size:var(--text-sm);color:var(--text3)"></span>
        <span style="display:flex;gap:6px">
          <button id="ar-prev" class="pager-btn" onclick="arPage(-1)">&lsaquo; Prev</button>
          <button id="ar-next" class="pager-btn" onclick="arPage(1)">Next &rsaquo;</button>
        </span>
      </div>
    </div>
  </div>
  {{end}}
</div>

{{end}}

<script>
// Agent Risk pagination
(function(){
  var items=document.querySelectorAll('.ar-item');
  if(!items.length)return;
  var sz=15,cur=1,total=items.length,pages=Math.ceil(total/sz);
  var pager=document.getElementById('ar-pager');
  var info=document.getElementById('ar-info');
  if(pages>1&&pager)pager.style.display='block';
  function render(){
    var s=(cur-1)*sz,e=Math.min(s+sz,total);
    items.forEach(function(r,i){r.style.display=(i>=s&&i<e)?'':'none'});
    if(info)info.textContent='Showing '+(s+1)+'–'+e+' of '+total;
    var p=document.getElementById('ar-prev'),n=document.getElementById('ar-next');
    if(p)p.disabled=cur<=1;
    if(n)n.disabled=cur>=pages;
  }
  window.arPage=function(d){cur=Math.max(1,Math.min(pages,cur+d));render()};
  render();
})();
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
    label.textContent = 'live updates connected';
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
        recentDiv.innerHTML = '<table><thead><tr><th>Time</th><th>From</th><th>To</th><th>Status</th></tr></thead><tbody id="events-tbody"></tbody></table>';
        tbody = document.getElementById('events-tbody');
      }

      var statusBadge = '';
      switch(entry.status) {
        case 'delivered': statusBadge = '<span class="badge-delivered">delivered</span>'; break;
        case 'blocked': statusBadge = '<span class="badge-blocked">blocked</span>'; break;
        case 'rejected': statusBadge = '<span class="badge-rejected">rejected</span>'; break;
        case 'quarantined': statusBadge = '<span class="badge-quarantined">quarantined</span>'; break;
        default: statusBadge = _esc(entry.status);
      }

      var row = document.createElement('tr');
      row.className = 'clickable new-event';
      row.setAttribute('hx-get', '/dashboard/api/event/' + entry.id);
      row.setAttribute('hx-target', '#panel-content');
      row.setAttribute('hx-swap', 'innerHTML');
      row.innerHTML = '<td data-ts="' + _esc(entry.timestamp) + '">' + _esc(entry.timestamp) + '</td><td>' + agentCellHTML(entry.from_agent) + '</td><td>' + agentCellHTML(entry.to_agent) + '</td><td>' + statusBadge + '</td>';
      tbody.insertBefore(row, tbody.firstChild);
      htmx.process(row);
      if(typeof humanizeTimestamps==='function')humanizeTimestamps();

      // Keep only 20 rows
      while (tbody.children.length > 20) tbody.removeChild(tbody.lastChild);
    } catch(err) {}
  };

  // Poll hero stats
  function pollHeroStats(){
    fetch('/dashboard/api/stats?_t='+Date.now(),{credentials:'same-origin',cache:'no-store'}).then(function(r){return r.json()}).then(function(d){
      var el=function(id){return document.getElementById(id)};
      if(el('stat-total'))el('stat-total').textContent=d.total_messages.toLocaleString();
      if(el('stat-blocked'))el('stat-blocked').textContent=(d.blocked+d.rejected).toLocaleString();
    }).catch(function(){});
  }
  setInterval(pollHeroStats,4000);

  // Count-up animation on page load
  function animateNum(el){
    var text=el.textContent.replace(/,/g,'');
    var target=parseInt(text,10);
    if(isNaN(target)||target===0)return;
    var duration=600,start=0,startTime=null;
    function step(ts){
      if(!startTime)startTime=ts;
      var p=Math.min((ts-startTime)/duration,1);
      var ease=1-Math.pow(1-p,3); // easeOutCubic
      var val=Math.round(ease*target);
      el.textContent=val.toLocaleString();
      if(p<1)requestAnimationFrame(step);
    }
    el.textContent='0';
    requestAnimationFrame(step);
  }
  document.querySelectorAll('.hero-stat .num').forEach(animateNum);
})();
</script>
` + layoutFoot))

var recentPartialTmpl = template.Must(template.New("recent").Funcs(tmplFuncs).Parse(`
{{if .}}
<table>
  <thead><tr><th>Time</th><th>From</th><th>To</th><th>Status</th></tr></thead>
  <tbody>
  {{range .}}
  <tr class="clickable" hx-get="/dashboard/api/event/{{.ID}}" hx-target="#panel-content" hx-swap="innerHTML">
    <td data-ts="{{.Timestamp}}">{{.Timestamp}}</td>
    <td>{{agentCell .FromAgent}}</td>
    <td>{{agentCell .ToAgent}}</td>
    <td>
      {{if eq .Status "delivered"}}<span class="badge-delivered">delivered</span>
      {{else if eq .Status "blocked"}}<span class="badge-blocked">blocked</span>
      {{else if eq .Status "rejected"}}<span class="badge-rejected">rejected</span>
      {{else if eq .Status "quarantined"}}<span class="badge-quarantined">quarantined</span>
      {{else}}{{.Status}}{{end}}
    </td>
  </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<div class="empty">No events yet.</div>
{{end}}`))

var graphTablesTmpl = template.Must(template.New("graph-tables").Funcs(tmplFuncs).Parse(`
<div class="grid-2" style="gap:20px">
  <div class="card">
    <h2>Agent Risk Scores</h2>
    <p style="color:var(--text3);font-size:0.78rem;margin-bottom:4px">Higher scores mean more blocked or quarantined messages originating from this agent.</p>
    <div style="font-size:0.68rem;color:var(--text3);margin-bottom:12px">Scale 0&ndash;100. <span style="color:var(--success)">&#9679;</span> Low &middot; <span style="color:var(--warn)">&#9679;</span> Medium &middot; <span style="color:var(--danger)">&#9679;</span> High</div>
    {{if .Nodes}}
    <table>
      <thead><tr><th>Agent</th><th>Risk</th><th>Sent</th><th>Received</th><th>Role</th></tr></thead>
      <tbody>
      {{range .Nodes}}
      <tr class="clickable" onclick="location.href='/dashboard/agents/{{.Name}}'">
        <td style="font-weight:600"><a href="/dashboard/agents/{{.Name}}" style="color:inherit;text-decoration:none">{{agentCell .Name}}</a></td>
        <td><div style="display:flex;align-items:center;gap:8px"><div class="risk-bar" style="width:60px"><div class="risk-bar-fill {{if gt .ThreatScore 60.0}}risk-high{{else if gt .ThreatScore 30.0}}risk-med{{else}}risk-low{{end}}" style="width:{{printf "%.0f" .ThreatScore}}%"></div></div><span>{{printf "%.1f" .ThreatScore}}</span></div></td>
        <td>{{.TotalSent}}</td>
        <td>{{.TotalRecv}}</td>
        <td style="color:var(--text3)">{{if eq .Betweenness -1.0}}&#8212;{{else if gt .Betweenness 0.3}}Hub{{else if and (gt .TotalSent 0) (eq .TotalRecv 0)}}Sender{{else if and (eq .TotalSent 0) (gt .TotalRecv 0)}}Receiver{{else}}Peer{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">No agents detected</p>{{end}}
  </div>
  <div class="card">
    <h2>Connection Health</h2>
    <p style="color:var(--text3);font-size:0.78rem;margin-bottom:12px">Percentage of messages successfully delivered on each route.</p>
    {{if .Edges}}
    <table>
      <thead><tr><th>From</th><th>To</th><th>Health</th></tr></thead>
      <tbody id="ch-tbody">
      {{range .Edges}}
      <tr class="ch-row" data-health="{{printf "%.0f" .HealthScore}}" data-blocked="{{.Blocked}}" data-quarantined="{{.Quarantined}}">
        <td>{{.From}}</td>
        <td>{{.To}}</td>
        <td><div style="display:flex;align-items:center;gap:8px"><div class="risk-bar" style="width:60px"><div class="risk-bar-fill {{if lt .HealthScore 40.0}}risk-high{{else if lt .HealthScore 70.0}}risk-med{{else}}risk-low{{end}}" style="width:{{printf "%.0f" .HealthScore}}%"></div></div><span>{{printf "%.0f" .HealthScore}}%</span></div></td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{if gt (len .Edges) 10}}
    <button id="ch-toggle" onclick="toggleTablePagination('ch')" data-open="0" style="margin-top:8px;background:none;border:1px solid var(--border);color:var(--accent-light);padding:6px 16px;border-radius:6px;cursor:pointer;font-size:0.78rem">Show all ({{len .Edges}})</button>
    {{end}}
    {{else}}<p class="empty">No traffic in this time range</p>{{end}}
  </div>
</div>
{{if .ShadowEdges}}
<div class="card" id="unmonitored-section">
  <h2 style="color:var(--warn)">Unmonitored Routes</h2>
  <p style="color:var(--text2);font-size:0.82rem;margin-bottom:12px">Traffic between agents not covered by any security rule.</p>
  <table>
    <thead><tr><th>From</th><th>To</th><th>Messages</th><th></th></tr></thead>
    <tbody>{{range .ShadowEdges}}<tr><td>{{.From}}</td><td>{{.To}}</td><td>{{.Total}}</td><td style="text-align:right"><a href="/dashboard/agents" style="color:var(--accent-light);font-size:0.75rem;text-decoration:none">Add rule &rarr;</a></td></tr>{{end}}</tbody>
  </table>
</div>
{{end}}
{{if .UnrepresentedRoutes}}
<div class="card" id="unrepresented-routes-section">
  <h2>Routes seen but not represented in graph v1</h2>
  <p style="color:var(--text2);font-size:0.82rem;margin-bottom:12px">Forward-proxy domains, hostnames, and endpoints outside the agent-to-agent model in graph v1. Listed here so they remain visible end-to-end.</p>
  <table>
    <thead><tr><th>From</th><th>To</th><th>Total</th><th>Blocked</th><th>Quarantined</th><th>Reason</th></tr></thead>
    <tbody id="ur-tbody">{{range .UnrepresentedRoutes}}<tr class="ur-row"><td style="font-family:var(--mono);font-size:0.8rem">{{.From}}</td><td style="font-family:var(--mono);font-size:0.8rem">{{.To}}</td><td>{{.Total}}</td><td>{{.Blocked}}</td><td>{{.Quarantined}}</td><td style="color:var(--text3);font-size:0.75rem">{{.Reason}}</td></tr>{{end}}</tbody>
  </table>
  {{if gt (len .UnrepresentedRoutes) 10}}
  <button id="ur-toggle" onclick="toggleTablePagination('ur')" data-open="0" style="margin-top:8px;background:none;border:1px solid var(--border);color:var(--accent-light);padding:6px 16px;border-radius:6px;cursor:pointer;font-size:0.78rem">Show all ({{len .UnrepresentedRoutes}})</button>
  {{end}}
</div>
{{end}}`))

var graphEventsTmpl = template.Must(template.New("graph-events").Funcs(tmplFuncs).Parse(`
{{range .}}
<div style="padding:6px 0;border-left:3px solid {{if eq .Status "blocked"}}#f85149{{else if eq .Status "quarantined"}}#d29922{{else}}var(--border){{end}};padding-left:10px;margin-bottom:6px">
  <div style="color:var(--text3);font-size:0.68rem" data-ts="{{.Timestamp}}">{{.Timestamp}}</div>
  {{if .ToolName}}<div style="display:flex;align-items:center;gap:5px">{{if .FromAgent}}<span style="color:var(--text2);font-size:0.7rem;font-weight:500">{{.FromAgent}}:</span> {{end}}{{toolDot .ToolName}} <span style="color:var(--text3);font-size:0.7rem">{{if eq .Status "blocked"}}blocked{{else if eq .Status "quarantined"}}quarantined{{else}}processed{{end}}</span></div>
  {{else}}<span style="color:{{if eq .Status "blocked"}}#f85149{{else if eq .Status "quarantined"}}#d29922{{else}}var(--text2){{end}};font-weight:{{if ne .Status "delivered"}}600{{else}}400{{end}}">{{.FromAgent}} &rarr; {{.ToAgent}}</span>{{end}}
</div>
{{else}}
<div style="color:var(--text3);padding:20px 0;text-align:center">No events yet</div>
{{end}}`))

var searchResultsTmpl = template.Must(template.New("search-results").Funcs(tmplFuncs).Parse(`
{{if .}}
<table>
  <thead><tr><th>Time</th><th>From</th><th>To</th><th>Status</th><th>Decision</th><th>Latency</th></tr></thead>
  <tbody>
  {{range .}}
  <tr class="clickable" hx-get="/dashboard/api/event/{{.ID}}" hx-target="#panel-content" hx-swap="innerHTML">
    <td data-ts="{{.Timestamp}}">{{.Timestamp}}</td>
    <td>{{agentCell .FromAgent}}</td>
    <td>{{agentCell .ToAgent}}</td>
    <td>
      {{if eq .Status "delivered"}}<span class="badge-delivered">delivered</span>
      {{else if eq .Status "blocked"}}<span class="badge-blocked">blocked</span>
      {{else if eq .Status "rejected"}}<span class="badge-rejected">rejected</span>
      {{else if eq .Status "quarantined"}}<span class="badge-quarantined">quarantined</span>
      {{else}}{{.Status}}{{end}}
    </td>
    <td>{{humanDecision .PolicyDecision}}</td>
    <td>{{.LatencyMs}}ms</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<div class="empty">No results found.</div>
{{end}}`))
