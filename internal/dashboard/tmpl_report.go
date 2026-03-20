package dashboard

import "html/template"

var reportTmpl = template.Must(template.New("report").Funcs(tmplFuncs).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>oktsec — Security Posture Report</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2128;
  --border:#30363d;--border-subtle:#21262d;
  --text:#e6edf3;--text2:#8b949e;--text3:#6e7681;
  --accent:#58a6ff;--accent-light:#58a6ff;
  --danger:#f85149;--success:#3fb950;--warn:#d29922;
  --mono:ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,monospace;
  --sans:'Inter',system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;
}
body{font-family:var(--sans);background:var(--bg);color:var(--text);font-size:0.88rem;line-height:1.5;-webkit-font-smoothing:antialiased}
.report{max-width:900px;margin:0 auto;padding:40px 32px}

/* Header */
.rpt-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:32px;padding-bottom:24px;border-bottom:1px solid var(--border)}
.rpt-brand{font-family:var(--mono);font-size:1.5rem;font-weight:700;color:var(--text)}
.rpt-meta{text-align:right;color:var(--text3);font-size:0.78rem}
.rpt-meta .date{font-family:var(--mono);color:var(--text2)}

/* Grade hero */
.grade-hero{display:flex;align-items:center;gap:32px;background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:28px 32px;margin-bottom:28px}
.grade-circle{width:80px;height:80px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-family:var(--mono);font-size:2rem;font-weight:800;flex-shrink:0}
.grade-A{background:rgba(63,185,80,0.12);color:var(--success);border:2px solid rgba(63,185,80,0.3)}
.grade-B{background:rgba(96,165,250,0.12);color:#58a6ff;border:2px solid rgba(96,165,250,0.3)}
.grade-C{background:rgba(251,191,36,0.12);color:var(--warn);border:2px solid rgba(251,191,36,0.3)}
.grade-D{background:rgba(251,146,60,0.12);color:#f85149;border:2px solid rgba(251,146,60,0.3)}
.grade-F{background:rgba(248,113,113,0.12);color:var(--danger);border:2px solid rgba(248,113,113,0.3)}
.grade-info h2{font-size:1.1rem;font-weight:600;margin-bottom:4px}
.grade-info .score-line{color:var(--text2);font-size:0.85rem}
.grade-info .score-line span{font-family:var(--mono);font-weight:700;color:var(--text)}

/* Section */
.rpt-section{margin-bottom:28px}
.rpt-section h3{font-size:0.92rem;font-weight:600;margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid var(--border);color:var(--text)}

/* Stats grid */
.rpt-stats{display:grid;grid-template-columns:repeat(5,1fr);gap:1px;background:var(--border);border:1px solid var(--border);border-radius:10px;overflow:hidden;margin-bottom:28px}
.rpt-stat{background:var(--surface);padding:16px;text-align:center}
.rpt-stat .label{color:var(--text3);font-size:0.68rem;text-transform:uppercase;letter-spacing:0.8px;margin-bottom:4px}
.rpt-stat .value{font-family:var(--mono);font-size:1.4rem;font-weight:700}

/* Table */
table{width:100%;border-collapse:collapse;font-size:0.82rem;margin-bottom:8px}
th{text-align:left;color:var(--text3);font-size:0.68rem;text-transform:uppercase;letter-spacing:0.8px;font-weight:500;padding:8px 12px;border-bottom:1px solid var(--border)}
td{padding:10px 12px;border-bottom:1px solid var(--border-subtle);color:var(--text2);font-family:var(--mono);font-size:0.78rem}

/* Severity */
.sev-critical{color:#f85149;font-weight:600}.sev-high{color:#f85149;font-weight:600}.sev-medium{color:#58a6ff}.sev-low{color:var(--text3)}

/* Risk bar */
.risk-bar{height:6px;border-radius:3px;background:var(--surface2);min-width:60px;display:inline-block;vertical-align:middle}
.risk-fill{height:100%;border-radius:3px;display:block}
.risk-low{background:var(--success)}.risk-med{background:var(--warn)}.risk-high{background:var(--danger)}

/* Chain */
.chain-status{display:inline-flex;align-items:center;gap:8px;padding:6px 14px;border-radius:6px;font-size:0.82rem;font-weight:600;font-family:var(--mono)}
.chain-valid{background:rgba(63,185,80,0.08);color:var(--success);border:1px solid rgba(63,185,80,0.2)}
.chain-broken{background:rgba(248,113,113,0.08);color:var(--danger);border:1px solid rgba(248,113,113,0.2)}

/* Finding */
.finding{padding:10px 14px;border-left:3px solid var(--border);margin-bottom:8px;background:var(--surface);border-radius:0 6px 6px 0}
.finding.critical{border-left-color:#f85149}.finding.high{border-left-color:#f85149}.finding.medium{border-left-color:#58a6ff}.finding.low{border-left-color:var(--text3)}
.finding .f-title{font-weight:600;font-size:0.82rem;margin-bottom:2px}
.finding .f-detail{color:var(--text3);font-size:0.78rem}
.finding .f-id{font-family:var(--mono);font-size:0.68rem;color:var(--text3)}

/* Footer */
.rpt-footer{margin-top:40px;padding-top:20px;border-top:1px solid var(--border);color:var(--text3);font-size:0.72rem;display:flex;justify-content:space-between}

/* Print styles */
@media print{
  body{background:#fff;color:#111;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  .report{padding:20px 0}
  .no-print{display:none!important}
  .grade-hero,.rpt-stat,.finding,.chain-status{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  :root{--bg:#fff;--surface:#f8f8f8;--surface2:#eee;--border:#ddd;--text:#111;--text2:#555;--text3:#888}
}
</style>
</head>
<body>
<div class="report">

<!-- Header -->
<div class="rpt-header">
  <div>
    <div class="rpt-brand">oktsec</div>
    <div style="color:var(--text3);font-size:0.78rem;margin-top:2px">Security Posture Report</div>
  </div>
  <div class="rpt-meta">
    <div class="date">{{.GeneratedAt}}</div>
    <div style="margin-top:4px">{{.AgentCount}} agents configured</div>
    <div class="no-print" style="margin-top:8px">
      <button onclick="window.print()" style="padding:6px 16px;background:var(--accent);color:#fff;border:none;border-radius:6px;font-size:0.78rem;cursor:pointer;font-family:var(--sans)">Print / Save PDF</button>
      <a href="/dashboard" style="margin-left:8px;color:var(--accent-light);font-size:0.78rem">Back to Dashboard</a>
    </div>
  </div>
</div>

<!-- Grade -->
<div class="grade-hero">
  <div class="grade-circle grade-{{.Grade}}">{{.Grade}}</div>
  <div class="grade-info">
    <h2>Security Posture: {{.Grade}} Grade</h2>
    <div class="score-line">Overall score: <span>{{.Score}}/100</span></div>
    <div style="color:var(--text3);font-size:0.78rem;margin-top:4px">
      {{.FindingSummary.Critical}} critical, {{.FindingSummary.High}} high, {{.FindingSummary.Medium}} medium, {{.FindingSummary.Low}} low findings
    </div>
  </div>
</div>

<!-- Traffic Stats -->
<div class="rpt-section">
  <h3>Traffic Summary</h3>
  <div class="rpt-stats">
    <div class="rpt-stat"><div class="label">Total</div><div class="value">{{.Stats.TotalMessages}}</div></div>
    <div class="rpt-stat"><div class="label">Delivered</div><div class="value" style="color:var(--success)">{{.Stats.Delivered}}</div></div>
    <div class="rpt-stat"><div class="label">Blocked</div><div class="value" style="color:var(--danger)">{{.Stats.Blocked}}</div></div>
    <div class="rpt-stat"><div class="label">Quarantined</div><div class="value" style="color:#c084fc">{{.Stats.Quarantined}}</div></div>
    <div class="rpt-stat"><div class="label">Rejected</div><div class="value" style="color:#f85149">{{.Stats.Rejected}}</div></div>
  </div>
  <div style="display:flex;gap:32px;color:var(--text2);font-size:0.82rem">
    <div>Detection rate: <span style="font-family:var(--mono);font-weight:600">{{.DetectionRate}}%</span></div>
    <div>Avg latency: <span style="font-family:var(--mono);font-weight:600">{{printf "%.1f" .AvgLatency}}ms</span></div>
    <div>Unsigned: <span style="font-family:var(--mono);font-weight:600">{{.UnsignedPct}}%</span></div>
    {{if .ChainValid}}<div>Audit chain: <span class="chain-status chain-valid">valid ({{.ChainCount}} entries)</span></div>
    {{else}}<div>Audit chain: <span class="chain-status chain-broken">broken</span></div>{{end}}
  </div>
</div>

<!-- Agent Risk Scores -->
{{if .AgentRisks}}
<div class="rpt-section">
  <h3>Agent Risk Scores</h3>
  <table>
    <thead><tr><th>Agent</th><th>Messages</th><th>Blocked</th><th>Quarantined</th><th>Risk Score</th><th style="min-width:120px">Risk</th></tr></thead>
    <tbody>
    {{range .AgentRisks}}
    <tr>
      <td style="font-weight:600;color:var(--text)">{{.Agent}}</td>
      <td>{{.Total}}</td>
      <td>{{.Blocked}}</td>
      <td>{{.Quarantined}}</td>
      <td>{{printf "%.0f" .RiskScore}}</td>
      <td>
        <div class="risk-bar" style="width:100%"><span class="risk-fill {{if gt .RiskScore 60.0}}risk-high{{else if gt .RiskScore 30.0}}risk-med{{else}}risk-low{{end}}" style="width:{{printf "%.0f" .RiskScore}}%"></span></div>
      </td>
    </tr>
    {{end}}
    </tbody>
  </table>
</div>
{{end}}

<!-- Top Triggered Rules -->
{{if .TopRules}}
<div class="rpt-section">
  <h3>Top Triggered Rules</h3>
  <table>
    <thead><tr><th>Rule ID</th><th>Name</th><th>Severity</th><th>Triggers</th></tr></thead>
    <tbody>
    {{range .TopRules}}
    <tr>
      <td>{{.RuleID}}</td>
      <td style="color:var(--text)">{{.Name}}</td>
      <td><span class="sev-{{.Severity}}">{{.Severity}}</span></td>
      <td>{{.Count}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
</div>
{{end}}

<!-- LLM Analysis Summary -->
{{if .LLMEnabled}}
<div class="rpt-section">
  <h3>LLM Threat Analysis</h3>
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--border);border:1px solid var(--border);border-radius:10px;overflow:hidden;margin-bottom:12px">
    <div class="rpt-stat"><div class="label">Analyses</div><div class="value">{{.LLMCompleted}}</div></div>
    <div class="rpt-stat"><div class="label">Threats</div><div class="value" style="color:var(--danger)">{{.LLMThreats}}</div></div>
    <div class="rpt-stat"><div class="label">Avg Risk</div><div class="value">{{printf "%.0f" .LLMAvgRisk}}</div></div>
    <div class="rpt-stat"><div class="label">Rules Generated</div><div class="value" style="color:var(--accent-light)">{{.LLMRulesGen}}</div></div>
  </div>
  <div style="color:var(--text3);font-size:0.78rem">Provider: <span style="font-family:var(--mono)">{{.LLMProvider}}</span></div>
</div>
{{end}}

<!-- Security Findings -->
{{if .Findings}}
<div class="rpt-section">
  <h3>Security Findings</h3>
  {{range .Findings}}
  <div class="finding {{.SeverityClass}}">
    <div style="display:flex;align-items:center;gap:8px">
      <span class="sev-{{.SeverityClass}}">{{.SeverityLabel}}</span>
      <span class="f-title">{{.Title}}</span>
      <span class="f-id" style="margin-left:auto">{{.CheckID}}</span>
    </div>
    {{if .Detail}}<div class="f-detail" style="margin-top:4px">{{.Detail}}</div>{{end}}
    {{if .Remediation}}<div style="margin-top:4px;font-size:0.75rem;color:var(--accent-light)">Fix: {{.Remediation}}</div>{{end}}
  </div>
  {{end}}
</div>
{{end}}

<!-- Quarantine Summary -->
{{if .QuarantineStats}}
<div class="rpt-section">
  <h3>Quarantine Queue</h3>
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--border);border:1px solid var(--border);border-radius:10px;overflow:hidden">
    <div class="rpt-stat"><div class="label">Pending</div><div class="value" style="color:#f85149">{{.QuarantineStats.Pending}}</div></div>
    <div class="rpt-stat"><div class="label">Approved</div><div class="value" style="color:var(--success)">{{.QuarantineStats.Approved}}</div></div>
    <div class="rpt-stat"><div class="label">Rejected</div><div class="value" style="color:var(--danger)">{{.QuarantineStats.Rejected}}</div></div>
    <div class="rpt-stat"><div class="label">Expired</div><div class="value" style="color:var(--text3)">{{.QuarantineStats.Expired}}</div></div>
  </div>
</div>
{{end}}

<!-- Pipeline Configuration -->
<div class="rpt-section">
  <h3>Pipeline Configuration</h3>
  <table>
    <thead><tr><th>Setting</th><th>Value</th></tr></thead>
    <tbody>
    <tr><td>Mode</td><td>{{if .RequireSig}}Enforce (signatures required){{else}}Observe (signatures optional){{end}}</td></tr>
    <tr><td>Default Policy</td><td>{{.DefaultPolicy}}</td></tr>
    <tr><td>Rate Limit</td><td>{{if .RateLimit}}{{.RateLimit}} req/min{{else}}disabled{{end}}</td></tr>
    <tr><td>Anomaly Detection</td><td>{{if .AnomalyEnabled}}enabled (threshold: {{printf "%.1f" .AnomalyThreshold}}){{else}}disabled{{end}}</td></tr>
    <tr><td>Quarantine</td><td>{{if .QuarantineEnabled}}enabled (TTL: {{.QuarantineTTL}}){{else}}disabled{{end}}</td></tr>
    <tr><td>Detection Rules</td><td>{{.RuleCount}} rules loaded</td></tr>
    <tr><td>Custom Rules</td><td>{{if .CustomRulesDir}}{{.CustomRulesDir}}{{else}}none{{end}}</td></tr>
    <tr><td>LLM Analysis</td><td>{{if .LLMEnabled}}enabled ({{.LLMProvider}}){{else}}disabled{{end}}</td></tr>
    <tr><td>Gateway</td><td>{{if .GatewayEnabled}}enabled ({{.MCPServerCount}} backends){{else}}disabled{{end}}</td></tr>
    </tbody>
  </table>
</div>

<!-- Footer -->
<div class="rpt-footer">
  <span>Generated by oktsec security proxy</span>
  <span>{{.GeneratedAt}}</span>
</div>

</div>
</body>
</html>
`))
