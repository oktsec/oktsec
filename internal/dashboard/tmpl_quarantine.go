package dashboard

import "html/template"

var quarantineDetailTmpl = template.Must(template.New("quarantine-detail").Funcs(tmplFuncs).Parse(`
<div class="panel-header">
  <h3>Quarantined Message</h3>
  <button class="panel-close" onclick="closePanel()" aria-label="Close panel">&times;</button>
</div>
<div class="panel-body">

  <!-- Status banner -->
  <div style="padding:12px 16px;border-radius:8px;margin-bottom:20px;font-size:0.85rem;line-height:1.5;
    {{if eq .Item.Status "pending"}}background:rgba(210,153,34,0.08);border:1px solid rgba(210,153,34,0.2);color:var(--warn)
    {{else if eq .Item.Status "approved"}}background:rgba(63,185,80,0.08);border:1px solid rgba(63,185,80,0.2);color:var(--success)
    {{else if eq .Item.Status "rejected"}}background:rgba(248,81,73,0.08);border:1px solid rgba(248,81,73,0.2);color:var(--danger)
    {{else}}background:var(--surface2);border:1px solid var(--border);color:var(--text3){{end}}">
    {{if eq .Item.Status "pending"}}{{if .IsStepUp}}This tool call exceeded its approval threshold. Approving lets the agent's NEXT retry of the exact same call proceed once.{{else}}This message is held for review. Approve to deliver or reject to discard.{{end}}
    {{else if eq .Item.Status "approved"}}{{if .IsStepUp}}Approved by {{.Item.ReviewedBy}} — the agent's next retry of this exact call will proceed once. Nothing has run yet.{{else}}Approved by {{.Item.ReviewedBy}} — message was delivered.{{end}}
    {{else if eq .Item.Status "rejected"}}Rejected by {{.Item.ReviewedBy}} — {{if .IsStepUp}}the call stays refused.{{else}}message was not delivered.{{end}}
    {{else if eq .Item.Status "expired"}}Expired without review — {{if .IsStepUp}}the call stays refused.{{else}}message was not delivered.{{end}}
    {{else if eq .Item.Status "consumed"}}Approved and already spent — the retried call proceeded once.
    {{else}}{{.Item.Status}}{{end}}
  </div>

  <!-- Message flow -->
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:20px;padding:12px 16px;background:var(--surface2);border-radius:8px">
    <span class="agent-cell" style="font-family:var(--mono);font-weight:600;font-size:0.85rem">{{avatar .Item.FromAgent 24}} {{.Item.FromAgent}}</span>
    <span style="color:var(--text3);font-size:0.82rem">&rarr;</span>
    <span class="agent-cell" style="font-family:var(--mono);font-weight:600;font-size:0.85rem">{{avatar .Item.ToAgent 24}} {{.Item.ToAgent}}</span>
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
    <a href="/dashboard/rules/{{.Category}}" class="q-rule-link">
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
    <tr><td style="color:var(--text3);padding:6px 0;width:100px">Created</td><td style="font-family:var(--mono);padding:6px 0" data-ts="{{.Item.CreatedAt}}">{{.Item.CreatedAt}}</td></tr>
    <tr><td style="color:var(--text3);padding:6px 0">Expires</td><td style="font-family:var(--mono);padding:6px 0" data-ts="{{.Item.ExpiresAt}}">{{.Item.ExpiresAt}}</td></tr>
    {{if .Item.ReviewedBy}}<tr><td style="color:var(--text3);padding:6px 0">Reviewed</td><td style="padding:6px 0">{{.Item.ReviewedBy}} at {{.Item.ReviewedAt}}</td></tr>{{end}}
  </table>

  <!-- AI analysis section -->
  {{if .LLMEnable}}
  <div style="margin-bottom:20px;padding:14px 16px;background:var(--surface2);border:1px solid var(--border);border-radius:8px">
    <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:{{if .SavedAnalysis}}10px{{else}}0{{end}}">
      <div>
        <div style="font-size:0.82rem;font-weight:600;color:var(--text)">AI Analysis</div>
        <div style="font-size:0.72rem;color:var(--text3);margin-top:2px">Let the model explain the risk and recommend approve or reject.</div>
      </div>
      <button class="btn btn-sm ss-ai-btn" id="q-ai-btn-{{.Item.ID}}" type="button" onclick="analyzeQuarantine('{{.Item.ID}}')" style="white-space:nowrap">
        {{if .SavedAnalysis}}Re-analyze{{else}}Analyze with AI{{end}}
      </button>
    </div>
    <div id="q-ai-result-{{.Item.ID}}">
      {{if .SavedAnalysis}}
      <div class="q-ai-content" style="font-size:0.82rem;line-height:1.55;color:var(--text2)">
        {{mdToHTML .SavedAnalysis}}
      </div>
      <div style="font-size:0.68rem;color:var(--text3);margin-top:10px;display:flex;gap:14px">
        <span>Model: {{.AnalysisModel}}</span>
        <span>Analyzed: {{.AnalysisDate}}</span>
      </div>
      {{end}}
    </div>
  </div>
  {{end}}

  {{if eq .Item.Status "pending"}}
  <div class="q-actions" style="margin-top:20px">
    <button class="btn btn-success" hx-post="/dashboard/api/quarantine/{{.Item.ID}}/approve" hx-confirm="Approve and deliver this quarantined message? It will be sent to the recipient." hx-target="#q-row-{{.Item.ID}}" hx-swap="outerHTML" onclick="closePanel()">Approve &amp; Deliver</button>
    <button class="btn btn-danger" hx-post="/dashboard/api/quarantine/{{.Item.ID}}/reject" hx-target="#q-row-{{.Item.ID}}" hx-swap="outerHTML" onclick="closePanel()">Reject</button>
  </div>
  {{end}}
</div>
<script>
function analyzeQuarantine(id) {
  var btn = document.getElementById('q-ai-btn-' + id);
  var out = document.getElementById('q-ai-result-' + id);
  if (!btn || !out) return;
  var original = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Analyzing...';
  fetch('/dashboard/api/quarantine/' + id + '/analyze', {method: 'POST'})
    .then(function(r) {
      if (!r.ok) return r.text().then(function(t){ throw new Error(t || r.statusText); });
      return r.text();
    })
    .then(function(html) {
      out.innerHTML = html;
      btn.disabled = false;
      btn.textContent = 'Re-analyze';
    })
    .catch(function(e) {
      // textContent (not innerHTML) so a hostile upstream provider
      // error body cannot inject markup into the dashboard.
      while (out.firstChild) { out.removeChild(out.firstChild); }
      var errDiv = document.createElement('div');
      errDiv.style.color = 'var(--danger)';
      errDiv.style.fontSize = '0.8rem';
      errDiv.style.padding = '8px 0';
      errDiv.textContent = 'Analysis failed: ' + (e && e.message ? e.message : String(e));
      out.appendChild(errDiv);
      btn.disabled = false;
      btn.textContent = original;
    });
}
</script>`))

var quarantineAnalysisTmpl = template.Must(template.New("quarantine-analysis").Funcs(tmplFuncs).Parse(`
<div class="q-ai-content" style="font-size:0.82rem;line-height:1.55;color:var(--text2)">
  {{mdToHTML .Analysis}}
</div>
<div style="font-size:0.68rem;color:var(--text3);margin-top:10px;display:flex;gap:14px">
  <span>Model: {{.Model}}</span>
  <span>Analyzed: {{.AnalysisDate}}</span>
</div>`))

var quarantineRowTmpl = template.Must(template.New("quarantine-row").Funcs(tmplFuncs).Parse(`<tr id="q-row-{{.Item.ID}}">
  <td data-ts="{{.Item.CreatedAt}}">{{.Item.CreatedAt}}</td>
  <td>{{agentCell .Item.FromAgent}}</td>
  <td>{{agentCell .Item.ToAgent}}</td>
  <td><div class="q-preview">{{truncate .Item.Content 80}}</div></td>
  <td>
    {{if eq .Item.Status "pending"}}<span class="badge-pending">pending</span>
    {{else if eq .Item.Status "approved"}}<span class="badge-approved">approved</span>
    {{else if eq .Item.Status "rejected"}}<span class="badge-rejected">rejected</span>
    {{else if eq .Item.Status "expired"}}<span class="badge-expired">expired</span>
    {{else}}{{.Item.Status}}{{end}}
  </td>
  <td style="font-size:0.72rem;white-space:nowrap">{{if eq .Item.Status "pending"}}<span data-expires="{{.Item.ExpiresAt}}"></span>{{else}}&mdash;{{end}}</td>
  <td>
    <div style="display:flex;gap:4px;align-items:center">
      <button class="btn btn-sm" style="padding:2px 8px;font-size:0.7rem" hx-get="/dashboard/api/quarantine/{{.Item.ID}}" hx-target="#panel-content" hx-swap="innerHTML">view</button>
    </div>
  </td>
</tr>`))
