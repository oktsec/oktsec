package dashboard

import "html/template"

var rulesTmpl = template.Must(template.New("rules").Funcs(tmplFuncs).Parse(layoutHead + `
<p class="page-desc">{{if .RuleCount}}{{.RuleCount}} detection rules active{{if .Categories}} across {{len .Categories}} categories{{end}}. Toggle rules on/off.{{else}}Manage detection rules and create custom rules for your organization.{{end}}</p>

<style>
.rules-tabs{display:flex;gap:0;margin-bottom:var(--sp-6);border-bottom:1px solid var(--border)}
.rules-tab{padding:var(--sp-3) var(--sp-6);color:var(--text3);font-size:var(--text-sm);font-weight:500;cursor:pointer;border-bottom:2px solid transparent;transition:color var(--ease-smooth),border-bottom-color var(--ease-smooth);text-decoration:none;display:inline-flex;align-items:center;gap:var(--sp-2)}
.rules-tab:hover{color:var(--text)}
.rules-tab.active{color:var(--text);border-bottom-color:var(--accent)}
.rules-tab .count{font-size:var(--text-xs);font-family:var(--mono);background:var(--surface2);padding:2px var(--sp-2);border-radius:10px;color:var(--text3)}
.rules-tab.active .count{background:rgba(56,139,253,0.15);color:var(--accent-light)}
.cat-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:1px;background:var(--border);border:1px solid var(--border);border-radius:var(--radius-xl);overflow:hidden;margin-bottom:var(--sp-6)}
@media(max-width:768px){.cat-grid{grid-template-columns:1fr}}
.cat-card{background:var(--surface);padding:var(--sp-5) var(--sp-5);cursor:pointer;transition:background var(--ease-default);text-decoration:none;color:inherit;display:block}
.cat-card:hover{background:var(--surface-hover)}
.cat-card-head{display:flex;align-items:baseline;justify-content:space-between;margin-bottom:var(--sp-2)}
.cat-card-name{font-weight:600;font-size:var(--text-md);letter-spacing:var(--ls-tight);color:var(--text)}
.cat-card-count{color:var(--text3);font-size:var(--text-sm);font-family:var(--mono);white-space:nowrap}
.cat-card-desc{color:var(--text3);font-size:var(--text-sm);line-height:1.5;margin-bottom:10px}
.cat-card-footer{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.cat-card-sev{display:inline-flex;align-items:center;gap:4px;font-size:0.65rem;font-family:var(--mono);padding:2px 7px;border-radius:4px}
.cat-card-sev.critical{background:rgba(248,81,73,0.08);color:#f85149}
.cat-card-sev.high{background:var(--danger-muted);color:var(--danger)}
.cat-card-sev.medium{background:var(--accent-muted);color:var(--accent)}
.cat-card-sev.low{background:var(--surface2);color:var(--text3)}
.cat-card-status{margin-left:auto;font-size:0.68rem;font-weight:500;color:var(--text3)}
.cat-card-status.some-off{color:var(--warn)}
.rules-filters{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}
.rules-filter{padding:4px 12px;border:1px solid var(--border);border-radius:20px;font-size:var(--text-xs);color:var(--text3);cursor:pointer;background:transparent;transition:all 0.15s;user-select:none;font-family:var(--sans)}
.rules-filter:hover{border-color:var(--text3);color:var(--text2)}
.rules-filter.active{background:rgba(56,139,253,0.1);border-color:var(--accent);color:var(--accent-light)}
.custom-rule-row{display:flex;align-items:center;gap:var(--sp-4);padding:14px var(--sp-5);background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-xl);margin-bottom:var(--sp-2);transition:border-color var(--ease-smooth)}
.custom-rule-row:hover{border-color:var(--accent)}
.custom-rule-id{font-family:var(--mono);font-weight:600;font-size:0.82rem;color:var(--text);min-width:200px}
.custom-rule-file{color:var(--text3);font-size:0.75rem;font-family:var(--mono);flex:1}
</style>

<!-- Tabs -->
<div class="rules-tabs">
  <a href="/dashboard/rules?tab=detection" class="rules-tab {{if eq .Tab "detection"}}active{{end}}">Detection Rules{{if .RuleCount}} <span class="count">{{.RuleCount}}</span>{{end}}</a>
  <a href="/dashboard/rules?tab=enforcement" class="rules-tab {{if eq .Tab "enforcement"}}active{{end}}">Enforcement{{if .EnforcementCount}} <span class="count">{{.EnforcementCount}}</span>{{end}}</a>
  {{if .LLMTotalCount}}<a href="/dashboard/rules?tab=llm-rules" class="rules-tab {{if eq .Tab "llm-rules"}}active{{end}}">LLM Rules{{if .LLMPendingCount}} <span class="count" style="background:var(--danger-muted);color:var(--danger)">{{.LLMPendingCount}} pending</span>{{else if .LLMTotalCount}} <span class="count">{{.LLMTotalCount}}</span>{{end}}</a>{{end}}
  <a href="/dashboard/rules?tab=custom" class="rules-tab {{if eq .Tab "custom"}}active{{end}}">Custom Rules{{if .CustomCount}} <span class="count">{{.CustomCount}}</span>{{end}}</a>
</div>

{{if eq .Tab "detection"}}
<!-- Detection Rules Tab -->
{{if .Categories}}

{{if .TopRules}}
<div style="margin-bottom:20px">
  <div style="font-size:var(--text-xs);font-weight:600;text-transform:uppercase;letter-spacing:var(--ls-caps);color:var(--text3);margin-bottom:var(--sp-2)">Most triggered rules</div>
  <div style="display:flex;gap:8px;flex-wrap:wrap">
    {{range .TopRules}}<a href="/dashboard/rules/{{.RuleID}}" style="display:inline-flex;align-items:center;gap:6px;padding:4px 12px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-md);font-size:var(--text-xs);color:var(--text);text-decoration:none;transition:border-color var(--ease-smooth)" title="{{.Name}}"><span style="font-family:var(--mono);font-weight:600">{{.RuleID}}</span><span style="color:var(--text3)">{{.Count}}x</span></a>{{end}}
  </div>
</div>
{{end}}

{{if or .LLMPendingCount .LLMActiveCount}}
<div style="display:flex;align-items:center;gap:16px;padding:14px 20px;margin-bottom:20px;background:var(--surface);border:1px solid rgba(56,139,253,0.2);border-radius:10px">
  <div style="flex:1;min-width:0">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:2px">
      <span style="font-weight:600;font-size:0.85rem">AI-Generated Rules</span>
      {{if .LLMPendingCount}}<span style="font-size:0.68rem;padding:2px 8px;border-radius:4px;background:var(--danger-muted);color:var(--danger);font-weight:600">{{.LLMPendingCount}} pending review</span>{{end}}
    </div>
    <span style="font-size:0.75rem;color:var(--text3)">{{.LLMActiveCount}} LLM-generated rules active{{if .LLMPendingCount}} &middot; {{.LLMPendingCount}} awaiting approval{{end}}</span>
  </div>
  <a href="/dashboard/rules?tab=llm-rules" class="btn btn-sm" style="font-size:0.72rem;white-space:nowrap">Review Rules</a>
</div>
{{end}}

<div class="rules-filters">
  <button class="rules-filter" data-filter="disabled" onclick="rfToggle(this)">Has disabled</button>
  <button class="rules-filter" data-filter="highplus" onclick="rfToggle(this)">High+ severity</button>
  <button class="rules-filter" data-filter="triggered" onclick="rfToggle(this)">Recently triggered</button>
</div>

<div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:16px">
  <span style="color:var(--text3);font-size:0.78rem">{{.RuleCount}} rules across {{len .Categories}} categories</span>
  <div style="display:flex;gap:8px">
    <button class="btn btn-sm" style="font-size:0.72rem" hx-post="/dashboard/api/rules/bulk-toggle" hx-vals='{"action":"enable-all"}' hx-confirm="Enable ALL {{.RuleCount}} detection rules?">Enable All ({{.RuleCount}})</button>
    <button class="btn btn-sm" style="font-size:0.72rem;background:transparent;border:1px solid var(--border);color:var(--text3)" hx-post="/dashboard/api/rules/bulk-toggle" hx-vals='{"action":"disable-all"}' hx-confirm="Disable ALL {{.RuleCount}} detection rules? This removes all security scanning.">Disable All ({{.RuleCount}})</button>
  </div>
</div>
<div class="cat-grid">
  {{range .Categories}}
  <a href="/dashboard/rules/{{.Name}}" class="cat-card" data-disabled="{{.Disabled}}" data-critical="{{.Critical}}" data-high="{{.High}}" data-triggered="{{.Triggered}}">
    <div class="cat-card-head">
      <span class="cat-card-name">{{kebabToTitle .Name}}</span>
      <span class="cat-card-count">{{.Total}}</span>
    </div>
    {{if .Description}}<div class="cat-card-desc">{{.Description}}</div>{{end}}
    <div class="cat-card-footer">
      {{if .Critical}}<span class="cat-card-sev critical">{{.Critical}} critical</span>{{end}}
      {{if .High}}<span class="cat-card-sev high">{{.High}} high</span>{{end}}
      {{if .Medium}}<span class="cat-card-sev medium">{{.Medium}} medium</span>{{end}}
      {{if .Low}}<span class="cat-card-sev low">{{.Low}} low</span>{{end}}
      {{if .Triggered}}<span class="cat-card-sev" style="background:rgba(187,128,9,0.08);color:var(--warn)">{{.Triggered}} triggered</span>{{end}}
      {{if and (gt .Disabled 0) (lt .Disabled .Total)}}<span class="cat-card-status some-off">{{.Disabled}} off</span>{{end}}
      {{if eq .Disabled .Total}}<span class="cat-card-status">all off</span>{{end}}
    </div>
  </a>
  {{end}}
</div>

<script>
(function(){
  var active = {};
  window.rfToggle = function(btn) {
    var f = btn.dataset.filter;
    if (active[f]) { delete active[f]; btn.classList.remove('active'); }
    else { active[f] = true; btn.classList.add('active'); }
    var cards = document.querySelectorAll('.cat-card');
    var keys = Object.keys(active);
    cards.forEach(function(c) {
      if (!keys.length) { c.style.display = ''; return; }
      var ok = true;
      if (active.disabled && parseInt(c.dataset.disabled) === 0) ok = false;
      if (active.highplus && parseInt(c.dataset.critical) + parseInt(c.dataset.high) === 0) ok = false;
      if (active.triggered && parseInt(c.dataset.triggered) === 0) ok = false;
      c.style.display = ok ? '' : 'none';
    });
  };
})();
</script>

{{else}}
<div class="empty">No rules loaded.</div>
{{end}}

{{else if eq .Tab "llm-rules"}}
<!-- LLM-Generated Rules Tab (Security Posture style) -->
<style>
.lr-fi{display:flex;align-items:flex-start;gap:10px;padding:12px 20px;border-bottom:1px solid var(--border)}
.lr-fi:last-child{border-bottom:none}
.lr-fi-sev{min-width:60px;flex-shrink:0;padding-top:1px}
.lr-fi-body{flex:1;min-width:0}
.lr-fi-head{display:flex;align-items:baseline;gap:8px}
.lr-fi-id{font-family:var(--mono);font-size:0.8125rem;font-weight:600;color:var(--text2)}
.lr-fi-title{font-size:0.8125rem;color:var(--text);font-weight:500}
.lr-fi-detail{font-size:0.75rem;color:var(--text3);margin-top:4px;line-height:1.5}
.lr-fi-meta{display:flex;align-items:center;gap:10px;margin-top:6px;font-size:0.72rem;color:var(--text3);flex-wrap:wrap}
.lr-fi-meta code{font-family:var(--mono);font-size:var(--text-sm);color:var(--accent-light);background:var(--surface);padding:2px 6px;border-radius:var(--radius-sm)}
.lr-fi-actions{display:flex;gap:8px;margin-top:8px}
.lr-sec{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-xl);overflow:hidden;margin-bottom:var(--sp-5)}
.lr-sec-title{font-size:0.72rem;font-weight:600;text-transform:uppercase;letter-spacing:0.8px;padding:14px 20px;border-bottom:1px solid var(--border)}
</style>

{{if .LLMPending}}
<div class="lr-sec">
  <div class="lr-sec-title" style="color:var(--warn)">Pending Review ({{len .LLMPending}})</div>
  {{range .LLMPending}}
  <div class="lr-fi">
    <span class="lr-fi-sev"><span class="ci-sev ci-sev-{{if eq .Severity "critical"}}c{{else if eq .Severity "high"}}h{{else if eq .Severity "medium"}}m{{else}}l{{end}}">{{upper .Severity}}</span></span>
    <div class="lr-fi-body">
      <div class="lr-fi-head">
        <span class="lr-fi-id">{{.ID}}</span>
        <span class="lr-fi-title">{{.Name}}</span>
      </div>
      <div class="lr-fi-detail">{{.Description}}</div>
      <div class="lr-fi-meta">
        <span>{{.Category}}</span>
        <span>confidence: <strong style="color:var(--text)">{{printf "%.0f" (mulf .Confidence 100)}}%</strong></span>
        <span>model: <span style="font-family:var(--mono)">{{.GeneratedBy}}</span></span>
        {{if .MessageID}}<span>from: <a href="/dashboard/llm/case/llm-{{.MessageID}}" style="color:var(--accent);font-family:var(--mono)">{{truncate .MessageID 12}}...</a></span>{{end}}
        {{range .Patterns}}<code>{{.Value}}</code>{{end}}
      </div>
      <div class="lr-fi-actions" id="lr-act-{{.ID}}">
        <button class="btn btn-sm btn-success" hx-post="/dashboard/api/rules/llm/{{.ID}}/approve" hx-confirm="Activate this AI-generated rule? It will start scanning all messages." hx-target="#lr-act-{{.ID}}" hx-swap="innerHTML">Approve &amp; Activate</button>
        <button class="btn btn-sm" style="background:var(--surface2);color:var(--text3)" hx-post="/dashboard/api/rules/llm/{{.ID}}/reject" hx-confirm="Reject this rule? It will be discarded." hx-target="#lr-act-{{.ID}}" hx-swap="innerHTML">Reject</button>
      </div>
    </div>
  </div>
  {{end}}
</div>
{{end}}

{{if .LLMActive}}
<div class="lr-sec">
  <div class="lr-sec-title" style="color:var(--success)">Active ({{len .LLMActive}})</div>
  {{range .LLMActive}}
  <div class="lr-fi">
    <span class="lr-fi-sev"><span class="ci-sev ci-sev-{{if eq .Severity "critical"}}c{{else if eq .Severity "high"}}h{{else if eq .Severity "medium"}}m{{else}}l{{end}}">{{upper .Severity}}</span></span>
    <div class="lr-fi-body">
      <div class="lr-fi-head">
        <span class="lr-fi-id">{{.ID}}</span>
        <span class="lr-fi-title">{{.Name}}</span>
      </div>
      <div class="lr-fi-detail">{{.Description}}</div>
      <div class="lr-fi-meta">
        <span>{{.Category}}</span>
        <span>confidence: <strong style="color:var(--text)">{{printf "%.0f" (mulf .Confidence 100)}}%</strong></span>
        {{range .Patterns}}<code>{{.Value}}</code>{{end}}
      </div>
    </div>
    <div class="lr-fi-actions" id="lr-act-{{.ID}}">
      <button class="btn btn-sm" style="background:var(--surface2);color:var(--text3)" hx-post="/dashboard/api/rules/llm/{{.ID}}/deactivate" hx-target="#lr-act-{{.ID}}" hx-swap="innerHTML">Deactivate</button>
    </div>
  </div>
  {{end}}
</div>
{{end}}

{{if .LLMDisabled}}
<div class="lr-sec">
  <div class="lr-sec-title" style="color:var(--text3)">Disabled ({{len .LLMDisabled}})</div>
  {{range .LLMDisabled}}
  <div class="lr-fi" style="opacity:0.6">
    <span class="lr-fi-sev"><span class="ci-sev ci-sev-{{if eq .Severity "critical"}}c{{else if eq .Severity "high"}}h{{else if eq .Severity "medium"}}m{{else}}l{{end}}">{{upper .Severity}}</span></span>
    <div class="lr-fi-body">
      <div class="lr-fi-head">
        <span class="lr-fi-id">{{.ID}}</span>
        <span class="lr-fi-title">{{.Name}}</span>
      </div>
      <div class="lr-fi-detail">{{.Description}}</div>
      <div class="lr-fi-meta">
        <span>{{.Category}}</span>
        <span>confidence: <strong style="color:var(--text)">{{printf "%.0f" (mulf .Confidence 100)}}%</strong></span>
        {{range .Patterns}}<code>{{.Value}}</code>{{end}}
      </div>
    </div>
    <div class="lr-fi-actions" id="lr-act-{{.ID}}">
      <button class="btn btn-sm btn-success" hx-post="/dashboard/api/rules/llm/{{.ID}}/approve" hx-target="#lr-act-{{.ID}}" hx-swap="innerHTML">Re-activate</button>
    </div>
  </div>
  {{end}}
</div>
{{end}}

{{if and (not .LLMPending) (not .LLMActive) (not .LLMDisabled)}}
<div class="empty">No LLM-generated rules found. Rules are generated when the LLM layer detects threats with high confidence.</div>
{{end}}

{{else if eq .Tab "enforcement"}}
<!-- Enforcement Tab -->
<style>
.enf-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-xl);padding:var(--sp-4) var(--sp-5);margin-bottom:10px;transition:border-color var(--ease-smooth)}
.enf-card:hover{border-color:var(--accent)}
.enf-card-top{display:flex;align-items:center;gap:12px}
.enf-id{font-family:var(--mono);font-weight:600;font-size:0.85rem;color:var(--text)}
.enf-name{color:var(--text2);font-size:0.78rem;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.enf-badge{font-size:0.68rem;font-family:var(--mono);padding:3px 10px;border-radius:4px;font-weight:600;text-transform:uppercase;white-space:nowrap}
.enf-badge.block{background:rgba(248,81,73,0.08);color:#f85149}
.enf-badge.quarantine{background:var(--danger-muted);color:var(--danger)}
.enf-badge.allow-and-flag{background:var(--accent-muted);color:var(--accent)}
.enf-badge.ignore{background:var(--surface2);color:var(--text3)}
.enf-meta{display:flex;align-items:center;gap:8px;margin-top:8px;flex-wrap:wrap}
.enf-tag{font-size:0.68rem;font-family:var(--mono);padding:2px 8px;border-radius:4px;background:var(--surface2);color:var(--text3)}
.enf-tag.sev-critical{background:rgba(248,81,73,0.06);color:#f85149}
.enf-tag.sev-high{background:var(--danger-muted);color:var(--danger)}
.enf-tag.sev-medium{background:var(--accent-muted);color:var(--accent)}
.enf-urls{margin-top:var(--sp-2);padding:var(--sp-2) var(--sp-3);background:var(--surface);border-radius:var(--radius-md);font-family:var(--mono);font-size:var(--text-sm);color:var(--text3);line-height:1.8;word-break:break-all}
.enf-btns{display:flex;gap:6px}
/* Combobox */
.combo-wrap{position:relative}
.combo-input{width:100%;font-family:var(--mono);font-size:0.82rem}
.combo-drop{position:absolute;top:100%;left:0;right:0;max-height:260px;overflow-y:auto;background:var(--surface);border:1px solid var(--border);border-top:none;border-radius:0 0 8px 8px;z-index:100;display:none}
.combo-drop.open{display:block}
.combo-item{padding:8px 14px;cursor:pointer;font-size:0.8rem;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
.combo-item:last-child{border-bottom:none}
.combo-item:hover,.combo-item.hl{background:var(--surface2)}
.combo-item .cid{font-family:var(--mono);font-weight:600;font-size:0.78rem;color:var(--text);min-width:120px}
.combo-item .cnm{color:var(--text2);font-size:0.75rem;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.combo-item .csv{font-size:0.65rem;font-family:var(--mono);padding:2px 6px;border-radius:3px}
.csv.critical{background:rgba(248,81,73,0.08);color:#f85149}
.csv.high{background:var(--danger-muted);color:var(--danger)}
.csv.medium{background:var(--accent-muted);color:var(--accent)}
.csv.low{background:var(--surface2);color:var(--text3)}
.combo-empty{padding:12px 14px;color:var(--text3);font-size:0.78rem;font-style:italic}
/* Channel chips */
.ch-chip{display:inline-flex;align-items:center;gap:5px;padding:5px 12px;border-radius:20px;background:var(--surface);border:1px solid var(--border);cursor:pointer;font-size:0.78rem;font-family:var(--mono);color:var(--text2);transition:background 0.15s,border-color 0.15s,color 0.15s;user-select:none;white-space:nowrap}
.ch-chip:hover{border-color:var(--accent-dim);color:var(--text)}
.ch-chip input{position:absolute;opacity:0;pointer-events:none}
.ch-check{display:none;font-size:0.65rem;color:var(--accent-light)}
.ch-chip:has(input:checked){background:rgba(56,139,253,0.1);border-color:var(--accent);color:var(--accent-light)}
.ch-chip:has(input:checked) .ch-check{display:inline}
</style>

<div class="card" style="border-color:var(--accent-dim);border-width:1px">
  <h2 id="enf-title" style="margin-bottom:4px">Add Override</h2>
  <p style="color:var(--text2);font-size:0.82rem;margin-bottom:20px;line-height:1.6">
    Override the default severity-based action for specific rules. Escalate, downgrade, or silence rules regardless of their built-in severity.
  </p>

  <form id="enf-form" method="POST" action="/dashboard/rules/enforcement">
    <div class="form-row">
      <div class="form-group" style="flex:3">
        <label>Rule</label>
        <div class="combo-wrap">
          <input type="hidden" name="rule_id" id="enf-rid">
          <input type="text" class="combo-input" id="enf-search" placeholder="Search by ID, name, or category..." autocomplete="off">
          <div class="combo-drop" id="enf-drop"></div>
        </div>
      </div>
      <div class="form-group" style="flex:1;min-width:200px">
        <label>Action</label>
        <select name="action" id="enf-action" required>
          <option value="block">Block</option>
          <option value="quarantine">Quarantine</option>
          <option value="allow-and-flag">Flag</option>
          <option value="ignore">Ignore</option>
        </select>
      </div>
    </div>

    {{if .WebhookChannels}}
    <div class="form-group" style="margin-bottom:16px">
      <label>Notify Channels</label>
      <div id="enf-channels" style="display:flex;flex-wrap:wrap;gap:6px;align-items:center">
        {{range .WebhookChannels}}{{if .Name}}
        <label class="ch-chip">
          <input type="checkbox" name="notify_channel" value="{{.Name}}">
          <span class="ch-check">&#10003;</span>
          <span class="ch-name">{{.Name}}</span>
        </label>
        {{end}}{{end}}
        <a href="/dashboard/alerts" style="color:var(--text3);font-size:0.7rem;margin-left:4px;text-decoration:none;opacity:0.7" title="Manage channels in Notifications">+ manage</a>
      </div>
    </div>
    {{end}}

    <div class="form-group" style="margin-bottom:16px">
      <label>Additional Webhook URLs <span style="color:var(--text3);font-weight:400;text-transform:none;letter-spacing:0">(optional, one per line)</span></label>
      <textarea name="notify_urls" id="enf-notify" placeholder="https://hooks.slack.com/services/T00/B00/xxx" style="min-height:40px;line-height:1.8"></textarea>
    </div>

    <div class="form-group" id="enf-tmpl-group" style="margin-bottom:16px">
      <label>Webhook Message</label>
      <textarea name="template" id="enf-tmpl" style="min-height:80px;line-height:1.7;font-size:0.85rem">🚨 *{{"{{RULE}}"}}* — {{"{{RULE_NAME}}"}}
• *Severity:* {{"{{SEVERITY}}"}} | *Category:* {{"{{CATEGORY}}"}}
• *Agents:* {{"{{FROM}}"}} → {{"{{TO}}"}}
• *Match:* '{{"{{MATCH}}"}}'
• *Message:* {{"{{MESSAGE_ID}}"}}
• *Time:* {{"{{TIMESTAMP}}"}}</textarea>
      <div style="color:var(--text3);font-size:0.72rem;margin-top:4px;line-height:1.5">
        Variables: <code>{{"{{RULE}}"}}</code>
        <code>{{"{{RULE_NAME}}"}}</code>
        <code>{{"{{CATEGORY}}"}}</code>
        <code>{{"{{MATCH}}"}}</code>
        <code>{{"{{ACTION}}"}}</code>
        <code>{{"{{SEVERITY}}"}}</code>
        <code>{{"{{FROM}}"}}</code>
        <code>{{"{{TO}}"}}</code>
        <code>{{"{{MESSAGE_ID}}"}}</code>
        <code>{{"{{TIMESTAMP}}"}}</code>.
        Write plain text — automatically formatted for Slack/Discord.
      </div>
    </div>

    <input type="hidden" name="severity" value="">

    <div style="display:flex;align-items:center;gap:12px">
      <button type="submit" class="btn" id="enf-btn">Save Override</button>
      <button type="button" class="btn" id="enf-cancel" style="display:none;background:var(--surface2);color:var(--text2)" onclick="enfReset()">Cancel</button>
      <span style="color:var(--text3);font-size:0.72rem">Takes effect immediately.</span>
    </div>
  </form>
</div>

{{if .Overrides}}
<h2 style="font-size:0.95rem;font-weight:600;margin:28px 0 16px">Active Overrides <span style="color:var(--text3);font-weight:400;font-size:0.78rem">({{len .Overrides}})</span></h2>
{{range .Overrides}}
<div class="enf-card" id="enf-card-{{.ID}}" data-action="{{.Action}}" data-notify="{{range $i, $u := .Notify}}{{if $i}}&#10;{{end}}{{$u}}{{end}}" data-template="{{.Template}}">
  <div class="enf-card-top">
    <span class="enf-id">{{.ID}}</span>
    {{if .Name}}<span class="enf-name">{{.Name}}</span>{{end}}
    <span class="enf-badge {{.Action}}">{{.Action}}</span>
    <div class="enf-btns">
      <button class="btn btn-sm" style="background:var(--surface2);color:var(--text2)" onclick="enfEdit(this.closest('.enf-card'))">edit</button>
      <button class="btn btn-sm btn-danger" hx-delete="/dashboard/rules/enforcement/{{.ID}}" hx-confirm="Remove override for {{.ID}}?" hx-target="#enf-card-{{.ID}}" hx-swap="outerHTML swap:200ms">remove</button>
    </div>
  </div>
  {{if .Description}}<div style="color:var(--text2);font-size:0.78rem;margin-top:6px;line-height:1.5">{{.Description}}</div>{{end}}
  <div class="enf-meta">
    {{if .Category}}<span class="enf-tag">{{.Category}}</span>{{end}}
    {{if .DefaultSeverity}}<span class="enf-tag sev-{{.DefaultSeverity}}">default: {{.DefaultSeverity}}</span>{{end}}
    {{if .Notify}}{{range .Notify}}{{if not (contains . "://")}} <span class="enf-tag" style="background:rgba(56,139,253,0.1);color:var(--accent-light)">{{.}}</span>{{end}}{{end}}<span class="enf-tag" style="cursor:pointer" onclick="document.getElementById('enf-wh-{{$.ID}}').style.display=document.getElementById('enf-wh-{{$.ID}}').style.display==='none'?'block':'none'">{{len .Notify}} webhook{{if gt (len .Notify) 1}}s{{end}} &#9662;</span>{{end}}
    {{if .Template}}<span class="enf-tag" style="cursor:pointer" onclick="document.getElementById('enf-tp-{{.ID}}').style.display=document.getElementById('enf-tp-{{.ID}}').style.display==='none'?'block':'none'">template &#9662;</span>{{end}}
  </div>
  {{if .Notify}}<div class="enf-urls" id="enf-wh-{{.ID}}" style="display:none">{{range .Notify}}{{.}}<br>{{end}}</div>{{end}}
  {{if .Template}}<div class="enf-urls" id="enf-tp-{{.ID}}" style="display:none;white-space:pre-wrap">{{.Template}}</div>{{end}}
</div>
{{end}}
{{else}}
<div class="empty" style="padding:20px 0;margin-top:24px">No overrides configured. Rules use their default severity-based actions.</div>
{{end}}

<div class="card" style="margin-top:24px;background:var(--bg);border-style:dashed">
  <details>
    <summary style="color:var(--text2);font-size:0.82rem;cursor:pointer;user-select:none;font-weight:500">How enforcement overrides work</summary>
    <div style="color:var(--text3);font-size:0.78rem;line-height:1.7;margin-top:14px;padding-left:4px">
      <p style="margin-bottom:8px"><strong style="color:var(--text2)">1. Default behavior.</strong> Without overrides, the action is determined by rule severity: critical &rarr; block, high &rarr; quarantine, medium &rarr; flag.</p>
      <p style="margin-bottom:8px"><strong style="color:var(--text2)">2. Override actions.</strong> <strong>Block</strong> rejects the message. <strong>Quarantine</strong> holds it for human review. <strong>Flag</strong> delivers with a warning. <strong>Ignore</strong> suppresses the finding entirely.</p>
      <p style="margin-bottom:8px"><strong style="color:var(--text2)">3. Pipeline order.</strong> Overrides apply before per-agent blocked content and history escalation, so safety nets remain active even after a downgrade.</p>
      <p><strong style="color:var(--text2)">4. Webhooks.</strong> Per-rule webhook URLs receive a <code style="background:var(--surface);padding:1px 5px;border-radius:3px;font-family:var(--mono);font-size:0.72rem">rule_triggered</code> event whenever the rule fires, independent of the action taken.</p>
    </div>
  </details>
</div>

<script>
(function(){
  var R = {{.RulesJSON | safeJS}};
  var search = document.getElementById('enf-search');
  var hidden = document.getElementById('enf-rid');
  var drop = document.getElementById('enf-drop');
  var aidx = -1;

  function html(items) {
    if (!items.length) { drop.innerHTML = '<div class="combo-empty">No matching rules</div>'; drop.classList.add('open'); return; }
    drop.innerHTML = items.map(function(r,i){
      return '<div class="combo-item" data-id="'+r.id+'">'
        +'<span class="cid">'+r.id+'</span>'
        +'<span class="cnm">'+r.name+'</span>'
        +'<span class="csv '+r.severity+'">'+r.severity+'</span>'
        +'</div>';
    }).join('');
    drop.classList.add('open'); aidx=-1;
  }

  function doFilter() {
    var q = search.value.toLowerCase();
    if (!q) { html(R.slice(0,40)); return; }
    html(R.filter(function(r){ return r.id.toLowerCase().indexOf(q)>=0||r.name.toLowerCase().indexOf(q)>=0||r.category.toLowerCase().indexOf(q)>=0; }).slice(0,40));
  }

  function pick(id) {
    hidden.value = id;
    var r = R.find(function(x){return x.id===id;});
    search.value = r ? r.id+' — '+r.name : id;
    drop.classList.remove('open');
  }

  search.addEventListener('input', doFilter);
  search.addEventListener('focus', function(){ if(!drop.classList.contains('open')) doFilter(); });
  drop.addEventListener('click', function(e){ var it=e.target.closest('.combo-item'); if(it) pick(it.dataset.id); });

  search.addEventListener('keydown', function(e){
    var items = drop.querySelectorAll('.combo-item');
    if(e.key==='ArrowDown'){e.preventDefault();aidx=Math.min(aidx+1,items.length-1);}
    else if(e.key==='ArrowUp'){e.preventDefault();aidx=Math.max(aidx-1,0);}
    else if(e.key==='Enter'&&aidx>=0&&items[aidx]){e.preventDefault();pick(items[aidx].dataset.id);return;}
    else if(e.key==='Escape'){drop.classList.remove('open');return;}
    else return;
    items.forEach(function(el,i){el.classList.toggle('hl',i===aidx);});
    if(items[aidx]) items[aidx].scrollIntoView({block:'nearest'});
  });

  document.addEventListener('click', function(e){ if(!e.target.closest('.combo-wrap')) drop.classList.remove('open'); });

  var notifyEl = document.getElementById('enf-notify');
  var tmplEl = document.getElementById('enf-tmpl');
  var defaultTmpl = tmplEl.value;

  // Validate: require a selected rule
  document.getElementById('enf-form').addEventListener('submit', function(e){
    if(!hidden.value){e.preventDefault();search.focus();search.style.outline='2px solid #f85149';setTimeout(function(){search.style.outline='';},1500);}
  });

  // Edit: populate form from card data attributes
  // Helper: get all channel checkbox names
  function channelNames() {
    var cbs = document.querySelectorAll('#enf-channels input[type=checkbox]');
    var names = {};
    cbs.forEach(function(cb){ names[cb.value]=cb; });
    return names;
  }

  window.enfEdit = function(card) {
    var id = card.id.replace('enf-card-','');
    pick(id);
    document.getElementById('enf-action').value = card.dataset.action;
    tmplEl.value = card.dataset.template||'';

    // Split data-notify into channel names vs raw URLs
    var raw = (card.dataset.notify||'').split('\n');
    var chs = channelNames();
    var urls = [];
    // Uncheck all first
    Object.values(chs).forEach(function(cb){ cb.checked=false; });
    raw.forEach(function(line){
      line = line.trim();
      if (!line) return;
      if (chs[line]) { chs[line].checked = true; }
      else { urls.push(line); }
    });
    notifyEl.value = urls.join('\n');

    document.getElementById('enf-title').textContent = 'Edit Override — '+id;
    document.getElementById('enf-btn').textContent = 'Update Override';
    document.getElementById('enf-cancel').style.display = '';
    search.readOnly = true; search.style.opacity='0.6';
    window.scrollTo({top:0,behavior:'smooth'});
  };

  window.enfReset = function() {
    hidden.value=''; search.value=''; search.readOnly=false; search.style.opacity='';
    document.getElementById('enf-action').value='block';
    notifyEl.value=''; tmplEl.value=defaultTmpl;
    // Uncheck all channel checkboxes
    document.querySelectorAll('#enf-channels input[type=checkbox]').forEach(function(cb){ cb.checked=false; });
    document.getElementById('enf-title').textContent='Add Override';
    document.getElementById('enf-btn').textContent='Save Override';
    document.getElementById('enf-cancel').style.display='none';
  };
})();
</script>

{{else}}
<!-- Custom Rules Tab -->
<div class="card" style="border-color:var(--accent-dim);border-width:1px">
  <h2 style="margin-bottom:4px">Create Custom Rule</h2>
  <p style="color:var(--text2);font-size:0.82rem;margin-bottom:20px;line-height:1.6">
    Block messages containing keywords specific to your organization. Custom rules work alongside the built-in detection engine.
  </p>

  <form method="POST" action="/dashboard/rules/custom">
    <div class="form-row">
      <div class="form-group" style="flex:2">
        <label>Rule Name</label>
        <input type="text" name="name" placeholder="e.g. Block internal API keys" required>
        <div style="color:var(--text3);font-size:0.72rem;margin-top:4px">A short description of what this rule detects.</div>
      </div>
      <div class="form-group" style="max-width:180px">
        <label>Severity</label>
        <select name="severity">
          <option value="critical">Critical &mdash; block</option>
          <option value="high" selected>High &mdash; quarantine</option>
          <option value="medium">Medium &mdash; flag</option>
          <option value="low">Low &mdash; log only</option>
        </select>
        <div style="color:var(--text3);font-size:0.72rem;margin-top:4px">Determines the action taken.</div>
      </div>
    </div>

    <div class="form-group" style="margin-bottom:16px">
      <label>Keywords <span style="color:var(--text3);font-weight:400;text-transform:none;letter-spacing:0">(one per line)</span></label>
      <textarea name="patterns" required placeholder="aws_secret_access_key&#10;PRIVATE KEY&#10;password123&#10;internal_db_connection" style="min-height:110px;line-height:1.8"></textarea>
      <div style="color:var(--text3);font-size:0.72rem;margin-top:4px;line-height:1.5">
        Messages containing <strong style="color:var(--text2)">any</strong> of these keywords will trigger the rule. Case-insensitive substring match.
      </div>
    </div>

    <input type="hidden" name="rule_id" value="">
    <input type="hidden" name="category" value="custom">

    <div style="display:flex;align-items:center;gap:12px">
      <button type="submit" class="btn">Create Rule</button>
      <span style="color:var(--text3);font-size:0.72rem">Takes effect immediately for new messages.</span>
    </div>
  </form>
</div>

{{if .CustomFiles}}
<h2 style="font-size:0.95rem;font-weight:600;margin:28px 0 16px">Your Rules</h2>
{{range .CustomFiles}}
<div class="custom-rule-row">
  <div style="flex:1;min-width:0">
    <div class="custom-rule-id">{{.ID}}</div>
    {{if .Name}}<div style="color:var(--text2);font-size:0.75rem;font-family:var(--sans);margin-top:2px">{{.Name}}</div>{{end}}
  </div>
  {{if .Severity}}
  <span class="sev-{{.Severity}}" style="text-transform:lowercase">{{.Severity}}</span>
  {{end}}
  {{if .PatternCount}}<span style="color:var(--text3);font-size:0.72rem;font-family:var(--mono)">{{.PatternCount}} pattern{{if gt .PatternCount 1}}s{{end}}</span>{{end}}
  <button class="btn btn-sm btn-danger" hx-delete="/dashboard/rules/custom/{{.ID}}" hx-confirm="Delete custom rule {{.ID}}?" hx-target="closest .custom-rule-row" hx-swap="outerHTML swap:200ms">delete</button>
</div>
{{end}}
{{end}}

<div class="card" style="margin-top:24px;background:var(--bg);border-style:dashed">
  <details>
    <summary style="color:var(--text2);font-size:0.82rem;cursor:pointer;user-select:none;font-weight:500">How custom rules work</summary>
    <div style="color:var(--text3);font-size:0.78rem;line-height:1.7;margin-top:14px;padding-left:4px">
      <p style="margin-bottom:8px"><strong style="color:var(--text2)">1. Keywords are matched as substrings.</strong> If you add <code style="background:var(--surface);padding:1px 5px;border-radius:3px;font-family:var(--mono);font-size:0.72rem">secret_key</code>, it will match any message containing that text anywhere.</p>
      <p style="margin-bottom:8px"><strong style="color:var(--text2)">2. Severity controls the response.</strong> Critical and High rules block or quarantine messages. Medium rules flag them but still deliver. Low rules only log.</p>
      <p style="margin-bottom:8px"><strong style="color:var(--text2)">3. Rules are stored as YAML files</strong>{{if .CustomRulesDir}} in <code style="background:var(--surface);padding:1px 5px;border-radius:3px;font-family:var(--mono);font-size:0.72rem">{{.CustomRulesDir}}</code>{{end}}. You can also create them manually for advanced patterns (regex, multi-match).</p>
      <p><strong style="color:var(--text2)">4. Disable or delete anytime.</strong> Custom rules appear in the Detection Rules tab and can be toggled on/off like built-in rules.</p>
    </div>
  </details>
</div>
{{end}}
` + layoutFoot))

// --- Category detail page ---

var categoryDetailTmpl = template.Must(template.New("category-detail").Funcs(tmplFuncs).Parse(layoutHead + `
<style>
.breadcrumb{display:flex;align-items:center;gap:var(--sp-2);margin-bottom:var(--sp-5);font-size:var(--text-sm);font-family:var(--mono);color:var(--text3)}
.breadcrumb a{color:var(--text3);text-decoration:none;transition:color var(--ease-default)}
.breadcrumb a:hover{color:var(--accent-light)}
.breadcrumb .sep{opacity:0.5}
.cat-header{display:flex;align-items:center;gap:var(--sp-4);margin-bottom:var(--sp-2)}
.cat-header h1{margin:0}
.cat-toggle{margin-left:auto;display:flex;align-items:center;gap:var(--sp-2);font-size:var(--text-sm);color:var(--text2)}
.rule-table{width:100%;border-collapse:collapse;table-layout:fixed}
.rule-table th{text-align:left;color:var(--text3);font-size:var(--text-xs);text-transform:uppercase;letter-spacing:var(--ls-caps);padding:10px var(--sp-3);border-bottom:1px solid var(--border)}
.rule-table td{padding:var(--sp-3);border-bottom:1px solid var(--border);font-size:var(--text-sm);vertical-align:top}
.rule-table tr:hover td{background:var(--surface-hover)}
.rule-table .rule-name{font-weight:600;font-family:var(--mono);font-size:var(--text-sm);color:var(--text);cursor:pointer;display:inline}
.rule-table .rule-name:hover{color:var(--accent-light)}
.rule-table .rule-desc{color:var(--text3);font-size:var(--text-sm);display:inline;margin-left:6px}
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

{{if .Webhooks}}
<div class="card" style="margin-bottom:20px;padding:16px 20px">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
    <h3 style="margin:0;font-size:0.82rem;font-weight:600">Notify on trigger</h3>
    <span style="font-size:0.68rem;color:var(--text3)">Alert when any rule in this category fires</span>
  </div>
  <form method="POST" action="/dashboard/rules/{{.Category.Name}}/webhooks" style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">
    {{range .Webhooks}}
    <label style="display:flex;align-items:center;gap:6px;font-size:0.82rem;cursor:pointer">
      <input type="checkbox" name="notify_channel" value="{{.Name}}" {{if $.CategoryWebhook}}{{if inSlice .Name $.CategoryWebhook.Notify}}checked{{end}}{{end}}>
      <span style="font-family:var(--mono);color:var(--text)">{{.Name}}</span>
    </label>
    {{end}}
    <button type="submit" class="btn btn-sm">Save</button>
  </form>
</div>
{{end}}

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
        <a class="rule-name" href="/dashboard/rules/{{.Category}}/{{.ID}}" style="text-decoration:none;color:inherit">{{.ID}}</a>
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

var ruleDetailTmpl = template.Must(template.New("rule-detail").Parse(`
<div class="panel-header">
  <h3>Rule Detail</h3>
  <button class="panel-close" onclick="closePanel()" aria-label="Close panel">&times;</button>
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
  {{if .CustomRulesDir}}No custom rules in {{.CustomRulesDir}}.{{else}}Set <code style="color:var(--accent-light)">custom_rules_dir</code> in oktsec.yaml to enable custom rules.{{end}}
</div>
{{end}}`))

var ruleToggleTmpl = template.Must(template.New("rule-toggle").Parse(`<span id="toggle-{{.ID}}">
  <label class="toggle" title="{{if .Enabled}}Disable{{else}}Enable{{end}} this rule">
    <input type="checkbox" {{if .Enabled}}checked{{end}} hx-post="/dashboard/api/rule/{{.ID}}/toggle" hx-target="#toggle-{{.ID}}" hx-swap="outerHTML">
    <span class="toggle-slider"></span>
  </label>
</span>`))

var ruleDetailPageTmpl = template.Must(template.New("rule-detail-page").Funcs(tmplFuncs).Parse(layoutHead + `
<style>
.rd-breadcrumb{display:flex;align-items:center;gap:var(--sp-2);margin-bottom:var(--sp-5);font-size:var(--text-sm);font-family:var(--mono);color:var(--text3)}
.rd-breadcrumb a{color:var(--text3);text-decoration:none;transition:color var(--ease-default)}
.rd-breadcrumb a:hover{color:var(--accent-light)}
.rd-breadcrumb .sep{opacity:0.5}
.rd-header{display:flex;align-items:center;gap:var(--sp-4);margin-bottom:var(--sp-2)}
.rd-header h1{margin:0;font-size:var(--text-xl)}
.rd-meta{display:flex;gap:var(--sp-4);align-items:center;margin-bottom:var(--sp-6)}
.rd-patterns{list-style:none;padding:0;margin:0}
.rd-patterns li{font-family:var(--mono);font-size:var(--text-sm);color:var(--text2);padding:var(--sp-2) var(--sp-3);background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-md);margin-bottom:var(--sp-2)}
.rd-examples{margin-top:var(--sp-2)}
.rd-examples .ex{font-family:var(--mono);font-size:var(--text-sm);padding:var(--sp-2) var(--sp-3);background:var(--bg);border-radius:var(--radius-sm);margin-bottom:var(--sp-1);border-left:3px solid var(--border)}
.rd-examples .ex.tp{border-left-color:var(--danger)}
.rd-examples .ex.fp{border-left-color:var(--success)}
.rd-test-result{margin-top:var(--sp-3)}
</style>

<div class="rd-breadcrumb">
  <a href="/dashboard/rules">Rules</a>
  <span class="sep">/</span>
  <a href="/dashboard/rules/{{.Category}}">{{.Category}}</a>
  <span class="sep">/</span>
  <span>{{.Detail.ID}}</span>
</div>

<div class="rd-header">
  <h1>{{.Detail.ID}}</h1>
  <span id="toggle-{{.Detail.ID}}">
    <label class="toggle" title="{{if .Disabled}}Enable{{else}}Disable{{end}} this rule">
      <input type="checkbox" {{if not .Disabled}}checked{{end}} hx-post="/dashboard/api/rule/{{.Detail.ID}}/toggle" hx-target="#toggle-{{.Detail.ID}}" hx-swap="outerHTML">
      <span class="toggle-slider"></span>
    </label>
  </span>
</div>
<div class="rd-meta">
  {{$sev := lower .Detail.Severity}}
  {{if eq $sev "critical"}}<span class="sev-critical">critical</span>
  {{else if eq $sev "high"}}<span class="sev-high">high</span>
  {{else if eq $sev "medium"}}<span class="sev-medium">medium</span>
  {{else if eq $sev "low"}}<span class="sev-low">low</span>
  {{else}}<span class="sev-low">{{.Detail.Severity}}</span>{{end}}
  <span style="color:var(--text3);font-size:0.78rem">{{.Detail.Name}}</span>
</div>

<!-- Details Card -->
<div class="card">
  <h2>Details</h2>
  {{if .Detail.Description}}<p class="desc">{{.Detail.Description}}</p>{{end}}

  {{if .Detail.Patterns}}
  <div style="margin-bottom:16px">
    <div style="color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Patterns</div>
    <ul class="rd-patterns">
      {{range .Detail.Patterns}}<li>{{.}}</li>{{end}}
    </ul>
  </div>
  {{end}}

  {{if .Detail.TruePositives}}
  <div class="rd-examples" style="margin-bottom:16px">
    <div style="color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">True Positive Examples</div>
    {{range .Detail.TruePositives}}<div class="ex tp">{{.}}</div>{{end}}
  </div>
  {{end}}

  {{if .Detail.FalsePositives}}
  <div class="rd-examples">
    <div style="color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">False Positive Examples</div>
    {{range .Detail.FalsePositives}}<div class="ex fp">{{.}}</div>{{end}}
  </div>
  {{end}}
</div>

<!-- Test Rule Card -->
<div class="card">
  <h2>Test Rule</h2>
  <p style="color:var(--text3);font-size:0.78rem;margin-bottom:12px">Paste sample text to check if this rule triggers.</p>
  <form hx-post="/dashboard/api/rule/{{.Detail.ID}}/test" hx-target="#test-result" hx-swap="innerHTML">
    <textarea name="content" rows="4" placeholder="Paste content to test..." style="width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:var(--mono);font-size:0.78rem;padding:10px;resize:vertical;margin-bottom:10px"></textarea>
    <button type="submit" class="btn">Run Test</button>
  </form>
  <div id="test-result" class="rd-test-result"></div>
</div>

<!-- Enforcement Card -->
<div class="card">
  <h2>Enforcement Override</h2>
  <p style="color:var(--text3);font-size:0.78rem;margin-bottom:16px">Configure how this rule is enforced. Overrides the default severity-based verdict.</p>
  <form method="POST" action="/dashboard/rules/{{.Category}}/{{.Detail.ID}}/enforcement">
    <div class="form-row">
      <div class="form-group">
        <label>Action</label>
        <select name="action" style="width:100%;padding:8px 12px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:0.82rem">
          <option value="block" {{if .Override}}{{if eq .Override.Action "block"}}selected{{end}}{{end}}>Block</option>
          <option value="quarantine" {{if .Override}}{{if eq .Override.Action "quarantine"}}selected{{end}}{{end}}>Quarantine</option>
          <option value="allow-and-flag" {{if .Override}}{{if eq .Override.Action "allow-and-flag"}}selected{{end}}{{end}}>Allow &amp; Flag</option>
          <option value="ignore" {{if .Override}}{{if eq .Override.Action "ignore"}}selected{{end}}{{end}}>Ignore</option>
        </select>
      </div>
      <div class="form-group">
        <label>Severity Override</label>
        <select name="severity" style="width:100%;padding:8px 12px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:0.82rem">
          <option value="">Default ({{.Detail.Severity}})</option>
          <option value="critical" {{if .Override}}{{if eq .Override.Severity "critical"}}selected{{end}}{{end}}>Critical</option>
          <option value="high" {{if .Override}}{{if eq .Override.Severity "high"}}selected{{end}}{{end}}>High</option>
          <option value="medium" {{if .Override}}{{if eq .Override.Severity "medium"}}selected{{end}}{{end}}>Medium</option>
          <option value="low" {{if .Override}}{{if eq .Override.Severity "low"}}selected{{end}}{{end}}>Low</option>
        </select>
      </div>
    </div>

    {{if $.Webhooks}}
    <div style="margin-bottom:12px">
      <label style="display:block;color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Notify Channels</label>
      {{range $.Webhooks}}
      <label style="display:flex;align-items:center;gap:8px;padding:4px 0;font-size:0.82rem;cursor:pointer">
        <input type="checkbox" name="notify_channel" value="{{.Name}}" {{if $.Override}}{{if inSlice .Name $.Override.Notify}}checked{{end}}{{end}}>
        <span style="font-family:var(--mono);color:var(--text)">{{.Name}}</span>
      </label>
      {{end}}
      {{if .CategoryWebhook}}
      <div style="color:var(--text3);font-size:0.72rem;margin-top:6px">Inherited from category: {{range .CategoryWebhook.Notify}}<span style="font-family:var(--mono)">{{.}}</span> {{end}}</div>
      {{end}}
    </div>
    {{end}}

    <div class="form-group" style="margin-bottom:12px">
      <label>Additional Webhook URLs (one per line)</label>
      <textarea name="notify_urls" rows="2" style="width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:var(--mono);font-size:0.78rem;padding:8px;resize:vertical">{{if .Override}}{{range .Override.Notify}}{{if contains . "://"}}{{.}}
{{end}}{{end}}{{end}}</textarea>
    </div>

    <div class="form-group" style="margin-bottom:16px">
      <label>Message Template</label>
      <textarea name="template" rows="3" placeholder="RULE triggered on message from FROM to TO" style="width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:var(--mono);font-size:0.78rem;padding:8px;resize:vertical">{{if .Override}}{{.Override.Template}}{{end}}</textarea>
      <div style="color:var(--text3);font-size:0.68rem;margin-top:4px">Variables: {{"{{RULE}} {{RULE_NAME}} {{SEVERITY}} {{CATEGORY}} {{MATCH}} {{ACTION}} {{FROM}} {{TO}}"}}</div>
    </div>

    <button type="submit" class="btn">Save Enforcement</button>
  </form>
</div>
` + layoutFoot))

var ruleTestResultTmpl = template.Must(template.New("rule-test-result").Parse(`{{if .Matched}}<div style="padding:12px 16px;border-radius:8px;background:rgba(248,81,73,0.08);border:1px solid rgba(248,81,73,0.15);color:var(--danger);font-size:0.82rem"><strong>Match found</strong> &mdash; rule <span style="font-family:var(--mono)">{{.RuleID}}</span> triggered.{{if .MatchText}}<div style="font-family:var(--mono);font-size:0.75rem;margin-top:6px;padding:6px 10px;background:rgba(0,0,0,0.2);border-radius:4px">{{.MatchText}}</div>{{end}}</div>{{else}}<div style="padding:12px 16px;border-radius:8px;background:rgba(63,185,80,0.08);border:1px solid rgba(63,185,80,0.15);color:var(--success);font-size:0.82rem"><strong>Clean</strong> &mdash; rule <span style="font-family:var(--mono)">{{.RuleID}}</span> did not trigger.</div>{{end}}`))
