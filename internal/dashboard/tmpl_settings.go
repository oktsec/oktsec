package dashboard

import "html/template"

var settingsTmpl = template.Must(template.New("settings").Funcs(tmplFuncs).Parse(layoutHead + `
<style>
.st-section{background:var(--surface);border:1px solid var(--border);border-radius:12px;overflow:hidden;margin-bottom:20px}
.st-section-hdr{padding:12px 20px;border-bottom:1px solid var(--border);font-size:0.68rem;font-weight:600;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);background:var(--surface2)}
.st-item{display:flex;align-items:center;gap:16px;padding:14px 20px;border-bottom:1px solid var(--border)}
.st-item:last-child{border-bottom:none}
.st-item-info{flex:1;min-width:0}
.st-item-name{font-size:0.85rem;font-weight:600;color:var(--text);margin-bottom:2px}
.st-item-desc{font-size:0.72rem;color:var(--text3);line-height:1.4}
.st-item-value{display:flex;align-items:center;gap:10px;flex-shrink:0}
.st-item-value .val{font-family:var(--mono);font-size:0.82rem;color:var(--text2);background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:4px 10px;min-width:60px;text-align:center}
.st-expand{display:none;padding:0 20px 14px;border-bottom:1px solid var(--border)}
.st-expand.open{display:block}
.st-row{display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end}
.st-row .form-group{flex:1;min-width:140px}
.st-timing{font-size:0.62rem;color:var(--text3);font-weight:500;text-transform:uppercase;letter-spacing:0.5px;margin-top:3px}
.st-timing.immediate{color:var(--success)}
.st-timing.restart{color:var(--warn)}
.st-inline-confirm{display:none;padding:12px 20px;border-bottom:1px solid var(--border);background:rgba(210,153,34,0.10);border-left:3px solid var(--warn);animation:stSlide 0.15s ease}
.st-inline-confirm.open{display:flex;align-items:center;gap:12px}
.st-inline-confirm .st-ic-msg{font-size:0.78rem;color:var(--text2);flex:1;line-height:1.4}
.st-inline-confirm .st-ic-impact{font-size:0.68rem;color:var(--warn);margin-top:2px}
@keyframes stSlide{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:translateY(0)}}
.st-toast{position:fixed;bottom:20px;right:20px;padding:10px 18px;border-radius:8px;font-size:0.82rem;font-weight:500;color:#fff;z-index:999;animation:stToastIn 0.2s ease}
.st-toast.success{background:var(--success)}
.st-toast.error{background:var(--danger)}
@keyframes stToastIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
</style>
<p class="page-desc">System status, access control, and threat response settings.</p>

<div style="display:flex;gap:8px;margin-bottom:var(--sp-5);flex-wrap:wrap">
  <a href="#sec-status" class="btn btn-sm btn-outline" style="text-decoration:none;font-size:var(--text-xs)">System Status</a>
  <a href="#sec-access" class="btn btn-sm btn-outline" style="text-decoration:none;font-size:var(--text-xs)">Access Control</a>
  <a href="#sec-threat" class="btn btn-sm btn-outline" style="text-decoration:none;font-size:var(--text-xs)">Threat Response</a>
  <a href="#sec-infra" class="btn btn-sm btn-outline" style="text-decoration:none;font-size:var(--text-xs)">Infrastructure</a>
</div>

<!-- Section 1: System Status -->
<div class="st-section" id="sec-status">
  <div class="st-section-hdr">System Status</div>
  <div class="st-item">
    <div class="st-item-info">
      <div class="st-item-name">Security Mode</div>
      <div class="st-item-desc">{{if .RequireSig}}All messages are verified before delivery. Suspicious content is blocked.{{else}}Signatures optional; content enforcement still active according to rules.{{end}}</div>
      <div class="st-timing immediate">Takes effect immediately</div>
    </div>
    <div class="st-item-value">
      <span class="val" style="{{if .RequireSig}}color:var(--success){{else}}color:var(--warn){{end}}">{{if .RequireSig}}Protection Active{{else}}Monitor Only{{end}}</span>
      <form id="frm-mode" method="POST" action="/dashboard/mode/toggle"><button type="button" class="btn btn-sm btn-outline" onclick="stShowConfirm('confirm-mode')">Switch to {{if .RequireSig}}Monitor Only{{else}}Active Protection{{end}}</button></form>
    </div>
  </div>
  <div class="st-inline-confirm" id="confirm-mode">
    <div>
      <div class="st-ic-msg">{{if .RequireSig}}Switch to monitor-only mode?{{else}}Switch to active protection mode?{{end}}</div>
      <div class="st-ic-impact">{{if .RequireSig}}Unsigned messages will be allowed through. Content enforcement stays active.{{else}}Unsigned messages will be rejected. All agents need valid Ed25519 signatures.{{end}}</div>
    </div>
    <button type="button" class="btn btn-sm btn-primary" onclick="document.getElementById('frm-mode').submit()">{{if .RequireSig}}Switch to Monitor Only{{else}}Enable Active Protection{{end}}</button>
    <button type="button" class="btn btn-sm btn-outline" onclick="stHideConfirm('confirm-mode')">Cancel</button>
  </div>
  <div class="st-item">
    <div class="st-item-info">
      <div class="st-item-name">MCP Gateway</div>
      <div class="st-item-desc">{{if .GatewayEnabled}}Accepting connections on port {{.GatewayPort}}{{else}}Gateway is not running. Enable it in your configuration file.{{end}}</div>
      <div class="st-timing restart">Requires restart</div>
    </div>
    <div class="st-item-value">
      <span class="val" style="{{if .GatewayEnabled}}color:var(--success){{else}}color:var(--text3){{end}}">{{if .GatewayEnabled}}active{{else}}inactive{{end}}</span>
      {{if .GatewayEnabled}}<a href="/dashboard/gateway" class="btn btn-sm btn-outline" style="text-decoration:none">Configure &rarr;</a>{{end}}
    </div>
  </div>
</div>

<!-- Section 2: Access Control -->
<div class="st-section" id="sec-access">
  <div class="st-section-hdr">Access Control</div>
  <div class="st-item">
    <div class="st-item-info">
      <div class="st-item-name">Default Policy</div>
      <div class="st-item-desc">{{if eq .DefaultPolicy "deny"}}Agents can only reach explicitly approved targets.{{else}}All agents can communicate freely unless specifically denied.{{end}}</div>
      <div class="st-timing immediate">Takes effect immediately</div>
    </div>
    <div class="st-item-value">
      <span class="val" style="{{if eq .DefaultPolicy "deny"}}color:var(--success){{else}}color:var(--warn){{end}}">{{if eq .DefaultPolicy "deny"}}Block unknown{{else}}Allow all{{end}}</span>
      <form id="frm-policy" method="POST" action="/dashboard/settings/default-policy"><input type="hidden" name="default_policy" value="{{if eq .DefaultPolicy "deny"}}allow{{else}}deny{{end}}"><button type="button" class="btn btn-sm btn-outline" onclick="stShowConfirm('confirm-policy')">{{if eq .DefaultPolicy "deny"}}Allow All{{else}}Block Unknown{{end}}</button></form>
    </div>
  </div>
  <div class="st-inline-confirm" id="confirm-policy">
    <div>
      <div class="st-ic-msg">Switch default policy to {{if eq .DefaultPolicy "deny"}}allow{{else}}deny{{end}}?</div>
      <div class="st-ic-impact">{{if eq .DefaultPolicy "deny"}}All agents will be able to communicate freely unless specifically denied.{{else}}Agents will only reach explicitly approved targets. Unregistered agents are blocked.{{end}}</div>
    </div>
    <button type="button" class="btn btn-sm btn-primary" onclick="document.getElementById('frm-policy').submit()">{{if eq .DefaultPolicy "deny"}}Switch to Allow All{{else}}Switch to Block Unknown{{end}}</button>
    <button type="button" class="btn btn-sm btn-outline" onclick="stHideConfirm('confirm-policy')">Cancel</button>
  </div>
  <div class="st-item" style="flex-wrap:wrap">
    <div class="st-item-info">
      <div class="st-item-name">Internal Networks</div>
      <div class="st-item-desc">Domains and networks considered inside your organization. Agents with internal scope can only reach these.</div>
      <div class="st-timing immediate">Takes effect immediately</div>
    </div>
    <div class="st-item-value">
      <span class="val">{{.TrustBoundariesCount}} defined</span>
      <button type="button" class="btn btn-sm btn-outline" onclick="var el=document.getElementById('trust-boundaries-detail');el.open=!el.open">{{if .TrustBoundariesCount}}Edit{{else}}Configure{{end}}</button>
    </div>
  </div>
  <details id="trust-boundaries-detail" style="padding:0">
  <summary style="display:none"></summary>
  <form method="POST" action="/dashboard/settings/trust-boundaries" style="padding:0 16px 16px">
    <textarea name="internal" rows="4" style="width:100%;font-size:0.75rem;font-family:var(--mono);background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:10px;color:var(--text1);resize:vertical" placeholder="One domain or CIDR per line, e.g.&#10;*.mycompany.com&#10;10.0.0.0/8&#10;github.com/myorg">{{range .TrustBoundariesInternal}}{{.}}&#10;{{end}}</textarea>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px">
      <span style="font-size:0.68rem;color:var(--text3)">One per line. Supports wildcards (*.example.com).</span>
      <button type="submit" class="btn btn-sm btn-primary">Save Trust Boundaries</button>
    </div>
  </form>
  </details>
</div>

<!-- Section 3: Threat Response -->
<div class="st-section" id="sec-threat">
  <div class="st-section-hdr">Threat Response</div>
  <form method="POST" action="/dashboard/settings/quarantine">
  <div class="st-item">
    <div class="st-item-info">
      <div class="st-item-name">Quarantine{{if .QPending}} <span style="color:var(--warn);font-size:0.72rem;font-weight:400">{{.QPending}} pending</span>{{end}}</div>
      <div class="st-item-desc">Hold suspicious messages for human review. Window: {{.QExpiryHours}}h, retain {{.QRetentionDays}}d</div>
      <div class="st-timing immediate">Takes effect immediately</div>
    </div>
    <div class="st-item-value">
      <span class="toggle"><input type="checkbox" name="enabled" value="true" aria-label="Toggle quarantine" {{if .QEnabled}}checked{{end}} onchange="this.form.submit()"><span class="toggle-slider"></span></span>
    </div>
  </div>
  <input type="hidden" name="expiry_hours" value="{{.QExpiryHours}}">
  <input type="hidden" name="retention_days" value="{{.QRetentionDays}}">
  </form>

  <form method="POST" action="/dashboard/settings/anomaly">
  <div class="st-item">
    <div class="st-item-info">
      <div class="st-item-name">Behavior Monitoring</div>
      <div class="st-item-desc">Automatically pause agents that show suspicious behavior patterns</div>
      <div class="st-timing immediate">Takes effect immediately</div>
    </div>
    <div class="st-item-value">
      <span class="toggle"><input type="checkbox" name="auto_suspend" value="true" aria-label="Toggle behavior monitoring" {{if .AnomalyAutoSuspend}}checked{{end}} onchange="this.form.submit()"><span class="toggle-slider"></span></span>
    </div>
  </div>
  <input type="hidden" name="check_interval" value="{{if .AnomalyCheckInterval}}{{.AnomalyCheckInterval}}{{else}}60{{end}}">
  <input type="hidden" name="risk_threshold" value="{{printf "%.1f" .AnomalyRiskThreshold}}">
  <input type="hidden" name="min_messages" value="{{.AnomalyMinMessages}}">
  </form>

  <form method="POST" action="/dashboard/settings/rate-limit">
  <div class="st-item">
    <div class="st-item-info">
      <div class="st-item-name">Rate Limiting</div>
      <div class="st-item-desc">Limit how many messages each agent can send per minute</div>
      <div class="st-timing immediate">Takes effect immediately</div>
    </div>
    <div class="st-item-value">
      <span class="val">{{.RateLimitPerAgent}} / min</span>
    </div>
  </div>
  <input type="hidden" name="per_agent" value="{{.RateLimitPerAgent}}">
  <input type="hidden" name="window" value="{{if .RateLimitWindow}}{{.RateLimitWindow}}{{else}}60{{end}}">
  </form>

  <form method="POST" action="/dashboard/settings/intent">
  <div class="st-item">
    <div class="st-item-info">
      <div class="st-item-name">Purpose Verification</div>
      <div class="st-item-desc">Require agents to declare what they're doing. Flag mismatches between stated intent and actual content.</div>
      <div class="st-timing immediate">Takes effect immediately</div>
    </div>
    <div class="st-item-value">
      <span class="toggle"><input type="checkbox" name="require_intent" value="true" aria-label="Toggle purpose verification" {{if .RequireIntent}}checked{{end}} onchange="this.form.submit()"><span class="toggle-slider"></span></span>
    </div>
  </div>
  </form>

  <form method="POST" action="/dashboard/settings/testcase-export">
  <div class="st-item">
    <div class="st-item-info">
      <div class="st-item-name">Testcase Export</div>
      <div class="st-item-desc">Save blocked and quarantined content as test cases for detection rule validation. Files are stored locally in ~/.oktsec/testcases/</div>
      <div class="st-timing immediate">Takes effect immediately</div>
    </div>
    <div class="st-item-value">
      <span class="toggle"><input type="checkbox" name="export_blocked" value="true" aria-label="Toggle testcase export" {{if .ExportBlocked}}checked{{end}} onchange="this.form.submit()"><span class="toggle-slider"></span></span>
    </div>
  </div>
  </form>

  <form method="POST" action="/dashboard/settings/forward-proxy">
  <div class="st-item">
    <div class="st-item-info">
      <div class="st-item-name">Outbound Traffic</div>
      <div class="st-item-desc">Inspect and control what agents send outside your network</div>
      <div class="st-timing restart">Requires restart</div>
    </div>
    <div class="st-item-value">
      <span class="toggle"><input type="checkbox" id="fp-toggle" name="enabled" value="true" aria-label="Toggle outbound traffic inspection" {{if .FPEnabled}}checked{{end}} onchange="toggleEgressDetails();this.form.submit()"><span class="toggle-slider"></span></span>
    </div>
  </div>
  <div id="fp-details" style="{{if not .FPEnabled}}display:none;{{end}}">
  <div style="padding:14px 20px;border-bottom:1px solid var(--border)">
    <div style="display:flex;gap:20px;margin-bottom:16px">
      <label style="display:flex;align-items:center;gap:6px;font-size:0.78rem;cursor:pointer"><input type="checkbox" name="scan_requests" value="true" {{if .FPScanRequests}}checked{{end}}> Scan outgoing</label>
      <label style="display:flex;align-items:center;gap:6px;font-size:0.78rem;cursor:pointer"><input type="checkbox" name="scan_responses" value="true" {{if .FPScanResponses}}checked{{end}}> Scan incoming</label>
      <div style="margin-left:auto;display:flex;align-items:center;gap:6px"><label style="font-size:0.68rem;color:var(--text3);text-transform:uppercase;letter-spacing:0.5px">Max body</label><input type="number" name="max_body_size" value="{{.FPMaxBodySize}}" min="0" style="width:90px;font-size:0.78rem"></div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
      <div>
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
          <label style="font-size:0.72rem;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:0.5px">Allowed domains</label>
          <span style="font-size:0.68rem;color:var(--text3);font-family:var(--mono)">{{if .FPAllowedDomains}}active{{else}}allow all{{end}}</span>
        </div>
        <textarea name="allowed_domains" rows="4" style="font-family:var(--mono);font-size:0.75rem;width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:10px 12px;resize:vertical;line-height:1.6" placeholder="api.openai.com&#10;api.anthropic.com&#10;*.github.com">{{.FPAllowedDomains}}</textarea>
        <div style="font-size:0.65rem;color:var(--text3);margin-top:4px">One per line. Empty = allow all. Supports wildcards (*.example.com)</div>
      </div>
      <div>
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
          <label style="font-size:0.72rem;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:0.5px">Blocked domains</label>
          <span style="font-size:0.68rem;color:var(--text3);font-family:var(--mono)">{{if .FPBlockedDomains}}active{{else}}none{{end}}</span>
        </div>
        <textarea name="blocked_domains" rows="4" style="font-family:var(--mono);font-size:0.75rem;width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:10px 12px;resize:vertical;line-height:1.6" placeholder="*.ru&#10;*.cn&#10;malware.example.com">{{.FPBlockedDomains}}</textarea>
        <div style="font-size:0.65rem;color:var(--text3);margin-top:4px">Takes precedence over allowed. Block TLDs with *.ru, *.cn, etc.</div>
      </div>
    </div>
  </div>
  <div style="display:flex;justify-content:flex-end;padding:10px 20px">
    <button type="submit" class="btn btn-sm">Save Proxy Settings</button>
  </div>
  </div>
  </form>
</div>

<!-- Section 4: Infrastructure -->
<div class="st-section" id="sec-infra">
  <div class="st-section-hdr">Infrastructure</div>
  <div class="st-item">
    <div class="st-item-info">
      <div class="st-item-name">Server</div>
      <div class="st-item-desc">Port {{.ServerPort}} &middot; {{.ServerBind}}</div>
      <div class="st-timing restart">Requires restart</div>
    </div>
    <div class="st-item-value"></div>
  </div>

  <div class="st-item" style="flex-wrap:wrap">
    <div class="st-item-info">
      <div class="st-item-name">Database</div>
      <div class="st-item-desc" id="db-desc">{{if eq .DBBackend "PostgreSQL"}}Production database, requires a PostgreSQL server{{else}}Local file database, no server needed{{end}}</div>
      <div class="st-timing restart">Requires restart</div>
    </div>
    <div class="st-item-value">
      <div style="display:flex;border:1px solid var(--border);border-radius:6px;overflow:hidden">
        <button type="button" id="db-pill-sqlite" onclick="selectDB('sqlite')" style="padding:4px 14px;font-size:0.78rem;border:none;cursor:pointer;font-family:var(--mono);{{if ne .DBBackend "PostgreSQL"}}background:#1F6FEB;color:#fff{{else}}background:var(--bg);color:#8B949E;border:1px solid #30363D{{end}}">SQLite</button>
        <button type="button" id="db-pill-postgres" onclick="selectDB('postgres')" style="padding:4px 14px;font-size:0.78rem;border:none;border-left:1px solid var(--border);cursor:pointer;font-family:var(--mono);{{if eq .DBBackend "PostgreSQL"}}background:#1F6FEB;color:#fff{{else}}background:var(--bg);color:#8B949E;border:1px solid #30363D{{end}}">PostgreSQL</button>
      </div>
    </div>
  </div>

  <!-- SQLite config (shown when sqlite selected) -->
  <div id="db-sqlite-cfg" style="padding:14px 20px;border-bottom:1px solid var(--border){{if eq .DBBackend "PostgreSQL"}};display:none{{end}}">
    <div class="st-row">
      <div class="form-group">
        <label style="font-size:0.72rem;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:0.5px;display:block;margin-bottom:4px">Database path</label>
        <input type="text" id="db-sqlite-path" value="{{.DBPath}}" style="font-family:var(--mono);font-size:0.78rem;width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text2);padding:8px 12px" readonly>
      </div>
    </div>
  </div>

  <!-- PostgreSQL config (shown when postgres selected) -->
  <div id="db-pg-cfg" style="padding:14px 20px;border-bottom:1px solid var(--border){{if ne .DBBackend "PostgreSQL"}};display:none{{end}}">
    <div style="font-size:0.72rem;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px">PostgreSQL connection</div>
    <div style="display:grid;grid-template-columns:2fr 1fr;gap:12px;margin-bottom:12px">
      <div>
        <label style="font-size:0.72rem;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:0.5px;display:block;margin-bottom:4px">Host</label>
        <input type="text" id="db-pg-host" value="{{.PGHost}}" placeholder="localhost" style="font-family:var(--mono);font-size:0.78rem;width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:8px 12px">
      </div>
      <div>
        <label style="font-size:0.72rem;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:0.5px;display:block;margin-bottom:4px">Port</label>
        <input type="number" id="db-pg-port" value="{{.PGPort}}" placeholder="5432" style="font-family:var(--mono);font-size:0.78rem;width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:8px 12px">
      </div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px">
      <div>
        <label style="font-size:0.72rem;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:0.5px;display:block;margin-bottom:4px">User</label>
        <input type="text" id="db-pg-user" value="{{.PGUser}}" placeholder="oktsec" style="font-family:var(--mono);font-size:0.78rem;width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:8px 12px">
      </div>
      <div>
        <label style="font-size:0.72rem;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:0.5px;display:block;margin-bottom:4px">Password</label>
        <input type="password" id="db-pg-pass" value="" placeholder="{{if .PGHost}}****{{else}}password{{end}}" style="font-family:var(--mono);font-size:0.78rem;width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:8px 12px">
      </div>
    </div>
    <div style="display:grid;grid-template-columns:2fr 1fr;gap:12px;margin-bottom:16px">
      <div>
        <label style="font-size:0.72rem;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:0.5px;display:block;margin-bottom:4px">Database</label>
        <input type="text" id="db-pg-name" value="{{.PGDatabase}}" placeholder="oktsec" style="font-family:var(--mono);font-size:0.78rem;width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:8px 12px">
      </div>
      <div>
        <label style="font-size:0.72rem;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:0.5px;display:block;margin-bottom:4px">SSL Mode</label>
        <select id="db-pg-ssl" style="font-size:0.78rem;width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:8px 10px;font-family:var(--mono)">
          <option value="disable" {{if eq .PGSSLMode "disable"}}selected{{end}}>disable</option>
          <option value="require" {{if eq .PGSSLMode "require"}}selected{{end}}>require</option>
          <option value="verify-ca" {{if eq .PGSSLMode "verify-ca"}}selected{{end}}>verify-ca</option>
          <option value="verify-full" {{if eq .PGSSLMode "verify-full"}}selected{{end}}>verify-full</option>
        </select>
      </div>
    </div>
    <div style="display:flex;gap:8px;align-items:center">
      <button type="button" class="btn btn-sm btn-outline" onclick="testDBConnection()">Test connection</button>
      <span id="db-test-result" style="font-size:0.75rem;font-family:var(--mono)"></span>
    </div>
  </div>

  <div style="display:flex;justify-content:flex-end;padding:10px 20px;border-bottom:1px solid var(--border)">
    <button type="button" class="btn btn-sm" id="db-save-btn" onclick="saveDBConfig()">Save Database &amp; Restart</button>
  </div>
</div>

<script>
function stShowConfirm(id) {
  document.querySelectorAll('.st-inline-confirm').forEach(function(el) { el.classList.remove('open'); });
  var el = document.getElementById(id);
  if (el) el.classList.add('open');
}
function stHideConfirm(id) {
  var el = document.getElementById(id);
  if (el) el.classList.remove('open');
}
function stToast(msg, type) {
  var el = document.createElement('div');
  el.className = 'st-toast ' + (type || 'success');
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(function() { el.remove(); }, 3000);
}

function toggleEgressDetails() {
  var cb = document.getElementById('fp-toggle');
  var det = document.getElementById('fp-details');
  det.style.display = cb.checked ? '' : 'none';
}

var _dbSelected = '{{if eq .DBBackend "PostgreSQL"}}postgres{{else}}sqlite{{end}}';
function selectDB(v) {
  _dbSelected = v;
  document.getElementById('db-sqlite-cfg').style.display = v === 'sqlite' ? '' : 'none';
  document.getElementById('db-pg-cfg').style.display = v === 'postgres' ? '' : 'none';
  document.getElementById('db-test-result').textContent = '';
  var ps = document.getElementById('db-pill-sqlite');
  var pp = document.getElementById('db-pill-postgres');
  ps.style.background = v === 'sqlite' ? '#1F6FEB' : 'var(--bg)';
  ps.style.color = v === 'sqlite' ? '#fff' : '#8B949E';
  ps.style.border = v === 'sqlite' ? 'none' : '1px solid #30363D';
  pp.style.background = v === 'postgres' ? '#1F6FEB' : 'var(--bg)';
  pp.style.color = v === 'postgres' ? '#fff' : '#8B949E';
  pp.style.border = v === 'postgres' ? 'none' : '1px solid #30363D';
  document.getElementById('db-desc').textContent = v === 'sqlite' ? 'Local file database — no server needed' : 'Production database — requires a PostgreSQL server';
}

function buildPGDSN() {
  var h = document.getElementById('db-pg-host').value || 'localhost';
  var p = document.getElementById('db-pg-port').value || '5432';
  var u = document.getElementById('db-pg-user').value || 'oktsec';
  var pw = document.getElementById('db-pg-pass').value;
  var db = document.getElementById('db-pg-name').value || 'oktsec';
  var ssl = document.getElementById('db-pg-ssl').value || 'disable';
  return 'postgres://' + encodeURIComponent(u) + (pw ? ':' + encodeURIComponent(pw) : '') + '@' + h + ':' + p + '/' + db + '?sslmode=' + ssl;
}

function testDBConnection() {
  var res = document.getElementById('db-test-result');
  res.style.color = 'var(--text3)';
  res.textContent = 'Testing...';
  var dsn = buildPGDSN();
  fetch('/dashboard/api/db/test', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({backend: 'postgres', dsn: dsn})
  }).then(function(r) { return r.json(); }).then(function(d) {
    if (d.ok) {
      res.style.color = 'var(--success)';
      res.textContent = 'Connected (' + (d.version || 'ok') + ')';
    } else {
      res.style.color = 'var(--danger)';
      res.textContent = d.error || 'Connection failed';
    }
  }).catch(function(e) {
    res.style.color = 'var(--danger)';
    res.textContent = 'Request failed';
  });
}

function saveDBConfig() {
  var backend = _dbSelected;
  var body = {backend: backend};
  if (backend === 'postgres') {
    body.dsn = buildPGDSN();
  }
  fetch('/dashboard/api/db/save', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)
  }).then(function(r) { return r.json(); }).then(function(d) {
    var res = document.getElementById('db-test-result');
    if (d.ok) {
      res.style.color = 'var(--success)';
      res.textContent = 'Saved. Restarting...';
      stToast('Database configuration saved. Restarting...', 'success');
      setTimeout(function() { window.location.reload(); }, 3000);
    } else {
      res.style.color = 'var(--danger)';
      res.textContent = d.error || 'Save failed';
      stToast(d.error || 'Save failed', 'error');
    }
  });
}
</script>
` + layoutFoot))
