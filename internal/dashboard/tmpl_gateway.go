package dashboard

import "html/template"

var gatewayTmpl = template.Must(template.New("gateway").Funcs(tmplFuncs).Parse(layoutHead + `
<style>
.gw-tabs{display:flex;gap:0;border-bottom:2px solid var(--border);margin-bottom:var(--sp-5)}
.gw-tab{padding:10px var(--sp-5);font-size:var(--text-sm);font-weight:500;color:var(--text3);cursor:pointer;border:none;background:none;border-bottom:2px solid transparent;margin-bottom:-2px;transition:color var(--ease-default),border-color var(--ease-default)}
.gw-tab:hover{color:var(--text2)}
.gw-tab.active{color:var(--text);border-bottom-color:var(--accent);font-weight:600}
.gw-panel{display:none}
.gw-panel.active{display:block}
</style>
<p class="page-desc">The Gateway is the secure checkpoint for all AI agent tool calls. Every tool your agents use passes through here for security scanning and access control.</p>

<div class="gw-tabs" role="tablist">
  <button class="gw-tab {{if ne .Tab "discovery"}}active{{end}}" onclick="gwTab('config')">Configuration</button>
  <button class="gw-tab {{if eq .Tab "discovery"}}active{{end}}" onclick="gwTab('discovery')">Auto-detected{{if .Discovered}} <span style="font-size:0.68rem;color:var(--text3)">({{len .Discovered}})</span>{{end}}</button>
</div>
<script>
function gwTab(name){
  document.querySelectorAll('.gw-tab').forEach(function(t){t.classList.remove('active')});
  document.querySelectorAll('.gw-panel').forEach(function(p){p.classList.remove('active')});
  var idx=name==='discovery'?1:0;
  document.querySelectorAll('.gw-tab')[idx].classList.add('active');
  document.getElementById('gw-'+name).classList.add('active');
  history.replaceState(null,'',name==='discovery'?'?tab=discovery':'/dashboard/gateway');
}
</script>

<div id="gw-config" class="gw-panel {{if ne .Tab "discovery"}}active{{end}}">
<div class="card">
  <h2>Gateway Status</h2>
  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:16px">
    <div style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:16px;text-align:center">
      <div style="color:var(--text3);font-size:0.68rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Status</div>
      <div id="gateway-health" hx-get="/dashboard/api/gateway/health" hx-trigger="load" hx-swap="innerHTML">
        <span style="color:var(--text3);font-size:0.85rem">checking...</span>
      </div>
    </div>
    <div style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:16px;text-align:center">
      <div style="color:var(--text3);font-size:0.68rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Configured Servers</div>
      <div style="font-size:1.2rem;font-weight:700">{{len .Servers}}</div>
    </div>
    <div style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:16px;text-align:center">
      <div style="color:var(--text3);font-size:0.68rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Listening on</div>
      <div style="font-size:1.2rem;font-weight:700">Port {{if .Gateway.Port}}{{.Gateway.Port}}{{else}}9090{{end}}</div>
    </div>
  </div>
  {{if eq (len .Servers) 0}}<div style="text-align:center;padding-bottom:8px"><a href="#add-server" class="btn btn-sm btn-outline" style="text-decoration:none">+ Add tool server</a></div>{{end}}
</div>

<div class="card">
  <h2>Configuration</h2>
  <p class="desc">Changes take effect after the gateway restarts.</p>
  <form method="POST" action="/dashboard/gateway/settings">
    <div style="display:flex;flex-direction:column;gap:0;margin-bottom:0">
      <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer;padding:14px 0;border-bottom:1px solid var(--border)">
        <span class="toggle" style="margin-top:2px"><input type="checkbox" id="gw-master" name="enabled" value="true" {{if .Gateway.Enabled}}checked{{end}} onchange="var s=this.checked;document.getElementById('gw-secondary').style.opacity=s?'1':'0.4';document.getElementById('gw-secondary').style.pointerEvents=s?'auto':'none'"><span class="toggle-slider"></span></span>
        <span><span style="font-size:0.88rem;font-weight:600;color:var(--text1)">Gateway active</span><div style="font-size:0.72rem;color:var(--text3);margin-top:2px">Route agent traffic through the security gateway</div></span>
      </label>
      <div id="gw-secondary" style="display:flex;flex-direction:column;gap:0;{{if not .Gateway.Enabled}}opacity:0.4;pointer-events:none{{end}}">
        <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer;padding:14px 0;border-bottom:1px solid var(--border)">
          <span class="toggle" style="margin-top:2px"><input type="checkbox" name="scan_responses" value="true" {{if .Gateway.ScanResponses}}checked{{end}}><span class="toggle-slider"></span></span>
          <span><span style="font-size:0.85rem;color:var(--text2)">Inspect tool responses</span><div style="font-size:0.72rem;color:var(--text3);margin-top:2px">Check what tools return to agents</div></span>
        </label>
        <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer;padding:14px 0;border-bottom:1px solid var(--border)">
          <span class="toggle" style="margin-top:2px"><input type="checkbox" name="dep_check" value="true" {{if .Gateway.DepCheck}}checked{{end}}><span class="toggle-slider"></span></span>
          <span><span style="font-size:0.85rem;color:var(--text2)">Verify tools on startup</span><div style="font-size:0.72rem;color:var(--text3);margin-top:2px">Check that connected tools are safe before accepting connections</div></span>
        </label>
      </div>
    </div>
    <details style="margin-top:16px">
      <summary style="font-size:0.72rem;color:var(--text3);cursor:pointer;user-select:none">Advanced connection settings</summary>
      <div style="padding:12px 0">
        <div class="form-row">
          <div class="form-group">
            <label>Port</label>
            <input type="number" name="port" value="{{.Gateway.Port}}" min="1" max="65535">
          </div>
          <div class="form-group">
            <label>Bind Address</label>
            <input type="text" name="bind" value="{{.Gateway.Bind}}" placeholder="127.0.0.1">
          </div>
          <div class="form-group">
            <label>Endpoint Path</label>
            <input type="text" name="endpoint_path" value="{{.Gateway.EndpointPath}}" placeholder="/mcp">
          </div>
        </div>
      </div>
    </details>
    <button type="submit" class="btn btn-sm" style="margin-top:12px">Save Configuration</button>
  </form>
</div>

<div class="card" id="add-server">
  <h2>Tool Servers</h2>
  <p class="desc">
    Add the tool servers your agents use. oktsec monitors all tool calls passing through them.
  </p>
  {{if .Servers}}
  <table>
    <thead><tr><th>Name</th><th>Transport</th><th>Target</th><th>Sandbox</th><th></th></tr></thead>
    <tbody>
    {{range .Servers}}
    <tr id="server-row-{{.Name}}">
      <td style="font-weight:600"><a href="/dashboard/gateway/servers/{{.Name}}" style="color:var(--accent-light);text-decoration:none">{{.Name}}</a></td>
      <td><span class="badge-{{if eq .Transport "stdio"}}delivered{{else}}quarantined{{end}}" style="font-size:0.7rem">{{.Transport}}</span></td>
      <td style="color:var(--text3);font-family:var(--mono);font-size:0.8rem">{{if eq .Transport "stdio"}}{{.Command}}{{else}}{{.URL}}{{end}}</td>
      <td>{{if .EgressSandbox}}<span style="color:var(--success)">&#9679;</span>{{else}}<span style="color:var(--text3)">&mdash;</span>{{end}}</td>
      <td style="text-align:right" onclick="event.stopPropagation()"><button class="btn btn-sm btn-danger" hx-delete="/dashboard/gateway/servers/{{.Name}}" hx-confirm="Delete server {{.Name}}?" hx-target="#server-row-{{.Name}}" hx-swap="outerHTML swap:200ms">delete</button></td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}
  <div class="empty">No tools connected yet. Add one below or import from the <a href="#" onclick="gwTab('discovery');return false" style="color:var(--accent-light);text-decoration:underline">Auto-detected</a> tab.</div>
  {{end}}

  {{if .Tools}}
  <h3 style="margin-top:var(--sp-6);margin-bottom:var(--sp-3)">Individual Tools</h3>
  <table>
    <thead><tr><th>Tool</th><th>Backend</th><th>Impact</th><th>Risk</th></tr></thead>
    <tbody>
    {{range .Tools}}
    <tr>
      <td style="font-weight:600">{{.FrontendName}}</td>
      <td style="color:var(--text3)">{{.BackendName}}</td>
      <td>{{.ImpactTier}}</td>
      <td>{{if eq .RiskTier "low"}}<span style="background:var(--success);color:#fff;padding:2px 8px;border-radius:4px;font-size:0.7rem">low</span>{{else if eq .RiskTier "medium"}}<span style="background:#f0ad4e;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.7rem">medium</span>{{else if eq .RiskTier "high"}}<span style="background:#f08040;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.7rem">high</span>{{else if eq .RiskTier "critical"}}<span style="background:var(--danger);color:#fff;padding:2px 8px;border-radius:4px;font-size:0.7rem">critical</span>{{else}}{{.RiskTier}}{{end}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{end}}

  <form method="POST" action="/dashboard/gateway/servers" class="inline-add">
    <div class="form-group" style="min-width:150px">
      <label>Name</label>
      <input type="text" name="name" required pattern="[a-zA-Z0-9][a-zA-Z0-9_-]*" placeholder="e.g. my-server">
    </div>
    <div class="form-group" style="min-width:180px;flex:0.7">
      <label>Transport</label>
      <select name="transport" style="min-width:170px" onchange="var s=this.value;document.getElementById('stdio-fields').style.display=s==='stdio'?'':'none';document.getElementById('http-fields').style.display=s==='http'?'':'none'">
        <option value="stdio">Local process (stdio)</option>
        <option value="http">Remote server (HTTP)</option>
      </select>
    </div>
    <div class="form-group" style="flex:2" id="stdio-fields">
      <label>Command</label>
      <input type="text" name="command" placeholder="e.g. npx -y @example/server">
    </div>
    <div class="form-group" style="flex:2;display:none" id="http-fields">
      <label>URL</label>
      <input type="text" name="url" placeholder="e.g. http://localhost:8080/mcp">
    </div>
    <button type="submit" class="btn">Add Server</button>
  </form>
  <p style="color:var(--text3);font-size:0.72rem;margin-top:8px">Configure args, env vars, and headers from the server detail page.</p>
</div>
</div><!-- /gw-config -->

<div id="gw-discovery" class="gw-panel {{if eq .Tab "discovery"}}active{{end}}">
<div class="card">
  <h2>Auto-detected Tools</h2>
  <p class="desc">
    Tools found on this machine from AI client configurations (Claude Desktop, Cursor, VS Code, Cline, Windsurf, etc.).
  </p>
  {{if .Discovered}}
  <p style="color:var(--text3);font-size:0.78rem;margin-bottom:12px">Found {{len .Discovered}} tool server(s).</p>
  <table>
    <thead><tr><th>Name</th><th>Client(s)</th><th>Command</th><th></th></tr></thead>
    <tbody>
    {{range .Discovered}}
    <tr>
      <td><strong>{{.Name}}</strong></td>
      <td>{{.Client}}</td>
      <td><code style="background:var(--surface);padding:2px 8px;border-radius:4px;font-family:var(--mono);font-size:0.82rem">{{truncate .Command 80}}</code></td>
      <td style="text-align:right"><form method="POST" action="/dashboard/gateway/servers" style="margin:0" onsubmit="return confirm('Add server to gateway?\n\nName: {{.Name}}\nTransport: {{.Transport}}\nCommand: {{.Command}}')"><input type="hidden" name="name" value="{{.Name}}"><input type="hidden" name="transport" value="{{.Transport}}"><input type="hidden" name="command" value="{{.Command}}"><button type="submit" class="btn btn-sm btn-outline">Add to Gateway</button></form></td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}
  <p style="color:var(--text3);font-size:0.82rem">No MCP servers discovered. Checked paths for Claude Desktop, Cursor, VS Code, Cline, Windsurf, and more.</p>
  {{end}}
</div>
</div><!-- /gw-discovery -->
` + layoutFoot))

var mcpServerDetailTmpl = template.Must(template.New("mcpServerDetail").Funcs(tmplFuncs).Parse(layoutHead + `
<div class="breadcrumb">
  <a href="/dashboard/gateway">GATEWAY</a>
  <span class="sep">/</span>
  <span style="color:var(--accent-light)">{{.Name}}</span>
</div>
<h1>MCP Server: <span>{{.Name}}</span></h1>

<div class="card">
  <h2>Server Configuration</h2>
  <p class="desc">
    Current settings for this backend MCP server. The gateway connects to this server to discover and proxy tool calls.
  </p>
  <table>
    <tbody>
    <tr><td style="color:var(--text3);font-weight:600;width:140px">Transport</td><td><span class="badge-{{if eq .Server.Transport "stdio"}}delivered{{else}}quarantined{{end}}" style="font-size:0.7rem">{{.Server.Transport}}</span></td></tr>
    {{if eq .Server.Transport "stdio"}}
    <tr><td style="color:var(--text3);font-weight:600">Command</td><td><code style="background:var(--surface);padding:2px 8px;border-radius:4px;font-family:var(--mono);font-size:0.82rem;color:var(--accent-light)">{{.Server.Command}}</code></td></tr>
    {{if .Server.Args}}<tr><td style="color:var(--text3);font-weight:600">Args</td><td>{{range $i, $a := .Server.Args}}{{if $i}} {{end}}<code style="background:var(--surface);padding:2px 8px;border-radius:4px;font-family:var(--mono);font-size:0.82rem">{{$a}}</code>{{end}}</td></tr>{{end}}
    {{else}}
    <tr><td style="color:var(--text3);font-weight:600">URL</td><td><code style="background:var(--surface);padding:2px 8px;border-radius:4px;font-family:var(--mono);font-size:0.82rem;color:var(--accent-light)">{{.Server.URL}}</code></td></tr>
    {{if .Server.Headers}}<tr><td style="color:var(--text3);font-weight:600">Headers</td><td>{{range $k, $v := .Server.Headers}}<code style="background:var(--surface);padding:2px 6px;border-radius:4px;font-family:var(--mono);font-size:0.78rem">{{$k}}: {{$v}}</code><br>{{end}}</td></tr>{{end}}
    {{end}}
    {{if .Server.Env}}<tr><td style="color:var(--text3);font-weight:600">Env vars</td><td>{{range $k, $v := .Server.Env}}<code style="background:var(--surface);padding:2px 6px;border-radius:4px;font-family:var(--mono);font-size:0.78rem">{{$k}}={{$v}}</code><br>{{end}}</td></tr>{{end}}
    {{if .Server.EgressSandbox}}<tr><td style="color:var(--text3);font-weight:600">Egress Sandbox</td><td><span style="color:var(--success);font-weight:600">enabled</span> &middot; HTTP traffic routes through proxy</td></tr>{{else}}<tr><td style="color:var(--text3);font-weight:600">Egress Sandbox</td><td><span style="color:var(--text3)">disabled</span></td></tr>{{end}}
    {{if .Server.WorkingDir}}<tr><td style="color:var(--text3);font-weight:600">Working Dir</td><td><code style="font-size:0.72rem">{{.Server.WorkingDir}}</code></td></tr>{{end}}
    </tbody>
  </table>
</div>

<div class="card">
  <h2>Edit Server</h2>
  <form method="POST" action="/dashboard/gateway/servers/{{.Name}}/edit">
    <div class="form-row">
      <div class="form-group" style="flex:0.5;min-width:120px">
        <label>Transport</label>
        <select name="transport" onchange="var s=this.value;document.getElementById('edit-stdio').style.display=s==='stdio'?'flex':'none';document.getElementById('edit-http').style.display=s==='http'?'flex':'none'">
          <option value="stdio" {{if eq .Server.Transport "stdio"}}selected{{end}}>stdio</option>
          <option value="http" {{if eq .Server.Transport "http"}}selected{{end}}>http</option>
        </select>
      </div>
    </div>
    <div class="form-row" id="edit-stdio" style="display:{{if eq .Server.Transport "stdio"}}flex{{else}}none{{end}}">
      <div class="form-group" style="flex:2">
        <label>Command</label>
        <input type="text" name="command" value="{{.Server.Command}}">
      </div>
      <div class="form-group" style="flex:1">
        <label>Args (space-separated)</label>
        <input type="text" name="args" value="{{range $i, $a := .Server.Args}}{{if $i}} {{end}}{{$a}}{{end}}">
      </div>
    </div>
    <div class="form-row" id="edit-http" style="display:{{if eq .Server.Transport "http"}}flex{{else}}none{{end}}">
      <div class="form-group">
        <label>URL</label>
        <input type="text" name="url" value="{{.Server.URL}}">
      </div>
    </div>
    <div class="form-group" style="margin-bottom:12px">
      <label>Env Vars (KEY=VALUE per line)</label>
      <textarea name="env" rows="3" style="font-family:var(--mono);font-size:0.82rem">{{range $k, $v := .Server.Env}}{{$k}}={{$v}}
{{end}}</textarea>
    </div>
    <div style="display:flex;gap:8px;align-items:center">
      <button type="submit" class="btn btn-sm">Save Changes</button>
      <button type="button" class="btn btn-sm btn-danger" hx-delete="/dashboard/gateway/servers/{{.Name}}" hx-confirm="Delete server {{.Name}}? This cannot be undone." hx-swap="none">Delete Server</button>
    </div>
  </form>
</div>

{{if .RelatedAgents}}
<div class="card">
  <h2>Related Agents</h2>
  <p class="desc">
    Agents that have tool allowlists configured. These restrictions apply when agents call tools through the gateway.
  </p>
  <table>
    <thead><tr><th>Agent</th><th>Allowed Tools</th></tr></thead>
    <tbody>
    {{range .RelatedAgents}}
    <tr>
      <td style="font-weight:600"><a href="/dashboard/agents/{{.Name}}" style="color:var(--accent-light);text-decoration:none">{{.Name}}</a></td>
      <td>{{range $i, $t := .AllowedTools}}{{if $i}} {{end}}<span class="acl-target">{{$t}}</span>{{end}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
</div>
{{end}}
` + layoutFoot))
