package dashboard

import (
	"fmt"
	"html/template"
	"strings"
)

// tmplFuncs is the shared FuncMap for all event-rendering templates.
var tmplFuncs = template.FuncMap{
	"humanDecision": humanReadableDecision,
	"truncate": func(s string, n int) string {
		if len(s) <= n {
			return s
		}
		return s[:n] + "..."
	},
	"avatar":    agentAvatar,
	"agentCell": agentCell,
	"gradeColor": func(g string) string {
		switch g {
		case "A", "B":
			return "success"
		case "C":
			return "warn"
		default:
			return "danger"
		}
	},
	"upper": strings.ToUpper,
	"lower": strings.ToLower,
	"inc": func(i int) int { return i + 1 },
	"divf": func(a, b int) float64 {
		if b == 0 {
			return 0
		}
		return float64(a) / float64(b)
	},
	"mulf":   func(a, b int) int { return a * b },
	"safeJS":   func(s string) template.JS { return template.JS(s) },
	"contains": strings.Contains,
	"printf":   fmt.Sprintf,
}

var loginTmpl = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>oktsec — dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#09090b;--surface:#18181b;--surface2:#27272a;--border:#3f3f46;
  --text:#fafafa;--text2:#a1a1aa;--text3:#71717a;
  --accent:#6366f1;--accent-light:#818cf8;--accent-dim:#4f46e5;
  --danger:#ef4444;--success:#10b981;--warn:#f59e0b;
  --mono:'JetBrains Mono','SF Mono','Fira Code',monospace;
  --sans:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
}
@keyframes fadeIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
body{font-family:var(--sans);background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center}
.backdrop{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);width:600px;height:600px;background:radial-gradient(circle,rgba(99,102,241,0.06) 0%,transparent 70%);pointer-events:none;z-index:0}
.login-card{position:relative;z-index:1;background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:48px 40px;max-width:400px;width:100%;text-align:center;box-shadow:0 1px 2px rgba(0,0,0,0.3),0 4px 16px rgba(0,0,0,0.2);animation:fadeIn 0.4s ease-out}
.icon{margin-bottom:20px}
.icon svg{width:48px;height:48px;color:var(--accent)}
.logo{font-family:var(--mono);font-size:1.5rem;font-weight:700;letter-spacing:-0.3px;margin-bottom:8px}
.subtitle{color:var(--text2);font-size:0.85rem;margin-bottom:32px}
.help{color:var(--text3);font-size:0.78rem;margin-bottom:24px;line-height:1.6}
.help code{background:var(--surface2);padding:2px 6px;border-radius:4px;font-family:var(--mono);font-size:0.75rem;color:var(--accent-light)}
input[type=text]{
  width:100%;padding:14px 16px;background:var(--bg);border:1px solid var(--border);
  border-radius:8px;color:var(--text);font-family:var(--mono);font-size:1.2rem;
  text-align:center;letter-spacing:4px;outline:none;transition:border-color 0.2s,box-shadow 0.2s;
}
input[type=text]:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(99,102,241,0.15)}
input[type=text]::placeholder{letter-spacing:0;font-size:0.85rem;color:var(--text3)}
button{
  width:100%;padding:12px;margin-top:16px;background:var(--accent);color:#fff;
  border:none;border-radius:8px;font-size:0.9rem;font-weight:600;cursor:pointer;
  transition:background 0.2s,transform 0.1s,box-shadow 0.2s;
}
button:hover{background:var(--accent-dim);box-shadow:0 4px 12px rgba(99,102,241,0.25)}
button:active{transform:scale(0.98)}
.error{display:flex;align-items:center;gap:8px;justify-content:center;margin-top:14px;padding:10px 14px;background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.15);border-radius:8px;color:var(--danger);font-size:0.82rem}
.error svg{flex-shrink:0;width:16px;height:16px}
.footer{margin-top:32px;color:var(--text3);font-size:0.72rem}
</style>
</head>
<body>
<div class="backdrop"></div>
<div class="login-card">
  <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><rect x="9" y="11" width="6" height="5" rx="1"/><path d="M12 11V9a2 2 0 0 0-4 0"/></svg></div>
  <div class="logo">oktsec</div>
  <div class="subtitle">Dashboard Access</div>
  <p class="help">Enter the access code shown in your terminal.<br>Run <code>oktsec serve</code> to get a code.</p>
  <form method="POST" action="/dashboard/login" autocomplete="off">
    <input type="text" name="code" placeholder="00000000" maxlength="8" pattern="\d{8}" inputmode="numeric" autofocus required>
    <button type="submit">Authenticate</button>
  </form>
  {{if .Error}}<div class="error"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>{{.Error}}</div>{{end}}
  <p class="footer">Local access only <span style="opacity:0.4;margin:0 6px">&middot;</span> 127.0.0.1</p>
</div>
</body>
</html>`))

// SplashTmpl is the root landing page template, exported for use by the proxy server.
var SplashTmpl = template.Must(template.New("splash").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>oktsec</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#09090b;--surface:#18181b;--border:#3f3f46;
  --text:#fafafa;--text2:#a1a1aa;--text3:#71717a;
  --accent:#6366f1;--accent-light:#818cf8;--accent-dim:#4f46e5;
  --mono:'JetBrains Mono','SF Mono','Fira Code',monospace;
  --sans:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
}
@keyframes fadeIn{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
@keyframes pulse{0%,100%{opacity:0.15}50%{opacity:0.25}}
body{font-family:var(--sans);background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;overflow:hidden}
.backdrop{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);width:800px;height:800px;background:radial-gradient(circle,rgba(99,102,241,0.08) 0%,transparent 65%);pointer-events:none;animation:pulse 6s ease-in-out infinite}
.container{position:relative;z-index:1;text-align:center;animation:fadeIn 0.6s ease-out}
.logo{font-family:var(--mono);font-size:4.5rem;font-weight:700;letter-spacing:-2px;margin-bottom:12px;background:linear-gradient(135deg,var(--text) 0%,var(--accent-light) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.tagline{color:var(--text3);font-size:1rem;letter-spacing:0.5px;margin-bottom:40px}
.links{display:flex;gap:16px;justify-content:center;flex-wrap:wrap}
.links a{display:inline-flex;align-items:center;gap:8px;padding:10px 22px;border-radius:8px;font-size:0.88rem;font-weight:500;text-decoration:none;transition:background 0.2s,transform 0.1s,box-shadow 0.2s}
.links a:active{transform:scale(0.98)}
.primary{background:var(--accent);color:#fff}
.primary:hover{background:var(--accent-dim);box-shadow:0 4px 12px rgba(99,102,241,0.25)}
.secondary{background:var(--surface);color:var(--text2);border:1px solid var(--border)}
.secondary:hover{border-color:var(--accent);color:var(--text)}
.version{margin-top:48px;color:var(--text3);font-family:var(--mono);font-size:0.72rem;opacity:0.6}
</style>
</head>
<body>
<div class="backdrop"></div>
<div class="container">
  <div class="logo">OKTSEC</div>
  <p class="tagline">Security proxy for inter-agent communication</p>
  <div class="links">
    <a class="primary" href="/dashboard">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>
      Dashboard
    </a>
    <a class="secondary" href="/health">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
      Health
    </a>
  </div>
  <p class="version">v0.1.0</p>
</div>
</body>
</html>`))

var notFoundTmpl = template.Must(template.New("notfound").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>oktsec — 404</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#09090b;--surface:#18181b;--surface2:#27272a;--border:#3f3f46;
  --text:#fafafa;--text2:#a1a1aa;--text3:#71717a;
  --accent:#6366f1;--accent-light:#818cf8;--accent-dim:#4f46e5;
  --mono:'JetBrains Mono','SF Mono','Fira Code',monospace;
  --sans:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
}
@keyframes fadeIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
body{font-family:var(--sans);background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center}
.backdrop{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);width:600px;height:600px;background:radial-gradient(circle,rgba(99,102,241,0.06) 0%,transparent 70%);pointer-events:none;z-index:0}
.card{position:relative;z-index:1;background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:48px 40px;max-width:420px;width:100%;text-align:center;box-shadow:0 1px 2px rgba(0,0,0,0.3),0 4px 16px rgba(0,0,0,0.2);animation:fadeIn 0.4s ease-out}
.icon{margin-bottom:20px}
.icon svg{width:48px;height:48px;color:var(--accent);opacity:0.8}
.code{font-family:var(--mono);font-size:4rem;font-weight:700;letter-spacing:-2px;color:var(--accent);line-height:1;margin-bottom:8px}
.title{font-size:1.25rem;font-weight:600;margin-bottom:12px}
.desc{color:var(--text3);font-size:0.85rem;line-height:1.6;margin-bottom:32px}
.back{display:inline-block;padding:10px 24px;background:var(--accent);color:#fff;border:none;border-radius:8px;font-size:0.9rem;font-weight:600;text-decoration:none;cursor:pointer;transition:background 0.2s,transform 0.1s,box-shadow 0.2s}
.back:hover{background:var(--accent-dim);box-shadow:0 4px 12px rgba(99,102,241,0.25)}
.back:active{transform:scale(0.98)}
.footer{margin-top:32px;color:var(--text3);font-size:0.72rem}
</style>
</head>
<body>
<div class="backdrop"></div>
<div class="card">
  <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polygon points="16.24 7.76 14.12 14.12 7.76 16.24 9.88 9.88 16.24 7.76"/></svg></div>
  <div class="code">404</div>
  <div class="title">Page not found</div>
  <p class="desc">The page you're looking for doesn't exist or has been moved.</p>
  <a class="back" href="/dashboard">Back to Dashboard</a>
  <p class="footer">oktsec</p>
</div>
</body>
</html>`))

const layoutHead = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>oktsec — {{.Active}}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<script src="https://unpkg.com/htmx.org@2.0.4" integrity="sha384-HGfztofotfshcF7+8n44JQL2oJmowVChPTg48S+jvZoztPfvwD79OC/LTtG6dMp+" crossorigin="anonymous"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#09090b;--surface:#18181b;--surface2:#27272a;--surface-hover:#303033;
  --border:#3f3f46;--border-hover:#52525b;--border-subtle:rgba(255,255,255,0.06);
  --text:#fafafa;--text2:#a1a1aa;--text3:#71717a;
  --accent:#6366f1;--accent-light:#818cf8;--accent-dim:#4f46e5;
  --accent-glow:rgba(99,102,241,0.08);--accent-glow-md:rgba(99,102,241,0.15);--accent-border:rgba(99,102,241,0.2);
  --danger:#ef4444;--success:#10b981;--warn:#f59e0b;
  --mono:'JetBrains Mono','SF Mono','Fira Code',monospace;
  --sans:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
}
body{font-family:var(--sans);background:var(--bg);color:var(--text);min-height:100vh;font-size:0.88rem;line-height:1.5;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}

/* Sidebar */
.sidebar{position:fixed;top:0;left:0;width:240px;height:100vh;background:var(--bg);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:100;overflow-y:auto}
.sidebar .brand{padding:20px 20px 24px;font-family:var(--mono);font-size:1.12rem;font-weight:700;letter-spacing:-0.3px;color:var(--text);text-decoration:none;display:block}
.sidebar-section{padding:0 12px;margin-bottom:16px}
.sidebar-section-label{font-size:0.65rem;text-transform:uppercase;letter-spacing:1px;color:var(--text3);font-weight:500;padding:8px 12px 6px;user-select:none}
.sidebar-item{display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:6px;color:var(--text3);font-size:0.82rem;font-weight:500;text-decoration:none;transition:all 0.15s;border-left:2px solid transparent;margin-bottom:1px}
.sidebar-item:hover{background:var(--surface-hover);color:var(--text2)}
.sidebar-item.active{color:var(--accent);background:var(--accent-glow);border-left-color:var(--accent)}
.sidebar-item svg{width:18px;height:18px;flex-shrink:0;opacity:0.7}
.sidebar-item.active svg{opacity:1}

/* Top bar */
.topbar{position:fixed;top:0;left:240px;right:0;height:48px;background:rgba(24,24,27,0.85);border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 24px;z-index:99;backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px)}
.topbar .page-title{font-size:0.9rem;font-weight:600;color:var(--text)}
.topbar .spacer{flex:1}
.topbar .mode-pill{display:inline-flex;align-items:center;gap:6px;background:var(--accent-glow);border:1px solid var(--accent-border);padding:4px 14px 4px 10px;border-radius:100px;font-size:0.72rem;font-weight:500;color:var(--accent-light);font-family:var(--mono);transition:all 0.2s}
.topbar .mode-pill .dot{width:5px;height:5px;border-radius:50%;animation:pulse 2s infinite}
.topbar .mode-pill.enforce .dot{background:var(--success)}
.topbar .mode-pill.enforce{background:rgba(16,185,129,0.08);border-color:rgba(16,185,129,0.2);color:var(--success)}
.topbar .mode-pill.observe .dot{background:var(--warn)}
.topbar .mode-pill.observe{background:rgba(245,158,11,0.08);border-color:rgba(245,158,11,0.2);color:var(--warn)}

/* Main */
main{margin-left:240px;padding:80px 32px 32px;background:var(--surface);min-height:100vh}
h1{font-size:1.3rem;font-weight:600;margin-bottom:6px;letter-spacing:-0.2px}
h1 span{color:var(--text2);font-weight:400}
.page-desc{color:var(--text3);font-size:0.82rem;margin-bottom:28px}

/* Stats */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:28px}
.stat{background:var(--surface2);border:1px solid var(--border);border-radius:12px;padding:18px 20px;transition:all 0.2s}
.stat:hover{background:var(--surface-hover);border-color:var(--border-hover)}
.stat .label{color:var(--text3);font-size:0.68rem;text-transform:uppercase;letter-spacing:0.8px;font-weight:500;margin-bottom:6px}
.stat .value{font-family:var(--mono);font-size:1.7rem;font-weight:700}
.stat .value.success{color:var(--success)}
.stat .value.danger{color:var(--danger)}
.stat .value.warn{color:var(--warn)}

/* Card */
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px;margin-bottom:16px;transition:all 0.15s}
.card:hover{border-color:var(--border-hover)}
.card h2{font-size:0.92rem;font-weight:600;margin-bottom:16px;display:flex;align-items:center;gap:8px}
.card h2 .dot{width:6px;height:6px;border-radius:50%;background:var(--success);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.3}}

/* Table */
table{width:100%;border-collapse:collapse;font-size:0.82rem}
th{text-align:left;color:var(--text3);font-size:0.68rem;text-transform:uppercase;letter-spacing:0.8px;font-weight:500;padding:8px 12px;border-bottom:1px solid var(--border)}
td{padding:10px 12px;border-bottom:1px solid rgba(63,63,70,0.6);color:var(--text2);font-family:var(--mono);font-size:0.78rem;transition:background 0.15s}
tr:hover td{background:var(--surface2)}

/* Status badges — pills with tinted bg (what happened to the message) */
.badge-delivered{background:#22c55e18;color:#4ade80;padding:3px 10px;border-radius:4px;font-size:0.7rem;font-weight:600}
.badge-blocked{background:#ef444418;color:#f87171;padding:3px 10px;border-radius:4px;font-size:0.7rem;font-weight:600}
.badge-rejected{background:#f9731618;color:#fb923c;padding:3px 10px;border-radius:4px;font-size:0.7rem;font-weight:600}
.badge-quarantined{background:#a855f718;color:#c084fc;padding:3px 10px;border-radius:4px;font-size:0.7rem;font-weight:600}
.badge-verified{color:var(--success)}
.badge-unsigned{color:var(--text3)}
.badge-invalid{color:var(--danger)}

/* Agent list */
.agent-row{display:flex;align-items:center;gap:12px;padding:12px 0;border-bottom:1px solid var(--border)}
.agent-row:last-child{border-bottom:none}
.agent-name{font-family:var(--mono);font-weight:600;min-width:160px}
.agent-name a{color:var(--text);text-decoration:none;transition:color 0.2s}
.agent-name a:hover{color:var(--accent-light)}
.agent-targets{color:var(--text3);font-size:0.78rem}

/* Severity labels */
.sev-critical{color:#ef4444;font-size:0.68rem;font-weight:600;font-family:var(--mono);text-transform:uppercase;letter-spacing:0.3px}
.sev-high{color:#f97316;font-size:0.68rem;font-weight:600;font-family:var(--mono);text-transform:uppercase;letter-spacing:0.3px}
.sev-medium{color:#3b82f6;font-size:0.68rem;font-weight:500;font-family:var(--mono);text-transform:uppercase;letter-spacing:0.3px}
.sev-low{color:var(--text3);font-size:0.68rem;font-weight:500;font-family:var(--mono);text-transform:uppercase;letter-spacing:0.3px}
.sev-info{color:var(--text3);font-size:0.68rem;font-weight:500;font-family:var(--mono);text-transform:uppercase;letter-spacing:0.3px}

/* Action badges */
.act-block{background:#ef444418;color:#f87171;padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:600}
.act-quarantine{background:#a855f718;color:#c084fc;padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:600}
.act-allow-and-flag{background:#f9731618;color:#fb923c;padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:600}
.act-ignore{background:var(--surface2);color:var(--text3);padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:600}

/* Chart */
.chart{display:flex;align-items:flex-end;gap:3px;height:80px;padding:8px 0}
.chart-bar{flex:1;background:var(--accent);border-radius:2px 2px 0 0;min-width:4px;transition:background 0.2s;position:relative}
.chart-bar:hover{background:var(--accent-light)}
.chart-labels{display:flex;justify-content:space-between;color:var(--text3);font-size:0.65rem;font-family:var(--mono);padding-top:4px}

/* Toggle */
.toggle-btn{display:inline-block;padding:6px 14px;background:var(--surface2);color:var(--text2);border:1px solid var(--border);border-radius:8px;font-size:0.78rem;cursor:pointer;text-decoration:none;transition:all 0.2s}
.toggle-btn:hover{background:var(--accent-dim);color:#fff;border-color:var(--accent)}

/* Key table */
.fp{color:var(--text3);font-size:0.72rem}

/* Empty state */
.empty{color:var(--text3);text-align:center;padding:40px 0;font-size:0.85rem}

/* Search bar */
.search-bar{position:relative;margin-bottom:16px}
.search-bar input{
  width:100%;padding:10px 16px 10px 36px;background:var(--bg);border:1px solid var(--border);
  border-radius:8px;color:var(--text);font-family:var(--mono);font-size:0.82rem;outline:none;transition:border-color 0.2s;
}
.search-bar input:focus{border-color:var(--accent)}
.search-bar input::placeholder{color:var(--text3)}
.search-bar .search-icon{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--text3);font-size:0.82rem;pointer-events:none}

/* Slide-in panel */
.panel-overlay{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.4);z-index:199;opacity:0;pointer-events:none;transition:opacity 0.3s ease}
.panel-overlay.open{opacity:1;pointer-events:auto}
.panel{position:fixed;top:0;right:0;width:480px;max-width:90vw;height:100%;background:var(--surface);border-left:1px solid var(--border);z-index:200;transform:translateX(100%);transition:transform 0.3s ease;overflow-y:auto;padding:0}
.panel.open{transform:translateX(0)}
.panel-header{display:flex;align-items:center;justify-content:space-between;padding:20px 24px;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--surface);z-index:1}
.panel-header h3{font-size:0.95rem;font-weight:600}
.panel-close{background:none;border:none;color:var(--text3);font-size:1.2rem;cursor:pointer;padding:4px 8px;border-radius:4px;transition:all 0.2s;width:auto;margin:0}
.panel-close:hover{color:var(--text);background:var(--surface2)}
.panel-body{padding:24px}
.panel-body .field{margin-bottom:16px}
.panel-body .field-label{color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px}
.panel-body .field-value{font-family:var(--mono);font-size:0.82rem;color:var(--text);word-break:break-all}
.panel-body .field-value.hash{font-size:0.72rem;color:var(--text2)}

/* Tabs */
.tabs{display:flex;gap:0;margin-bottom:20px;border-bottom:1px solid var(--border)}
.tab{padding:10px 20px;color:var(--text3);font-size:0.82rem;cursor:pointer;border-bottom:2px solid transparent;transition:all 0.2s;background:none;border-top:none;border-left:none;border-right:none;width:auto}
.tab:hover{color:var(--text)}
.tab.active{color:var(--accent-light);border-bottom-color:var(--accent-light)}
.tab-content{display:none}
.tab-content.active{display:block}

/* Form elements */
.form-row{display:flex;gap:12px;margin-bottom:12px;align-items:flex-end}
.form-group{flex:1}
.form-group label{display:block;color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px}
.form-group input,.form-group select,.form-group textarea{
  width:100%;padding:8px 12px;background:var(--bg);border:1px solid var(--border);
  border-radius:6px;color:var(--text);font-family:var(--mono);font-size:0.82rem;outline:none;transition:border-color 0.2s;
}
.form-group input:focus,.form-group select:focus,.form-group textarea:focus{border-color:var(--accent)}
.form-group select{cursor:pointer;-webkit-appearance:none;appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%23555570' d='M6 8L1 3h10z'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 10px center;padding-right:28px}
.form-group textarea{resize:vertical;min-height:80px}
.btn{display:inline-block;padding:8px 18px;background:var(--accent);color:#fff;border:none;border-radius:6px;font-size:0.82rem;font-weight:600;cursor:pointer;transition:all 0.15s;width:auto;margin:0}
.btn:hover{background:var(--accent-light)}
.btn-sm{padding:4px 12px;font-size:0.72rem}
.btn-danger{background:var(--danger)}
.btn-danger:hover{background:#dc2626}

/* Clickable rows */
tr.clickable{cursor:pointer}
tr.clickable:hover td{background:var(--surface2)}

/* Rule card in list */
.rule-list-item{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--border);cursor:pointer;transition:background 0.2s}
.rule-list-item:last-child{border-bottom:none}
.rule-list-item:hover{background:var(--surface2);margin:0 -20px;padding:10px 20px}
.rule-id-col{font-family:var(--mono);font-weight:600;min-width:200px;font-size:0.78rem;color:var(--text)}
.rule-name-col{flex:1;color:var(--text2);font-size:0.78rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rule-cat-col{color:var(--text3);font-size:0.72rem;min-width:100px}

/* SSE indicator */
.sse-indicator{display:inline-flex;align-items:center;gap:6px;font-size:0.72rem;color:var(--text3)}
.sse-dot{width:6px;height:6px;border-radius:50%;background:var(--text3)}
.sse-dot.connected{background:var(--success);animation:pulse 2s infinite}

/* Pattern display */
.pattern-item{font-family:var(--mono);font-size:0.72rem;color:var(--text2);background:var(--bg);padding:6px 10px;border-radius:4px;margin-bottom:4px;word-break:break-all}

/* Quarantine */
.q-preview{font-family:var(--mono);font-size:0.75rem;color:var(--text2);background:var(--bg);padding:8px 12px;border-radius:6px;max-height:60px;overflow:hidden;white-space:pre-wrap;word-break:break-all}
.q-content{font-family:var(--mono);font-size:0.78rem;color:var(--text);background:var(--bg);padding:12px 16px;border-radius:6px;white-space:pre-wrap;word-break:break-all;max-height:300px;overflow-y:auto;border:1px solid var(--border)}
.q-actions{display:flex;gap:8px;margin-top:8px}
.pending-badge{background:#f97316;color:#000;font-size:0.65rem;font-weight:700;padding:2px 6px;border-radius:8px;margin-left:6px}
.badge-pending{background:#f9731618;color:#fb923c;padding:3px 10px;border-radius:4px;font-size:0.7rem;font-weight:600}
.badge-approved{background:#22c55e18;color:#4ade80;padding:3px 10px;border-radius:4px;font-size:0.7rem;font-weight:600}
.badge-expired{background:var(--surface2);color:var(--text3);padding:3px 10px;border-radius:4px;font-size:0.7rem;font-weight:600}

/* Agent tags — outlined pills */
.agent-tag{display:inline-block;padding:2px 8px;border:1px solid var(--border);border-radius:4px;font-size:0.7rem;color:var(--text2);font-family:var(--sans);background:transparent}
.avatar{border-radius:50%;vertical-align:middle;flex-shrink:0}
.agent-cell{display:inline-flex;align-items:center;gap:6px;white-space:nowrap}

/* ACL target pills */
.acl-target{display:inline-block;padding:2px 8px;background:rgba(99,102,241,0.1);border-radius:4px;font-size:0.72rem;color:var(--accent-light);font-family:var(--mono)}

/* Risk bar */
.risk-bar{height:8px;border-radius:4px;background:var(--surface2);position:relative;min-width:60px}
.risk-bar-fill{height:100%;border-radius:4px;transition:width 0.3s}
.risk-low{background:var(--success)}
.risk-med{background:var(--warn)}
.risk-high{background:var(--danger)}

/* Horizontal bar chart */
.hbar{display:flex;align-items:center;gap:8px;margin-bottom:6px}
.hbar-label{min-width:80px;font-family:var(--mono);font-size:0.75rem;color:var(--text2);text-align:right}
.hbar-track{flex:1;height:20px;background:var(--surface2);border-radius:4px;overflow:hidden}
.hbar-fill{height:100%;border-radius:4px;transition:width 0.3s}
.hbar-count{min-width:40px;font-family:var(--mono);font-size:0.75rem;color:var(--text3)}

/* Alert banner */
.alert-banner{padding:14px 20px;border-radius:10px;margin-bottom:20px;display:flex;align-items:center;gap:12px;font-size:0.88rem}
.alert-banner.warn{background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.3);color:var(--warn)}
.alert-banner strong{font-weight:600}
.alert-banner .btn{margin-left:auto;white-space:nowrap}

/* Rule categories accordion */
.rule-category{border-bottom:1px solid var(--border)}
.rule-category:last-child{border-bottom:none}
.rule-cat-header{display:flex;align-items:center;gap:12px;padding:14px 4px;cursor:pointer;list-style:none;user-select:none;transition:background 0.15s}
.rule-cat-header:hover{background:var(--surface2)}
.rule-cat-header::-webkit-details-marker{display:none}
.rule-cat-header::before{content:'\25B8';color:var(--text3);font-size:0.75rem;transition:transform 0.2s;width:14px;text-align:center}
details[open] > .rule-cat-header::before{transform:rotate(90deg)}
.rule-cat-name{font-weight:600;font-size:0.85rem;min-width:180px}
.rule-cat-count{color:var(--text3);font-size:0.72rem;font-family:var(--mono)}
.rule-cat-badges{display:flex;gap:4px;margin-left:auto}
.rule-cat-body{padding:0 0 8px 26px}

/* Toggle switch */
.toggle{position:relative;display:inline-block;width:36px;height:20px;flex-shrink:0}
.toggle input{opacity:0;width:0;height:0}
.toggle-slider{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background:var(--surface2);border:1px solid var(--border);border-radius:20px;transition:all 0.2s}
.toggle-slider::before{content:'';position:absolute;height:14px;width:14px;left:2px;bottom:2px;background:var(--text3);border-radius:50%;transition:all 0.2s}
input:checked + .toggle-slider{background:var(--accent-dim);border-color:var(--accent)}
input:checked + .toggle-slider::before{transform:translateX(16px);background:var(--accent-light)}

/* Rule row with toggle */
.rule-list-item{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--border);transition:background 0.2s}
.rule-list-item:last-child{border-bottom:none}
.rule-list-item:hover{background:var(--surface2);margin:0 -20px;padding:10px 20px}
.rule-list-item.disabled{opacity:0.45}
.rule-desc{color:var(--text3);font-size:0.72rem;font-family:var(--sans);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:350px}
.rule-info{flex:1;min-width:0;cursor:pointer}
.rule-info .rule-id-col{font-family:var(--mono);font-weight:600;font-size:0.78rem;color:var(--text)}
.rule-info .rule-name-col{color:var(--text2);font-size:0.75rem;font-family:var(--sans);margin-top:1px}

/* Category header with toggle */
.rule-cat-header{display:flex;align-items:center;gap:12px;padding:16px 4px;cursor:pointer;list-style:none;user-select:none;transition:background 0.15s}
.rule-cat-desc{color:var(--text3);font-size:0.72rem;font-family:var(--sans);margin-top:2px}
.cat-disabled-label{color:var(--text3);font-size:0.7rem;font-style:italic}

/* Inline add form */
.inline-add{display:flex;gap:8px;align-items:flex-end;padding:16px 0;border-top:1px solid var(--border);margin-top:8px}
.inline-add .form-group{margin:0}
.inline-add .form-group label{margin-bottom:2px}

/* Tooltip */
[data-tooltip]{position:relative;cursor:help;border-bottom:1px dotted var(--text3)}
[data-tooltip]::after{content:attr(data-tooltip);position:absolute;bottom:calc(100% + 6px);left:50%;transform:translateX(-50%);background:var(--surface2);color:var(--text);border:1px solid var(--border);padding:6px 10px;border-radius:6px;font-size:0.72rem;white-space:normal;z-index:300;opacity:0;pointer-events:none;transition:opacity 0.15s;font-family:var(--sans);font-weight:400;line-height:1.4;max-width:260px;text-align:center}
[data-tooltip]:hover::after{opacity:1}

/* Stat sub-description */
.stat .sub{color:var(--text3);font-size:0.68rem;margin-top:4px;font-family:var(--sans)}

/* Responsive */
@media(max-width:768px){
  .sidebar{display:none}
  .topbar{left:0}
  main{margin-left:0;padding:64px 16px 16px}
  .stats{grid-template-columns:repeat(2,1fr)}
  .panel{width:100%;max-width:100%}
  .form-row{flex-direction:column}
  .inline-add{flex-direction:column;align-items:stretch}
}
</style>
</head>
<body>
<aside class="sidebar">
  <a href="/dashboard" class="brand">oktsec</a>
  <div class="sidebar-section">
    <div class="sidebar-section-label">Main</div>
    <a href="/dashboard" class="sidebar-item {{if eq .Active "overview"}}active{{end}}">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>
      Overview
    </a>
    <a href="/dashboard/events" class="sidebar-item {{if eq .Active "events"}}active{{end}}">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>
      Events
    </a>
    <a href="/dashboard/graph" class="sidebar-item {{if eq .Active "graph"}}active{{end}}">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
      Graph
    </a>
  </div>
  <div class="sidebar-section">
    <div class="sidebar-section-label">Security</div>
    <a href="/dashboard/agents" class="sidebar-item {{if eq .Active "agents"}}active{{end}}">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
      Agents
    </a>
    <a href="/dashboard/rules" class="sidebar-item {{if eq .Active "rules"}}active{{end}}">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      Rules
    </a>
    <a href="/dashboard/audit" class="sidebar-item {{if eq .Active "audit"}}active{{end}}">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/></svg>
      Audit
    </a>
  </div>
  <div class="sidebar-section">
    <div class="sidebar-section-label">Management</div>
    <a href="/dashboard/settings" class="sidebar-item {{if eq .Active "settings"}}active{{end}}">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
      Settings
    </a>
  </div>
</aside>
<div class="topbar">
  <span class="page-title">{{.Active | upper}}</span>
  <div class="spacer"></div>
  <span class="mode-pill {{if .RequireSig}}enforce{{else}}observe{{end}}" data-tooltip="{{if .RequireSig}}Signatures required — unsigned messages are rejected{{else}}Signatures optional — content scanning only{{end}}"><span class="dot"></span>{{if .RequireSig}}enforce{{else}}observe{{end}}</span>
  <form method="POST" action="/dashboard/logout" style="margin-left:10px;display:inline"><button type="submit" style="background:none;border:1px solid var(--border);color:var(--text3);padding:5px 12px;border-radius:8px;font-size:0.72rem;cursor:pointer;font-family:var(--sans);transition:all 0.2s" onmouseover="this.style.color='var(--text2)';this.style.borderColor='var(--border-hover)'" onmouseout="this.style.color='var(--text3)';this.style.borderColor='var(--border)'">Logout</button></form>
</div>
<main>`

const layoutFoot = `</main>

<!-- Slide-in panel -->
<div class="panel-overlay" id="panel-overlay" onclick="closePanel()"></div>
<div class="panel" id="detail-panel">
  <div id="panel-content"></div>
</div>

<script>
function openPanel(html) {
  document.getElementById('panel-content').innerHTML = html;
  document.getElementById('detail-panel').classList.add('open');
  document.getElementById('panel-overlay').classList.add('open');
}
function closePanel() {
  document.getElementById('detail-panel').classList.remove('open');
  document.getElementById('panel-overlay').classList.remove('open');
}
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') closePanel();
});

// HTMX: when a panel response arrives, open the panel
document.body.addEventListener('htmx:afterSwap', function(e) {
  if (e.detail.target.id === 'panel-content') {
    document.getElementById('detail-panel').classList.add('open');
    document.getElementById('panel-overlay').classList.add('open');
  }
});

// Tabs
function switchTab(group, tabName) {
  document.querySelectorAll('[data-tab-group="'+group+'"] .tab').forEach(function(t) {
    t.classList.toggle('active', t.dataset.tab === tabName);
  });
  document.querySelectorAll('[data-tab-content="'+group+'"]').forEach(function(c) {
    c.classList.toggle('active', c.dataset.tabName === tabName);
  });
}

// Humanize timestamps (global so SSE code can call it)
function _relTime(ts){
  var d=new Date(ts),now=new Date(),s=Math.floor((now-d)/1000);
  if(isNaN(s))return ts;
  if(s<60)return 'just now';
  if(s<3600)return Math.floor(s/60)+'m ago';
  if(s<86400)return Math.floor(s/3600)+'h ago';
  if(s<604800)return Math.floor(s/86400)+'d ago';
  return d.toLocaleDateString(undefined,{month:'short',day:'numeric'})+' '+d.toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit'});
}
function humanizeTimestamps(){
  document.querySelectorAll('[data-ts]').forEach(function(el){
    var ts=el.getAttribute('data-ts');
    if(ts){el.textContent=_relTime(ts);el.title=ts;}
  });
}
humanizeTimestamps();
document.body.addEventListener('htmx:afterSettle',humanizeTimestamps);

// Agent avatar generator (mirrors Go agentAvatar — pastel palette, abstract patterns)
var _avPal=['#7ec8e3','#a78bda','#c9a9e0','#e8a0bf','#f4b183','#b5d99c','#8cc5b2','#d6c28e'];
var _avN=0;
function _fnv(s){var h=2166136261>>>0;for(var i=0;i<s.length;i++){h^=s.charCodeAt(i);h=Math.imul(h,16777619)>>>0;}return h>>>0;}
function agentAvatar(name,sz){
  if(!name)return'';
  var h=_fnv(name),uid='av'+(++_avN),pl=_avPal.length;
  var i1=h%pl,i2=Math.floor(h/pl)%pl,i3=Math.floor(h/pl/pl)%pl;
  if(i2===i1)i2=(i2+1)%pl;
  if(i3===i1||i3===i2)i3=(i3+2)%pl;
  var c1=_avPal[i1],c2=_avPal[i2],c3=_avPal[i3],b='';
  switch((h>>>16)%8){
  case 0:b='<defs><radialGradient id="'+uid+'"><stop offset="0%" stop-color="'+c1+'"/><stop offset="100%" stop-color="'+c2+'"/></radialGradient></defs><circle cx="20" cy="20" r="20" fill="url(#'+uid+')"/>';break;
  case 1:b='<clipPath id="'+uid+'"><circle cx="20" cy="20" r="20"/></clipPath><g clip-path="url(#'+uid+')">';var cc=[c1,c2,c3,c1];for(var r=0;r<4;r++)for(var c=0;c<4;c++){b+='<rect x="'+(c*10)+'" y="'+(r*10)+'" width="11" height="11" fill="'+cc[(h>>>(r*4+c))&3]+'"/>';}b+='</g>';break;
  case 2:b='<circle cx="20" cy="20" r="20" fill="'+c1+'"/><circle cx="20" cy="20" r="13" fill="'+c2+'"/><circle cx="20" cy="20" r="7" fill="'+c3+'"/>';break;
  case 3:b='<defs><radialGradient id="'+uid+'"><stop offset="0%" stop-color="'+c3+'"/><stop offset="40%" stop-color="'+c3+'"/><stop offset="70%" stop-color="'+c1+'"/><stop offset="100%" stop-color="'+c2+'"/></radialGradient></defs><circle cx="20" cy="20" r="20" fill="url(#'+uid+')"/>';break;
  case 4:b='<defs><clipPath id="'+uid+'"><circle cx="20" cy="20" r="20"/></clipPath></defs><circle cx="20" cy="20" r="20" fill="'+c1+'"/><line x1="-2" y1="28" x2="42" y2="12" stroke="'+c2+'" stroke-width="6" clip-path="url(#'+uid+')" opacity="0.6"/>';break;
  case 5:b='<defs><clipPath id="'+uid+'"><circle cx="20" cy="20" r="20"/></clipPath></defs><g clip-path="url(#'+uid+')"><rect x="0" y="0" width="20" height="20" fill="'+c1+'"/><rect x="20" y="0" width="20" height="20" fill="'+c2+'"/><rect x="0" y="20" width="20" height="20" fill="'+c3+'"/><rect x="20" y="20" width="20" height="20" fill="'+c1+'"/></g>';break;
  case 6:b='<defs><clipPath id="'+uid+'"><circle cx="20" cy="20" r="20"/></clipPath></defs><circle cx="20" cy="20" r="20" fill="'+c1+'"/><rect x="0" y="14" width="40" height="12" fill="'+c2+'" clip-path="url(#'+uid+')" opacity="0.55"/>';break;
  case 7:var cx=30+(h>>>20)%40,cy=30+(h>>>24)%40;b='<defs><radialGradient id="'+uid+'" cx="'+cx+'%" cy="'+cy+'%"><stop offset="0%" stop-color="'+c1+'"/><stop offset="50%" stop-color="'+c2+'"/><stop offset="100%" stop-color="'+c3+'"/></radialGradient></defs><circle cx="20" cy="20" r="20" fill="url(#'+uid+')"/>';break;
  }
  return '<svg class="avatar" width="'+sz+'" height="'+sz+'" viewBox="0 0 40 40">'+b+'</svg>';
}
function agentCellHTML(name){if(!name)return'';return '<span class="agent-cell">'+agentAvatar(name,20)+' '+name+'</span>';}
</script>
</body>
</html>`

var overviewTmpl = template.Must(template.New("overview").Funcs(tmplFuncs).Parse(layoutHead + `
<h1>Dashboard <span>Overview</span></h1>
<p class="page-desc">Messages between agents are scanned for threats, verified for identity, and logged here. <span class="sse-indicator" id="sse-status"><span class="sse-dot" id="sse-dot"></span> <span id="sse-label">connecting</span></span></p>

{{if .PendingReview}}
<div class="alert-banner warn">
  <strong>{{.PendingReview}} message{{if gt .PendingReview 1}}s{{end}} pending review</strong>
  <span style="color:var(--text2);font-size:0.78rem">Quarantined content awaiting human decision</span>
  <a href="/dashboard/events?tab=quarantine" class="btn btn-sm" style="background:var(--warn);color:#000">Review Now</a>
</div>
{{end}}

<div class="stats" hx-get="/dashboard/api/stats" hx-trigger="every 5s" hx-swap="none">
  <div class="stat">
    <div class="label">Total Messages</div>
    <div class="value" id="stat-total">{{.Stats.TotalMessages}}</div>
    <div class="sub">All messages processed</div>
  </div>
  <div class="stat">
    <div class="label">Delivered</div>
    <div class="value success" id="stat-delivered">{{.Stats.Delivered}}</div>
    <div class="sub">Passed all checks</div>
  </div>
  <div class="stat">
    <div class="label">Blocked</div>
    <div class="value danger" id="stat-blocked">{{.Stats.Blocked}}</div>
    <div class="sub">Dangerous content detected</div>
  </div>
  <div class="stat">
    <div class="label">Rejected</div>
    <div class="value warn" id="stat-rejected">{{.Stats.Rejected}}</div>
    <div class="sub">ACL or signature failure</div>
  </div>
</div>

{{if .Stats.TotalMessages}}
<div class="stats" style="grid-template-columns:1fr 1fr 1fr">
  <div class="stat">
    <div class="label">Detection Rate</div>
    <div class="value {{if gt .DetectionRate 20}}danger{{else if gt .DetectionRate 5}}warn{{else}}success{{end}}">{{.DetectionRate}}%</div>
    <div class="sub">Messages blocked or quarantined</div>
  </div>
  <div class="stat">
    <div class="label">Unsigned Messages (24h)</div>
    <div class="value {{if gt .UnsignedPct 50}}danger{{else if gt .UnsignedPct 20}}warn{{else}}success{{end}}">{{.UnsignedCount}}</div>
    <div class="sub">{{.UnsignedPct}}% of recent traffic</div>
  </div>
  <div class="stat">
    <div class="label">Avg Latency (24h)</div>
    <div class="value {{if ge .AvgLatency 200}}danger{{else if ge .AvgLatency 50}}warn{{else}}success{{end}}">{{.AvgLatency}}ms</div>
    <div class="sub">Average proxy processing time</div>
  </div>
</div>
{{end}}

<div class="card" style="display:flex;align-items:center;gap:20px;padding:16px 24px">
  <div>
    <div class="label" style="font-size:0.75rem;color:var(--text2)">Security Health</div>
    <div style="font-size:1.8rem;font-weight:700" class="{{gradeColor .Grade}}">{{.Score}}/100</div>
  </div>
  <div style="font-size:2.2rem;font-weight:700;color:var(--text3)">{{.Grade}}</div>
  <div style="flex:1"></div>
  <a href="/dashboard/audit" style="font-size:0.78rem;color:var(--accent-light);text-decoration:none;border:1px solid var(--border);padding:6px 14px;border-radius:6px;transition:all 0.2s" onmouseover="this.style.borderColor='var(--accent-light)'" onmouseout="this.style.borderColor='var(--border)'">View Audit</a>
</div>

{{if .Chart}}
<div class="card">
  <h2>24h Activity</h2>
  <div class="chart">
    {{range .Chart}}<div class="chart-bar" style="height:{{.Percent}}%" title="{{.Label}}: {{.Count}} msgs"></div>{{end}}
  </div>
  <div class="chart-labels">
    <span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>23:00</span>
  </div>
</div>
{{end}}

{{if .TopRules}}
<div class="card">
  <h2>Top Triggered Rules (24h)</h2>
  <table>
    <thead><tr><th>Rule</th><th>Severity</th><th>Triggers</th></tr></thead>
    <tbody>
    {{range .TopRules}}
    <tr class="clickable" hx-get="/dashboard/api/rules/{{.RuleID}}" hx-target="#panel-content" hx-swap="innerHTML">
      <td><span style="font-weight:600">{{.Name}}</span><br><span style="color:var(--text3);font-size:0.72rem;font-family:var(--mono)">{{.RuleID}}</span></td>
      <td>{{if eq .Severity "critical"}}<span class="badge-blocked">critical</span>{{else if eq .Severity "high"}}<span class="badge-blocked">high</span>{{else if eq .Severity "medium"}}<span class="badge-quarantined">medium</span>{{else}}<span class="badge-delivered">low</span>{{end}}</td>
      <td style="font-family:var(--mono);font-weight:600">{{.Count}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
</div>
{{end}}

{{if .AgentRisks}}
<div class="card">
  <h2>Agent Risk (24h)</h2>
  <table>
    <thead><tr><th>Agent</th><th>Messages</th><th>Blocked</th><th>Quarantined</th><th>Risk</th></tr></thead>
    <tbody>
    {{range .AgentRisks}}
    <tr class="clickable" onclick="window.location='/dashboard/agents/{{.Agent}}'">
      <td>{{agentCell .Agent}}</td>
      <td style="font-family:var(--mono)">{{.Total}}</td>
      <td style="font-family:var(--mono)">{{.Blocked}}</td>
      <td style="font-family:var(--mono)">{{.Quarantined}}</td>
      <td style="min-width:120px">
        <div style="display:flex;align-items:center;gap:8px">
          <div class="risk-bar" style="flex:1">
            <div class="risk-bar-fill {{if gt .RiskScore 60.0}}risk-high{{else if gt .RiskScore 30.0}}risk-med{{else}}risk-low{{end}}" style="width:{{printf "%.0f" .RiskScore}}%"></div>
          </div>
          <span style="font-family:var(--mono);font-size:0.75rem;color:var(--text2)">{{printf "%.0f" .RiskScore}}</span>
        </div>
      </td>
    </tr>
    {{end}}
    </tbody>
  </table>
</div>
{{end}}

<div class="card">
  <h2><span class="dot"></span> Recent Events</h2>
  <div class="search-bar">
    <span class="search-icon">&#x1f50d;</span>
    <input type="text" placeholder="Search events..." hx-get="/dashboard/api/search" hx-trigger="input changed delay:300ms" hx-target="#search-results" name="q">
  </div>
  <div id="search-results" style="display:none"></div>
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
    <div class="empty" id="empty-msg">No events yet. Send a message through the proxy to see activity.</div>
    {{end}}
  </div>
</div>


<script>
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
    label.textContent = 'live';
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
        default: statusBadge = entry.status;
      }

      var row = document.createElement('tr');
      row.className = 'clickable';
      row.setAttribute('hx-get', '/dashboard/api/event/' + entry.id);
      row.setAttribute('hx-target', '#panel-content');
      row.setAttribute('hx-swap', 'innerHTML');
      row.innerHTML = '<td data-ts="' + entry.timestamp + '">' + entry.timestamp + '</td><td>' + agentCellHTML(entry.from_agent) + '</td><td>' + agentCellHTML(entry.to_agent) + '</td><td>' + statusBadge + '</td>';
      tbody.insertBefore(row, tbody.firstChild);
      htmx.process(row);
      if(typeof humanizeTimestamps==='function')humanizeTimestamps();

      // Keep only 20 rows
      while (tbody.children.length > 20) tbody.removeChild(tbody.lastChild);
    } catch(err) {}
  };
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

var agentsTmpl = template.Must(template.New("agents").Funcs(tmplFuncs).Parse(layoutHead + `
<h1>Registered <span>Agents</span></h1>
<p class="page-desc">Each agent can only message destinations listed in its ACL. Manage agents, generate keypairs, and view message history.</p>

<div class="card">
  {{if .AgentRows}}
  <div style="overflow-x:auto">
  <table>
    <thead><tr><th>Agent</th><th>Description</th><th>Messages</th><th>Blocked</th><th>Risk</th><th>Key</th><th>Last Active</th></tr></thead>
    <tbody>
    {{range .AgentRows}}
    <tr class="clickable" onclick="window.location='/dashboard/agents/{{.Name}}'">
      <td style="font-weight:600">{{agentCell .Name}}{{if .Suspended}} <span class="badge-blocked" style="font-size:0.6rem;padding:2px 6px">SUSPENDED</span>{{end}}</td>
      <td style="color:var(--text2);font-family:var(--sans);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{.Description}}</td>
      <td style="font-family:var(--mono)">{{.Total}}</td>
      <td>{{if .Total}}<span style="font-family:var(--mono);{{if gt .BlockedPct 20}}color:var(--danger){{else if gt .BlockedPct 5}}color:var(--warn){{else}}color:var(--text2){{end}}">{{.BlockedPct}}%</span>{{else}}<span style="color:var(--text3)">--</span>{{end}}</td>
      <td style="min-width:100px">
        <div style="display:flex;align-items:center;gap:6px">
          <div class="risk-bar" style="flex:1">
            <div class="risk-bar-fill {{if gt .RiskScore 60.0}}risk-high{{else if gt .RiskScore 30.0}}risk-med{{else}}risk-low{{end}}" style="width:{{printf "%.0f" .RiskScore}}%"></div>
          </div>
          <span style="font-family:var(--mono);font-size:0.72rem;color:var(--text3)">{{printf "%.0f" .RiskScore}}</span>
        </div>
      </td>
      <td style="text-align:center">{{if .HasKey}}<span title="Key registered" style="color:var(--success)">&#x1f512;</span>{{else}}<span title="No key" style="color:var(--text3)">&#x1f513;</span>{{end}}</td>
      <td style="color:var(--text2);font-size:0.78rem" {{if .LastSeen}}data-ts="{{.LastSeen}}"{{end}}>{{if .LastSeen}}{{.LastSeen}}{{else}}<span style="color:var(--text3)">never</span>{{end}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  {{else}}
  <div class="empty">No agents configured.</div>
  {{end}}
</div>

{{if .DiscoveredAgents}}
<div class="card">
  <h2 style="color:var(--warn)">Discovered from Traffic</h2>
  <p style="color:var(--text2);font-size:0.82rem;margin-bottom:12px">These agents appeared in traffic but are not registered. Unregistered agents bypass ACL checks.</p>
  <table>
    <thead><tr><th>Agent</th><th>Action</th></tr></thead>
    <tbody>
    {{range .DiscoveredAgents}}
    <tr>
      <td>{{agentCell .}}</td>
      <td>
        <form method="POST" action="/dashboard/agents" style="display:inline">
          <input type="hidden" name="name" value="{{.}}">
          <button type="submit" class="btn btn-sm">Register</button>
        </form>
      </td>
    </tr>
    {{end}}
    </tbody>
  </table>
</div>
{{end}}

<div class="card">
  <h2>Add Agent</h2>
  <form method="POST" action="/dashboard/agents" class="inline-add">
    <div class="form-group" style="min-width:180px">
      <label>Name</label>
      <input type="text" name="name" placeholder="e.g. research-agent" required pattern="[a-zA-Z0-9][a-zA-Z0-9_-]*">
    </div>
    <div class="form-group" style="flex:2">
      <label>Can Message (comma-separated)</label>
      <input type="text" name="can_message" placeholder="e.g. target-agent, helper-agent">
    </div>
    <button type="submit" class="btn">Add</button>
  </form>
  <p style="color:var(--text3);font-size:0.72rem;margin-top:8px">Add description, tags, and other metadata from the agent detail page.</p>
</div>
` + layoutFoot))

var agentDetailTmpl = template.Must(template.New("agent-detail").Funcs(tmplFuncs).Parse(layoutHead + `
<div style="display:flex;align-items:center;gap:14px;margin-bottom:16px">
  {{avatar .Name 40}}
  <div style="min-width:0">
    <h1 style="margin:0;font-size:1.3rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">Agent: <span>{{.Name}}</span></h1>
    <p style="color:var(--text2);font-size:0.82rem;margin:2px 0 0">{{if .Agent.Description}}{{.Agent.Description}}{{else}}Detail view for agent {{.Name}}.{{end}}</p>
  </div>
</div>

<div class="stats">
  <div class="stat">
    <div class="label">Total Messages</div>
    <div class="value">{{.TotalMsgs}}</div>
  </div>
  <div class="stat">
    <div class="label">Delivered</div>
    <div class="value success">{{.Delivered}}</div>
  </div>
  <div class="stat">
    <div class="label">Blocked</div>
    <div class="value danger">{{.Blocked}}</div>
  </div>
  <div class="stat">
    <div class="label">Quarantined</div>
    <div class="value" style="color:var(--accent-light)">{{.Quarantined}}</div>
  </div>
</div>

<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:20px">
  <div class="card" style="margin-bottom:0">
    <div class="label" style="font-size:0.75rem;color:var(--text2);margin-bottom:6px">Risk Score</div>
    <div style="display:flex;align-items:center;gap:10px">
      <div style="font-size:1.6rem;font-weight:700" class="{{if gt .RiskScore 60.0}}danger{{else if gt .RiskScore 30.0}}warn{{else}}success{{end}}">{{printf "%.0f" .RiskScore}}</div>
      <div style="flex:1">
        <div class="risk-bar"><div class="risk-bar-fill {{if gt .RiskScore 60.0}}risk-high{{else if gt .RiskScore 30.0}}risk-med{{else}}risk-low{{end}}" style="width:{{printf "%.0f" .RiskScore}}%"></div></div>
      </div>
      <div style="font-size:0.72rem;color:var(--text3)">{{if gt .RiskScore 60.0}}High{{else if gt .RiskScore 30.0}}Medium{{else}}Low{{end}}</div>
    </div>
  </div>

  {{if .TopRules}}
  <div class="card" style="margin-bottom:0;grid-column:span 2">
    <div class="label" style="font-size:0.75rem;color:var(--text2);margin-bottom:6px">Top Triggered Rules (24h)</div>
    <table style="font-size:0.82rem">
      <thead><tr><th>Rule</th><th>Severity</th><th style="text-align:right">Count</th></tr></thead>
      <tbody>
      {{range .TopRules}}
      <tr class="clickable" hx-get="/dashboard/api/rules/{{.RuleID}}" hx-target="#panel-content" hx-swap="innerHTML">
        <td><span style="font-weight:600">{{.Name}}</span><br><span style="color:var(--text3);font-size:0.68rem;font-family:var(--mono)">{{.RuleID}}</span></td>
        <td>{{if eq .Severity "critical"}}<span class="badge-blocked">critical</span>{{else if eq .Severity "high"}}<span class="badge-blocked">high</span>{{else if eq .Severity "medium"}}<span class="badge-quarantined">medium</span>{{else}}<span class="badge-delivered">low</span>{{end}}</td>
        <td style="text-align:right;font-family:var(--mono);font-weight:600">{{.Count}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
  </div>
  {{else}}
  <div class="card" style="margin-bottom:0;grid-column:span 2">
    <div class="label" style="font-size:0.75rem;color:var(--text2);margin-bottom:6px">Top Triggered Rules (24h)</div>
    <div class="empty" style="padding:12px 0">No rules triggered for this agent.</div>
  </div>
  {{end}}
</div>

{{if .CommPartners}}
<div class="card">
  <h2>Communication Partners (24h)</h2>
  <table>
    <thead><tr><th>From</th><th>To</th><th style="text-align:right">Total</th><th style="text-align:right">Delivered</th><th style="text-align:right">Blocked</th><th style="text-align:right">Block Rate</th></tr></thead>
    <tbody>
    {{range .CommPartners}}
    <tr class="clickable" onclick="window.location='/dashboard/graph/edge?from={{.From}}&to={{.To}}'">
      <td>{{agentCell .From}}</td>
      <td>{{agentCell .To}}</td>
      <td style="text-align:right;font-family:var(--mono)">{{.Total}}</td>
      <td style="text-align:right;font-family:var(--mono)">{{.Delivered}}</td>
      <td style="text-align:right;font-family:var(--mono)">{{.Blocked}}</td>
      <td style="text-align:right;font-family:var(--mono)">{{if .Total}}{{printf "%.0f" (divf (mulf .Blocked 100) .Total)}}%{{else}}0%{{end}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
</div>
{{end}}

<div class="card">
  <h2>Configuration</h2>
  <table>
    <tr><td style="color:var(--text3)">Can message</td><td>{{range $i, $t := .Agent.CanMessage}}{{if $i}} {{end}}<span class="acl-target">{{$t}}</span>{{end}}{{if not .Agent.CanMessage}}<span style="color:var(--text3)">none</span>{{end}}</td></tr>
    {{if .Agent.BlockedContent}}<tr><td style="color:var(--text3)">Blocked content</td><td>{{range $i, $c := .Agent.BlockedContent}}{{if $i}}, {{end}}{{$c}}{{end}}</td></tr>{{end}}
    {{if .Agent.Location}}<tr><td style="color:var(--text3)">Location</td><td>{{.Agent.Location}}</td></tr>{{end}}
    {{if .Agent.Tags}}<tr><td style="color:var(--text3)">Tags</td><td>{{range $i, $tag := .Agent.Tags}}{{if $i}} {{end}}<span class="agent-tag">{{$tag}}</span>{{end}}</td></tr>{{end}}
    {{if .Agent.CreatedBy}}<tr><td style="color:var(--text3)">Created by</td><td>{{.Agent.CreatedBy}}</td></tr>{{end}}
    {{if .Agent.CreatedAt}}<tr><td style="color:var(--text3)">Created at</td><td>{{.Agent.CreatedAt}}</td></tr>{{end}}
    {{if .KeyFP}}<tr><td style="color:var(--text3)">Key fingerprint</td><td class="fp">{{.KeyFP}}</td></tr>{{end}}
  </table>
  <div style="margin-top:16px;display:flex;gap:8px">
    <form method="POST" action="/dashboard/agents/{{.Name}}/keygen" style="display:inline"><button type="submit" class="btn btn-sm" onclick="return confirm('Generate new keypair for {{.Name}}? Existing key will be overwritten.')">Generate Keypair</button></form>
    <form method="POST" action="/dashboard/agents/{{.Name}}/suspend" style="display:inline">{{if .Suspended}}<button type="submit" class="btn btn-sm" style="background:var(--success)">Unsuspend</button>{{else}}<button type="submit" class="btn btn-sm" style="background:var(--warn);color:#000">Suspend</button>{{end}}</form>
    <button class="btn btn-sm btn-danger" hx-delete="/dashboard/agents/{{.Name}}" hx-confirm="Delete agent {{.Name}}? This cannot be undone." hx-swap="none" onclick="setTimeout(function(){window.location='/dashboard/agents'},300)">Delete Agent</button>
  </div>
</div>

<div class="card">
  <h2>Edit Metadata</h2>
  <form method="POST" action="/dashboard/agents/{{.Name}}/edit">
    <div class="form-row">
      <div class="form-group">
        <label>Description</label>
        <input type="text" name="description" value="{{.Agent.Description}}">
      </div>
      <div class="form-group">
        <label>Location</label>
        <input type="text" name="location" value="{{.Agent.Location}}">
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>Can Message (space-separated)</label>
        <input type="text" name="can_message" value="{{range $i, $t := .Agent.CanMessage}}{{if $i}} {{end}}{{$t}}{{end}}">
      </div>
      <div class="form-group">
        <label>Tags (space-separated)</label>
        <input type="text" name="tags" value="{{range $i, $t := .Agent.Tags}}{{if $i}} {{end}}{{$t}}{{end}}">
      </div>
    </div>
    <button type="submit" class="btn btn-sm">Save</button>
  </form>
</div>

<div class="card">
  <h2>Recent Messages</h2>
  {{if .Entries}}
  <table>
    <thead><tr><th>Time</th><th>From</th><th>To</th><th>Status</th><th style="text-align:right">Latency</th></tr></thead>
    <tbody>
    {{range .Entries}}
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
      <td style="text-align:right;color:var(--text3)">{{.LatencyMs}}ms</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}
  <div class="empty">No messages for this agent yet.</div>
  {{end}}
</div>
` + layoutFoot))

var rulesTmpl = template.Must(template.New("rules").Funcs(tmplFuncs).Parse(layoutHead + `
<h1>Detection <span>Rules</span></h1>
<p class="page-desc">Manage built-in detection rules and create custom rules for your organization.</p>

<style>
.rules-tabs{display:flex;gap:0;margin-bottom:24px;border-bottom:1px solid var(--border)}
.rules-tab{padding:12px 24px;color:var(--text3);font-size:0.88rem;font-weight:500;cursor:pointer;border-bottom:2px solid transparent;transition:all 0.2s;text-decoration:none;display:inline-flex;align-items:center;gap:8px}
.rules-tab:hover{color:var(--text)}
.rules-tab.active{color:var(--accent-light);border-bottom-color:var(--accent-light)}
.rules-tab .count{font-size:0.68rem;font-family:var(--mono);background:var(--surface2);padding:2px 8px;border-radius:10px;color:var(--text3)}
.rules-tab.active .count{background:rgba(99,102,241,0.15);color:var(--accent-light)}
.cat-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:16px;margin-bottom:24px}
@media(max-width:768px){.cat-grid{grid-template-columns:1fr}}
.cat-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px;cursor:pointer;transition:all 0.2s;position:relative;text-decoration:none;color:inherit;display:block}
.cat-card:hover{border-color:var(--accent);background:var(--surface2)}
.cat-card-head{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:10px}
.cat-card-name{font-weight:600;font-size:0.92rem}
.cat-card-count{color:var(--text3);font-size:0.72rem;font-family:var(--mono);white-space:nowrap}
.cat-card-desc{color:var(--text3);font-size:0.78rem;line-height:1.5;margin-bottom:14px}
.cat-card-footer{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.cat-card-sev{display:inline-flex;align-items:center;gap:4px;font-size:0.68rem;font-family:var(--mono);padding:3px 8px;border-radius:4px}
.cat-card-sev.critical{background:#ef444415;color:#f87171}
.cat-card-sev.high{background:#f9731615;color:#fb923c}
.cat-card-sev.medium{background:#3b82f615;color:#60a5fa}
.cat-card-sev.low{background:var(--surface2);color:var(--text3)}
.cat-card-status{margin-left:auto;font-size:0.72rem;font-weight:600}
.cat-card-status.all-on{color:var(--success)}
.cat-card-status.some-off{color:var(--warn)}
.cat-card-status.all-off{color:var(--text3)}
.custom-rule-row{display:flex;align-items:center;gap:16px;padding:14px 20px;background:var(--surface);border:1px solid var(--border);border-radius:10px;margin-bottom:8px;transition:border-color 0.2s}
.custom-rule-row:hover{border-color:var(--accent)}
.custom-rule-id{font-family:var(--mono);font-weight:600;font-size:0.82rem;color:var(--text);min-width:200px}
.custom-rule-file{color:var(--text3);font-size:0.75rem;font-family:var(--mono);flex:1}
</style>

<!-- Tabs -->
<div class="rules-tabs">
  <a href="/dashboard/rules?tab=detection" class="rules-tab {{if eq .Tab "detection"}}active{{end}}">Detection Rules{{if .RuleCount}} <span class="count">{{.RuleCount}}</span>{{end}}</a>
  <a href="/dashboard/rules?tab=enforcement" class="rules-tab {{if eq .Tab "enforcement"}}active{{end}}">Enforcement{{if .EnforcementCount}} <span class="count">{{.EnforcementCount}}</span>{{end}}</a>
  <a href="/dashboard/rules?tab=custom" class="rules-tab {{if eq .Tab "custom"}}active{{end}}">Custom Rules{{if .CustomCount}} <span class="count">{{.CustomCount}}</span>{{end}}</a>
</div>

{{if eq .Tab "detection"}}
<!-- Detection Rules Tab -->
{{if .Categories}}
<div class="cat-grid">
  {{range .Categories}}
  <a href="/dashboard/rules/{{.Name}}" class="cat-card">
    <div class="cat-card-head">
      <span class="cat-card-name">{{.Name}}</span>
      <span class="cat-card-count">{{.Total}} rules</span>
    </div>
    {{if .Description}}<div class="cat-card-desc">{{.Description}}</div>{{end}}
    <div class="cat-card-footer">
      {{if .Critical}}<span class="cat-card-sev critical">{{.Critical}} critical</span>{{end}}
      {{if .High}}<span class="cat-card-sev high">{{.High}} high</span>{{end}}
      {{if .Medium}}<span class="cat-card-sev medium">{{.Medium}} medium</span>{{end}}
      {{if .Low}}<span class="cat-card-sev low">{{.Low}} low</span>{{end}}
      {{if eq .Disabled 0}}<span class="cat-card-status all-on">All enabled</span>
      {{else if eq .Disabled .Total}}<span class="cat-card-status all-off">All disabled</span>
      {{else}}<span class="cat-card-status some-off">{{.Disabled}}/{{.Total}} disabled</span>{{end}}
    </div>
  </a>
  {{end}}
</div>
{{else}}
<div class="empty">No rules loaded.</div>
{{end}}

{{else if eq .Tab "enforcement"}}
<!-- Enforcement Tab -->
<style>
.enf-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px 20px;margin-bottom:10px;transition:border-color 0.2s}
.enf-card:hover{border-color:var(--accent)}
.enf-card-top{display:flex;align-items:center;gap:12px}
.enf-id{font-family:var(--mono);font-weight:600;font-size:0.85rem;color:var(--text)}
.enf-name{color:var(--text2);font-size:0.78rem;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.enf-badge{font-size:0.68rem;font-family:var(--mono);padding:3px 10px;border-radius:4px;font-weight:600;text-transform:uppercase;white-space:nowrap}
.enf-badge.block{background:#ef444415;color:#f87171}
.enf-badge.quarantine{background:#f9731615;color:#fb923c}
.enf-badge.allow-and-flag{background:#3b82f615;color:#60a5fa}
.enf-badge.ignore{background:var(--surface2);color:var(--text3)}
.enf-meta{display:flex;align-items:center;gap:8px;margin-top:8px;flex-wrap:wrap}
.enf-tag{font-size:0.68rem;font-family:var(--mono);padding:2px 8px;border-radius:4px;background:var(--surface2);color:var(--text3)}
.enf-tag.sev-critical{background:#ef444410;color:#f87171}
.enf-tag.sev-high{background:#f9731610;color:#fb923c}
.enf-tag.sev-medium{background:#3b82f610;color:#60a5fa}
.enf-urls{margin-top:8px;padding:8px 12px;background:var(--bg);border-radius:6px;font-family:var(--mono);font-size:0.72rem;color:var(--text3);line-height:1.8;word-break:break-all}
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
.csv.critical{background:#ef444415;color:#f87171}
.csv.high{background:#f9731615;color:#fb923c}
.csv.medium{background:#3b82f615;color:#60a5fa}
.csv.low{background:var(--surface2);color:var(--text3)}
.combo-empty{padding:12px 14px;color:var(--text3);font-size:0.78rem;font-style:italic}
/* Channel chips */
.ch-chip{display:inline-flex;align-items:center;gap:5px;padding:5px 12px;border-radius:20px;background:var(--surface);border:1px solid var(--border);cursor:pointer;font-size:0.78rem;font-family:var(--mono);color:var(--text2);transition:all 0.15s;user-select:none;white-space:nowrap}
.ch-chip:hover{border-color:var(--accent-dim);color:var(--text)}
.ch-chip input{position:absolute;opacity:0;pointer-events:none}
.ch-check{display:none;font-size:0.65rem;color:var(--accent-light)}
.ch-chip:has(input:checked){background:rgba(99,102,241,0.1);border-color:var(--accent);color:var(--accent-light)}
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
        <a href="/dashboard/settings" style="color:var(--text3);font-size:0.7rem;margin-left:4px;text-decoration:none;opacity:0.7" title="Manage channels in Settings">+ manage</a>
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
        Variables: <code style="background:var(--surface);padding:1px 5px;border-radius:3px;font-family:var(--mono);font-size:0.7rem">{{"{{RULE}}"}}</code>
        <code style="background:var(--surface);padding:1px 5px;border-radius:3px;font-family:var(--mono);font-size:0.7rem">{{"{{RULE_NAME}}"}}</code>
        <code style="background:var(--surface);padding:1px 5px;border-radius:3px;font-family:var(--mono);font-size:0.7rem">{{"{{CATEGORY}}"}}</code>
        <code style="background:var(--surface);padding:1px 5px;border-radius:3px;font-family:var(--mono);font-size:0.7rem">{{"{{MATCH}}"}}</code>
        <code style="background:var(--surface);padding:1px 5px;border-radius:3px;font-family:var(--mono);font-size:0.7rem">{{"{{ACTION}}"}}</code>
        <code style="background:var(--surface);padding:1px 5px;border-radius:3px;font-family:var(--mono);font-size:0.7rem">{{"{{SEVERITY}}"}}</code>
        <code style="background:var(--surface);padding:1px 5px;border-radius:3px;font-family:var(--mono);font-size:0.7rem">{{"{{FROM}}"}}</code>
        <code style="background:var(--surface);padding:1px 5px;border-radius:3px;font-family:var(--mono);font-size:0.7rem">{{"{{TO}}"}}</code>
        <code style="background:var(--surface);padding:1px 5px;border-radius:3px;font-family:var(--mono);font-size:0.7rem">{{"{{MESSAGE_ID}}"}}</code>
        <code style="background:var(--surface);padding:1px 5px;border-radius:3px;font-family:var(--mono);font-size:0.7rem">{{"{{TIMESTAMP}}"}}</code>.
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
    {{if .Notify}}{{range .Notify}}{{if not (contains . "://")}} <span class="enf-tag" style="background:rgba(99,102,241,0.1);color:var(--accent-light)">{{.}}</span>{{end}}{{end}}<span class="enf-tag" style="cursor:pointer" onclick="document.getElementById('enf-wh-{{$.ID}}').style.display=document.getElementById('enf-wh-{{$.ID}}').style.display==='none'?'block':'none'">{{len .Notify}} webhook{{if gt (len .Notify) 1}}s{{end}} &#9662;</span>{{end}}
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
    search.value = r ? r.id+' \u2014 '+r.name : id;
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
    if(!hidden.value){e.preventDefault();search.focus();search.style.outline='2px solid #f87171';setTimeout(function(){search.style.outline='';},1500);}
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

    document.getElementById('enf-title').textContent = 'Edit Override \u2014 '+id;
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
.breadcrumb{display:flex;align-items:center;gap:8px;margin-bottom:20px;font-size:0.82rem}
.breadcrumb a{color:var(--accent-light);text-decoration:none}
.breadcrumb a:hover{text-decoration:underline}
.breadcrumb .sep{color:var(--text3)}
.cat-header{display:flex;align-items:center;gap:16px;margin-bottom:8px}
.cat-header h1{margin:0}
.cat-toggle{margin-left:auto;display:flex;align-items:center;gap:8px;font-size:0.78rem;color:var(--text2)}
.rule-table{width:100%;border-collapse:collapse;table-layout:fixed}
.rule-table th{text-align:left;color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;padding:10px 12px;border-bottom:1px solid var(--border)}
.rule-table td{padding:12px;border-bottom:1px solid var(--border);font-size:0.82rem;vertical-align:top}
.rule-table tr:hover td{background:var(--surface2)}
.rule-table .rule-name{font-weight:600;font-family:var(--mono);font-size:0.78rem;color:var(--text);cursor:pointer;display:inline}
.rule-table .rule-name:hover{color:var(--accent-light)}
.rule-table .rule-desc{color:var(--text3);font-size:0.75rem;display:inline;margin-left:6px}
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
        <span class="rule-name" hx-get="/dashboard/api/rule/{{.ID}}" hx-target="#panel-content" hx-swap="innerHTML">{{.ID}}</span>
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

var eventDetailTmpl = template.Must(template.New("event-detail").Funcs(tmplFuncs).Parse(`
<div class="panel-header">
  <h3>Event Detail</h3>
  <button class="panel-close" onclick="closePanel()">&times;</button>
</div>
<div class="panel-body">

  <!-- Status banner -->
  <div style="padding:12px 16px;border-radius:8px;margin-bottom:20px;font-size:0.85rem;line-height:1.5;
    {{if eq .Entry.Status "delivered"}}background:rgba(34,197,94,0.08);border:1px solid rgba(34,197,94,0.2);color:var(--success)
    {{else if eq .Entry.Status "blocked"}}background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.2);color:var(--danger)
    {{else if eq .Entry.Status "quarantined"}}background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.2);color:var(--warn)
    {{else if eq .Entry.Status "rejected"}}background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.2);color:var(--warn)
    {{else}}background:var(--surface2);border:1px solid var(--border);color:var(--text2){{end}}">
    {{.Decision}}
  </div>

  <!-- Message flow -->
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:20px;padding:12px 16px;background:var(--surface2);border-radius:8px">
    <span class="agent-cell" style="font-family:var(--mono);font-weight:600;font-size:0.85rem">{{avatar .Entry.FromAgent 24}} {{.Entry.FromAgent}}</span>
    <span style="color:var(--text3);font-size:0.82rem">&rarr;</span>
    <span class="agent-cell" style="font-family:var(--mono);font-weight:600;font-size:0.85rem">{{avatar .Entry.ToAgent 24}} {{.Entry.ToAgent}}</span>
    <span style="margin-left:auto;color:var(--text3);font-size:0.72rem;font-family:var(--mono)">{{.Entry.LatencyMs}}ms</span>
  </div>

  {{if .Rules}}
  <!-- Triggered rules — clickable, link to category page -->
  <div style="margin-bottom:20px">
    <div style="color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px">Rules triggered</div>
    {{range .Rules}}
    <a href="/dashboard/rules/{{.Category}}" style="display:flex;align-items:center;gap:10px;padding:10px 14px;background:var(--bg);border:1px solid var(--border);border-radius:8px;margin-bottom:6px;text-decoration:none;color:inherit;transition:border-color 0.2s"
       onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'">
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
  <div style="color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px">Details</div>
  <table style="width:100%;font-size:0.78rem;border-collapse:collapse">
    <tr><td style="color:var(--text3);padding:6px 0;width:120px">Time</td><td style="font-family:var(--mono);padding:6px 0" data-ts="{{.Entry.Timestamp}}">{{.Entry.Timestamp}}</td></tr>
    <tr><td style="color:var(--text3);padding:6px 0">Status</td><td style="padding:6px 0">
      {{if eq .Entry.Status "delivered"}}<span class="badge-delivered">delivered</span>
      {{else if eq .Entry.Status "blocked"}}<span class="badge-blocked">blocked</span>
      {{else if eq .Entry.Status "rejected"}}<span class="badge-rejected">rejected</span>
      {{else if eq .Entry.Status "quarantined"}}<span class="badge-quarantined">quarantined</span>
      {{else}}{{.Entry.Status}}{{end}}
    </td></tr>
    <tr><td style="color:var(--text3);padding:6px 0">Signature</td><td style="padding:6px 0">
      {{if eq .Entry.SignatureVerified 1}}<span style="color:var(--success)">Verified</span>
      {{else if eq .Entry.SignatureVerified -1}}<span style="color:var(--danger)">Invalid</span>
      {{else}}<span style="color:var(--text3)">Not signed</span>{{end}}
    </td></tr>
    {{if .Entry.PubkeyFingerprint}}<tr><td style="color:var(--text3);padding:6px 0">Key</td><td style="font-family:var(--mono);font-size:0.7rem;color:var(--text2);padding:6px 0;word-break:break-all">{{.Entry.PubkeyFingerprint}}</td></tr>{{end}}
    <tr><td style="color:var(--text3);padding:6px 0">Content hash</td><td style="font-family:var(--mono);font-size:0.7rem;color:var(--text2);padding:6px 0;word-break:break-all">{{.Entry.ContentHash}}</td></tr>
  </table>
</div>`))

var ruleDetailTmpl = template.Must(template.New("rule-detail").Parse(`
<div class="panel-header">
  <h3>Rule Detail</h3>
  <button class="panel-close" onclick="closePanel()">&times;</button>
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
  {{if .CustomRulesDir}}No custom rules in {{.CustomRulesDir}}.{{else}}Set <code style="background:var(--surface2);padding:2px 6px;border-radius:4px;font-family:var(--mono);font-size:0.75rem;color:var(--accent-light)">custom_rules_dir</code> in oktsec.yaml to enable custom rules.{{end}}
</div>
{{end}}`))

// --- Quarantine templates ---

var quarantineDetailTmpl = template.Must(template.New("quarantine-detail").Funcs(tmplFuncs).Parse(`
<div class="panel-header">
  <h3>Quarantined Message</h3>
  <button class="panel-close" onclick="closePanel()">&times;</button>
</div>
<div class="panel-body">

  <!-- Status banner -->
  <div style="padding:12px 16px;border-radius:8px;margin-bottom:20px;font-size:0.85rem;line-height:1.5;
    {{if eq .Item.Status "pending"}}background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.2);color:var(--warn)
    {{else if eq .Item.Status "approved"}}background:rgba(34,197,94,0.08);border:1px solid rgba(34,197,94,0.2);color:var(--success)
    {{else if eq .Item.Status "rejected"}}background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.2);color:var(--danger)
    {{else}}background:var(--surface2);border:1px solid var(--border);color:var(--text3){{end}}">
    {{if eq .Item.Status "pending"}}This message is held for review. Approve to deliver or reject to discard.
    {{else if eq .Item.Status "approved"}}Approved by {{.Item.ReviewedBy}} — message was delivered.
    {{else if eq .Item.Status "rejected"}}Rejected by {{.Item.ReviewedBy}} — message was not delivered.
    {{else if eq .Item.Status "expired"}}Expired without review — message was not delivered.
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
    <a href="/dashboard/rules/{{.Category}}" style="display:flex;align-items:center;gap:10px;padding:10px 14px;background:var(--bg);border:1px solid var(--border);border-radius:8px;margin-bottom:6px;text-decoration:none;color:inherit;transition:border-color 0.2s"
       onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'">
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

  {{if eq .Item.Status "pending"}}
  <div class="q-actions" style="margin-top:20px">
    <button class="btn" style="background:var(--success)" hx-post="/dashboard/api/quarantine/{{.Item.ID}}/approve" hx-target="#q-row-{{.Item.ID}}" hx-swap="outerHTML" onclick="closePanel()">Approve &amp; Deliver</button>
    <button class="btn btn-danger" hx-post="/dashboard/api/quarantine/{{.Item.ID}}/reject" hx-target="#q-row-{{.Item.ID}}" hx-swap="outerHTML" onclick="closePanel()">Reject</button>
  </div>
  {{end}}
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

// --- Rule toggle partial ---

var ruleToggleTmpl = template.Must(template.New("rule-toggle").Parse(`<span id="toggle-{{.ID}}">
  <label class="toggle" title="{{if .Enabled}}Disable{{else}}Enable{{end}} this rule">
    <input type="checkbox" {{if .Enabled}}checked{{end}} hx-post="/dashboard/api/rule/{{.ID}}/toggle" hx-target="#toggle-{{.ID}}" hx-swap="outerHTML">
    <span class="toggle-slider"></span>
  </label>
</span>`))

// --- Settings page ---

var settingsTmpl = template.Must(template.New("settings").Funcs(tmplFuncs).Parse(layoutHead + `
<h1>Settings</h1>
<p class="page-desc">Security mode, agent identity keys, quarantine behavior, and server configuration.</p>

<div class="card">
  <h2>Security Mode</h2>
  <p style="color:var(--text2);font-size:0.82rem;margin-bottom:16px;line-height:1.6">
    Controls how oktsec handles message signatures. This is the most important setting — it determines whether agents can communicate without proving their identity.
  </p>
  <div style="display:flex;gap:16px;margin-bottom:16px">
    <div style="flex:1;padding:16px;border-radius:8px;border:1px solid {{if .RequireSig}}var(--accent){{else}}var(--border){{end}};background:{{if .RequireSig}}rgba(99,102,241,0.06){{else}}var(--surface){{end}}">
      <div style="font-weight:600;font-size:0.88rem;margin-bottom:6px;color:{{if .RequireSig}}var(--accent-light){{else}}var(--text2){{end}}">
        {{if .RequireSig}}&#x2713; {{end}}Enforce Mode
      </div>
      <p style="color:var(--text3);font-size:0.78rem;line-height:1.5">
        Every message must include a valid Ed25519 signature. Unsigned or tampered messages are <strong style="color:var(--danger)">rejected</strong>. Use this in production.
      </p>
    </div>
    <div style="flex:1;padding:16px;border-radius:8px;border:1px solid {{if not .RequireSig}}var(--warn){{else}}var(--border){{end}};background:{{if not .RequireSig}}rgba(245,158,11,0.06){{else}}var(--surface){{end}}">
      <div style="font-weight:600;font-size:0.88rem;margin-bottom:6px;color:{{if not .RequireSig}}var(--warn){{else}}var(--text2){{end}}">
        {{if not .RequireSig}}&#x2713; {{end}}Observe Mode
      </div>
      <p style="color:var(--text3);font-size:0.78rem;line-height:1.5">
        Messages are scanned for threats but signatures are <strong style="color:var(--warn)">not required</strong>. Useful for onboarding agents gradually.
      </p>
    </div>
  </div>
  <form method="POST" action="/dashboard/mode/toggle">
    <button type="submit" class="btn" style="background:{{if .RequireSig}}var(--warn){{else}}var(--accent){{end}}">
      Switch to {{if .RequireSig}}Observe{{else}}Enforce{{end}} Mode
    </button>
  </form>
</div>

<div class="card">
  <h2>Agent Identity &amp; Keys</h2>
  <p style="color:var(--text2);font-size:0.82rem;margin-bottom:16px;line-height:1.6">
    Each agent has an Ed25519 keypair. The public key is stored here; the agent holds the private key. Keys are used to sign and verify messages between agents.
  </p>
  <div style="color:var(--text3);font-size:0.78rem;margin-bottom:12px">
    <strong>Keys directory:</strong> <code style="background:var(--bg);padding:2px 8px;border-radius:4px;font-family:var(--mono);font-size:0.75rem;color:var(--accent-light)">{{.KeysDir}}</code>
  </div>
  {{if .Keys}}
  <table>
    <thead><tr><th>Agent</th><th>Fingerprint</th><th>Status</th><th></th></tr></thead>
    <tbody>
    {{range .Keys}}
    <tr>
      <td style="font-weight:600">{{.Name}}</td>
      <td class="fp">{{.Fingerprint}}</td>
      <td>{{if index $.RevokedFPs .Fingerprint}}<span class="badge-rejected">revoked</span>{{else}}<span class="badge-delivered">active</span>{{end}}</td>
      <td>
        {{if not (index $.RevokedFPs .Fingerprint)}}
        <form method="POST" action="/dashboard/identity/revoke" style="display:inline">
          <input type="hidden" name="agent" value="{{.Name}}">
          <button type="submit" class="btn btn-sm btn-danger" onclick="return confirm('Revoke key for {{.Name}}? This agent will not be able to send signed messages.')">Revoke</button>
        </form>
        {{end}}
      </td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}
  <div class="empty">No agent keys found. Generate keys from the <a href="/dashboard/agents" style="color:var(--accent-light)">Agents</a> page.</div>
  {{end}}

  {{if .Revoked}}
  <div style="margin-top:16px">
    <h3 style="font-size:0.82rem;color:var(--text3);margin-bottom:8px">Revoked Keys</h3>
    <table>
      <thead><tr><th>Agent</th><th>Fingerprint</th><th>Revoked</th></tr></thead>
      <tbody>
      {{range .Revoked}}
      <tr>
        <td>{{.AgentName}}</td>
        <td class="fp">{{.Fingerprint}}</td>
        <td style="color:var(--text3)">{{.RevokedAt}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
  </div>
  {{end}}
</div>

<div class="card">
  <h2>Quarantine Queue</h2>
  <p style="color:var(--text2);font-size:0.82rem;margin-bottom:16px;line-height:1.6">
    When a message triggers high-severity rules, it's held in quarantine instead of being delivered. A human must approve or reject it before the content reaches the destination agent.
  </p>
  <div style="display:flex;gap:24px;margin-bottom:16px">
    <div>
      <span style="color:var(--text3);font-size:0.72rem;text-transform:uppercase;letter-spacing:1px">Status</span>
      <div style="font-size:1rem;font-weight:600;margin-top:4px;color:{{if .QEnabled}}var(--success){{else}}var(--danger){{end}}">
        {{if .QEnabled}}Enabled{{else}}Disabled{{end}}
      </div>
    </div>
    <div>
      <span style="color:var(--text3);font-size:0.72rem;text-transform:uppercase;letter-spacing:1px">Auto-Expiry</span>
      <div style="font-size:1rem;font-weight:600;margin-top:4px">{{.QExpiryHours}}h</div>
    </div>
    <div>
      <span style="color:var(--text3);font-size:0.72rem;text-transform:uppercase;letter-spacing:1px">Pending</span>
      <div style="font-size:1rem;font-weight:600;margin-top:4px;color:{{if .QPending}}var(--warn){{else}}var(--success){{end}}">{{.QPending}}</div>
    </div>
  </div>
  <p style="color:var(--text3);font-size:0.78rem;line-height:1.5">
    Quarantined messages expire after <strong>{{.QExpiryHours}} hours</strong> if not reviewed.
    Expired messages are preserved for audit but the content is not delivered.
    Edit <code style="background:var(--bg);padding:2px 6px;border-radius:4px;font-size:0.72rem;font-family:var(--mono);color:var(--accent-light)">quarantine.expiry_hours</code> in the config file to change this.
  </p>
</div>

<div class="card">
  <h2>Webhook Channels</h2>
  <p style="color:var(--text2);font-size:0.82rem;margin-bottom:16px;line-height:1.6">
    Define webhook destinations once by name. Use channel names in enforcement overrides instead of pasting raw URLs.
  </p>

  <form method="POST" action="/dashboard/settings/webhooks" style="margin-bottom:20px">
    <div class="form-row">
      <div class="form-group" style="flex:1;min-width:140px">
        <label>Name</label>
        <input type="text" name="name" placeholder="e.g. slack-security" required pattern="[a-zA-Z0-9][a-zA-Z0-9_-]*">
      </div>
      <div class="form-group" style="flex:3">
        <label>URL</label>
        <input type="url" name="url" placeholder="https://hooks.slack.com/services/T00/B00/xxx" required>
      </div>
      <div class="form-group" style="align-self:flex-end">
        <button type="submit" class="btn">Save</button>
      </div>
    </div>
  </form>

  {{if .WebhookChannels}}
  <table>
    <thead><tr><th>Name</th><th>URL</th><th></th></tr></thead>
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
  <div class="empty">No webhook channels configured. Add one above to use in enforcement overrides.</div>
  {{end}}
</div>

<div class="card">
  <h2>Server</h2>
  <p style="color:var(--text2);font-size:0.82rem;margin-bottom:16px;line-height:1.6">
    Core proxy settings. These require a server restart to take effect.
  </p>
  <table>
    <tbody>
    <tr><td style="color:var(--text3);font-weight:600;width:160px">Port</td><td>{{.ServerPort}}</td></tr>
    <tr><td style="color:var(--text3);font-weight:600">Bind Address</td><td>{{.ServerBind}}</td></tr>
    <tr><td style="color:var(--text3);font-weight:600">Log Level</td><td>{{.LogLevel}}</td></tr>
    <tr><td style="color:var(--text3);font-weight:600">Custom Rules Dir</td><td>{{if .CustomRulesDir}}{{.CustomRulesDir}}{{else}}<span style="color:var(--text3)">not set</span>{{end}}</td></tr>
    <tr><td style="color:var(--text3);font-weight:600">Webhooks</td><td>{{.WebhookCount}} configured</td></tr>
    </tbody>
  </table>
</div>
` + layoutFoot))

// --- Events page (merged audit log + quarantine) ---

var eventsTmpl = template.Must(template.New("events").Funcs(tmplFuncs).Parse(layoutHead + `
<h1>Events</h1>
<p class="page-desc">Quarantined messages need human review. Blocked messages were stopped automatically. <span class="sse-indicator" id="sse-status"><span class="sse-dot" id="sse-dot"></span> <span id="sse-label">connecting</span></span></p>

<div style="display:flex;gap:12px;margin-bottom:16px;align-items:center">
  <select id="filter-agent" style="padding:6px 12px;border-radius:6px;border:1px solid var(--border);background:var(--surface);color:var(--text);font-size:0.82rem">
    <option value="">All Agents</option>
    {{range .AgentNames}}<option value="{{.}}" {{if eq . $.FilterAgent}}selected{{end}}>{{.}}</option>{{end}}
  </select>
  <input type="date" id="filter-since" value="{{.FilterSince}}" style="padding:6px 12px;border-radius:6px;border:1px solid var(--border);background:var(--surface);color:var(--text);font-size:0.82rem">
  <button class="btn btn-sm" onclick="clearEventFilters()" style="font-size:0.78rem">Clear</button>
</div>
<script>
function applyEventFilters() {
  var agent = document.getElementById('filter-agent').value;
  var since = document.getElementById('filter-since').value;
  var tab = '{{.Tab}}';
  var url = '/dashboard/events?tab=' + tab;
  if (agent) url += '&agent=' + encodeURIComponent(agent);
  if (since) url += '&since=' + encodeURIComponent(since + 'T00:00:00Z');
  window.location = url;
}
function clearEventFilters() {
  window.location = '/dashboard/events?tab={{.Tab}}';
}
document.getElementById('filter-agent').addEventListener('change', applyEventFilters);
document.getElementById('filter-since').addEventListener('change', applyEventFilters);
</script>

<div class="tabs" data-tab-group="events">
  <a href="/dashboard/events?tab=all{{if .FilterAgent}}&agent={{.FilterAgent}}{{end}}{{if .FilterSince}}&since={{.FilterSince}}{{end}}" class="tab {{if eq .Tab "all"}}active{{end}}">All Events</a>
  <a href="/dashboard/events?tab=quarantine{{if .FilterAgent}}&agent={{.FilterAgent}}{{end}}{{if .FilterSince}}&since={{.FilterSince}}{{end}}" class="tab {{if eq .Tab "quarantine"}}active{{end}}">Quarantine{{if .QPending}} <span class="pending-badge">{{.QPending}}</span>{{end}}</a>
  <a href="/dashboard/events?tab=blocked{{if .FilterAgent}}&agent={{.FilterAgent}}{{end}}{{if .FilterSince}}&since={{.FilterSince}}{{end}}" class="tab {{if eq .Tab "blocked"}}active{{end}}">Blocked</a>
</div>

<!-- All Events -->
<div class="tab-content {{if eq .Tab "all"}}active{{end}}" data-tab-content="events" data-tab-name="all">
  <div class="search-bar">
    <span class="search-icon">&#x1F50D;</span>
    <input type="text" placeholder="Search events by agent, rule, or content hash..."
           hx-get="/dashboard/api/search" hx-trigger="keyup changed delay:300ms" hx-target="#search-results" name="q">
  </div>

  <div id="search-results">
  {{if .Entries}}
  <table>
    <thead><tr><th>Time</th><th>From</th><th>To</th><th>Status</th><th>Signature</th></tr></thead>
    <tbody id="events-body">
    {{range .Entries}}
    <tr class="clickable" hx-get="/dashboard/api/event/{{.ID}}" hx-target="#panel-content" hx-swap="innerHTML">
      <td data-ts="{{.Timestamp}}">{{.Timestamp}}</td>
      <td>{{agentCell .FromAgent}}</td>
      <td>{{agentCell .ToAgent}}</td>
      <td><span class="badge-{{.Status}}">{{.Status}}</span></td>
      <td>
        {{if eq .SignatureVerified 1}}<span class="badge-verified" title="Signature verified">&#10003; Verified</span>
        {{else if eq .SignatureVerified -1}}<span class="badge-invalid" title="Invalid signature">&#10007; Invalid</span>
        {{else}}<span class="badge-unsigned" title="Message was not signed">&mdash; Unsigned</span>{{end}}
      </td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}
  <div class="empty">No events yet. Send a message through the proxy to see activity here.</div>
  {{end}}
  </div>
</div>

<!-- Quarantine -->
<div class="tab-content {{if eq .Tab "quarantine"}}active{{end}}" data-tab-content="events" data-tab-name="quarantine">
  {{if .QStats}}
  <div class="stats" style="grid-template-columns:repeat(4,1fr);margin-bottom:20px">
    <div class="stat">
      <div class="label">Pending</div>
      <div class="value warn">{{.QStats.Pending}}</div>
    </div>
    <div class="stat">
      <div class="label">Approved</div>
      <div class="value success">{{.QStats.Approved}}</div>
    </div>
    <div class="stat">
      <div class="label">Rejected</div>
      <div class="value danger">{{.QStats.Rejected}}</div>
    </div>
    <div class="stat">
      <div class="label">Expired</div>
      <div class="value" style="color:var(--text3)">{{.QStats.Expired}}</div>
    </div>
  </div>
  {{end}}

  <div style="display:flex;gap:8px;margin-bottom:16px">
    <a href="/dashboard/events?tab=quarantine&status=pending" class="toggle-btn {{if eq .QStatusFilter "pending"}}active{{end}}" style="{{if eq .QStatusFilter "pending"}}background:var(--accent-dim);color:#fff;border-color:var(--accent){{end}}">Pending</a>
    <a href="/dashboard/events?tab=quarantine&status=approved" class="toggle-btn {{if eq .QStatusFilter "approved"}}active{{end}}" style="{{if eq .QStatusFilter "approved"}}background:var(--accent-dim);color:#fff;border-color:var(--accent){{end}}">Approved</a>
    <a href="/dashboard/events?tab=quarantine&status=rejected" class="toggle-btn {{if eq .QStatusFilter "rejected"}}active{{end}}" style="{{if eq .QStatusFilter "rejected"}}background:var(--accent-dim);color:#fff;border-color:var(--accent){{end}}">Rejected</a>
    <a href="/dashboard/events?tab=quarantine&status=" class="toggle-btn {{if eq .QStatusFilter ""}}active{{end}}" style="{{if eq .QStatusFilter ""}}background:var(--accent-dim);color:#fff;border-color:var(--accent){{end}}">All</a>
  </div>

  {{if .QItems}}
  <table>
    <thead><tr><th>Time</th><th>From</th><th>To</th><th>Content</th><th>Status</th><th>Expires</th><th>Actions</th></tr></thead>
    <tbody>
    {{range .QItems}}
    <tr id="q-row-{{.ID}}">
      <td data-ts="{{.CreatedAt}}">{{.CreatedAt}}</td>
      <td>{{agentCell .FromAgent}}</td>
      <td>{{agentCell .ToAgent}}</td>
      <td><div class="q-preview" style="cursor:pointer" hx-get="/dashboard/api/quarantine/{{.ID}}" hx-target="#panel-content" hx-swap="innerHTML">{{truncate .Content 80}}</div></td>
      <td><span class="badge-{{.Status}}">{{.Status}}</span></td>
      <td style="font-size:0.72rem;white-space:nowrap">{{if eq .Status "pending"}}<span data-expires="{{.ExpiresAt}}"></span>{{else}}&mdash;{{end}}</td>
      <td>
        {{if eq .Status "pending"}}
        <div class="q-actions">
          <button class="btn btn-sm" style="background:var(--success)" hx-post="/dashboard/api/quarantine/{{.ID}}/approve" hx-target="#q-row-{{.ID}}" hx-swap="outerHTML">Approve</button>
          <button class="btn btn-sm btn-danger" hx-post="/dashboard/api/quarantine/{{.ID}}/reject" hx-target="#q-row-{{.ID}}" hx-swap="outerHTML">Reject</button>
        </div>
        {{else}}
        <button class="btn btn-sm" style="padding:2px 8px;font-size:0.7rem" hx-get="/dashboard/api/quarantine/{{.ID}}" hx-target="#panel-content" hx-swap="innerHTML">view</button>
        {{end}}
      </td>
    </tr>
    {{end}}
    </tbody>
  </table>
  <script>
  function updateExpiry() {
    document.querySelectorAll('[data-expires]').forEach(function(el) {
      var exp = new Date(el.dataset.expires);
      var now = new Date();
      var diff = exp - now;
      var hours = Math.floor(diff / 3600000);
      var mins = Math.floor((diff % 3600000) / 60000);
      if (diff <= 0) { el.textContent = 'expired'; el.style.color = 'var(--danger)'; }
      else if (hours < 1) { el.textContent = mins + 'm'; el.style.color = 'var(--danger)'; }
      else if (hours < 4) { el.textContent = hours + 'h ' + mins + 'm'; el.style.color = 'var(--warn)'; }
      else { el.textContent = hours + 'h'; el.style.color = 'var(--text3)'; }
    });
  }
  setInterval(updateExpiry, 60000);
  updateExpiry();
  </script>
  {{else}}
  <div class="empty">No quarantined messages{{if .QStatusFilter}} with status "{{.QStatusFilter}}"{{end}}.</div>
  {{end}}
</div>

<!-- Blocked -->
<div class="tab-content {{if eq .Tab "blocked"}}active{{end}}" data-tab-content="events" data-tab-name="blocked">
  {{if .BlockedEntries}}
  <table>
    <thead><tr><th>Time</th><th>From</th><th>To</th><th>Status</th><th>Rules</th></tr></thead>
    <tbody>
    {{range .BlockedEntries}}
    <tr class="clickable" hx-get="/dashboard/api/event/{{.ID}}" hx-target="#panel-content" hx-swap="innerHTML">
      <td data-ts="{{.Timestamp}}">{{.Timestamp}}</td>
      <td>{{agentCell .FromAgent}}</td>
      <td>{{agentCell .ToAgent}}</td>
      <td><span class="badge-{{.Status}}">{{.Status}}</span></td>
      <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{.RulesTriggered}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}
  <div class="empty">No blocked or rejected messages.</div>
  {{end}}
</div>

<script>
// SSE for live events
(function() {
  var src = new EventSource('/dashboard/api/events');
  var dot = document.getElementById('sse-dot');
  var label = document.getElementById('sse-label');
  src.onopen = function() { dot.classList.add('connected'); label.textContent = 'live'; };
  src.onerror = function() { dot.classList.remove('connected'); label.textContent = 'reconnecting'; };
  src.onmessage = function(e) {
    try {
      var ev = JSON.parse(e.data);
      var tbody = document.getElementById('events-body');
      if (!tbody) return;
      var sigLabel = '<span class="badge-unsigned" title="Message was not signed">&mdash; Unsigned</span>';
      if (ev.signature_verified === 1) sigLabel = '<span class="badge-verified" title="Signature verified">&#10003; Verified</span>';
      else if (ev.signature_verified === -1) sigLabel = '<span class="badge-invalid" title="Invalid signature">&#10007; Invalid</span>';
      var row = document.createElement('tr');
      row.className = 'clickable';
      row.setAttribute('hx-get', '/dashboard/api/event/' + ev.id);
      row.setAttribute('hx-target', '#panel-content');
      row.setAttribute('hx-swap', 'innerHTML');
      row.innerHTML = '<td data-ts="' + ev.timestamp + '">' + ev.timestamp + '</td><td>' + agentCellHTML(ev.from_agent||'') + '</td><td>' + agentCellHTML(ev.to_agent||'') + '</td><td><span class="badge-' + ev.status + '">' + ev.status + '</span></td><td>' + sigLabel + '</td>';
      tbody.insertBefore(row, tbody.firstChild);
      htmx.process(row);
      if(typeof humanizeTimestamps==='function')humanizeTimestamps();
    } catch(err) {}
  };
})();
</script>
` + layoutFoot))

var graphTmpl = template.Must(template.New("graph").Funcs(tmplFuncs).Parse(layoutHead + `
<h1>Agent Interaction <span>Graph</span></h1>
<p class="page-desc">Red nodes have high threat scores. Shadow edges indicate traffic outside ACL policy. Data covers the last 24 hours.</p>

<div class="stats">
  <div class="stat"><div class="label">Nodes</div><div class="value">{{.Graph.TotalNodes}}</div></div>
  <div class="stat"><div class="label" data-tooltip="Connections with observed traffic between agents">Active Edges</div><div class="value">{{.Graph.TotalEdges}}</div></div>
  <div class="stat"><div class="label" data-tooltip="Traffic between agents not defined in ACL policy — may indicate misconfiguration">Shadow Edges</div><div class="value{{if .Graph.ShadowEdges}} warn{{end}}">{{len .Graph.ShadowEdges}}</div></div>
  <div class="stat"><div class="label" data-tooltip="ACL entries with no observed traffic — consider tightening permissions">Unused ACL</div><div class="value{{if .Graph.UnusedACL}} warn{{end}}">{{len .Graph.UnusedACL}}</div></div>
</div>

{{if .Graph.ShadowEdges}}
<div class="alert-banner warn">
  <strong>Shadow communications detected</strong> — {{len .Graph.ShadowEdges}} edge(s) with traffic not defined in ACL policy.
</div>
{{end}}

<div class="card">
  <h2>Network Topology</h2>
  <div id="graph-container" style="width:100%;height:500px;background:var(--bg);border-radius:8px;border:1px solid var(--border);position:relative;overflow:hidden"></div>
  <div style="display:flex;gap:20px;margin-top:12px;font-size:0.72rem;color:var(--text3)">
    <span><svg width="12" height="12"><circle cx="6" cy="6" r="5" fill="#22c55e" fill-opacity="0.3" stroke="#22c55e" stroke-width="1.5"/></svg> Low threat</span>
    <span><svg width="12" height="12"><circle cx="6" cy="6" r="5" fill="#f59e0b" fill-opacity="0.3" stroke="#f59e0b" stroke-width="1.5"/></svg> Medium threat</span>
    <span><svg width="12" height="12"><circle cx="6" cy="6" r="5" fill="#ef4444" fill-opacity="0.3" stroke="#ef4444" stroke-width="1.5"/></svg> High threat</span>
    <span style="margin-left:12px"><svg width="20" height="12"><line x1="0" y1="6" x2="20" y2="6" stroke="#22c55e" stroke-width="2"/></svg> Healthy edge</span>
    <span><svg width="20" height="12"><line x1="0" y1="6" x2="20" y2="6" stroke="#f59e0b" stroke-width="2"/></svg> Degraded</span>
    <span><svg width="20" height="12"><line x1="0" y1="6" x2="20" y2="6" stroke="#ef4444" stroke-width="2"/></svg> Unhealthy</span>
    <span style="margin-left:12px"><svg width="20" height="12"><line x1="0" y1="6" x2="20" y2="6" stroke="#71717a" stroke-width="1" stroke-dasharray="4 3" stroke-opacity="0.5"/></svg> ACL (no traffic)</span>
  </div>
</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
  <div class="card">
    <h2>Node Threat Scores</h2>
    <p style="color:var(--text3);font-size:0.78rem;margin-bottom:12px">Higher scores mean more blocked or quarantined messages originating from this agent.</p>
    {{if .Graph.Nodes}}
    <table>
      <thead><tr><th>Agent</th><th data-tooltip="Score based on ratio of blocked and quarantined messages">Threat</th><th>Sent</th><th>Recv</th><th data-tooltip="How central this agent is in the network — high values mean many paths go through it">Betweenness</th></tr></thead>
      <tbody>
      {{range .Graph.Nodes}}
      <tr class="clickable" onclick="location.href='/dashboard/agents/{{.Name}}'">
        <td style="font-weight:600">{{agentCell .Name}}</td>
        <td>
          <div style="display:flex;align-items:center;gap:8px">
            <div class="risk-bar" style="width:60px">
              <div class="risk-bar-fill {{if gt .ThreatScore 60.0}}risk-high{{else if gt .ThreatScore 30.0}}risk-med{{else}}risk-low{{end}}" style="width:{{printf "%.0f" .ThreatScore}}%"></div>
            </div>
            <span>{{printf "%.1f" .ThreatScore}}</span>
          </div>
        </td>
        <td>{{.TotalSent}}</td>
        <td>{{.TotalRecv}}</td>
        <td>{{if eq .Betweenness -1.0}}—{{else}}{{printf "%.3f" .Betweenness}}{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">No agents detected in the last 24h</p>{{end}}
  </div>

  <div class="card">
    <h2>Edge Health</h2>
    <p style="color:var(--text3);font-size:0.78rem;margin-bottom:12px">Percentage of messages on each connection that were delivered successfully.</p>
    {{if .Graph.Edges}}
    <table>
      <thead><tr><th>From</th><th>To</th><th>Total</th><th data-tooltip="Ratio of delivered messages to total — lower scores indicate more blocked or quarantined traffic">Health</th></tr></thead>
      <tbody>
      {{range .Graph.Edges}}
      <tr class="clickable" hx-get="/dashboard/api/graph/edge?from={{.From}}&amp;to={{.To}}" hx-target="#panel-content" hx-swap="innerHTML">
        <td>{{.From}}</td>
        <td>{{.To}}</td>
        <td>{{.Total}}</td>
        <td>
          <div style="display:flex;align-items:center;gap:8px">
            <div class="risk-bar" style="width:60px">
              <div class="risk-bar-fill {{if lt .HealthScore 40.0}}risk-high{{else if lt .HealthScore 70.0}}risk-med{{else}}risk-low{{end}}" style="width:{{printf "%.0f" .HealthScore}}%"></div>
            </div>
            <span>{{printf "%.0f" .HealthScore}}%</span>
          </div>
        </td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">No traffic in the last 24h</p>{{end}}
  </div>
</div>

{{if .Graph.ShadowEdges}}
<div class="card">
  <h2 style="color:var(--warn)">Shadow Edges</h2>
  <p style="color:var(--text2);font-size:0.82rem;margin-bottom:12px">Traffic between agents not defined in ACL policy. May indicate misconfiguration or unauthorized communication.</p>
  <table>
    <thead><tr><th>From</th><th>To</th><th>Messages</th></tr></thead>
    <tbody>
    {{range .Graph.ShadowEdges}}
    <tr><td>{{.From}}</td><td>{{.To}}</td><td>{{.Total}}</td></tr>
    {{end}}
    </tbody>
  </table>
</div>
{{end}}

{{if .Graph.UnusedACL}}
<div class="card">
  <h2>Unused ACL Permissions</h2>
  <p style="color:var(--text2);font-size:0.82rem;margin-bottom:12px">ACL entries with no observed traffic. Consider tightening permissions.</p>
  <table>
    <thead><tr><th>From</th><th>To</th><th>Status</th></tr></thead>
    <tbody>
    {{range .Graph.UnusedACL}}
    <tr><td>{{.From}}</td><td>{{.To}}</td><td><span style="color:var(--text3)">no traffic</span></td></tr>
    {{end}}
    </tbody>
  </table>
</div>
{{end}}

<script>
(function() {
  var container = document.getElementById('graph-container');
  if (!container) return;

  fetch('/dashboard/api/graph')
    .then(function(r) { return r.json(); })
    .then(function(data) { renderGraph(container, data); });

  function renderGraph(el, data) {
    if (!data.nodes || data.nodes.length === 0) {
      el.innerHTML = '<p style="color:var(--text3);text-align:center;padding-top:200px">No graph data available</p>';
      return;
    }

    var W = el.clientWidth, H = el.clientHeight;
    var NR = 18; // node radius
    var PAD = 60;
    var nodes = data.nodes.map(function(n) {
      return {name: n.name, threat: n.threat_score, sent: n.total_sent||0, recv: n.total_recv||0, betweenness: n.betweenness!=null?n.betweenness:-1, x: PAD + Math.random()*(W-2*PAD), y: PAD + Math.random()*(H-2*PAD), vx: 0, vy: 0};
    });
    var nodeIdx = {};
    nodes.forEach(function(n, i) { nodeIdx[n.name] = i; });

    var links = (data.edges || []).filter(function(e) {
      return nodeIdx[e.from] !== undefined && nodeIdx[e.to] !== undefined;
    }).map(function(e) {
      return {from: nodeIdx[e.from], to: nodeIdx[e.to], health: e.health_score, total: e.total, fromName: e.from, toName: e.to};
    });

    // ACL edges — policy connections (shown as dashed lines)
    var trafficSet = {};
    links.forEach(function(e) { trafficSet[e.fromName+'>'+e.toName] = true; });
    var aclLinks = (data.acl_edges || []).filter(function(e) {
      return nodeIdx[e.from] !== undefined && nodeIdx[e.to] !== undefined && !trafficSet[e.from+'>'+e.to];
    }).map(function(e) {
      return {from: nodeIdx[e.from], to: nodeIdx[e.to], fromName: e.from, toName: e.to};
    });

    // All connections for layout (traffic + ACL)
    var allLinks = links.concat(aclLinks);

    // Fruchterman-Reingold layout
    var k = Math.sqrt(W * H / Math.max(nodes.length, 1)) * 0.9;
    var temp = W / 3;
    for (var iter = 0; iter < 150; iter++) {
      for (var i = 0; i < nodes.length; i++) {
        nodes[i].vx = 0; nodes[i].vy = 0;
        for (var j = 0; j < nodes.length; j++) {
          if (i === j) continue;
          var dx = nodes[i].x - nodes[j].x, dy = nodes[i].y - nodes[j].y;
          var dist = Math.sqrt(dx*dx + dy*dy) || 1;
          var f = (k * k) / dist;
          nodes[i].vx += (dx / dist) * f;
          nodes[i].vy += (dy / dist) * f;
        }
      }
      for (var e = 0; e < allLinks.length; e++) {
        var s = nodes[allLinks[e].from], t = nodes[allLinks[e].to];
        var dx = t.x - s.x, dy = t.y - s.y;
        var dist = Math.sqrt(dx*dx + dy*dy) || 1;
        var f = (dist * dist) / k;
        var fx = (dx / dist) * f, fy = (dy / dist) * f;
        s.vx += fx; s.vy += fy;
        t.vx -= fx; t.vy -= fy;
      }
      for (var i = 0; i < nodes.length; i++) {
        var d = Math.sqrt(nodes[i].vx*nodes[i].vx + nodes[i].vy*nodes[i].vy) || 1;
        var c = Math.min(d, temp);
        nodes[i].x += (nodes[i].vx / d) * c;
        nodes[i].y += (nodes[i].vy / d) * c;
        nodes[i].x = Math.max(PAD, Math.min(W-PAD, nodes[i].x));
        nodes[i].y = Math.max(PAD, Math.min(H-PAD, nodes[i].y));
      }
      temp *= 0.95;
    }

    // Build SVG
    var NS = 'http://www.w3.org/2000/svg';
    var svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('width', W); svg.setAttribute('height', H);
    svg.setAttribute('viewBox', '0 0 '+W+' '+H);
    svg.style.width = '100%'; svg.style.height = '100%';

    // Arrow markers — smaller, refined
    var defs = document.createElementNS(NS, 'defs');
    var edgeColors = {ok:'#4ade80', warn:'#fbbf24', bad:'#f87171'};
    ['ok','warn','bad'].forEach(function(k) {
      var m = document.createElementNS(NS, 'marker');
      m.setAttribute('id', 'arr-'+k); m.setAttribute('viewBox', '0 0 8 6');
      m.setAttribute('refX', '8'); m.setAttribute('refY', '3');
      m.setAttribute('markerWidth', '6'); m.setAttribute('markerHeight', '5');
      m.setAttribute('orient', 'auto');
      var p = document.createElementNS(NS, 'path');
      p.setAttribute('d', 'M0,0.5 L7,3 L0,5.5'); p.setAttribute('fill', edgeColors[k]);
      m.appendChild(p); defs.appendChild(m);
    });
    // ACL arrow marker (dim)
    var mAcl = document.createElementNS(NS, 'marker');
    mAcl.setAttribute('id', 'arr-acl'); mAcl.setAttribute('viewBox', '0 0 8 6');
    mAcl.setAttribute('refX', '8'); mAcl.setAttribute('refY', '3');
    mAcl.setAttribute('markerWidth', '5'); mAcl.setAttribute('markerHeight', '4');
    mAcl.setAttribute('orient', 'auto');
    var pAcl = document.createElementNS(NS, 'path');
    pAcl.setAttribute('d', 'M0,0.5 L7,3 L0,5.5'); pAcl.setAttribute('fill', '#71717a');
    mAcl.appendChild(pAcl); defs.appendChild(mAcl);
    svg.appendChild(defs);

    var lineEls = [];

    // Draw ACL edges — dashed lines showing policy connections
    aclLinks.forEach(function(e) {
      var s = nodes[e.from], t = nodes[e.to];
      var dx = t.x - s.x, dy = t.y - s.y;
      var dist = Math.sqrt(dx*dx + dy*dy) || 1;
      var ex = t.x - (dx/dist)*(NR+6), ey = t.y - (dy/dist)*(NR+6);
      var el = document.createElementNS(NS, 'line');
      el.setAttribute('x1', s.x); el.setAttribute('y1', s.y);
      el.setAttribute('x2', ex); el.setAttribute('y2', ey);
      el.setAttribute('stroke', '#71717a');
      el.setAttribute('stroke-width', '1');
      el.setAttribute('stroke-opacity', '0.25');
      el.setAttribute('stroke-dasharray', '4 3');
      el.setAttribute('marker-end', 'url(#arr-acl)');
      svg.appendChild(el);
      lineEls.push({el: el, link: e, curved: false});
    });

    // Draw traffic edges — curved paths for parallel edges
    var edgePairs = {};
    links.forEach(function(e) {
      var key = Math.min(e.from,e.to)+'-'+Math.max(e.from,e.to);
      edgePairs[key] = (edgePairs[key]||0)+1;
    });
    var edgePairCount = {};
    var particles = [];
    links.forEach(function(e) {
      var hk = e.health >= 70 ? 'ok' : (e.health >= 40 ? 'warn' : 'bad');

      // Offset for parallel edges
      var key = Math.min(e.from,e.to)+'-'+Math.max(e.from,e.to);
      var pairTotal = edgePairs[key]||1;
      edgePairCount[key] = (edgePairCount[key]||0)+1;
      var co = 0;
      if (pairTotal > 1) co = (edgePairCount[key]%2===0?1:-1) * 20;

      var el;
      if (co !== 0) {
        el = document.createElementNS(NS, 'path');
        el.setAttribute('fill', 'none');
      } else {
        el = document.createElementNS(NS, 'line');
      }
      el.setAttribute('stroke', edgeColors[hk]);
      el.setAttribute('stroke-width', '1.5');
      el.setAttribute('stroke-opacity', '0.5');
      el.setAttribute('marker-end', 'url(#arr-'+hk+')');
      el.style.cursor = 'pointer';
      el.addEventListener('click', function() {
        htmx.ajax('GET', '/dashboard/api/graph/edge?from='+encodeURIComponent(e.fromName)+'&to='+encodeURIComponent(e.toName), {target:'#panel-content', swap:'innerHTML'});
      });
      el.addEventListener('mouseenter', function(){ this.setAttribute('stroke-opacity','0.9'); this.setAttribute('stroke-width','2.5'); });
      el.addEventListener('mouseleave', function(){ this.setAttribute('stroke-opacity','0.5'); this.setAttribute('stroke-width','1.5'); });
      svg.appendChild(el);

      // Particle dot — position computed in animation loop
      var dot = document.createElementNS(NS, 'circle');
      dot.setAttribute('r', '2.5');
      dot.setAttribute('fill', edgeColors[hk]);
      dot.setAttribute('opacity', '0.8');
      svg.appendChild(dot);
      particles.push({dot: dot, link: e, co: co, t: Math.random(), speed: 0.003 + Math.random()*0.004});

      lineEls.push({el: el, link: e, curved: co!==0, co: co});
    });

    // Helper: compute edge endpoints from live node positions
    function edgeEndpoints(le) {
      var s = nodes[le.link.from], t = nodes[le.link.to];
      var dx = t.x - s.x, dy = t.y - s.y, d = Math.sqrt(dx*dx+dy*dy)||1;
      var ex = t.x-(dx/d)*(NR+6), ey = t.y-(dy/d)*(NR+6);
      return {sx:s.x, sy:s.y, ex:ex, ey:ey, dx:dx, dy:dy, d:d};
    }

    // Initial edge positions
    function updateEdges() {
      lineEls.forEach(function(le) {
        var ep = edgeEndpoints(le);
        if (le.curved) {
          var mx = (ep.sx+ep.ex)/2 + (-ep.dy/ep.d)*le.co;
          var my = (ep.sy+ep.ey)/2 + (ep.dx/ep.d)*le.co;
          le.el.setAttribute('d', 'M'+ep.sx+','+ep.sy+' Q'+mx+','+my+' '+ep.ex+','+ep.ey);
        } else {
          le.el.setAttribute('x1', ep.sx); le.el.setAttribute('y1', ep.sy);
          le.el.setAttribute('x2', ep.ex); le.el.setAttribute('y2', ep.ey);
        }
      });
    }
    updateEdges();

    // Particle animation loop — reads live node positions
    function animParticles() {
      particles.forEach(function(p) {
        p.t += p.speed;
        if (p.t > 1) p.t -= 1;
        var s = nodes[p.link.from], t = nodes[p.link.to];
        var dx = t.x-s.x, dy = t.y-s.y, d = Math.sqrt(dx*dx+dy*dy)||1;
        var ex = t.x-(dx/d)*(NR+6), ey = t.y-(dy/d)*(NR+6);
        var tt = p.t, x, y;
        if (p.co !== 0) {
          var mx = (s.x+ex)/2+(-dy/d)*p.co, my = (s.y+ey)/2+(dx/d)*p.co;
          var u = 1-tt;
          x = u*u*s.x + 2*u*tt*mx + tt*tt*ex;
          y = u*u*s.y + 2*u*tt*my + tt*tt*ey;
        } else {
          x = s.x + (ex-s.x)*tt;
          y = s.y + (ey-s.y)*tt;
        }
        p.dot.setAttribute('cx', x);
        p.dot.setAttribute('cy', y);
      });
      requestAnimationFrame(animParticles);
    }
    requestAnimationFrame(animParticles);

    // Inline popover for node click
    var popover = document.createElement('div');
    popover.style.cssText = 'position:absolute;display:none;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 16px;min-width:200px;z-index:10;box-shadow:0 8px 24px rgba(0,0,0,0.5);font-family:var(--sans);pointer-events:auto';
    el.appendChild(popover);
    var activePopNode = null;

    function showPopover(n) {
      if (activePopNode === n.name) { popover.style.display='none'; activePopNode=null; return; }
      activePopNode = n.name;
      var threatLbl = n.threat > 60 ? 'High' : (n.threat > 30 ? 'Medium' : 'Low');
      var threatClr = n.threat > 60 ? '#f87171' : (n.threat > 30 ? '#fbbf24' : '#4ade80');
      popover.innerHTML =
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">'+agentCellHTML(n.name)+'</div>'+
        '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px 16px;font-size:0.75rem;margin-bottom:12px">'+
          '<div><span style="color:var(--text3)">Threat</span><div style="font-weight:700;color:'+threatClr+';font-family:var(--mono)">'+n.threat.toFixed(1)+' '+threatLbl+'</div></div>'+
          '<div><span style="color:var(--text3)">Betweenness</span><div style="font-weight:600;font-family:var(--mono)">'+(n.betweenness>=0?n.betweenness.toFixed(3):'\u2014')+'</div></div>'+
          '<div><span style="color:var(--text3)">Sent</span><div style="font-weight:600;font-family:var(--mono)">'+n.sent+'</div></div>'+
          '<div><span style="color:var(--text3)">Received</span><div style="font-weight:600;font-family:var(--mono)">'+n.recv+'</div></div>'+
        '</div>'+
        '<a href="/dashboard/agents/'+encodeURIComponent(n.name)+'" style="display:block;text-align:center;padding:6px 14px;background:var(--surface2);border:1px solid var(--border);color:var(--text2);border-radius:6px;font-size:0.75rem;font-weight:500;text-decoration:none;transition:all 0.15s" onmouseover="this.style.borderColor=\'var(--accent)\';this.style.color=\'var(--text)\'" onmouseout="this.style.borderColor=\'var(--border)\';this.style.color=\'var(--text2)\'">View Profile &rarr;</a>';
      // Position: above node, centered
      var px = n.x - 100, py = n.y - NR - 160;
      if (py < 8) py = n.y + NR + 20; // flip below if too close to top
      if (px < 8) px = 8;
      if (px + 200 > W) px = W - 208;
      popover.style.left = px+'px'; popover.style.top = py+'px';
      popover.style.display = 'block';
    }

    // Close popover on background click
    svg.addEventListener('click', function(ev) {
      if (ev.target === svg) { popover.style.display='none'; activePopNode=null; }
    });

    // Draw nodes — avatar circle + label below
    nodes.forEach(function(n, i) {
      var g = document.createElementNS(NS, 'g');
      g.style.cursor = 'pointer';

      // Threat-based ring color
      var ringColor = n.threat > 60 ? '#f87171' : (n.threat > 30 ? '#fbbf24' : '#4ade80');

      // Outer ring (threat indicator)
      var ring = document.createElementNS(NS, 'circle');
      ring.setAttribute('cx', n.x); ring.setAttribute('cy', n.y); ring.setAttribute('r', NR+2);
      ring.setAttribute('fill', 'none');
      ring.setAttribute('stroke', ringColor); ring.setAttribute('stroke-width', '1.5');
      ring.setAttribute('stroke-opacity', '0.6');

      // Avatar as foreignObject
      var fo = document.createElementNS(NS, 'foreignObject');
      fo.setAttribute('x', n.x-NR); fo.setAttribute('y', n.y-NR);
      fo.setAttribute('width', NR*2); fo.setAttribute('height', NR*2);
      var avDiv = document.createElement('div');
      avDiv.innerHTML = agentAvatar(n.name, NR*2);
      fo.appendChild(avDiv);

      // Label below node
      var label = document.createElementNS(NS, 'text');
      label.setAttribute('x', n.x); label.setAttribute('y', n.y + NR + 14);
      label.setAttribute('text-anchor', 'middle'); label.setAttribute('fill', '#a1a1aa');
      label.setAttribute('font-size', '10'); label.setAttribute('font-family', '-apple-system, BlinkMacSystemFont, sans-serif');
      label.textContent = n.name;

      g.appendChild(ring); g.appendChild(fo); g.appendChild(label);

      // Click: show inline popover (not panel)
      var didDrag = false;
      g.addEventListener('click', function(ev) {
        ev.stopPropagation();
        if (didDrag) { didDrag = false; return; }
        showPopover(n);
      });

      // Drag support
      var dragging = false, startX, startY;
      fo.addEventListener('mousedown', function(ev) { dragging = true; startX = ev.clientX; startY = ev.clientY; ev.preventDefault(); });
      svg.addEventListener('mousemove', function(ev) {
        if (!dragging) return;
        didDrag = true;
        popover.style.display = 'none'; activePopNode = null;
        var rect = svg.getBoundingClientRect();
        n.x = ev.clientX - rect.left; n.y = ev.clientY - rect.top;
        ring.setAttribute('cx', n.x); ring.setAttribute('cy', n.y);
        fo.setAttribute('x', n.x-NR); fo.setAttribute('y', n.y-NR);
        label.setAttribute('x', n.x); label.setAttribute('y', n.y + NR + 14);
        updateEdges();
      });
      svg.addEventListener('mouseup', function() {
        if (dragging && !didDrag) didDrag = false;
        dragging = false;
      });

      svg.appendChild(g);
    });

    el.appendChild(svg);
  }
})();
</script>
` + layoutFoot))

var edgeDetailTmpl = template.Must(template.New("edge-detail").Funcs(tmplFuncs).Parse(`
<div class="panel-header">
  <h3><span class="agent-cell">{{avatar .From 20}} {{.From}}</span> &rarr; <span class="agent-cell">{{avatar .To 20}} {{.To}}</span></h3>
  <button class="panel-close" onclick="closePanel()">&times;</button>
</div>
<div class="panel-body">
  {{if .Rules}}
  <div class="field">
    <div class="field-label">Top Triggered Rules</div>
    <table style="margin-top:8px">
      <thead><tr><th>Rule</th><th>Severity</th><th>Count</th></tr></thead>
      <tbody>
      {{range .Rules}}
      <tr>
        <td><span style="font-weight:600">{{.RuleID}}</span><br><span style="color:var(--text3);font-size:0.72rem">{{.Name}}</span></td>
        <td><span class="sev-{{.Severity}}">{{.Severity}}</span></td>
        <td>{{.Count}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
  </div>
  {{else}}
  <div class="field">
    <div class="field-label">Rules</div>
    <p style="color:var(--text3);font-size:0.82rem">No rules triggered on this edge</p>
  </div>
  {{end}}

  {{if .Entries}}
  <div class="field" style="margin-top:20px">
    <div class="field-label">Recent Messages</div>
    <table style="margin-top:8px">
      <thead><tr><th>Time</th><th>Status</th></tr></thead>
      <tbody>
      {{range .Entries}}
      <tr>
        <td data-ts="{{.Timestamp}}">{{.Timestamp}}</td>
        <td><span class="badge-{{.Status}}">{{.Status}}</span></td>
      </tr>
      {{end}}
      </tbody>
    </table>
  </div>
  {{end}}
</div>
`))

