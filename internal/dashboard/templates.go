package dashboard

import (
	"encoding/json"
	"fmt"
	"html/template"
	"strconv"
	"strings"
	"time"
)

// snakeToTitle converts snake_case to Title Case.
func snakeToTitle(s string) string {
	words := strings.Split(s, "_")
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

// kebabToTitle converts kebab-case to Title Case.
func kebabToTitle(s string) string {
	words := strings.FieldsFunc(s, func(r rune) bool { return r == '-' || r == '_' })
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

func toFloat64(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	default:
		return 0
	}
}

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
	"formatNum": func(n int) string {
		if n < 1000 {
			return strconv.Itoa(n)
		}
		s := strconv.Itoa(n)
		var b strings.Builder
		for i, c := range s {
			if i > 0 && (len(s)-i)%3 == 0 {
				b.WriteByte(',')
			}
			b.WriteRune(c)
		}
		return b.String()
	},
	"toolDot": func(toolName string) template.HTML {
		colors := map[string]string{
			"Bash": "#d29922", "Write": "#c084fc", "Edit": "#818cf8",
			"Read": "#22d3ee", "Glob": "#2dd4bf", "Grep": "#2dd4bf",
			"WebFetch": "#f472b6", "WebSearch": "#f472b6", "Agent": "#a78bfa",
		}
		c := "#6e7681"
		if v, ok := colors[toolName]; ok {
			c = v
		}
		return template.HTML(fmt.Sprintf(`<span style="display:inline-flex;align-items:center;gap:5px"><span style="width:6px;height:6px;border-radius:50%%;background:%s;flex-shrink:0"></span>%s</span>`, c, template.HTMLEscapeString(toolName)))
	},
	"hasRules": func(s string) bool { return s != "" && s != "[]" && s != "null" },
	"pageTitle": func(active string) string {
		titles := map[string]string{
			"events":    "Events",
			"audit":     "Security Posture",
			"llm":       "AI Analysis",
			"discovery": "Discovery",
			"overview":  "Overview",
			"agents":    "Agents",
			"rules":     "Rules",
			"graph":     "Graph",
			"gateway":   "Gateway",
			"settings":  "Settings",
			"alerts":    "Webhooks",
		}
		if t, ok := titles[active]; ok {
			return strings.ToUpper(t)
		}
		return strings.ToUpper(active)
	},
	"inSlice": func(item string, list []string) bool {
		for _, s := range list {
			if s == item {
				return true
			}
		}
		return false
	},
	"lower": strings.ToLower,
	"inc": func(i int) int { return i + 1 },
	"divf": func(a, b any) float64 {
		fb := toFloat64(b)
		if fb == 0 {
			return 0
		}
		return toFloat64(a) / fb
	},
	"mulf": func(a, b any) float64 { return toFloat64(a) * toFloat64(b) },
	"toFloat": func(v any) float64 {
		switch n := v.(type) {
		case float64:
			return n
		case float32:
			return float64(n)
		case int:
			return float64(n)
		case int64:
			return float64(n)
		case json.Number:
			f, _ := n.Float64()
			return f
		default:
			return 0
		}
	},
	"add":    func(a, b int) int { return a + b },
	"safeJS":   func(s string) template.JS { return template.JS(s) },
	"contains": strings.Contains,
	"printf":   fmt.Sprintf,
	"snakeToTitle": snakeToTitle,
	"kebabToTitle": kebabToTitle,
	"truncTS": func(ts string) string {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			return t.Format("Jan 02 15:04")
		}
		if len(ts) > 16 {
			return ts[:16]
		}
		return ts
	},
	"toMap": func(v any) map[string]any {
		if m, ok := v.(map[string]any); ok {
			return m
		}
		return nil
	},
	"toString": func(v any) string {
		if v == nil {
			return ""
		}
		return fmt.Sprintf("%v", v)
	},
	"parseJSONMap": func(s string) map[string]any {
		s = strings.TrimSpace(s)
		if s == "" || s == "{}" || s == "null" {
			return nil
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			return nil
		}
		return m
	},
	"parseJSONArray": func(s string) []any {
		s = strings.TrimSpace(s)
		if s == "" || s == "[]" || s == "null" {
			return nil
		}
		var arr []any
		if err := json.Unmarshal([]byte(s), &arr); err != nil {
			return nil
		}
		return arr
	},
	"countJSONArray": func(s string) int {
		s = strings.TrimSpace(s)
		if s == "" || s == "[]" || s == "null" {
			return 0
		}
		var arr []any
		if err := json.Unmarshal([]byte(s), &arr); err != nil {
			return 0
		}
		return len(arr)
	},
	"latencySec": func(ms int64) string {
		return fmt.Sprintf("%.1f", float64(ms)/1000.0)
	},
	"relativeTime": func(ts string) string {
		layouts := []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02 15:04:05"}
		var t time.Time
		var err error
		for _, l := range layouts {
			t, err = time.Parse(l, ts)
			if err == nil {
				break
			}
		}
		if err != nil {
			return ts
		}
		d := time.Since(t)
		switch {
		case d < time.Minute:
			return "just now"
		case d < time.Hour:
			return fmt.Sprintf("%dm ago", int(d.Minutes()))
		case d < 24*time.Hour:
			return fmt.Sprintf("%dh ago", int(d.Hours()))
		default:
			return fmt.Sprintf("%dd ago", int(d.Hours()/24))
		}
	},
	"fullThreatSummary": func(threatsJSON string, riskScore float64) string {
		if threatsJSON == "" || threatsJSON == "null" || threatsJSON == "[]" {
			if riskScore > 10 {
				return "Elevated risk — review recommended"
			}
			return "No threats detected"
		}
		var threats []map[string]any
		if err := json.Unmarshal([]byte(threatsJSON), &threats); err != nil || len(threats) == 0 {
			return "Threat detected"
		}
		t := threats[0]
		if desc, _ := t["description"].(string); desc != "" {
			return desc
		}
		if typ, _ := t["type"].(string); typ != "" {
			return snakeToTitle(typ)
		}
		return "Threat detected"
	},
	"firstThreatSummary": func(threatsJSON string, riskScore float64) string {
		if threatsJSON == "" || threatsJSON == "null" || threatsJSON == "[]" {
			if riskScore > 10 {
				return "Elevated risk — review recommended"
			}
			return "No threats detected"
		}
		var threats []map[string]any
		if err := json.Unmarshal([]byte(threatsJSON), &threats); err != nil || len(threats) == 0 {
			return "Threat detected"
		}
		t := threats[0]
		desc, _ := t["description"].(string)
		typ, _ := t["type"].(string)
		if desc != "" {
			if len(desc) > 90 {
				desc = desc[:87] + "..."
			}
			return desc
		}
		if typ != "" {
			return snakeToTitle(typ)
		}
		return "Threat detected"
	},
}

var loginTmpl = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>oktsec — dashboard</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%236366f1' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'/%3E%3Cpath d='M9 12l2 2 4-4'/%3E%3C/svg%3E">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2128;--border:#30363d;
  --text:#e6edf3;--text2:#8b949e;--text3:#6e7681;
  --accent:#6366f1;--accent-light:#818cf8;--accent-dim:#4f46e5;
  --danger:#f85149;--success:#3fb950;--warn:#d29922;
  --mono:ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,'Liberation Mono',monospace;
  --sans:'Inter',system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans',Helvetica,Arial,sans-serif;
}
@font-face{font-family:'Inter';src:url('/dashboard/static/fonts/Inter.woff2') format('woff2');font-weight:100 900;font-style:normal;font-display:swap}
@keyframes fadeIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
body{font-family:var(--sans);background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;-webkit-font-smoothing:antialiased}
.backdrop{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);width:600px;height:600px;background:radial-gradient(circle,rgba(99,102,241,0.06) 0%,transparent 70%);pointer-events:none;z-index:0}
.login-card{position:relative;z-index:1;background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:48px 40px;max-width:400px;width:100%;text-align:center;box-shadow:0 4px 24px rgba(0,0,0,0.4);animation:fadeIn 0.4s ease-out}
.icon{margin-bottom:20px}
.icon svg{width:48px;height:48px;color:var(--accent)}
.logo{font-family:var(--mono);font-size:1.5rem;font-weight:700;letter-spacing:-0.3px;margin-bottom:8px;color:var(--text)}
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
button:hover{background:var(--accent-light);box-shadow:0 0 24px rgba(99,102,241,0.35)}
button:active{transform:scale(0.98)}
.error{display:flex;align-items:center;gap:8px;justify-content:center;margin-top:14px;padding:10px 14px;background:rgba(248,81,73,0.1);border:1px solid rgba(248,81,73,0.2);border-radius:8px;color:var(--danger);font-size:0.82rem}
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
  <p class="help">Enter the access code shown in your terminal.<br>Run <code>oktsec run</code> to get a code.<br><small style="opacity:0.5">Code changes each time the server restarts.</small></p>
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
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%236366f1' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'/%3E%3Cpath d='M9 12l2 2 4-4'/%3E%3C/svg%3E">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#0d1117;--surface:#161b22;--border:#30363d;
  --text:#e6edf3;--text2:#8b949e;--text3:#6e7681;
  --accent:#6366f1;--accent-light:#818cf8;--accent-dim:#4f46e5;
  --mono:ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,'Liberation Mono',monospace;
  --sans:'Inter',system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans',Helvetica,Arial,sans-serif;
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
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%236366f1' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'/%3E%3Cpath d='M9 12l2 2 4-4'/%3E%3C/svg%3E">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2128;--border:#30363d;
  --text:#e6edf3;--text2:#8b949e;--text3:#6e7681;
  --accent:#6366f1;--accent-light:#818cf8;--accent-dim:#4f46e5;
  --mono:ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,'Liberation Mono',monospace;
  --sans:'Inter',system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans',Helvetica,Arial,sans-serif;
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
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%236366f1' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'/%3E%3Cpath d='M9 12l2 2 4-4'/%3E%3C/svg%3E">
<script src="/dashboard/static/htmx.min.js"></script>
<link rel="stylesheet" href="/dashboard/static/dashboard.css">
</head>
<body>
<aside class="sidebar">
  <a href="/dashboard" class="brand">oktsec</a>
  <div class="sidebar-section">
    <div class="sidebar-section-label">Monitor</div>
    <a href="/dashboard" class="sidebar-item {{if eq .Active "overview"}}active{{end}}">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>
      Overview
    </a>
    <a href="/dashboard/events" class="sidebar-item {{if eq .Active "events"}}active{{end}}">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>
      Events
    </a>
    <a href="/dashboard/alerts" class="sidebar-item {{if eq .Active "alerts"}}active{{end}}">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
      Webhooks
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
      Security Posture
    </a>
  </div>
  <div class="sidebar-section">
    <div class="sidebar-section-label">Analyze</div>
    <a href="/dashboard/llm" class="sidebar-item {{if eq .Active "llm"}}active{{end}}">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2a4 4 0 0 1 4 4v2a4 4 0 0 1-8 0V6a4 4 0 0 1 4-4z"/><path d="M16 14H8a4 4 0 0 0-4 4v2h16v-2a4 4 0 0 0-4-4z"/><circle cx="12" cy="6" r="1"/><path d="M9 22v-2"/><path d="M15 22v-2"/></svg>
      AI Analysis
    </a>
    <a href="/dashboard/graph" class="sidebar-item {{if eq .Active "graph"}}active{{end}}">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
      Graph
    </a>
  </div>
  <div class="sidebar-section">
    <div class="sidebar-section-label">Configure</div>
    <a href="/dashboard/gateway" class="sidebar-item {{if eq .Active "gateway"}}active{{end}}">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="1" y="4" width="22" height="16" rx="2" ry="2"/><line x1="1" y1="10" x2="23" y2="10"/><line x1="12" y1="4" x2="12" y2="20"/></svg>
      Gateway
    </a>
    <a href="/dashboard/settings" class="sidebar-item {{if eq .Active "settings"}}active{{end}}">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
      Settings
    </a>
  </div>
</aside>
<div class="sidebar-overlay" onclick="toggleSidebar()"></div>
<div class="topbar">
  <button class="hamburger" onclick="toggleSidebar()" aria-label="Toggle menu">
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
  </button>
  <span class="page-title">{{pageTitle .Active}}</span>
  <div class="spacer"></div>
  <a href="/dashboard/settings?tab=security" class="mode-pill {{if .RequireSig}}enforce{{else}}observe{{end}}" data-tooltip="{{if .RequireSig}}Enforce mode — signatures required, unsigned messages rejected{{else}}Observe mode — scanning active, signatures optional. Click to configure.{{end}}"><span class="dot"></span>{{if .RequireSig}}enforce{{else}}observe{{end}}</a>
  <form method="POST" action="/dashboard/logout" style="margin-left:10px;display:inline"><button type="submit" class="topbar-logout">Logout</button></form>
</div>
<main>`

const layoutFoot = `</main>

<!-- Slide-in panel -->
<div class="panel-overlay" id="panel-overlay" onclick="closePanel()"></div>
<div class="panel" id="detail-panel">
  <div id="panel-loading" class="htmx-indicator" style="text-align:center;padding:40px"><span class="loading-spinner" style="width:24px;height:24px"></span></div>
  <div id="panel-content"></div>
</div>

<script>
function toggleSidebar() {
  document.querySelector('.sidebar').classList.toggle('mobile-open');
  document.querySelector('.sidebar-overlay').classList.toggle('open');
}

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

// HTMX: show loading spinner when panel requests start
document.body.addEventListener('htmx:beforeRequest', function(e) {
  if (e.detail.target && e.detail.target.id === 'panel-content') {
    document.getElementById('panel-loading').style.display='block';
    document.getElementById('panel-content').innerHTML='';
    document.getElementById('detail-panel').classList.add('open');
    document.getElementById('panel-overlay').classList.add('open');
  }
});
// HTMX: when a panel response arrives, open the panel
document.body.addEventListener('htmx:afterSwap', function(e) {
  if (e.detail.target.id === 'panel-content') {
    document.getElementById('panel-loading').style.display='none';
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

// Custom confirm modal (replaces ALL confirm dialogs)
(function(){
  var overlay=document.createElement('div');
  overlay.className='modal-overlay';
  overlay.innerHTML='<div class="modal"><div class="modal-title">Confirm</div><div class="modal-msg" id="modal-msg"></div><div class="modal-actions"><button class="btn btn-outline" id="modal-cancel">Cancel</button><button class="btn" id="modal-ok">Confirm</button></div></div>';
  document.body.appendChild(overlay);
  var pendingResolve=null;
  function closeModal(result){overlay.classList.remove('open');if(pendingResolve){pendingResolve(result);pendingResolve=null;}}
  document.getElementById('modal-cancel').onclick=function(){closeModal(false)};
  overlay.onclick=function(e){if(e.target===overlay)closeModal(false)};
  document.addEventListener('keydown',function(e){if(e.key==='Escape'&&overlay.classList.contains('open'))closeModal(false)});
  document.getElementById('modal-ok').onclick=function(){closeModal(true)};
  function showModal(msg){
    document.getElementById('modal-msg').textContent=msg;
    var isDestructive=msg.toLowerCase().indexOf('delete')>-1||msg.toLowerCase().indexOf('suspend')>-1||msg.toLowerCase().indexOf('revoke')>-1;
    var okBtn=document.getElementById('modal-ok');
    okBtn.className=isDestructive?'btn btn-danger':'btn';
    okBtn.textContent=isDestructive?'Confirm':'OK';
    overlay.classList.add('open');
    return new Promise(function(resolve){pendingResolve=resolve});
  }
  // Override native window.confirm
  window.confirm=function(msg){
    // For sync callers (onclick="return confirm()"), we can't use Promise.
    // Instead, prevent the default form submit and re-submit after confirmation.
    return false; // block by default; the click handler below handles it
  };
  // Intercept clicks on elements with onclick="return confirm(...)"
  document.addEventListener('click',function(e){
    var btn=e.target.closest('[onclick*="confirm("]');
    if(!btn)return;
    var match=btn.getAttribute('onclick').match(/confirm\(['"](.+?)['"]\)/);
    if(!match)return;
    e.preventDefault();e.stopPropagation();
    showModal(match[1]).then(function(ok){
      if(!ok)return;
      // Remove the confirm onclick and re-click
      var orig=btn.getAttribute('onclick');
      btn.setAttribute('onclick','');
      btn.click();
      btn.setAttribute('onclick',orig);
    });
  },true);
  // HTMX confirm intercept
  document.body.addEventListener('htmx:confirm',function(e){
    var msg=e.detail.question;
    if(!msg)return;
    e.preventDefault();
    showModal(msg).then(function(ok){
      if(ok){e.detail.issueRequest=true;htmx.trigger(e.detail.elt,'confirmed');}
    });
  });
})();

// Toast notification system
(function(){
  var container=document.createElement('div');
  container.className='toast-container';
  document.body.appendChild(container);
  window.showToast=function(msg,type){
    type=type||'success';
    var t=document.createElement('div');
    t.className='toast '+type;
    var icon=type==='success'?'&#10003;':'&#10007;';
    t.innerHTML='<span class="toast-icon">'+icon+'</span><span class="toast-msg">'+msg+'</span>';
    container.appendChild(t);
    setTimeout(function(){t.classList.add('hiding');setTimeout(function(){t.remove()},200)},3000);
  };
  // Auto-show toast on HTMX successful actions
  document.body.addEventListener('htmx:afterRequest',function(e){
    var t=e.detail.target;
    if(e.detail.successful&&e.detail.requestConfig&&e.detail.requestConfig.verb==='post'){
      var path=e.detail.requestConfig.path||'';
      if(path.indexOf('/approve')>-1)showToast('Approved successfully');
      else if(path.indexOf('/reject')>-1)showToast('Rejected');
      else if(path.indexOf('/dismiss')>-1)showToast('Dismissed as false positive');
      else if(path.indexOf('/confirm')>-1)showToast('Confirmed as threat','error');
      else if(path.indexOf('/toggle')>-1)showToast('Updated');
      else if(path.indexOf('/suspend')>-1)showToast('Agent status updated');
    }
  });
})();
</script>
</body>
</html>`

var overviewTmpl = template.Must(template.New("overview").Funcs(tmplFuncs).Parse(layoutHead + `
<style>
.hero-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--border);border:1px solid var(--border);border-radius:var(--radius-xl);overflow:hidden;margin-bottom:var(--sp-6)}
.hero-stat{background:var(--surface2);padding:var(--sp-6) var(--sp-5);text-align:center;transition:background var(--ease-smooth);position:relative}
.hero-stat::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--accent-dim),var(--accent-light));opacity:0;transition:opacity var(--ease-smooth)}
.hero-stat:hover{background:var(--surface2)}
.hero-stat:hover::before{opacity:1}
.hero-stat .num{font-size:var(--text-3xl);font-weight:800;letter-spacing:-0.04em;font-family:var(--sans);line-height:1}
.hero-stat .lbl{font-size:var(--text-xs);text-transform:uppercase;letter-spacing:var(--ls-caps);color:var(--text3);margin-top:var(--sp-2);font-weight:500}
.ov-grid{display:grid;grid-template-columns:1fr 1fr;gap:var(--sp-4);margin-bottom:var(--sp-4)}
.ov-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-xl);padding:var(--sp-5);transition:all var(--ease-smooth)}
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
.pipeline-stages{display:flex;flex-wrap:wrap;gap:var(--sp-2) var(--sp-4);margin-bottom:var(--sp-4)}
.pipeline-stage{display:flex;align-items:center;gap:6px;font-size:var(--text-sm);color:var(--text2)}
.pipeline-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.pipeline-dot.active{background:var(--success)}
.pipeline-dot.inactive{background:var(--text3);opacity:0.4}
.pipeline-summary{font-size:var(--text-sm);color:var(--text3);padding-top:var(--sp-3);border-top:1px solid var(--border)}
.sparkline-wrap{padding:var(--sp-2) 0}
.sparkline-chart{display:flex;align-items:flex-end;gap:2px;height:48px}
.sparkline-bar{flex:1;background:var(--accent);border-radius:1px 1px 0 0;min-width:3px;transition:background var(--ease-smooth)}
.sparkline-bar:hover{background:var(--accent-light)}
.empty-state{text-align:center;padding:var(--sp-16) var(--sp-6)}
.empty-state svg{width:48px;height:48px;color:var(--accent);opacity:0.6;margin-bottom:var(--sp-5)}
.empty-state h2{font-size:var(--text-xl);font-weight:600;margin-bottom:var(--sp-2);letter-spacing:var(--ls-tight)}
.empty-state p{color:var(--text2);font-size:var(--text-md);margin-bottom:var(--sp-8);max-width:420px;margin-left:auto;margin-right:auto;line-height:1.6}
.empty-steps{display:flex;flex-direction:column;gap:var(--sp-3);max-width:320px;margin:0 auto}
.empty-step{display:flex;align-items:center;gap:var(--sp-3);padding:var(--sp-3) var(--sp-4);background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-lg);font-size:var(--text-sm);color:var(--text2);text-align:left}
.empty-step .step-num{width:24px;height:24px;border-radius:50%;background:var(--accent-glow);border:1px solid var(--accent-border);color:var(--accent-light);font-size:var(--text-xs);font-weight:600;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.empty-step code{background:var(--surface2);padding:1px 6px;border-radius:var(--radius-sm);font-family:var(--mono);font-size:var(--text-xs);color:var(--accent-light)}
.score-ring{position:relative;display:inline-flex;align-items:center;justify-content:center}
.score-ring svg{display:block}
.score-ring-fill{transition:stroke-dashoffset 0.8s ease-out}
.score-ring-fill.success{stroke:var(--success)}
.score-ring-fill.warn{stroke:var(--warn)}
.score-ring-fill.danger{stroke:var(--danger)}
.score-ring-val{position:absolute;font-size:var(--text-md);font-weight:700;font-family:var(--sans);letter-spacing:-0.02em}
.score-ring-val.success{color:var(--success)}
.score-ring-val.warn{color:var(--warn)}
.score-ring-val.danger{color:var(--danger)}
@media(max-width:768px){.hero-stats{grid-template-columns:repeat(2,1fr)}.ov-grid{grid-template-columns:1fr}}
</style>

<p class="page-desc">Real-time security overview across all agents and tools. <span class="sse-indicator" id="sse-status"><span class="sse-dot" id="sse-dot"></span> <span id="sse-label">connecting</span></span></p>

{{if and (eq .Stats.TotalMessages 0) (eq .AgentCount 0)}}
<div class="empty-state">
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
  <h2>Welcome to oktsec</h2>
  <p>Your security pipeline is ready. No agent activity yet.</p>
  <div class="empty-steps">
    <div class="empty-step"><span class="step-num">1</span> Run <code>oktsec run</code></div>
    <div class="empty-step"><span class="step-num">2</span> Use your MCP clients normally</div>
    <div class="empty-step"><span class="step-num">3</span> Watch threats get caught here</div>
  </div>
</div>
{{else}}

<!-- Hero: the 4 numbers that tell the story -->
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
    <div class="lbl">Agents Secured</div>
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

<!-- Pipeline Health + Security Status -->
<div class="ov-grid">
  <div class="ov-card">
    <h3>Pipeline Health</h3>
    <div class="pipeline-stages">
      {{range .PipelineStages}}
      <div class="pipeline-stage">
        <span class="pipeline-dot {{if .Active}}active{{else}}inactive{{end}}"></span>
        {{.Name}}
      </div>
      {{end}}
    </div>
    <div class="pipeline-summary">
      {{.RuleCount}} rules &middot; {{if .RequireSig}}enforce{{else}}observe{{end}} mode &middot; chain {{if .ChainValid}}verified{{else}}broken{{end}} ({{formatNum .ChainCount}})
      {{if .AvgLatency}}<br><span style="color:var(--success);font-weight:600">{{.AvgLatency}}ms</span> <span style="opacity:0.7">median scan latency across {{.RuleCount}} rules</span>{{end}}
    </div>
  </div>
  <div class="ov-card">
    <h3>Security Status</h3>
    <a href="/dashboard/events?tab=blocked" class="ov-metric">
      <span class="k">Threat rate</span>
      <span class="v {{if gt .DetectionRate 20}}danger{{else if gt .DetectionRate 5}}warn{{end}}">{{if gt .DetectionRate 0}}{{.DetectionRate}}%{{else}}<span style="color:var(--success)">&lt; 1%</span>{{end}}</span>
    </a>
    <div class="ov-metric" data-tooltip="Median latency scanning {{.RuleCount}} detection rules per message">
      <span class="k">Scan latency (p50)</span>
      <span class="v {{if ge .AvgLatency 500}}warn{{else}}success{{end}}">{{.AvgLatency}}ms</span>
    </div>
    <a href="/dashboard/settings?tab=identity" class="ov-metric">
      <span class="k">Identity mode</span>
      <span class="v">{{if .RequireSig}}<span style="color:var(--success)">enforced</span>{{else}}<span style="color:var(--text2)">observe</span>{{end}}</span>
    </a>
    <a href="/dashboard/events?tab=quarantine" class="ov-metric">
      <span class="k">Quarantine</span>
      <span class="v">{{if .PendingReview}}<span style="color:var(--warn)">{{.PendingReview}} pending</span>{{else}}<span style="color:var(--success)">clear</span>{{end}}</span>
    </a>
    {{if .LLMEnabled}}
    <a href="/dashboard/llm" class="ov-metric">
      <span class="k">AI analysis</span>
      <span class="v {{if gt .LLMThreats 5}}warn{{else if gt .LLMThreats 0}}text-secondary{{end}}">{{.LLMThreats}} <span style="color:var(--text3);font-size:var(--text-xs);font-weight:400">findings</span></span>
    </a>
    {{end}}
  </div>
</div>

<!-- Live Feed -->
<div class="card">
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

{{if .Chart}}
<!-- Activity sparkline -->
<div class="sparkline-wrap">
  <div class="sparkline-chart">
    {{range .Chart}}<div class="sparkline-bar" style="height:{{.Percent}}%" title="{{.Label}}: {{.Count}} msgs"></div>{{end}}
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
      <span class="v">{{if eq .Severity "critical"}}<span style="color:var(--danger)">{{.Count}}</span>{{else if eq .Severity "high"}}<span style="color:#fb923c">{{.Count}}</span>{{else}}<span>{{.Count}}</span>{{end}}</span>
    </div>
    {{end}}
  </div>
  {{end}}

  {{if .AgentRisks}}
  <div class="ov-card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px"><h3 style="margin:0" data-tooltip="Risk score based on blocked and flagged messages per agent in the last 24 hours">Agent Risk (24h)</h3><a href="/dashboard/agents" style="font-size:var(--text-sm);color:var(--accent-light);text-decoration:none;font-weight:500">View all &rarr;</a></div>
    <div id="ar-list">
    {{range $i, $a := .AgentRisks}}{{if not (contains $a.Agent ":")}}
    <div class="ov-metric clickable ar-item" style="cursor:pointer" onclick="window.location='/dashboard/agents/{{$a.Agent}}'">
      <span class="k">{{if eq $a.Agent "unknown"}}<span style="color:var(--text3)">Unidentified</span>{{else}}{{$a.Agent}}{{end}}<br><span style="color:var(--text3);font-size:var(--text-xs);font-family:var(--mono)">{{$a.Total}} msgs</span></span>
      <span class="v">
        <div class="risk-bar" style="width:60px;display:inline-block;vertical-align:middle;margin-right:6px"><div class="risk-bar-fill {{if gt $a.RiskScore 60.0}}risk-high{{else if gt $a.RiskScore 30.0}}risk-med{{else}}risk-low{{end}}" style="width:{{printf "%.0f" $a.RiskScore}}%"></div></div>
        <span style="font-size:var(--text-sm)">{{printf "%.0f" $a.RiskScore}}</span>
      </span>
    </div>
    {{end}}{{end}}
    </div>
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
    if(info)info.textContent='Showing '+(s+1)+'\u2013'+e+' of '+total;
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
      row.className = 'clickable new-event';
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
    <h2>Node Threat Scores</h2>
    <p style="color:var(--text3);font-size:0.78rem;margin-bottom:12px">Higher scores mean more blocked or quarantined messages originating from this agent.</p>
    {{if .Nodes}}
    <table>
      <thead><tr><th>Agent</th><th>Threat</th><th>Sent</th><th>Recv</th><th>Role</th></tr></thead>
      <tbody>
      {{range .Nodes}}
      <tr class="clickable" onclick="location.href='/dashboard/agents/{{.Name}}'">
        <td style="font-weight:600">{{agentCell .Name}}</td>
        <td><div style="display:flex;align-items:center;gap:8px"><div class="risk-bar" style="width:60px"><div class="risk-bar-fill {{if gt .ThreatScore 60.0}}risk-high{{else if gt .ThreatScore 30.0}}risk-med{{else}}risk-low{{end}}" style="width:{{printf "%.0f" .ThreatScore}}%"></div></div><span>{{printf "%.1f" .ThreatScore}}</span></div></td>
        <td>{{.TotalSent}}</td>
        <td>{{.TotalRecv}}</td>
        <td style="color:var(--text3)">{{if eq .Betweenness -1.0}}&#8212;{{else if gt .Betweenness 0.3}}Hub{{else if and (gt .TotalSent 0) (eq .TotalRecv 0)}}Producer{{else if and (eq .TotalSent 0) (gt .TotalRecv 0)}}Consumer{{else}}Peer{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">No agents detected</p>{{end}}
  </div>
  <div class="card">
    <h2>Edge Health</h2>
    <p style="color:var(--text3);font-size:0.78rem;margin-bottom:12px">Percentage of messages on each connection that were delivered successfully.</p>
    {{if .Edges}}
    <table>
      <thead><tr><th>From</th><th>To</th><th>Total</th><th>Health</th></tr></thead>
      <tbody>
      {{range .Edges}}
      <tr>
        <td>{{.From}}</td>
        <td>{{.To}}</td>
        <td>{{.Total}}</td>
        <td><div style="display:flex;align-items:center;gap:8px"><div class="risk-bar" style="width:60px"><div class="risk-bar-fill {{if lt .HealthScore 40.0}}risk-high{{else if lt .HealthScore 70.0}}risk-med{{else}}risk-low{{end}}" style="width:{{printf "%.0f" .HealthScore}}%"></div></div><span>{{printf "%.0f" .HealthScore}}%</span></div></td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">No traffic in this time range</p>{{end}}
  </div>
</div>
{{if .ShadowEdges}}
<div class="card">
  <h2 style="color:var(--warn)">Shadow Edges</h2>
  <p style="color:var(--text2);font-size:0.82rem;margin-bottom:12px">Traffic between agents not defined in ACL policy.</p>
  <table>
    <thead><tr><th>From</th><th>To</th><th>Messages</th></tr></thead>
    <tbody>{{range .ShadowEdges}}<tr><td>{{.From}}</td><td>{{.To}}</td><td>{{.Total}}</td></tr>{{end}}</tbody>
  </table>
</div>
{{end}}`))

var graphEventsTmpl = template.Must(template.New("graph-events").Funcs(tmplFuncs).Parse(`
{{range .}}
<div style="padding:6px 0;border-left:3px solid {{if eq .Status "blocked"}}#f85149{{else if eq .Status "quarantined"}}#d29922{{else}}var(--border){{end}};padding-left:10px;margin-bottom:6px">
  <div style="color:var(--text3);font-size:0.68rem" data-ts="{{.Timestamp}}">{{.Timestamp}}</div>
  {{if .ToolName}}<div style="display:flex;align-items:center;gap:5px">{{toolDot .ToolName}} <span style="color:var(--text3);font-size:0.7rem">{{if eq .Status "blocked"}}blocked{{else if eq .Status "quarantined"}}quarantined{{else}}processed{{end}}</span></div>
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

var agentsTmpl = template.Must(template.New("agents").Funcs(tmplFuncs).Parse(layoutHead + `
<p class="page-desc">Registered agents with identity keys, message history, and risk scoring. Unregistered agents appear in Discovered below.</p>

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
          <span style="font-family:var(--mono);font-size:0.72rem;color:var(--text3)">{{printf "%.0f" .RiskScore}}</span>{{if gt .LLMThreatCount 0}}<span title="{{.LLMThreatCount}} LLM threats" style="font-size:0.6rem;color:var(--danger);margin-left:2px">&#x26A0;</span>{{end}}
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
  <h2 style="color:var(--warn)">Discovered from Traffic <span style="font-size:var(--text-xs);font-weight:400;color:var(--text3);margin-left:var(--sp-2)">{{len .DiscoveredAgents}} unregistered</span></h2>
  <p class="desc">These identifiers appeared as message destinations but aren't registered agents. They may be tool names, subagents, or external endpoints. Register to enforce identity and ACL policies.</p>
  <table>
    <thead><tr><th>Identifier</th><th></th></tr></thead>
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
<style>
.ad-grid{display:grid;grid-template-columns:1fr 1fr;gap:var(--sp-5);align-items:start}
.ad-grid>div{min-width:0}
.ad-grid table{width:100%}
.ad-grid .fp{word-break:break-all;overflow-wrap:break-word}
.ad-tabs{display:flex;gap:0;border-bottom:2px solid var(--border);margin-bottom:var(--sp-5)}
.ad-tab{padding:10px var(--sp-5);font-size:var(--text-sm);font-weight:500;color:var(--text3);cursor:pointer;border:none;background:none;border-bottom:2px solid transparent;margin-bottom:-2px;transition:color var(--ease-default),border-color var(--ease-default)}
.ad-tab:hover{color:var(--text2)}
.ad-tab.active{color:var(--text);border-bottom-color:var(--accent);font-weight:600}
.ad-panel{display:none}
.ad-panel.active{display:block}
.ad-slbl{font-size:var(--text-xs);font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:var(--ls-caps);margin-bottom:var(--sp-3);display:flex;align-items:center;gap:var(--sp-2)}
.ad-kv{display:flex;justify-content:space-between;align-items:baseline;padding:var(--sp-2) 0;font-size:var(--text-base);border-bottom:1px solid var(--border-subtle)}
.ad-kv:last-child{border-bottom:none}
.ad-kv .k{color:var(--text3);font-size:var(--text-sm)}
.ad-kv .v{font-family:var(--mono);font-size:var(--text-sm);color:var(--text);text-align:right;max-width:60%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ad-rule{display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.04);position:relative}
.ad-rule:last-child{border-bottom:none}
.ad-rule-bar{position:absolute;left:0;top:0;bottom:0;border-radius:4px;opacity:0.07;pointer-events:none}
.ad-gauge{display:flex;gap:2px;align-items:center}
.ad-gauge span{width:4px;height:16px;border-radius:2px;background:var(--border)}
.ad-gauge span.filled{background:var(--success)}
.ad-gauge span.filled.warn{background:var(--warn)}
.ad-gauge span.filled.danger{background:var(--danger)}
.ad-tool-bar{height:10px;border-radius:5px;display:flex;overflow:hidden}
@media(max-width:960px){.ad-grid{grid-template-columns:1fr}}
</style>

<!-- Breadcrumb -->
<div class="breadcrumb">
  <a href="/dashboard/agents">AGENTS</a>
  <span class="sep">/</span>
  <span style="color:var(--accent-light)">{{.Name}}</span>
</div>

<!-- Header: avatar + name + actions -->
<div class="page-header">
  {{avatar .Name 48}}
  <div class="page-header-info">
    <h1>{{.Name}}</h1>
    <div class="subtitle">{{if .Agent.Description}}{{.Agent.Description}}{{else}}Agent detail{{end}}</div>
  </div>
  <div class="page-header-actions">
    <form method="POST" action="/dashboard/agents/{{.Name}}/keygen" style="display:inline"><button type="submit" class="btn btn-sm btn-outline success" onclick="return confirm('Generate new keypair for {{.Name}}?')">Generate Keypair</button></form>
    <form method="POST" action="/dashboard/agents/{{.Name}}/suspend" style="display:inline">{{if .Suspended}}<button type="submit" class="btn btn-sm btn-outline success">Unsuspend</button>{{else}}<button type="submit" class="btn btn-sm btn-outline warn">Suspend</button>{{end}}</form>
    <button class="btn btn-sm btn-outline danger" hx-delete="/dashboard/agents/{{.Name}}" hx-confirm="Delete agent {{.Name}}? This cannot be undone." hx-swap="none" onclick="setTimeout(function(){window.location='/dashboard/agents'},300)">Delete</button>
  </div>
</div>

<!-- Stats -->
<div class="stats">
  <div class="stat"><div class="label">Total Messages</div><div class="value">{{formatNum .TotalMsgs}}</div></div>
  <div class="stat"><div class="label">Delivered</div><div class="value success">{{formatNum .Delivered}}</div></div>
  <div class="stat"><div class="label">Blocked</div><div class="value danger">{{formatNum .Blocked}}</div></div>
  <div class="stat"><div class="label">Quarantined</div><div class="value" style="color:var(--accent-light)">{{formatNum .Quarantined}}</div></div>
</div>

<!-- Risk Score + Tool Distribution -->
<div class="ad-grid" style="margin-bottom:20px">
  <div class="card" style="padding:16px 20px">
    <div class="ad-slbl">Risk Score</div>
    <div style="display:flex;align-items:center;gap:14px">
      <span style="font-size:1.5rem;font-weight:700;font-family:var(--mono)" class="{{if gt .RiskScore 60.0}}danger{{else if gt .RiskScore 30.0}}warn{{else}}success{{end}}">{{printf "%.0f" .RiskScore}}</span>
      <div class="ad-gauge" id="risk-gauge"></div>
      <span style="color:var(--text3);font-size:0.72rem;font-family:var(--mono)">/ 100</span>
    </div>
    <script>
    (function(){
      var g=document.getElementById('risk-gauge');if(!g)return;
      var score={{printf "%.0f" .RiskScore}};
      var segs=20;
      for(var i=0;i<segs;i++){
        var s=document.createElement('span');
        var threshold=i*(100/segs);
        if(threshold<score){
          s.className='filled'+(score>60?' danger':(score>30?' warn':''));
        }
        g.appendChild(s);
      }
    })();
    </script>
  </div>
  <div class="card" style="padding:16px 20px">
    <div class="ad-slbl">Tool Distribution</div>
    <div class="ad-tool-bar" id="tool-dist-bar"></div>
    <div id="tool-dist-legend" style="display:flex;gap:12px;flex-wrap:wrap;margin-top:10px;font-size:0.68rem;color:var(--text3)"></div>
    <script>
    (function(){
      var partners={{if .CommPartners}}[{{range .CommPartners}}{to:"{{.To}}",total:{{.Total}}},{{end}}]{{else}}[]{{end}};
      var toolColors={'Bash':'#d29922','Read':'#22d3ee','Edit':'#818cf8','Grep':'#f472b6','Write':'#c084fc','Glob':'#2dd4bf','Agent':'#a78bfa'};
      var tools={},total=0;
      partners.forEach(function(p){
        var parts=p.to.split('/');
        var t=parts.length>1?parts[parts.length-1]:p.to;
        if(!tools[t])tools[t]=0;
        tools[t]+=p.total;total+=p.total;
      });
      var sorted=Object.keys(tools).sort(function(a,b){return tools[b]-tools[a]});
      var bar=document.getElementById('tool-dist-bar');
      var legend=document.getElementById('tool-dist-legend');
      if(!bar||!total)return;
      sorted.forEach(function(t){
        var pct=(tools[t]/total*100).toFixed(0);
        if(pct<1)return;
        var seg=document.createElement('div');
        seg.style.cssText='width:'+pct+'%;background:'+(toolColors[t]||'#6e7681');
        bar.appendChild(seg);
        var l=document.createElement('span');
        l.innerHTML='<span style="display:inline-block;width:8px;height:8px;border-radius:2px;background:'+(toolColors[t]||'#6e7681')+';vertical-align:middle;margin-right:3px"></span>'+t+' '+pct+'%';
        legend.appendChild(l);
      });
    })();
    </script>
  </div>
</div>

<!-- Tabs -->
<div class="ad-tabs">
  <button class="ad-tab active" onclick="adTab('overview')">Overview</button>
  <button class="ad-tab" onclick="adTab('config')">Configuration</button>
  <button class="ad-tab" onclick="adTab('policies')">Tool Policies</button>
  <button class="ad-tab" onclick="adTab('messages')">Recent Messages</button>
</div>
<script>
function adTab(name){
  document.querySelectorAll('.ad-tab').forEach(function(t){t.classList.remove('active')});
  document.querySelectorAll('.ad-panel').forEach(function(p){p.classList.remove('active')});
  event.target.classList.add('active');
  document.getElementById('ad-'+name).classList.add('active');
}
</script>

<!-- Overview Tab -->
<div id="ad-overview" class="ad-panel active">
  <div class="ad-grid">
    <!-- Top Triggered Rules -->
    <div class="card" style="padding:18px 20px">
      <div class="ad-slbl">Top triggered rules (24h) {{if .TopRules}}<a href="/dashboard/rules" style="margin-left:auto;font-size:0.68rem;color:var(--accent-light);text-decoration:none;font-weight:400;text-transform:none;letter-spacing:0">View all &rarr;</a>{{end}}</div>
      {{if .TopRules}}
      {{range .TopRules}}
      <div class="ad-rule" style="padding-left:8px">
        <div class="ad-rule-bar" style="width:{{if $.TopRules}}{{printf "%.0f" (mulf (divf .Count (index $.TopRules 0).Count) 100)}}%{{else}}0%{{end}};background:{{if eq .Severity "critical"}}#f85149{{else if eq .Severity "high"}}#fb923c{{else}}var(--text3){{end}}"></div>
        <div style="flex:1;min-width:0;position:relative">
          <div style="font-size:0.82rem;font-weight:500;color:var(--text)">{{.Name}}</div>
          <div style="display:flex;align-items:center;gap:6px;margin-top:2px">
            <span style="font-family:var(--mono);font-size:0.68rem;color:var(--text3)">{{.RuleID}}</span>
            {{if eq .Severity "critical"}}<span class="sev-critical">critical</span>
            {{else if eq .Severity "high"}}<span class="sev-high">high</span>
            {{else if eq .Severity "medium"}}<span class="sev-medium">medium</span>
            {{else}}<span class="sev-low">low</span>{{end}}
          </div>
        </div>
        <span style="font-family:var(--mono);font-weight:700;font-size:1.05rem;color:var(--text);flex-shrink:0">{{.Count}}</span>
      </div>
      {{end}}
      {{else}}
      <div class="empty" style="padding:20px 0">No rules triggered for this agent.</div>
      {{end}}
    </div>

    <!-- Communication Partners -->
    <div class="card" style="padding:18px 20px">
      <div class="ad-slbl">Communication partners (24h)</div>
      {{if .CommPartners}}
      <table style="font-size:0.78rem">
        <thead><tr><th class="section-label">Partner</th><th style="text-align:right;font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);font-weight:600">Total</th><th style="text-align:right;font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);font-weight:600">Blocked</th><th style="text-align:right;font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);font-weight:600">Rate</th></tr></thead>
        <tbody>
        {{range .CommPartners}}
        <tr style="{{if eq .Total 0}}opacity:0.4{{end}}">
          <td>{{toolDot .To}}</td>
          <td style="text-align:right;font-family:var(--mono)">{{.Total}}</td>
          <td style="text-align:right;font-family:var(--mono);color:{{if .Blocked}}var(--danger){{else}}var(--success){{end}}">{{.Blocked}}</td>
          <td style="text-align:right;font-family:var(--mono)">{{if .Total}}{{printf "%.0f" (divf (mulf .Blocked 100) .Total)}}%{{else}}0%{{end}}</td>
        </tr>
        {{end}}
        </tbody>
      </table>
      {{else}}
      <div class="empty" style="padding:20px 0">No communication partners.</div>
      {{end}}
    </div>
  </div>

  {{if and .LLMEnabled .LLMHistory}}
  <div class="card" style="padding:18px 20px;margin-top:20px">
    <div class="ad-slbl">LLM Threat Intelligence</div>
    {{if gt .AgentRisk.LLMThreatCount 0}}
    <div style="display:flex;gap:16px;margin-bottom:12px;padding:10px;background:var(--surface2);border-radius:8px;font-size:0.82rem">
      <div style="text-align:center;flex:1"><div style="font-size:1.1rem;font-weight:700;color:{{if gt .AgentRisk.LLMThreatCount 3}}var(--danger){{else}}var(--text){{end}}">{{.AgentRisk.LLMThreatCount}}</div><div style="font-size:0.65rem;color:var(--text3)">Threats</div></div>
      <div style="text-align:center;flex:1"><div style="font-size:1.1rem;font-weight:700;color:var(--danger)">{{.AgentRisk.LLMConfirmed}}</div><div style="font-size:0.65rem;color:var(--text3)">Confirmed</div></div>
      <div style="text-align:center;flex:1"><div style="font-size:1.1rem;font-weight:700;color:{{if gt .AgentRisk.LLMAvgRisk 60.0}}var(--danger){{else if gt .AgentRisk.LLMAvgRisk 30.0}}var(--warn){{else}}var(--success){{end}}">{{printf "%.0f" .AgentRisk.LLMAvgRisk}}</div><div style="font-size:0.65rem;color:var(--text3)">Avg Risk</div></div>
    </div>
    {{end}}
    <table style="font-size:0.82rem">
      <thead><tr><th>Time</th><th style="text-align:right">Risk</th><th>Action</th><th>Status</th></tr></thead>
      <tbody>
      {{range .LLMHistory}}
      <tr class="clickable" onclick="window.location='/dashboard/llm/case/{{.ID}}'">
        <td data-ts="{{.Timestamp}}" style="font-size:0.75rem">{{.Timestamp}}</td>
        <td style="text-align:right;font-family:var(--mono);font-weight:600;color:{{if gt .RiskScore 60.0}}var(--danger){{else if gt .RiskScore 30.0}}var(--warn){{else}}var(--success){{end}}">{{printf "%.0f" .RiskScore}}</td>
        <td>{{if eq .RecommendedAction "block"}}<span class="badge-blocked">block</span>{{else if eq .RecommendedAction "investigate"}}<span class="badge-quarantined">investigate</span>{{else}}<span class="badge-delivered">none</span>{{end}}</td>
        <td>{{if eq .ReviewedStatus "confirmed"}}<span style="color:var(--danger);font-size:0.72rem;font-weight:600">confirmed</span>{{else if eq .ReviewedStatus "false_positive"}}<span style="color:var(--text3);font-size:0.72rem">dismissed</span>{{else}}<span style="color:var(--warn);font-size:0.72rem">pending</span>{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    <div style="margin-top:8px;text-align:right"><a href="/dashboard/llm" style="color:var(--accent);font-size:0.75rem">View all &rarr;</a></div>
  </div>
  {{end}}
</div>

<!-- Configuration Tab -->
<div id="ad-config" class="ad-panel">
  <div class="ad-grid">
    <div class="card" style="padding:18px 20px">
      <div class="ad-slbl">Identity</div>
      <div class="ad-kv"><span class="k">Can message</span><span class="v">{{range $i, $t := .Agent.CanMessage}}{{if $i}} {{end}}<span class="acl-target">{{$t}}</span>{{end}}{{if not .Agent.CanMessage}}<span style="color:var(--text3)">none</span>{{end}}</span></div>
      <div class="ad-kv"><span class="k">Location</span><span class="v">{{if .Agent.Location}}<code style="background:var(--bg3);padding:2px 6px;border-radius:4px;font-size:0.72rem">{{.Agent.Location}}</code>{{else}}unknown{{end}}</span></div>
      {{if .Agent.ToolConstraints}}<div class="ad-kv"><span class="k">Tool constraints</span><span class="v">{{range .Agent.ToolConstraints}}<code style="background:rgba(244,63,94,0.15);color:var(--danger);padding:2px 6px;border-radius:4px;font-size:0.72rem;margin-left:4px">{{.Tool}}</code>{{end}}</span></div>{{end}}
      {{if .KeyFP}}<div class="ad-kv"><span class="k">Key fingerprint</span><span class="v fp" title="{{.KeyFP}}">{{truncate .KeyFP 32}}</span></div>{{end}}
      {{if .Agent.CreatedBy}}<div class="ad-kv"><span class="k">Origin</span><span class="v" style="font-family:var(--sans)">{{.Agent.CreatedBy}}</span></div>{{end}}
      {{if .Agent.CreatedAt}}<div class="ad-kv"><span class="k">Created</span><span class="v" data-ts="{{.Agent.CreatedAt}}">{{.Agent.CreatedAt}}</span></div>{{end}}
    </div>
    <div class="card" style="padding:18px 20px">
      <div class="ad-slbl">Edit Metadata</div>
      <form method="POST" action="/dashboard/agents/{{.Name}}/edit">
        <div style="margin-bottom:12px"><label style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);display:block;margin-bottom:4px">Description</label><input type="text" name="description" value="{{.Agent.Description}}" style="width:100%;box-sizing:border-box"></div>
        <div style="margin-bottom:12px"><label style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);display:block;margin-bottom:4px">Location</label><input type="text" name="location" value="{{.Agent.Location}}" style="width:100%;box-sizing:border-box"></div>
        <div class="form-row">
          <div class="form-group"><label style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3)">Can Message (space-separated)</label><input type="text" name="can_message" value="{{range $i, $t := .Agent.CanMessage}}{{if $i}} {{end}}{{$t}}{{end}}"></div>
          <div class="form-group"><label style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3)">Tags (space-separated)</label><input type="text" name="tags" value="{{range $i, $t := .Agent.Tags}}{{if $i}} {{end}}{{$t}}{{end}}"></div>
        </div>
        <div class="form-row">
          <div class="form-group"><label style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3)">Blocked Content (space-separated categories)</label><input type="text" name="blocked_content" value="{{range $i, $c := .Agent.BlockedContent}}{{if $i}} {{end}}{{$c}}{{end}}"></div>
          <div class="form-group"><label style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3)">Allowed Tools (space-separated, empty = all)</label><input type="text" name="allowed_tools" value="{{range $i, $t := .Agent.AllowedTools}}{{if $i}} {{end}}{{$t}}{{end}}"></div>
        </div>
        <button type="submit" class="btn btn-sm btn-success">Save</button>
      </form>
    </div>
  </div>
</div>

<!-- Tool Policies Tab -->
<div id="ad-policies" class="ad-panel">
  <div class="card" style="padding:18px 20px">
    <div class="ad-slbl">Tool Policies</div>
    <p class="desc">Per-tool enforcement: spending limits, rate limits, and approval thresholds for MCP gateway tool calls.</p>
    {{if .Agent.ToolPolicies}}
    <table style="margin-bottom:16px">
      <thead><tr><th>Tool</th><th>Max/call</th><th>Daily limit</th><th>Approval above</th><th>Rate limit</th></tr></thead>
      <tbody>
      {{range $tool, $p := .Agent.ToolPolicies}}
      <tr>
        <td style="font-weight:600;font-family:var(--mono);font-size:0.82rem">{{$tool}}</td>
        <td style="font-family:var(--mono);font-size:0.82rem">{{if $p.MaxAmount}}{{printf "$%.0f" $p.MaxAmount}}{{else}}<span style="color:var(--text3)">-</span>{{end}}</td>
        <td style="font-family:var(--mono);font-size:0.82rem">{{if $p.DailyLimit}}{{printf "$%.0f" $p.DailyLimit}}{{else}}<span style="color:var(--text3)">-</span>{{end}}</td>
        <td style="font-family:var(--mono);font-size:0.82rem">{{if $p.RequireApprovalAbove}}{{printf "$%.0f" $p.RequireApprovalAbove}} <span style="color:var(--warn);font-size:0.68rem">quarantine</span>{{else}}<span style="color:var(--text3)">-</span>{{end}}</td>
        <td style="font-family:var(--mono);font-size:0.82rem">{{if $p.RateLimit}}{{$p.RateLimit}}/hr{{else}}<span style="color:var(--text3)">-</span>{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}
    <div class="empty" style="margin-bottom:16px">No tool policies configured.<br><span style="font-size:0.75rem;color:var(--text3)">Add policies below to enforce spending limits, rate limits, or approval thresholds.</span></div>
    {{end}}
    <div style="border-top:1px solid var(--border);padding-top:16px;margin-top:8px">
      <div class="ad-slbl">Add Tool Policy</div>
      <form method="POST" action="/dashboard/agents/{{.Name}}/edit">
        <input type="hidden" name="description" value="{{.Agent.Description}}">
        <input type="hidden" name="location" value="{{.Agent.Location}}">
        <input type="hidden" name="can_message" value="{{range $i, $t := .Agent.CanMessage}}{{if $i}} {{end}}{{$t}}{{end}}">
        <input type="hidden" name="tags" value="{{range $i, $t := .Agent.Tags}}{{if $i}} {{end}}{{$t}}{{end}}">
        <input type="hidden" name="blocked_content" value="{{range $i, $c := .Agent.BlockedContent}}{{if $i}} {{end}}{{$c}}{{end}}">
        <input type="hidden" name="allowed_tools" value="{{range $i, $t := .Agent.AllowedTools}}{{if $i}} {{end}}{{$t}}{{end}}">
        {{range $tool, $p := .Agent.ToolPolicies}}
        <input type="hidden" name="tp_{{$tool}}_max_amount" value="{{printf "%.0f" $p.MaxAmount}}">
        <input type="hidden" name="tp_{{$tool}}_daily_limit" value="{{printf "%.0f" $p.DailyLimit}}">
        <input type="hidden" name="tp_{{$tool}}_require_approval" value="{{printf "%.0f" $p.RequireApprovalAbove}}">
        <input type="hidden" name="tp_{{$tool}}_rate_limit" value="{{$p.RateLimit}}">
        {{end}}
        <input type="hidden" name="policy_tools" id="tp-policy-tools" value="{{range $tool, $p := .Agent.ToolPolicies}}{{$tool}} {{end}}">
        <div class="form-row" style="align-items:flex-end">
          <div class="form-group" style="flex:1.5"><label style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3)">Tool name</label><input type="text" id="tp-tool-name" placeholder="e.g. create_" required></div>
          <div class="form-group"><label style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3)">Max/call ($)</label><input type="number" id="tp-max" min="0" step="1" placeholder="100"></div>
          <div class="form-group"><label style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3)">Daily limit ($)</label><input type="number" id="tp-daily" min="0" step="1" placeholder="500"></div>
          <div class="form-group"><label style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3)">Approval above ($)</label><input type="number" id="tp-approval" min="0" step="1" placeholder="50"></div>
          <div class="form-group" style="flex:0.7"><label style="font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3)">Rate (/hr)</label><input type="number" id="tp-rate" min="0" step="1" placeholder="10"></div>
          <button type="submit" class="btn btn-sm" style="background:var(--success);margin-bottom:12px" onclick="return stagePolicy()">Save Policy</button>
        </div>
      </form>
    </div>
  </div>
</div>
<script>
function stagePolicy() {
  var name = document.getElementById('tp-tool-name').value.trim();
  if (!name) return false;
  var form = document.getElementById('tp-tool-name').closest('form');
  var prefix = 'tp_' + name + '_';
  form.querySelectorAll('[name^="' + prefix + '"]').forEach(function(el) { el.remove(); });
  var fields = {max_amount: 'tp-max', daily_limit: 'tp-daily', require_approval: 'tp-approval', rate_limit: 'tp-rate'};
  for (var k in fields) {
    var inp = document.createElement('input');
    inp.type = 'hidden'; inp.name = prefix + k; inp.value = document.getElementById(fields[k]).value || '0';
    form.appendChild(inp);
  }
  var toolsInput = document.getElementById('tp-policy-tools');
  var tools = toolsInput.value.trim().split(/\s+/).filter(Boolean);
  if (tools.indexOf(name) === -1) tools.push(name);
  toolsInput.value = tools.join(' ');
  return true;
}
</script>

<!-- Recent Messages Tab -->
<div id="ad-messages" class="ad-panel">
  <div class="card" style="padding:18px 20px">
    <div class="ad-slbl">Recent Messages {{if .Entries}}<a href="/dashboard/events?agent={{.Name}}" style="margin-left:auto;font-size:0.68rem;color:var(--accent-light);text-decoration:none;font-weight:400;text-transform:none;letter-spacing:0">View all in Event Log &rarr;</a>{{end}}</div>
    {{if .Entries}}
    <table style="font-size:0.78rem">
      <thead><tr><th class="section-label">Time</th><th class="section-label">To</th><th class="section-label">Status</th><th style="text-align:right;font-size:0.62rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text3);font-weight:600">Latency</th></tr></thead>
      <tbody>
      {{range .Entries}}
      <tr class="ad-msg clickable" hx-get="/dashboard/api/event/{{.ID}}" hx-target="#panel-content" hx-swap="innerHTML">
        <td data-ts="{{.Timestamp}}">{{.Timestamp}}</td>
        <td>{{if .ToolName}}{{toolDot .ToolName}}{{else}}{{agentCell .ToAgent}}{{end}}</td>
        <td>
          {{if eq .Status "delivered"}}<span class="badge-delivered">delivered</span>
          {{else if eq .Status "blocked"}}<span class="badge-blocked">blocked</span>
          {{else if eq .Status "rejected"}}<span class="badge-rejected">rejected</span>
          {{else if eq .Status "quarantined"}}<span class="badge-quarantined">quarantined</span>
          {{else}}{{.Status}}{{end}}
        </td>
        <td style="text-align:right;font-family:var(--mono);color:var(--text3)">{{.LatencyMs}}ms</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    <div style="display:flex;align-items:center;justify-content:space-between;padding:12px 0;font-size:0.78rem;color:var(--text3)">
      <span id="ad-pager-info"></span>
      <div style="display:flex;gap:4px">
        <button id="ad-prev" class="pager-btn" onclick="adPage(-1)" disabled>&larr; Prev</button>
        <button id="ad-next" class="pager-btn" onclick="adPage(1)">Next &rarr;</button>
      </div>
    </div>
    <script>
    var adCur=1,adSize=15;
    function adRender(){
      var rows=document.querySelectorAll('.ad-msg');
      var total=rows.length;
      var start=(adCur-1)*adSize,end=Math.min(start+adSize,total);
      rows.forEach(function(r,i){r.style.display=(i>=start&&i<end)?'':'none';});
      document.getElementById('ad-pager-info').textContent=total?'Showing '+(start+1)+'\u2013'+end+' of '+total:'';
      document.getElementById('ad-prev').disabled=adCur<=1;
      document.getElementById('ad-next').disabled=end>=total;
    }
    function adPage(d){adCur+=d;adRender();}
    adRender();
    </script>
    {{else}}
    <div class="empty">No messages for this agent yet.</div>
    {{end}}
  </div>
</div>
` + layoutFoot))

var rulesTmpl = template.Must(template.New("rules").Funcs(tmplFuncs).Parse(layoutHead + `
<p class="page-desc">{{if .RuleCount}}{{.RuleCount}} detection rules active{{if .Categories}} across {{len .Categories}} categories{{end}}. Toggle rules on/off.{{else}}Manage detection rules and create custom rules for your organization.{{end}}</p>

<style>
.rules-tabs{display:flex;gap:0;margin-bottom:var(--sp-6);border-bottom:1px solid var(--border)}
.rules-tab{padding:var(--sp-3) var(--sp-6);color:var(--text3);font-size:var(--text-sm);font-weight:500;cursor:pointer;border-bottom:2px solid transparent;transition:all var(--ease-smooth);text-decoration:none;display:inline-flex;align-items:center;gap:var(--sp-2)}
.rules-tab:hover{color:var(--text)}
.rules-tab.active{color:var(--text);border-bottom-color:var(--accent)}
.rules-tab .count{font-size:var(--text-xs);font-family:var(--mono);background:var(--surface2);padding:2px var(--sp-2);border-radius:10px;color:var(--text3)}
.rules-tab.active .count{background:rgba(99,102,241,0.15);color:var(--accent-light)}
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
.cat-card-sev.high{background:rgba(251,146,60,0.08);color:#fb923c}
.cat-card-sev.medium{background:rgba(96,165,250,0.06);color:#60a5fa}
.cat-card-sev.low{background:var(--surface2);color:var(--text3)}
.cat-card-status{margin-left:auto;font-size:0.68rem;font-weight:500;color:var(--text3)}
.cat-card-status.some-off{color:var(--warn)}
.custom-rule-row{display:flex;align-items:center;gap:var(--sp-4);padding:14px var(--sp-5);background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-xl);margin-bottom:var(--sp-2);transition:border-color var(--ease-smooth)}
.custom-rule-row:hover{border-color:var(--accent)}
.custom-rule-id{font-family:var(--mono);font-weight:600;font-size:0.82rem;color:var(--text);min-width:200px}
.custom-rule-file{color:var(--text3);font-size:0.75rem;font-family:var(--mono);flex:1}
</style>

<!-- Tabs -->
<div class="rules-tabs">
  <a href="/dashboard/rules?tab=detection" class="rules-tab {{if eq .Tab "detection"}}active{{end}}">Detection Rules{{if .RuleCount}} <span class="count">{{.RuleCount}}</span>{{end}}</a>
  <a href="/dashboard/rules?tab=enforcement" class="rules-tab {{if eq .Tab "enforcement"}}active{{end}}">Enforcement{{if .EnforcementCount}} <span class="count">{{.EnforcementCount}}</span>{{end}}</a>
  {{if .LLMTotalCount}}<a href="/dashboard/rules?tab=llm-rules" class="rules-tab {{if eq .Tab "llm-rules"}}active{{end}}">LLM Rules{{if .LLMPendingCount}} <span class="count" style="background:rgba(251,146,60,0.15);color:#fb923c">{{.LLMPendingCount}} pending</span>{{else if .LLMTotalCount}} <span class="count">{{.LLMTotalCount}}</span>{{end}}</a>{{end}}
  <a href="/dashboard/rules?tab=custom" class="rules-tab {{if eq .Tab "custom"}}active{{end}}">Custom Rules{{if .CustomCount}} <span class="count">{{.CustomCount}}</span>{{end}}</a>
</div>

{{if eq .Tab "detection"}}
<!-- Detection Rules Tab -->
{{if .Categories}}

{{if or .LLMPendingCount .LLMActiveCount}}
<div style="display:flex;align-items:center;gap:16px;padding:14px 20px;margin-bottom:20px;background:var(--surface);border:1px solid rgba(99,102,241,0.2);border-radius:10px">
  <div style="flex:1;min-width:0">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:2px">
      <span style="font-weight:600;font-size:0.85rem">AI-Generated Rules</span>
      {{if .LLMPendingCount}}<span style="font-size:0.68rem;padding:2px 8px;border-radius:4px;background:rgba(251,146,60,0.12);color:#fb923c;font-weight:600">{{.LLMPendingCount}} pending review</span>{{end}}
    </div>
    <span style="font-size:0.75rem;color:var(--text3)">{{.LLMActiveCount}} LLM-generated rules active{{if .LLMPendingCount}} &middot; {{.LLMPendingCount}} awaiting approval{{end}}</span>
  </div>
  <a href="/dashboard/rules?tab=llm-rules" class="btn btn-sm" style="font-size:0.72rem;white-space:nowrap">Review Rules</a>
</div>
{{end}}

<div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:16px">
  <span style="color:var(--text3);font-size:0.78rem">{{.RuleCount}} rules across {{len .Categories}} categories</span>
  <div style="display:flex;gap:8px">
    <button class="btn btn-sm" style="font-size:0.72rem" hx-post="/dashboard/api/rules/bulk-toggle" hx-vals='{"action":"enable-all"}' hx-confirm="Enable ALL detection rules?">Enable All</button>
    <button class="btn btn-sm" style="font-size:0.72rem;background:transparent;border:1px solid var(--border);color:var(--text3)" hx-post="/dashboard/api/rules/bulk-toggle" hx-vals='{"action":"disable-all"}' hx-confirm="Disable ALL detection rules? This removes all security scanning.">Disable All</button>
  </div>
</div>
<div class="cat-grid">
  {{range .Categories}}
  <a href="/dashboard/rules/{{.Name}}" class="cat-card">
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
      {{if and (gt .Disabled 0) (lt .Disabled .Total)}}<span class="cat-card-status some-off">{{.Disabled}} off</span>{{end}}
      {{if eq .Disabled .Total}}<span class="cat-card-status">all off</span>{{end}}
    </div>
  </a>
  {{end}}
</div>

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
        <button class="btn btn-sm btn-success" hx-post="/dashboard/api/rules/llm/{{.ID}}/approve" hx-target="#lr-act-{{.ID}}" hx-swap="innerHTML">Approve &amp; Activate</button>
        <button class="btn btn-sm" style="background:var(--surface2);color:var(--text3)" hx-post="/dashboard/api/rules/llm/{{.ID}}/reject" hx-target="#lr-act-{{.ID}}" hx-swap="innerHTML">Reject</button>
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
.enf-badge.quarantine{background:rgba(251,146,60,0.08);color:#fb923c}
.enf-badge.allow-and-flag{background:rgba(96,165,250,0.08);color:#60a5fa}
.enf-badge.ignore{background:var(--surface2);color:var(--text3)}
.enf-meta{display:flex;align-items:center;gap:8px;margin-top:8px;flex-wrap:wrap}
.enf-tag{font-size:0.68rem;font-family:var(--mono);padding:2px 8px;border-radius:4px;background:var(--surface2);color:var(--text3)}
.enf-tag.sev-critical{background:rgba(248,81,73,0.06);color:#f85149}
.enf-tag.sev-high{background:rgba(251,146,60,0.06);color:#fb923c}
.enf-tag.sev-medium{background:rgba(96,165,250,0.06);color:#60a5fa}
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
.csv.high{background:rgba(251,146,60,0.08);color:#fb923c}
.csv.medium{background:rgba(96,165,250,0.08);color:#60a5fa}
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

{{if .Webhooks}}
<div class="card" style="margin-top:20px">
  <h2>Category Webhooks</h2>
  <p style="color:var(--text3);font-size:0.78rem;margin-bottom:16px">Notifications sent when any rule in this category triggers, unless the rule has its own webhook override.</p>
  <form method="POST" action="/dashboard/rules/{{.Category.Name}}/webhooks">
    {{range .Webhooks}}
    <label style="display:flex;align-items:center;gap:8px;padding:6px 0;font-size:0.82rem;cursor:pointer">
      <input type="checkbox" name="notify_channel" value="{{.Name}}" {{if $.CategoryWebhook}}{{if inSlice .Name $.CategoryWebhook.Notify}}checked{{end}}{{end}}>
      <span style="font-family:var(--mono);color:var(--text)">{{.Name}}</span>
    </label>
    {{end}}
    <div style="margin-top:12px">
      <label style="display:block;color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Additional URLs (one per line)</label>
      <textarea name="notify_urls" rows="2" style="width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:var(--mono);font-size:0.78rem;padding:8px;resize:vertical">{{if .CategoryWebhook}}{{range .CategoryWebhook.Notify}}{{if contains . "://"}}{{.}}
{{end}}{{end}}{{end}}</textarea>
    </div>
    <button type="submit" class="btn" style="margin-top:12px">Save Category Webhooks</button>
  </form>
</div>
{{end}}
` + layoutFoot))

var eventDetailTmpl = template.Must(template.New("event-detail").Funcs(tmplFuncs).Parse(`
<style>
.ed-hdr{display:flex;align-items:center;gap:var(--sp-3);padding:var(--sp-4) var(--sp-5);border-bottom:1px solid var(--border)}
.ed-close{background:none;border:none;color:var(--text3);font-size:1.2rem;cursor:pointer;padding:var(--sp-1) var(--sp-2);border-radius:var(--radius-sm);line-height:1}
.ed-close:hover{background:var(--surface-hover);color:var(--text)}
.ed-body{padding:0}
.ed-section{border-bottom:1px solid var(--border);padding:var(--sp-5) var(--sp-5)}
.ed-section:last-child{border-bottom:none}
.ed-slbl{font-size:var(--text-xs);font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:var(--ls-caps);margin-bottom:var(--sp-3)}
.ed-row{display:flex;justify-content:space-between;align-items:baseline;padding:var(--sp-2) 0;border-bottom:1px solid var(--border-subtle)}
.ed-row:last-child{border-bottom:none}
.ed-row .k{color:var(--text3);font-size:var(--text-sm)}
.ed-row .v{font-family:var(--mono);font-size:var(--text-sm);color:var(--text);text-align:right;max-width:60%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ed-row .v a{color:var(--accent-light)}
</style>
<div class="ed-hdr">
  <div style="display:flex;align-items:center;gap:8px">
    {{if eq .Entry.Status "delivered"}}<span class="badge-delivered">delivered</span>
    {{else if eq .Entry.Status "blocked"}}<span class="badge-blocked">blocked</span>
    {{else if eq .Entry.Status "rejected"}}<span class="badge-rejected">rejected</span>
    {{else if eq .Entry.Status "quarantined"}}<span class="badge-quarantined">quarantined</span>
    {{else}}<span style="color:var(--text2);font-size:0.75rem">{{.Entry.Status}}</span>{{end}}
  </div>
  <span style="flex:1;font-family:var(--mono);font-size:var(--text-sm);color:var(--text2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{.Entry.FromAgent}} &rarr; {{.Entry.ToAgent}}</span>
  <a href="/dashboard/events/{{.Entry.ID}}" class="btn btn-sm btn-outline" style="font-size:var(--text-xs);white-space:nowrap;border-color:var(--accent-border);color:var(--accent-light)">Detail &rarr;</a>
  <button class="ed-close" onclick="closePanel()">&times;</button>
</div>
<div style="font-size:var(--text-sm);color:var(--text3);padding:var(--sp-2) var(--sp-5);border-bottom:1px solid var(--border);font-family:var(--mono)" data-ts="{{.Entry.Timestamp}}">{{.Entry.Timestamp}}</div>
<div class="ed-body">

  <!-- Message received -->
  <div class="ed-section">
    <div class="ed-slbl">Message received</div>
    <div class="ed-row"><span class="k">Event ID</span><span class="v" title="{{.Entry.ID}}">{{.Entry.ID}}</span></div>
    <div class="ed-row"><span class="k">From</span><span class="v"><a href="/dashboard/agents/{{.Entry.FromAgent}}">{{.Entry.FromAgent}}</a></span></div>
    <div class="ed-row"><span class="k">To</span><span class="v">{{if .Entry.ToolName}}{{toolDot .Entry.ToolName}}{{else}}{{.Entry.ToAgent}}{{end}}</span></div>
    <div class="ed-row"><span class="k">Latency</span><span class="v" style="color:var(--warn)">{{.Entry.LatencyMs}}ms</span></div>
    {{if .Entry.SessionID}}<div class="ed-row"><span class="k">Session</span><span class="v" title="{{.Entry.SessionID}}">{{truncate .Entry.SessionID 24}}</span></div>{{end}}
  </div>

  <!-- Pipeline -->
  <div class="ed-section">
    <div class="ed-slbl">Pipeline</div>
    <div class="ed-row"><span class="k">Identity</span><span class="v">{{if eq .Entry.SignatureVerified 1}}<span style="color:var(--success)">Verified</span>{{else if eq .Entry.SignatureVerified -1}}<span style="color:var(--danger)">Invalid</span>{{else}}{{if .RequireSig}}<span style="color:var(--danger)">Missing</span>{{else}}<span style="color:var(--text3)">Not required</span>{{end}}{{end}}</span></div>
    <div class="ed-row"><span class="k">Content scan</span><span class="v">{{if .Rules}}<span style="color:var(--warn);font-weight:600">{{len .Rules}} {{if eq (len .Rules) 1}}rule{{else}}rules{{end}} triggered</span>{{else}}<span style="color:var(--success)">Clean</span>{{end}} <span style="color:var(--text3);font-size:0.62rem">({{.RuleCount}})</span></span></div>
    <div class="ed-row"><span class="k">Verdict</span><span class="v">{{if eq .Entry.Status "delivered"}}<span style="color:var(--success)">Allowed</span>{{else if eq .Entry.Status "blocked"}}<span style="color:var(--danger);font-weight:600">Blocked</span>{{else if eq .Entry.Status "quarantined"}}<span style="color:var(--warn);font-weight:600">Quarantined</span>{{else}}<span style="color:var(--warn)">Rejected</span>{{end}}</span></div>
    {{if ge .LLMRiskScore 0.0}}<div class="ed-row"><span class="k">LLM risk</span><span class="v" style="{{if ge .LLMRiskScore 76.0}}color:#f85149{{else if ge .LLMRiskScore 51.0}}color:#fb923c{{else if ge .LLMRiskScore 31.0}}color:#d29922{{else}}color:var(--success){{end}}">{{printf "%.0f" .LLMRiskScore}} / 100{{if .LLMAction}} &middot; {{.LLMAction}}{{end}}</span></div>{{end}}
  </div>

  <!-- Rules triggered -->
  {{if .Rules}}
  <div class="ed-section">
    <div class="ed-slbl">Rules triggered ({{len .Rules}})</div>
    {{range .Rules}}
    <div style="display:flex;align-items:center;gap:var(--sp-2);padding:var(--sp-2) 0;font-size:var(--text-sm);border-bottom:1px solid var(--border-subtle)">
      {{if eq .Severity "CRITICAL"}}<span class="sev-critical">critical</span>
      {{else if eq .Severity "HIGH"}}<span class="sev-high">high</span>
      {{else if eq .Severity "MEDIUM"}}<span class="sev-medium">medium</span>
      {{else}}<span class="sev-low">{{.Severity}}</span>{{end}}
      <span style="font-family:var(--mono);font-weight:600;color:var(--text);font-size:var(--text-sm)">{{.RuleID}}</span>
      <span style="color:var(--text3);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:var(--text-sm)">{{.Name}}</span>
    </div>
    {{if .Match}}<div style="font-family:var(--mono);font-size:var(--text-xs);color:var(--text3);padding:2px 0 var(--sp-1);margin-left:var(--sp-1);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;opacity:0.7" title="{{.Match}}">{{truncate .Match 80}}</div>{{end}}
    {{end}}
  </div>
  {{end}}

  <!-- Forensics -->
  <div class="ed-section">
    <div class="ed-slbl">Forensics</div>
    {{if .Entry.ContentHash}}<div class="ed-row"><span class="k">Content hash</span><span class="v" title="{{.Entry.ContentHash}}">{{.Entry.ContentHash}}</span></div>{{end}}
    {{if .Entry.EntryHash}}<div class="ed-row"><span class="k">Chain hash</span><span class="v" title="{{.Entry.EntryHash}}">{{.Entry.EntryHash}}</span></div>{{end}}
    {{if .Entry.PubkeyFingerprint}}<div class="ed-row"><span class="k">Key fingerprint</span><span class="v" title="{{.Entry.PubkeyFingerprint}}">{{.Entry.PubkeyFingerprint}}</span></div>{{end}}
  </div>

  <!-- Agent -->
  <div class="ed-section">
    <div class="ed-slbl">Agent</div>
    <div class="ed-row"><span class="k">Name</span><span class="v"><a href="/dashboard/agents/{{.Entry.FromAgent}}">{{.Entry.FromAgent}}</a></span></div>
    {{if .AgentDesc}}<div class="ed-row"><span class="k">Description</span><span class="v" style="font-family:var(--sans)" title="{{.AgentDesc}}">{{truncate .AgentDesc 40}}</span></div>{{end}}
    {{if .ToolConstraintCount}}<div class="ed-row"><span class="k">Constraints</span><span class="v"><span style="color:var(--warn)">{{.ToolConstraintCount}} rules</span></span></div>{{end}}
    {{if .AgentSuspended}}<div class="ed-row"><span class="k">Status</span><span class="v"><span style="color:var(--danger);font-weight:600">Suspended</span></span></div>{{end}}
  </div>
</div>`))

// ciCSS is the shared CSS for "case investigation" style pages (Threat Intel, Event Detail).
const ciCSS = `
.ci-back{color:var(--text3);text-decoration:none;font-size:var(--text-sm);display:inline-flex;align-items:center;gap:6px;transition:color var(--ease-default);touch-action:manipulation}
.ci-back:hover{color:var(--accent-light)}
.ci-hdr{display:flex;align-items:flex-start;gap:var(--sp-5);margin-bottom:var(--sp-5)}
.ci-score{display:flex;flex-direction:column;align-items:center;justify-content:center;width:72px;height:72px;border-radius:var(--radius-xl);flex-shrink:0}
.ci-score .n{font-size:var(--text-2xl);font-weight:700;font-family:var(--sans);line-height:1;letter-spacing:-0.02em}
.ci-score .l{font-size:0.52rem;letter-spacing:0.6px;margin-top:var(--sp-1);opacity:0.7;font-weight:500}
.ci-hdr-body{flex:1;min-width:0}
.ci-title{font-size:var(--text-lg);font-weight:600;margin:0 0 var(--sp-2);line-height:1.4;color:var(--text);text-wrap:pretty}
.ci-hdr-row{display:flex;align-items:center;gap:var(--sp-2);flex-wrap:wrap;font-size:var(--text-sm);color:var(--text3)}
.ci-hdr-row .sep{color:var(--border)}
.ci-badge{display:inline-block;padding:var(--sp-1) 14px;border-radius:100px;font-size:var(--text-sm);font-weight:500;flex-shrink:0;align-self:center;letter-spacing:0.2px}
.ci-badge-blk{background:rgba(248,81,73,0.15);color:#f85149}
.ci-badge-inv{background:rgba(210,153,34,0.15);color:#d29922}
.ci-badge-qua{background:rgba(251,146,60,0.15);color:#fb923c}
.ci-badge-ok{background:var(--surface2);color:var(--text3)}
.ci-s{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-xl);padding:var(--sp-5) var(--sp-6);margin-bottom:var(--sp-5)}
.ci-s h3{font-size:var(--text-xs);font-weight:600;color:var(--text3);margin:0 0 var(--sp-4);text-transform:uppercase;letter-spacing:var(--ls-caps);display:flex;align-items:center;gap:var(--sp-2)}
.ci-s h3 .cnt{font-weight:500;font-family:var(--mono);text-transform:none}
.ci-context-row{display:grid;grid-template-columns:3fr 2fr;gap:var(--sp-5);align-items:start;margin-bottom:var(--sp-5)}
.ci-sev{display:inline-block;padding:2px var(--sp-2);border-radius:100px;font-size:0.6rem;font-weight:600;letter-spacing:0.3px}
.ci-sev-c{background:rgba(248,81,73,0.18);color:#f85149}
.ci-sev-h{background:rgba(251,146,60,0.18);color:#fb923c}
.ci-sev-m{background:rgba(210,153,34,0.18);color:#d29922}
.ci-sev-l{background:rgba(63,185,80,0.15);color:#3fb950}
.ci-thr{display:flex;align-items:flex-start;gap:var(--sp-3);padding:14px var(--sp-5);border-bottom:1px solid var(--border)}
.ci-thr:last-child{border-bottom:none}
.ci-thr-sev{flex-shrink:0;padding-top:2px}
.ci-thr-body{flex:1;min-width:0}
.ci-thr-head{display:flex;flex-direction:column;gap:var(--sp-1)}
.ci-thr-id{font-family:var(--mono);font-size:var(--text-sm);font-weight:600;color:var(--text2);text-transform:uppercase}
.ci-thr-name{font-size:var(--text-base);color:var(--text);font-weight:500;line-height:1.55}
.ci-thr-detail{font-size:var(--text-sm);color:var(--text3);margin-top:var(--sp-2);line-height:1.6}
.ci-benign{display:flex;align-items:center;gap:10px;color:var(--success);font-size:var(--text-md);padding:var(--sp-3) var(--sp-5)}
.ci-meta-row{display:flex;justify-content:space-between;align-items:baseline;padding:var(--sp-2) 0;border-bottom:1px solid var(--border-subtle);font-size:var(--text-sm)}
.ci-meta-row:last-child{border-bottom:none}
.ci-meta-row .mk{color:var(--text3);font-weight:500}
.ci-meta-row .mv{font-family:var(--mono);color:var(--text2);font-size:var(--text-sm);text-align:right;word-break:break-all}
@media(max-width:960px){.ci-context-row{grid-template-columns:1fr}.ci-hdr{flex-direction:column;gap:14px}.ci-s{padding:var(--sp-4) var(--sp-4)}}
`

var eventPageTmpl = template.Must(template.New("event-page").Funcs(tmplFuncs).Parse(layoutHead + `
<style>
.ep-back{color:var(--text3);text-decoration:none;font-size:var(--text-sm);display:inline-flex;align-items:center;gap:6px;transition:color var(--ease-default)}
.ep-back:hover{color:var(--accent-light)}
.ep-grid{display:grid;grid-template-columns:1fr 1fr;gap:var(--sp-5);align-items:start}
.ep-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-xl);overflow:hidden}
.ep-sec{border-bottom:1px solid var(--border);padding:var(--sp-5) var(--sp-6)}
.ep-sec:last-child{border-bottom:none}
.ep-slbl{font-size:var(--text-xs);font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:var(--ls-caps);margin-bottom:var(--sp-3);display:flex;align-items:center;gap:var(--sp-2)}
.ep-row{display:flex;justify-content:space-between;align-items:baseline;padding:var(--sp-2) 0;font-size:var(--text-base);border-bottom:1px solid var(--border-subtle)}
.ep-row:last-child{border-bottom:none}
.ep-row .k{color:var(--text3);flex-shrink:0;font-size:var(--text-sm)}
.ep-row .v{font-family:var(--mono);font-size:var(--text-sm);color:var(--text);text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-left:var(--sp-3)}
.ep-row .v a{color:var(--accent-light)}
.ep-rule{display:flex;align-items:center;gap:var(--sp-2);padding:var(--sp-2) 0;font-size:var(--text-sm);border-bottom:1px solid var(--border)}
.ep-rule:last-child{border-bottom:none}
.ep-rule-id{font-family:var(--mono);font-weight:600;color:var(--text);font-size:var(--text-sm)}
.ep-rule-name{color:var(--text3);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:var(--text-sm)}
.ep-rule-match{font-family:var(--mono);font-size:var(--text-xs);color:var(--text3);padding:2px 0 var(--sp-1);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ep-content{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:var(--sp-4) var(--sp-5);font-family:var(--mono);font-size:var(--text-sm);line-height:1.7;color:var(--text2);white-space:pre-wrap;word-break:break-all;max-height:400px;overflow-y:auto}
@media(max-width:960px){.ep-grid{grid-template-columns:1fr}}
</style>

<p style="margin-bottom:16px"><a href="/dashboard/events" class="ep-back">&larr; Event Log</a></p>

<!-- Header -->
<div style="display:flex;align-items:center;gap:14px;margin-bottom:20px">
  {{if eq .Entry.Status "delivered"}}<span class="badge-delivered" style="font-size:0.82rem;padding:4px 14px">delivered</span>
  {{else if eq .Entry.Status "blocked"}}<span class="badge-blocked" style="font-size:0.82rem;padding:4px 14px">blocked</span>
  {{else if eq .Entry.Status "rejected"}}<span class="badge-rejected" style="font-size:0.82rem;padding:4px 14px">rejected</span>
  {{else if eq .Entry.Status "quarantined"}}<span class="badge-quarantined" style="font-size:0.82rem;padding:4px 14px">quarantined</span>
  {{else}}<span style="color:var(--text2)">{{.Entry.Status}}</span>{{end}}
  <span style="font-family:var(--mono);font-size:0.78rem;color:var(--text2)">{{.Entry.FromAgent}} &rarr; {{.Entry.ToAgent}}</span>
  <span style="margin-left:auto;font-size:0.72rem;color:var(--text3);font-family:var(--mono)" data-ts="{{.Entry.Timestamp}}">{{relativeTime .Entry.Timestamp}}</span>
</div>

<div class="ep-grid">
  <!-- LEFT -->
  <div>
    <div class="ep-card" style="margin-bottom:20px">
      <!-- Message -->
      <div class="ep-sec">
        <div class="ep-slbl">Message</div>
        <div class="ep-row"><span class="k">From</span><span class="v"><a href="/dashboard/agents/{{.Entry.FromAgent}}">{{.Entry.FromAgent}}</a>{{if .AgentSuspended}} <span style="color:var(--danger);font-size:0.58rem;font-weight:600">SUSPENDED</span>{{end}}</span></div>
        <div class="ep-row"><span class="k">To</span><span class="v">{{if .Entry.ToolName}}{{toolDot .Entry.ToolName}}{{else}}{{.Entry.ToAgent}}{{end}}</span></div>
        <div class="ep-row"><span class="k">Latency</span><span class="v" style="color:var(--warn)">{{.Entry.LatencyMs}}ms</span></div>
        {{if .Entry.SessionID}}<div class="ep-row"><span class="k">Session</span><span class="v" title="{{.Entry.SessionID}}">{{truncate .Entry.SessionID 24}}</span></div>{{end}}
        <div class="ep-row"><span class="k">Decision</span><span class="v" style="color:var(--success);font-family:var(--sans)">{{.Decision}}</span></div>
      </div>

      <!-- Pipeline -->
      <div class="ep-sec">
        <div class="ep-slbl">Security pipeline</div>
        <div class="ep-row"><span class="k">Identity</span><span class="v">{{if eq .Entry.SignatureVerified 1}}<span style="color:var(--success)">Verified</span>{{else if eq .Entry.SignatureVerified -1}}<span style="color:var(--danger)">Invalid</span>{{else}}{{if .RequireSig}}<span style="color:var(--danger)">Missing</span>{{else}}<span style="color:var(--text3)">Not required</span>{{end}}{{end}}</span></div>
        <div class="ep-row"><span class="k">Content scan</span><span class="v">{{if .Rules}}<span style="color:var(--warn)">{{len .Rules}} triggered</span>{{else}}<span style="color:var(--success)">Clean</span>{{end}} <span style="color:var(--text3);font-size:0.62rem">/{{.RuleCount}}</span></span></div>
        <div class="ep-row"><span class="k">Verdict</span><span class="v">{{if eq .Entry.Status "delivered"}}<span style="color:var(--success)">Allowed</span>{{else if eq .Entry.Status "blocked"}}<span style="color:var(--danger)">Blocked</span>{{else if eq .Entry.Status "quarantined"}}<span style="color:var(--warn)">Quarantined</span>{{else}}<span style="color:var(--warn)">Rejected</span>{{end}}</span></div>
        {{if ge .LLMRiskScore 0.0}}<div class="ep-row"><span class="k">LLM risk</span><span class="v" style="{{if ge .LLMRiskScore 76.0}}color:#f85149{{else if ge .LLMRiskScore 51.0}}color:#fb923c{{else if ge .LLMRiskScore 31.0}}color:#d29922{{else}}color:var(--success){{end}}">{{printf "%.0f" .LLMRiskScore}}/100{{if .LLMAction}} &middot; {{.LLMAction}}{{end}}</span></div>{{end}}
      </div>

      <!-- Rules -->
      {{if .Rules}}
      <div class="ep-sec">
        <div class="ep-slbl">Rules triggered <span style="font-weight:500;font-family:var(--mono);text-transform:none;letter-spacing:0">({{len .Rules}})</span></div>
        {{range .Rules}}
        <div class="ep-rule">
          {{if eq .Severity "CRITICAL"}}<span class="sev-critical" style="font-size:0.58rem">critical</span>
          {{else if eq .Severity "HIGH"}}<span class="sev-high" style="font-size:0.58rem">high</span>
          {{else if eq .Severity "MEDIUM"}}<span class="sev-medium" style="font-size:0.58rem">medium</span>
          {{else}}<span class="sev-low" style="font-size:0.58rem">{{.Severity}}</span>{{end}}
          <span class="ep-rule-id">{{.RuleID}}</span>
          <span class="ep-rule-name">{{.Name}}</span>
          <a href="/dashboard/rules/{{.Category}}" style="color:var(--text3);text-decoration:none;font-size:0.82rem">&rsaquo;</a>
        </div>
        {{if .Match}}<div class="ep-rule-match" title="{{.Match}}">{{.Match}}</div>{{end}}
        {{end}}
      </div>
      {{end}}
    </div>

  </div>

  <!-- RIGHT -->
  <div>
    <!-- Intercepted content -->
    {{if .Entry.Intent}}
    <div class="ep-card" style="margin-bottom:20px">
      <div class="ep-sec">
        <div class="ep-slbl">Intercepted content</div>
        <div class="ep-content">{{.Entry.Intent}}</div>
      </div>
    </div>
    {{end}}

    <div class="ep-card" style="margin-bottom:20px">
      <!-- Agent -->
      <div class="ep-sec">
        <div class="ep-slbl">Agent</div>
        <div class="ep-row"><span class="k">Name</span><span class="v"><a href="/dashboard/agents/{{.Entry.FromAgent}}">{{.Entry.FromAgent}}</a></span></div>
        {{if .AgentDesc}}<div class="ep-row"><span class="k">Description</span><span class="v" style="font-family:var(--sans)" title="{{.AgentDesc}}">{{.AgentDesc}}</span></div>{{end}}
        {{if .AgentLocation}}<div class="ep-row"><span class="k">Location</span><span class="v">{{.AgentLocation}}</span></div>{{end}}
        {{if .AgentCreatedBy}}<div class="ep-row"><span class="k">Origin</span><span class="v" style="font-family:var(--sans)">{{.AgentCreatedBy}}</span></div>{{end}}
        {{if .ToolConstraintCount}}<div class="ep-row"><span class="k">Constraints</span><span class="v"><span style="color:var(--warn)">{{.ToolConstraintCount}} rules</span></span></div>{{end}}
      </div>

      <!-- Forensics -->
      <div class="ep-sec">
        <div class="ep-slbl">Forensics</div>
        <div class="ep-row"><span class="k">Event ID</span><span class="v" title="{{.Entry.ID}}">{{.Entry.ID}}</span></div>
        {{if .Entry.ContentHash}}<div class="ep-row"><span class="k">Content hash</span><span class="v" title="{{.Entry.ContentHash}}">{{.Entry.ContentHash}}</span></div>{{end}}
        {{if .Entry.EntryHash}}<div class="ep-row"><span class="k">Chain hash</span><span class="v" title="{{.Entry.EntryHash}}">{{.Entry.EntryHash}}</span></div>{{end}}
        {{if .Entry.PubkeyFingerprint}}<div class="ep-row"><span class="k">Key</span><span class="v" title="{{.Entry.PubkeyFingerprint}}">{{.Entry.PubkeyFingerprint}}</span></div>{{end}}
      </div>
    </div>

    <!-- LLM Analysis -->
    {{if .LLMAnalysis}}
    <div class="ep-card">
      <div class="ep-sec">
        <div class="ep-slbl">LLM Analysis <a href="/dashboard/llm/{{.LLMAnalysis.ID}}" style="margin-left:auto;font-size:0.72rem;color:var(--accent-light);text-decoration:none;font-weight:400;text-transform:none;letter-spacing:0">Full analysis &rarr;</a></div>
        <div class="ep-row"><span class="k">Risk</span><span class="v" style="{{if ge .LLMAnalysis.RiskScore 76.0}}color:#f85149{{else if ge .LLMAnalysis.RiskScore 51.0}}color:#fb923c{{else if ge .LLMAnalysis.RiskScore 31.0}}color:#d29922{{else}}color:var(--success){{end}}">{{printf "%.0f" .LLMAnalysis.RiskScore}} / 100</span></div>
        <div class="ep-row"><span class="k">Confidence</span><span class="v">{{printf "%.0f" .LLMAnalysis.Confidence}}%</span></div>
        <div class="ep-row"><span class="k">Action</span><span class="v" style="font-family:var(--sans)">{{.LLMAnalysis.RecommendedAction}}</span></div>
        <div class="ep-row"><span class="k">Model</span><span class="v">{{.LLMAnalysis.Model}}</span></div>
      </div>
    </div>
    {{end}}
  </div>
</div>
` + layoutFoot))

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
  {{if .CustomRulesDir}}No custom rules in {{.CustomRulesDir}}.{{else}}Set <code style="color:var(--accent-light)">custom_rules_dir</code> in oktsec.yaml to enable custom rules.{{end}}
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
    {{if eq .Item.Status "pending"}}background:rgba(210,153,34,0.08);border:1px solid rgba(210,153,34,0.2);color:var(--warn)
    {{else if eq .Item.Status "approved"}}background:rgba(63,185,80,0.08);border:1px solid rgba(63,185,80,0.2);color:var(--success)
    {{else if eq .Item.Status "rejected"}}background:rgba(248,81,73,0.08);border:1px solid rgba(248,81,73,0.2);color:var(--danger)
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

  {{if eq .Item.Status "pending"}}
  <div class="q-actions" style="margin-top:20px">
    <button class="btn btn-success" hx-post="/dashboard/api/quarantine/{{.Item.ID}}/approve" hx-target="#q-row-{{.Item.ID}}" hx-swap="outerHTML" onclick="closePanel()">Approve &amp; Deliver</button>
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
<style>
.st-grid{display:grid;grid-template-columns:1fr 1fr;gap:var(--sp-4);align-items:start}
.st-grid .card{margin-bottom:0}
.st-span{grid-column:1 / -1}
@media(max-width:960px){.st-grid{grid-template-columns:1fr}.st-span{grid-column:auto}}
</style>
<p class="page-desc">How oktsec protects your agents, verifies their identity, and handles threats.</p>

<div class="tabs" data-tab-group="settings">
  <a href="/dashboard/settings?tab=security" class="tab {{if eq .Tab "security"}}active{{end}}">Security</a>
  <a href="/dashboard/settings?tab=identity" class="tab {{if eq .Tab "identity"}}active{{end}}">Identity</a>
  <a href="/dashboard/settings?tab=pipeline" class="tab {{if eq .Tab "pipeline"}}active{{end}}">Pipeline</a>
  <a href="/dashboard/settings?tab=infra" class="tab {{if eq .Tab "infra"}}active{{end}}">Infrastructure</a>
</div>

<!-- Security -->
<div class="tab-content {{if eq .Tab "security"}}active{{end}}" data-tab-content="settings" data-tab-name="security">

<div class="card">
  <h2>Security Mode</h2>
  <p class="desc">
    The most important setting. Determines whether agents must prove their identity before sending messages.
  </p>
  <div style="display:flex;gap:16px;margin-bottom:16px">
    <div style="flex:1;padding:16px;border-radius:8px;border:1px solid {{if .RequireSig}}var(--accent){{else}}var(--border){{end}};background:{{if .RequireSig}}rgba(99,102,241,0.06){{else}}var(--surface){{end}}">
      <div style="font-weight:600;font-size:0.88rem;margin-bottom:6px;color:{{if .RequireSig}}var(--accent-light){{else}}var(--text2){{end}}">
        {{if .RequireSig}}&#x2713; {{end}}Enforce Mode
      </div>
      <p style="color:var(--text3);font-size:0.78rem;line-height:1.5">
        Every message must be signed. Unsigned or tampered messages are <strong style="color:var(--danger)">rejected</strong>. Recommended for production.
      </p>
    </div>
    <div style="flex:1;padding:16px;border-radius:8px;border:1px solid {{if not .RequireSig}}var(--warn){{else}}var(--border){{end}};background:{{if not .RequireSig}}rgba(210,153,34,0.06){{else}}var(--surface){{end}}">
      <div style="font-weight:600;font-size:0.88rem;margin-bottom:6px;color:{{if not .RequireSig}}var(--warn){{else}}var(--text2){{end}}">
        {{if not .RequireSig}}&#x2713; {{end}}Observe Mode
      </div>
      <p style="color:var(--text3);font-size:0.78rem;line-height:1.5">
        Messages are scanned but signatures are <strong style="color:var(--warn)">not required</strong>. Good for getting started and onboarding agents.
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
  <h2>Default Policy</h2>
  <p class="desc">
    Who can talk to whom. When set to <strong>deny</strong>, agents can only message targets you've explicitly allowed.
  </p>
  <div style="display:flex;gap:16px;margin-bottom:16px">
    <div style="flex:1;padding:16px;border-radius:8px;border:1px solid {{if eq .DefaultPolicy "deny"}}var(--accent){{else}}var(--border){{end}};background:{{if eq .DefaultPolicy "deny"}}rgba(99,102,241,0.06){{else}}var(--surface){{end}}">
      <div style="font-weight:600;font-size:0.88rem;margin-bottom:6px;color:{{if eq .DefaultPolicy "deny"}}var(--accent-light){{else}}var(--text2){{end}}">
        {{if eq .DefaultPolicy "deny"}}&#x2713; {{end}}Default Deny
      </div>
      <p style="color:var(--text3);font-size:0.78rem;line-height:1.5">
        Agents can only communicate with explicitly allowed targets. Recommended for <strong style="color:var(--accent-light)">production</strong>.
      </p>
    </div>
    <div style="flex:1;padding:16px;border-radius:8px;border:1px solid {{if ne .DefaultPolicy "deny"}}var(--warn){{else}}var(--border){{end}};background:{{if ne .DefaultPolicy "deny"}}rgba(210,153,34,0.06){{else}}var(--surface){{end}}">
      <div style="font-weight:600;font-size:0.88rem;margin-bottom:6px;color:{{if ne .DefaultPolicy "deny"}}var(--warn){{else}}var(--text2){{end}}">
        {{if ne .DefaultPolicy "deny"}}&#x2713; {{end}}Default Allow
      </div>
      <p style="color:var(--text3);font-size:0.78rem;line-height:1.5">
        All agents can message each other unless explicitly denied. <strong style="color:var(--warn)">Open</strong> — useful during onboarding.
      </p>
    </div>
  </div>
  <form method="POST" action="/dashboard/settings/default-policy">
    <input type="hidden" name="default_policy" value="{{if eq .DefaultPolicy "deny"}}allow{{else}}deny{{end}}">
    <button type="submit" class="btn" style="background:{{if eq .DefaultPolicy "deny"}}var(--warn){{else}}var(--accent){{end}}">
      Switch to Default {{if eq .DefaultPolicy "deny"}}Allow{{else}}Deny{{end}}
    </button>
  </form>
</div>

</div>

<!-- Identity -->
<div class="tab-content {{if eq .Tab "identity"}}active{{end}}" data-tab-content="settings" data-tab-name="identity">

<div class="card">
  <h2>Agent Keys</h2>
  <p class="desc">
    Each agent has a signing key to prove its identity. Public keys are stored here; agents hold their private keys. Revoke a key to immediately block an agent.
  </p>
  <div style="color:var(--text3);font-size:0.78rem;margin-bottom:12px">
    <strong>Keys directory:</strong> <code style="background:var(--surface);padding:2px 8px;border-radius:4px;font-family:var(--mono);font-size:0.75rem;color:var(--accent-light)">{{.KeysDir}}</code>
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

</div>

<!-- Pipeline -->
<div class="tab-content {{if eq .Tab "pipeline"}}active{{end}}" data-tab-content="settings" data-tab-name="pipeline">

<div class="st-grid">

<div class="card">
  <h2>Quarantine</h2>
  <p class="desc">
    Hold suspicious messages for human review before they reach the destination agent.
  </p>
  <form method="POST" action="/dashboard/settings/quarantine">
    <div style="display:flex;align-items:center;gap:16px;margin-bottom:20px">
      <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
        <span class="toggle"><input type="checkbox" name="enabled" value="true" {{if .QEnabled}}checked{{end}}><span class="toggle-slider"></span></span>
        <span style="font-size:0.85rem;color:var(--text2)">Enable quarantine</span>
      </label>
      {{if .QPending}}<span style="font-family:var(--mono);font-size:0.82rem;color:var(--warn);font-weight:600">{{.QPending}} pending</span>{{end}}
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>Review window (hours)</label>
        <input type="number" name="expiry_hours" value="{{.QExpiryHours}}" min="1">
      </div>
      <div class="form-group">
        <label>Keep history (days)</label>
        <input type="number" name="retention_days" value="{{.QRetentionDays}}" min="0">
      </div>
    </div>
    <button type="submit" class="btn btn-sm">Save</button>
  </form>
</div>

<div class="card">
  <h2>Behavior Monitoring</h2>
  <p class="desc">
    Track agent behavior over time and flag unusual patterns like sudden traffic spikes or new communication pairs.
  </p>
  <form method="POST" action="/dashboard/settings/anomaly">
    <div style="margin-bottom:20px">
      <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
        <span class="toggle"><input type="checkbox" name="auto_suspend" value="true" {{if .AnomalyAutoSuspend}}checked{{end}}><span class="toggle-slider"></span></span>
        <span style="font-size:0.85rem;color:var(--text2)">Auto-suspend risky agents</span>
      </label>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>Check every (seconds)</label>
        <input type="number" name="check_interval" value="{{if .AnomalyCheckInterval}}{{.AnomalyCheckInterval}}{{else}}60{{end}}" min="1">
      </div>
      <div class="form-group">
        <label>Risk threshold (0-100)</label>
        <input type="number" name="risk_threshold" value="{{printf "%.1f" .AnomalyRiskThreshold}}" min="0" max="100" step="0.1">
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>Min messages before scoring</label>
        <input type="number" name="min_messages" value="{{.AnomalyMinMessages}}" min="0">
      </div>
    </div>
    <button type="submit" class="btn btn-sm">Save</button>
  </form>
</div>

<div class="card">
  <h2>Message Limits</h2>
  <p class="desc">
    Prevent agents from flooding the system. Each agent gets a maximum number of messages per time window.
  </p>
  <form method="POST" action="/dashboard/settings/rate-limit">
    <div class="form-row">
      <div class="form-group">
        <label>Max messages per agent</label>
        <input type="number" name="per_agent" value="{{.RateLimitPerAgent}}" min="0">
      </div>
      <div class="form-group">
        <label>Time window (seconds)</label>
        <input type="number" name="window" value="{{if .RateLimitWindow}}{{.RateLimitWindow}}{{else}}60{{end}}" min="1">
      </div>
    </div>
    <button type="submit" class="btn btn-sm">Save</button>
  </form>
</div>

<div class="card">
  <h2>Intent Checks</h2>
  <p class="desc">
    Agents declare what they're doing (e.g. "code review", "deploy"). oktsec checks that the message content matches.
  </p>
  <form method="POST" action="/dashboard/settings/intent">
    <div style="margin-bottom:20px">
      <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
        <span class="toggle"><input type="checkbox" name="require_intent" value="true" {{if .RequireIntent}}checked{{end}}><span class="toggle-slider"></span></span>
        <span style="font-size:0.85rem;color:var(--text2)">Require intent on every message</span>
      </label>
    </div>
    <div style="color:var(--text3);font-size:0.78rem;margin-bottom:12px">
      <strong>Available:</strong>
      <span style="font-family:var(--mono);font-size:0.72rem;color:var(--text2)">code_review, deploy, data_query, monitoring, security, communication, file_ops, config</span>
    </div>
    <button type="submit" class="btn btn-sm">Save</button>
  </form>
</div>

</div><!-- /pipeline grid -->

</div>

<!-- Infrastructure -->
<div class="tab-content {{if eq .Tab "infra"}}active{{end}}" data-tab-content="settings" data-tab-name="infra">

<div class="st-grid">

<div class="card">
  <h2>Notifications</h2>
  <p class="desc">
    Get notified when oktsec blocks or quarantines a message. Add webhook URLs for Slack, email, or any HTTP endpoint.
  </p>

  <form method="POST" action="/dashboard/settings/webhooks" style="margin-bottom:20px">
    <div class="form-row">
      <div class="form-group" style="flex:1;min-width:140px">
        <label>Channel name</label>
        <input type="text" name="name" placeholder="e.g. slack-security" required pattern="[a-zA-Z0-9][a-zA-Z0-9_-]*">
      </div>
      <div class="form-group" style="flex:3">
        <label>Webhook URL</label>
        <input type="url" name="url" placeholder="https://hooks.slack.com/services/..." required>
      </div>
      <div class="form-group" style="align-self:flex-end">
        <button type="submit" class="btn">Add</button>
      </div>
    </div>
  </form>

  {{if .WebhookChannels}}
  <table>
    <thead><tr><th>Channel</th><th>URL</th><th></th></tr></thead>
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
  <div class="empty">No notification channels yet. Add one above to receive alerts.</div>
  {{end}}
</div>

<div class="card">
  <h2>Outbound Traffic</h2>
  <p class="desc">
    Control which external services agents can reach and scan their HTTP traffic for data leaks.
  </p>
  <form method="POST" action="/dashboard/settings/forward-proxy">
    <div style="display:flex;gap:32px;margin-bottom:20px;flex-wrap:wrap">
      <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
        <span class="toggle"><input type="checkbox" name="enabled" value="true" {{if .FPEnabled}}checked{{end}}><span class="toggle-slider"></span></span>
        <span style="font-size:0.85rem;color:var(--text2)">Enable proxy</span>
      </label>
      <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
        <span class="toggle"><input type="checkbox" name="scan_requests" value="true" {{if .FPScanRequests}}checked{{end}}><span class="toggle-slider"></span></span>
        <span style="font-size:0.85rem;color:var(--text2)">Scan outgoing</span>
      </label>
      <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
        <span class="toggle"><input type="checkbox" name="scan_responses" value="true" {{if .FPScanResponses}}checked{{end}}><span class="toggle-slider"></span></span>
        <span style="font-size:0.85rem;color:var(--text2)">Scan incoming</span>
      </label>
    </div>
    <div class="form-row">
      <div class="form-group" style="flex:1">
        <label>Allowed domains (one per line)</label>
        <textarea name="allowed_domains" rows="3" style="font-family:var(--mono);font-size:0.82rem" placeholder="api.example.com">{{.FPAllowedDomains}}</textarea>
      </div>
      <div class="form-group" style="flex:1">
        <label>Blocked domains (one per line)</label>
        <textarea name="blocked_domains" rows="3" style="font-family:var(--mono);font-size:0.82rem" placeholder="evil.com">{{.FPBlockedDomains}}</textarea>
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>Max body size (bytes)</label>
        <input type="number" name="max_body_size" value="{{.FPMaxBodySize}}" min="0">
      </div>
    </div>
    <button type="submit" class="btn btn-sm">Save</button>
  </form>
</div>

<div class="card st-span">
  <h2>Server Info</h2>
  <p class="desc">
    Current proxy configuration. Changes to these settings require a restart.
  </p>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:0">
    <div style="display:flex;align-items:baseline;gap:8px;padding:10px 0;border-bottom:1px solid var(--border)">
      <span style="color:var(--text3);font-weight:600;font-size:0.82rem;min-width:140px">Port</span>
      <span style="font-family:var(--mono);font-size:0.82rem">{{.ServerPort}}</span>
    </div>
    <div style="display:flex;align-items:baseline;gap:8px;padding:10px 0;border-bottom:1px solid var(--border)">
      <span style="color:var(--text3);font-weight:600;font-size:0.82rem;min-width:140px">Bind address</span>
      <span style="font-family:var(--mono);font-size:0.82rem">{{.ServerBind}}</span>
    </div>
    <div style="display:flex;align-items:baseline;gap:8px;padding:10px 0;border-bottom:1px solid var(--border)">
      <span style="color:var(--text3);font-weight:600;font-size:0.82rem;min-width:140px">Log level</span>
      <span style="font-family:var(--mono);font-size:0.82rem">{{.LogLevel}}</span>
    </div>
    <div style="display:flex;align-items:baseline;gap:8px;padding:10px 0;border-bottom:1px solid var(--border)">
      <span style="color:var(--text3);font-weight:600;font-size:0.82rem;min-width:140px">Custom rules</span>
      <span style="font-family:var(--mono);font-size:0.82rem">{{if .CustomRulesDir}}{{.CustomRulesDir}}{{else}}<span style="color:var(--text3)">default only</span>{{end}}</span>
    </div>
    <div style="display:flex;align-items:baseline;gap:8px;padding:10px 0">
      <span style="color:var(--text3);font-weight:600;font-size:0.82rem;min-width:140px">Notifications</span>
      <span style="font-family:var(--mono);font-size:0.82rem">{{.WebhookCount}} channel{{if ne .WebhookCount 1}}s{{end}}</span>
    </div>
  </div>
</div>

</div><!-- /infra grid -->

</div>

</div>
` + layoutFoot))

// --- LLM Analysis page ---

var llmTmpl = template.Must(template.New("llm").Funcs(tmplFuncs).Parse(layoutHead + `
<style>
/* ── Triage bar ── */
.tq-bar{display:flex;align-items:center;gap:0;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-xl);padding:var(--sp-5) var(--sp-6);margin-bottom:var(--sp-6)}
.tq-seg{display:flex;align-items:center;gap:10px;flex:1;min-width:0}
.tq-num{font-size:var(--text-2xl);font-weight:700;font-family:var(--sans);line-height:1;letter-spacing:var(--ls-tight);font-variant-numeric:tabular-nums;color:var(--text)}
.tq-label{font-size:var(--text-sm);color:var(--text3);font-weight:500;white-space:nowrap}
.tq-pill{font-size:0.62rem;padding:2px 8px;border-radius:100px;font-weight:500;white-space:nowrap}
.tq-pill-c{background:rgba(248,81,73,0.1);color:#f85149}
.tq-pill-m{background:rgba(210,153,34,0.08);color:#d29922}
.tq-div{width:1px;height:36px;background:var(--border);margin:0 20px;flex-shrink:0}

/* ── Triage table ── */
.tq-filters{display:flex;gap:var(--sp-2);margin-bottom:var(--sp-3);flex-wrap:wrap;align-items:center}
.tq-filters select,.tq-filters input{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:var(--radius-md);font-size:var(--text-sm);font-family:var(--sans)}
.tq-table{width:100%;border-collapse:collapse}
.tq-table th{font-size:var(--text-xs);text-transform:uppercase;letter-spacing:var(--ls-caps);color:var(--text3);font-weight:500;text-align:left;padding:var(--sp-2) var(--sp-3);border-bottom:2px solid var(--border)}
.tq-table td{padding:10px var(--sp-3);border-bottom:1px solid var(--border);font-size:var(--text-sm);font-family:var(--sans)}
.tq-table tr.tq-row{cursor:pointer;transition:background 0.1s}
.tq-table tr.tq-row:hover{background:var(--surface-hover)}
.tq-table tr.tq-dismissed{opacity:0.5}
.tq-table tr.tq-dismissed:hover{opacity:0.8}
.tq-risk{display:inline-flex;align-items:center;justify-content:center;width:36px;height:28px;border-radius:var(--radius-md);font-family:var(--sans);font-weight:700;font-size:var(--text-sm)}
.tq-pager{display:flex;align-items:center;justify-content:space-between;padding:12px 0;font-size:0.78rem;color:var(--text3)}
.tq-pager button{background:var(--bg);border:1px solid var(--border);color:var(--text2);padding:var(--sp-1) var(--sp-3);border-radius:var(--radius-md);cursor:pointer;font-size:var(--text-sm);font-family:var(--sans);transition:all var(--ease-smooth)}
.tq-pager button:hover:not(:disabled){background:var(--surface-hover)}
.tq-pager button:disabled{opacity:0.3;cursor:default}
.tq-action{padding:3px 10px;border-radius:100px;font-size:var(--text-xs);font-weight:600;text-transform:uppercase;letter-spacing:0.3px}
.tq-action.block{background:rgba(248,81,73,0.12);color:#f85149}
.tq-action.investigate{background:rgba(210,153,34,0.12);color:#d29922}
.tq-action.quarantine{background:rgba(251,146,60,0.12);color:#fb923c}
.tq-action.monitor,.tq-action.allow{background:var(--surface2);color:var(--text3)}
.tq-status{padding:3px 10px;border-radius:100px;font-size:var(--text-xs);font-weight:600;text-transform:uppercase;letter-spacing:0.3px}
.tq-status.new{background:rgba(99,102,241,0.12);color:var(--accent-light)}
.tq-status.dismissed{background:rgba(63,185,80,0.08);color:#3fb950}
.tq-status.confirmed{background:rgba(248,81,73,0.08);color:#f85149}
@media(max-width:768px){.tq-bar{flex-direction:column;gap:12px;align-items:flex-start}.tq-div{width:100%;height:1px;margin:0}}
.llm-grid{display:grid;grid-template-columns:1fr 1fr;gap:var(--sp-4);margin-bottom:var(--sp-4)}
.llm-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-xl);padding:var(--sp-5)}
.llm-card h3{font-size:var(--text-xs);letter-spacing:var(--ls-caps);color:var(--text3);margin-bottom:var(--sp-4);font-weight:600;text-transform:uppercase}
.llm-row{display:flex;justify-content:space-between;align-items:baseline;padding:var(--sp-2) 0;border-bottom:1px solid var(--border)}
.llm-row:last-child{border-bottom:none}
.llm-row .k{font-size:var(--text-base);color:var(--text2)}
.llm-row .v{font-family:var(--mono);font-weight:600;font-size:var(--text-md)}
.prov-opt{position:relative;flex:1;padding:16px;border-radius:8px;border:2px solid var(--border);cursor:pointer;transition:border-color 0.15s,background 0.15s;text-align:center}
.prov-opt:hover{border-color:var(--text3)}
.prov-opt:focus-within{outline:2px solid var(--accent);outline-offset:2px}
.prov-opt.sel{border-color:var(--accent);background:rgba(99,102,241,0.06)}
.prov-opt .pname{font-weight:600;font-size:0.88rem;margin-bottom:2px}
.prov-opt .pdesc{font-size:0.7rem;color:var(--text3);line-height:1.4}
.fw-step{display:flex;align-items:center;gap:6px;font-size:0.78rem;color:var(--text2)}
.fw-step .num{width:20px;height:20px;border-radius:50%;background:var(--accent);color:#fff;display:flex;align-items:center;justify-content:center;font-size:0.65rem;font-weight:700;flex-shrink:0}
.fw-arrow{color:var(--text3);font-size:0.7rem;flex-shrink:0}
.llm-tabs{display:flex;gap:0;border-bottom:2px solid var(--border);margin-bottom:var(--sp-5)}
.llm-tab{padding:10px var(--sp-5);font-size:var(--text-sm);font-weight:500;color:var(--text3);cursor:pointer;border:none;background:none;border-bottom:2px solid transparent;margin-bottom:-2px;transition:color var(--ease-default),border-color var(--ease-default)}
.llm-tab:hover{color:var(--text2)}
.llm-tab:focus-visible{outline:2px solid var(--accent);outline-offset:-2px;border-radius:2px}
.llm-tab.active{color:var(--text);border-bottom-color:var(--accent);font-weight:600}
.llm-tab-panel{display:none}
.llm-tab-panel.active{display:block}
.llm-status-bar{display:flex;align-items:center;gap:var(--sp-4);padding:var(--sp-3) var(--sp-5);background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-xl);margin-bottom:var(--sp-5);font-size:var(--text-sm);flex-wrap:wrap}
.llm-status-bar .dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.llm-conn-adv{display:none}
.llm-conn-adv.open{display:block}
.llm-adv-btn{display:flex;align-items:center;gap:6px;cursor:pointer;padding:10px 0 0 0;font-size:0.75rem;color:var(--text3);border:none;background:none;font-weight:500}
.llm-adv-btn:hover{color:var(--text2)}
.llm-adv-btn:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
.llm-adv-btn .arr{transition:transform 0.15s;font-size:0.6rem}
.llm-adv-btn .arr.open{transform:rotate(90deg)}
@media(max-width:768px){.llm-hero{grid-template-columns:repeat(2,1fr)}.llm-grid{grid-template-columns:1fr}}
</style>

<p class="page-desc">AI analysis catches threats that rules alone can't see. Runs async, never slows the pipeline.</p>

{{if not .Enabled}}
<!-- Setup state -->
<div class="card">
  <h2 style="font-size:1rem;margin-bottom:12px">Enable AI-Powered Detection</h2>
  <p style="color:var(--text2);font-size:0.82rem;line-height:1.6;margin-bottom:8px">
    oktsec's 188 rules catch known threats instantly. Add an AI layer to detect what patterns miss:
  </p>
  <ul style="color:var(--text2);font-size:0.82rem;line-height:1.8;margin:0 0 20px 18px;padding:0">
    <li>Semantic data exfiltration disguised as normal messages</li>
    <li>Social engineering between agents</li>
    <li>Intent drift (agent doing something it shouldn't)</li>
    <li>Auto-generates new detection rules from findings</li>
  </ul>

  <form method="POST" action="/dashboard/settings/llm">
    <input type="hidden" name="enabled" value="true">

    <label style="font-size:0.72rem;text-transform:uppercase;letter-spacing:0.5px;color:var(--text3);font-weight:500;display:block;margin-bottom:10px">Provider</label>
    <div style="display:flex;gap:10px;margin-bottom:20px">
      <label class="prov-opt sel" onclick="selectProvider('openai',this)">
        <input type="radio" name="provider" value="openai" checked style="position:absolute;opacity:0">
        <div class="pname">OpenAI-Compatible</div>
        <div class="pdesc">OpenAI, Ollama, vLLM, Groq, Azure, LM Studio</div>
      </label>
      <label class="prov-opt" onclick="selectProvider('claude',this)">
        <input type="radio" name="provider" value="claude" style="position:absolute;opacity:0">
        <div class="pname">Claude</div>
        <div class="pdesc">Anthropic API</div>
      </label>
      <label class="prov-opt" onclick="selectProvider('webhook',this)">
        <input type="radio" name="provider" value="webhook" style="position:absolute;opacity:0">
        <div class="pname">Webhook</div>
        <div class="pdesc">Custom endpoint</div>
      </label>
    </div>

    <div class="form-row" style="margin-bottom:12px" id="llm-fields-row">
      <div class="form-group" style="flex:1" id="llm-model-group">
        <label id="llm-model-label">Model</label>
        <input type="text" name="model" id="llm-model" placeholder="gpt-4o">
      </div>
      <div class="form-group" style="flex:1" id="llm-key-group">
        <label id="llm-key-label">API key env variable</label>
        <input type="text" name="api_key_env" id="llm-key" placeholder="OPENAI_API_KEY">
      </div>
    </div>
    <div class="form-row" style="margin-bottom:20px">
      <div class="form-group" style="flex:1">
        <label id="llm-url-label">Base URL <span style="color:var(--text3);font-size:0.72rem">(leave empty for provider defaults)</span></label>
        <input type="text" name="base_url" id="llm-url" placeholder="http://localhost:11434/v1">
      </div>
    </div>
    <script>
    var provCfg={openai:{model:'gpt-4o, qwen3.5:latest, llama3',modelLabel:'Model',key:'Optional for local models (Ollama, LM Studio)',keyLabel:'API key env variable <span style="color:var(--text3);font-size:0.72rem">(optional for local)</span>',url:'http://localhost:11434/v1',urlLabel:'Base URL <span style="color:var(--text3);font-size:0.72rem">(required for non-OpenAI)</span>',showModel:true,showKey:true},claude:{model:'claude-sonnet-4-6',modelLabel:'Model',key:'ANTHROPIC_API_KEY',keyLabel:'API key env variable',url:'https://api.anthropic.com',urlLabel:'Base URL <span style="color:var(--text3);font-size:0.72rem">(optional)</span>',showModel:true,showKey:true},webhook:{model:'',modelLabel:'',key:'',keyLabel:'',url:'https://your-endpoint.example.com/analyze',urlLabel:'Webhook URL',showModel:false,showKey:false}};
    function selectProvider(p,el){el.parentNode.querySelectorAll('.prov-opt').forEach(function(c){c.classList.remove('sel')});el.classList.add('sel');var c=provCfg[p];document.getElementById('llm-model').placeholder=c.model;document.getElementById('llm-key').placeholder=c.key;document.getElementById('llm-key-label').innerHTML=c.keyLabel;document.getElementById('llm-url').placeholder=c.url;document.getElementById('llm-url-label').innerHTML=c.urlLabel;document.getElementById('llm-model-group').style.display=c.showModel?'':'none';document.getElementById('llm-key-group').style.display=c.showKey?'':'none';if(!c.showModel)document.getElementById('llm-model').value='';if(!c.showKey)document.getElementById('llm-key').value=''}
    </script>
    <button type="submit" class="btn">Enable AI Analysis</button>
  </form>
</div>

{{else}}
<!-- Active state: tabs -->

<!-- Status bar (always visible above tabs) -->
<div class="llm-status-bar" style="margin-bottom:var(--sp-5)">
  <div style="display:flex;align-items:center;gap:8px">
    <div class="dot" style="background:var(--success)"></div>
    <span style="font-weight:500">{{.Cfg.Model}}</span>
  </div>
  {{if .BudgetStatus}}
  <div style="margin-left:auto;display:flex;gap:16px;align-items:center">
    {{if gt .BudgetStatus.DailyLimit 0.0}}
    <div style="display:flex;align-items:center;gap:6px">
      <span style="color:var(--text3)">Today:</span>
      <span style="font-family:var(--mono);font-weight:600;font-variant-numeric:tabular-nums;{{if .BudgetStatus.DailyExhausted}}color:var(--danger){{else if .BudgetStatus.DailyWarning}}color:var(--warn){{end}}">${{printf "%.2f" .BudgetStatus.DailySpent}} / ${{printf "%.2f" .BudgetStatus.DailyLimit}}</span>
    </div>
    {{end}}
    {{if gt .BudgetStatus.MonthlyLimit 0.0}}
    <div style="display:flex;align-items:center;gap:6px">
      <span style="color:var(--text3)">Month:</span>
      <span style="font-family:var(--mono);font-weight:600;font-variant-numeric:tabular-nums;{{if .BudgetStatus.MonthlyExhaust}}color:var(--danger){{else if .BudgetStatus.MonthlyWarning}}color:var(--warn){{end}}">${{printf "%.2f" .BudgetStatus.MonthlySpent}} / ${{printf "%.2f" .BudgetStatus.MonthlyLimit}}</span>
    </div>
    {{end}}
    {{if gt .BudgetStatus.DroppedBudget 0}}<span style="color:var(--danger);font-weight:500">{{.BudgetStatus.DroppedBudget}} dropped</span>{{end}}
  </div>
  {{end}}
  <div id="llm-toggle-wrap" style="margin-left:{{if not .BudgetStatus}}auto{{else}}0{{end}}">
    <button class="btn btn-sm" style="background:var(--surface2);color:var(--text2);font-size:0.72rem;padding:4px 12px" hx-post="/dashboard/api/llm/toggle" hx-swap="innerHTML" hx-target="#llm-toggle-wrap" hx-confirm="Disable AI analysis? Threat detection will rely on rules only.">Disable</button>
  </div>
</div>

<!-- Tabs -->
<div class="llm-tabs" role="tablist">
  <button class="llm-tab active" role="tab" aria-selected="true" aria-controls="llm-panel-monitor" onclick="llmSwitchTab('monitor')">Queue{{if .Triage}}{{if gt .Triage.NeedsReview 0}} <span style="font-size:0.68rem;color:var(--accent-light)">({{.Triage.NeedsReview}})</span>{{end}}{{end}}</button>
  <button class="llm-tab" role="tab" aria-selected="false" aria-controls="llm-panel-config" onclick="llmSwitchTab('config')">Configuration</button>
</div>
<script>
function llmSwitchTab(name){
  document.querySelectorAll('.llm-tab').forEach(function(t){t.classList.remove('active');t.setAttribute('aria-selected','false')});
  document.querySelectorAll('.llm-tab-panel').forEach(function(p){p.classList.remove('active')});
  var idx=name==='config'?1:0;
  document.querySelectorAll('.llm-tab')[idx].classList.add('active');
  document.querySelectorAll('.llm-tab')[idx].setAttribute('aria-selected','true');
  document.getElementById('llm-panel-'+name).classList.add('active');
}
</script>

<!-- TAB 1: Monitoring -->
<div id="llm-panel-monitor" class="llm-tab-panel active" role="tabpanel">

<!-- Triage summary -->
<div class="tq-bar">
  <div class="tq-seg">
    <div class="tq-num {{if gt .Triage.NeedsReview 0}}danger{{end}}">{{.Triage.NeedsReview}}</div>
    <div class="tq-label">Needs review</div>
    {{if gt .Triage.HighSeverity 0}}<span class="tq-pill tq-pill-c">{{.Triage.HighSeverity}} high</span>{{end}}
    {{if gt .Triage.MediumSeverity 0}}<span class="tq-pill tq-pill-m">{{.Triage.MediumSeverity}} med</span>{{end}}
  </div>
  <div class="tq-div"></div>
  <div class="tq-seg">
    <div class="tq-num" style="color:var(--success)">{{.Stats.TotalThreats}}</div>
    <div class="tq-label">Threats caught</div>
  </div>
  <div class="tq-div"></div>
  <div class="tq-seg">
    <div class="tq-num" style="color:var(--accent-light)">{{.Stats.RulesGenerated}}</div>
    <div class="tq-label">Rules generated</div>
  </div>
  <div class="tq-div"></div>
  <div class="tq-seg">
    <div class="tq-num" style="color:var(--text3)">{{.Triage.Resolved}}</div>
    <div class="tq-label">Resolved</div>
  </div>
</div>

{{if .Analyses}}
<!-- Filters -->
<div class="tq-filters">
  <select id="tq-risk-filter" onchange="tqApply()">
    <option value="">All risk levels</option>
    <option value="76">Critical (76+)</option>
    <option value="51">High (51+)</option>
    <option value="31">Medium (31+)</option>
  </select>
  <select id="tq-status-filter" onchange="tqApply()">
    <option value="">All statuses</option>
    <option value="new">New</option>
    <option value="false_positive">Dismissed</option>
    <option value="confirmed">Confirmed</option>
  </select>
  <input type="text" id="tq-agent-filter" placeholder="Filter by agent..." oninput="tqApply()" style="width:160px">
  <span id="tq-count" style="margin-left:auto;font-size:0.78rem;color:var(--text3)"></span>
</div>

<!-- Table -->
<div style="overflow-x:auto">
<table class="tq-table">
  <thead>
    <tr>
      <th style="width:50px">Risk</th>
      <th style="white-space:nowrap">Flow</th>
      <th>Threat</th>
      <th style="width:100px">Action</th>
      <th style="width:90px">Status</th>
      <th style="width:80px">Time</th>
    </tr>
  </thead>
  <tbody id="tq-tbody">
  {{range .Analyses}}
    <tr class="tq-row{{if eq .ReviewedStatus "false_positive"}} tq-dismissed{{end}}" data-risk="{{printf "%.0f" .RiskScore}}" data-status="{{.ReviewedStatus}}" data-agent="{{.FromAgent}} {{.ToAgent}}" onclick="window.location='/dashboard/llm/case/{{.ID}}'">
      <td><span class="tq-risk" style="{{if ge .RiskScore 76.0}}background:rgba(239,68,68,0.08);color:#f85149{{else if ge .RiskScore 51.0}}background:rgba(251,146,60,0.08);color:#fb923c{{else if ge .RiskScore 31.0}}background:rgba(210,153,34,0.07);color:#d29922{{else if gt .RiskScore 0.0}}background:rgba(34,197,94,0.06);color:#3fb950{{else}}background:var(--surface2);color:var(--text3){{end}}">{{printf "%.0f" .RiskScore}}</span></td>
      <td style="font-size:0.8rem;white-space:nowrap">{{.FromAgent}} <span style="color:var(--text3)">&rarr;</span> {{.ToAgent}}</td>
      <td style="font-size:0.8rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{firstThreatSummary .ThreatsJSON .RiskScore}}</td>
      <td><span class="tq-action {{.RecommendedAction}}">{{.RecommendedAction}}</span></td>
      <td>{{if eq .ReviewedStatus "false_positive"}}<span class="tq-status dismissed">dismissed</span>{{else if eq .ReviewedStatus "confirmed"}}<span class="tq-status confirmed">confirmed</span>{{else if ge .RiskScore 30.0}}<span class="tq-status new">new</span>{{else}}<span style="color:var(--text3);font-size:0.72rem">&#8212;</span>{{end}}</td>
      <td style="font-size:0.72rem;color:var(--text3);font-family:var(--mono)">{{relativeTime .Timestamp}}</td>
    </tr>
  {{end}}
  </tbody>
</table>
</div>

<!-- Pagination -->
<div class="tq-pager" id="tq-pager">
  <span id="tq-pager-info"></span>
  <div style="display:flex;gap:4px">
    <button id="tq-prev" onclick="tqNav(-1)" disabled>&larr; Prev</button>
    <button id="tq-next" onclick="tqNav(1)">Next &rarr;</button>
  </div>
</div>

<script>
var tqCurPage=1,tqSize=20;
function tqApply(){
  var rMin=parseInt(document.getElementById('tq-risk-filter').value)||0;
  var st=document.getElementById('tq-status-filter').value;
  var ag=document.getElementById('tq-agent-filter').value.toLowerCase();
  document.querySelectorAll('.tq-row').forEach(function(r){
    var risk=parseInt(r.dataset.risk)||0;
    var rs=r.dataset.status;
    var a=r.dataset.agent.toLowerCase();
    var ok=true;
    if(rMin&&risk<rMin)ok=false;
    if(st==='new'&&rs!=='')ok=false;
    if(st&&st!=='new'&&rs!==st)ok=false;
    if(ag&&a.indexOf(ag)===-1)ok=false;
    r.dataset.vis=ok?'1':'0';
  });
  tqCurPage=1;tqRender();
}
function tqRender(){
  var rows=document.querySelectorAll('.tq-row');
  var vis=[];
  rows.forEach(function(r){if(r.dataset.vis!=='0')vis.push(r);});
  var total=vis.length;
  var start=(tqCurPage-1)*tqSize;
  var end=Math.min(start+tqSize,total);
  rows.forEach(function(r){r.style.display='none';});
  for(var i=start;i<end;i++)vis[i].style.display='';
  document.getElementById('tq-pager-info').textContent=total?'Showing '+(start+1)+'\u2013'+end+' of '+total:'No results';
  document.getElementById('tq-prev').disabled=tqCurPage<=1;
  document.getElementById('tq-next').disabled=end>=total;
  document.getElementById('tq-count').textContent=total+' analyses';
}
function tqNav(d){tqCurPage+=d;tqRender();}
tqApply();
</script>

{{else}}
<div class="card" style="text-align:center;padding:48px;color:var(--text3)">
  <div style="font-size:0.88rem;font-weight:500;color:var(--text2);margin-bottom:4px">LLM analysis active, waiting for messages</div>
  <div style="font-size:0.78rem">Analyses will appear here when messages match your trigger conditions</div>
</div>
{{end}}
</div>

<!-- TAB 2: Configuration -->
<div id="llm-panel-config" class="llm-tab-panel" role="tabpanel">
<form method="POST" action="/dashboard/settings/llm" id="llm-config-form">
<input type="hidden" name="enabled" value="true">

<div class="llm-grid">
  <div class="llm-card">
    <h3 style="display:flex;align-items:center;gap:10px">Connection <span id="cfg-svc-badge" style="font-size:0.7rem;padding:2px 8px;border-radius:4px;font-weight:500;letter-spacing:0.3px"></span></h3>
    <input type="hidden" name="provider" id="cfg-provider" value="{{.Cfg.Provider}}">
    <div class="form-group" style="margin-bottom:14px">
      <label>Service</label>
      <div id="cfg-presets" style="display:flex;gap:6px;flex-wrap:wrap"></div>
    </div>
    <div class="form-group" style="margin-bottom:12px" id="cfg-url-group">
      <label id="cfg-url-label">Base URL</label>
      <input type="text" name="base_url" id="cfg-url" value="{{.Cfg.BaseURL}}" oninput="llmDetectAndRefresh()">
    </div>
    <div class="form-group" style="margin-bottom:12px" id="cfg-model-group">
      <label>Model</label>
      <input type="text" name="model" id="cfg-model" value="{{.Cfg.Model}}">
      <div id="cfg-model-hints" style="display:flex;gap:6px;margin-top:6px;flex-wrap:wrap"></div>
    </div>
    <div class="form-group" style="margin-bottom:8px" id="cfg-key-group">
      <label id="cfg-key-label">API Key</label>
      <div style="position:relative">
        <input type="password" name="api_key" id="cfg-key" value="{{.Cfg.APIKey}}" autocomplete="off" style="padding-right:40px" placeholder="sk-...">
        <button type="button" aria-label="Toggle API key visibility" onclick="var k=document.getElementById('cfg-key');k.type=k.type==='password'?'text':'password'" style="position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:none;color:var(--text3);cursor:pointer;padding:4px;font-size:0.75rem" title="Show/hide">&#x1f441;</button>
      </div>
    </div>
    <div class="form-group" style="margin-bottom:0" id="cfg-keyenv-group">
      <label>API Key Env Variable</label>
      <input type="text" name="api_key_env" id="cfg-keyenv" value="{{.Cfg.APIKeyEnv}}" autocomplete="off" placeholder="OPENROUTER_API_KEY">
      <div id="cfg-key-hint" style="font-size:0.7rem;color:var(--text3);margin-top:4px">Direct key takes precedence over env variable</div>
    </div>
    <button type="button" class="llm-adv-btn" aria-expanded="false" aria-controls="conn-advanced" onclick="var s=document.getElementById('conn-advanced');var a=this.querySelector('.arr');var open=s.classList.toggle('open');a.classList.toggle('open');this.setAttribute('aria-expanded',open)">
      <span class="arr">&#9654;</span> Advanced
    </button>
    <div id="conn-advanced" class="llm-conn-adv">
      <div class="form-row" style="margin-top:10px;margin-bottom:8px">
        <div class="form-group" style="flex:1">
          <label>Timeout</label>
          <input type="text" name="timeout" value="{{.Cfg.Timeout}}" placeholder="30s">
        </div>
        <div class="form-group" style="flex:1">
          <label>Max Concurrent</label>
          <input type="number" name="max_concurrent" value="{{if .Cfg.MaxConcurrent}}{{.Cfg.MaxConcurrent}}{{else}}3{{end}}" min="1" max="20" style="width:100%">
        </div>
      </div>
      <div class="form-row" style="margin-bottom:0">
        <div class="form-group" style="flex:1">
          <label>Max Tokens</label>
          <input type="number" name="max_tokens" value="{{if .Cfg.MaxTokens}}{{.Cfg.MaxTokens}}{{else}}1024{{end}}" min="1" style="width:100%">
        </div>
        <div class="form-group" style="flex:1">
          <label>Temperature</label>
          <input type="number" name="temperature" value="{{printf "%.1f" .Cfg.Temperature}}" min="0" max="2" step="0.1" style="width:100%">
        </div>
      </div>
    </div>
    <input type="hidden" name="queue_size" value="{{if .Cfg.QueueSize}}{{.Cfg.QueueSize}}{{else}}100{{end}}">
    <input type="hidden" name="max_daily" value="{{.Cfg.MaxDailyReqs}}">
    <script>
    var llmSvc={
      openrouter:{label:'OpenRouter',provider:'openai',url:'https://openrouter.ai/api/v1',bg:'rgba(168,85,247,0.15)',fg:'#a855f7',keyHint:'Set OPENROUTER_API_KEY in your environment',keyPh:'OPENROUTER_API_KEY',models:['deepseek/deepseek-chat-v3-0324','google/gemini-2.5-flash-preview','google/gemini-2.5-flash','anthropic/claude-sonnet-4','x-ai/grok-4-fast']},
      ollama:{label:'Ollama',provider:'openai',url:'http://localhost:11434/v1',bg:'rgba(34,197,94,0.15)',fg:'#3fb950',keyHint:'No API key needed for local Ollama',keyPh:'',models:['qwen3.5:latest','llama3:latest','mistral:latest','deepseek-r1:latest']},
      lmstudio:{label:'LM Studio',provider:'openai',url:'http://localhost:1234/v1',bg:'rgba(96,165,250,0.15)',fg:'#60a5fa',keyHint:'No API key needed for local LM Studio',keyPh:'',models:['loaded-model']},
      openai:{label:'OpenAI',provider:'openai',url:'https://api.openai.com/v1',bg:'rgba(168,162,158,0.15)',fg:'#a8a29e',keyHint:'Set OPENAI_API_KEY in your environment',keyPh:'OPENAI_API_KEY',models:['gpt-4o','gpt-4o-mini','gpt-4-turbo']},
      groq:{label:'Groq',provider:'openai',url:'https://api.groq.com/openai/v1',bg:'rgba(210,153,34,0.15)',fg:'#d29922',keyHint:'Set GROQ_API_KEY in your environment',keyPh:'GROQ_API_KEY',models:['llama-3.3-70b-versatile','mixtral-8x7b-32768']},
      azure:{label:'Azure',provider:'openai',url:'https://YOUR-RESOURCE.openai.azure.com/openai/deployments/YOUR-DEPLOYMENT',bg:'rgba(96,165,250,0.15)',fg:'#60a5fa',keyHint:'Set AZURE_OPENAI_API_KEY in your environment',keyPh:'AZURE_OPENAI_API_KEY',models:['gpt-4o']},
      vllm:{label:'vLLM',provider:'openai',url:'http://localhost:8000/v1',bg:'rgba(34,197,94,0.15)',fg:'#3fb950',keyHint:'No API key needed for local vLLM',keyPh:'',models:[]},
      claude:{label:'Claude',provider:'claude',url:'https://api.anthropic.com',bg:'rgba(217,119,87,0.15)',fg:'#d97756',keyHint:'Set ANTHROPIC_API_KEY in your environment',keyPh:'ANTHROPIC_API_KEY',models:['claude-sonnet-4-6','claude-haiku-4-5-20251001','claude-opus-4-6']},
      webhook:{label:'Webhook',provider:'webhook',url:'',bg:'rgba(168,162,158,0.15)',fg:'#a8a29e',keyHint:'',keyPh:'',models:[]}
    };
    function llmDetectCurrent(){
      var u=(document.getElementById('cfg-url').value||'').toLowerCase();
      var p=document.getElementById('cfg-provider').value;
      if(p==='claude') return 'claude';
      if(p==='webhook') return 'webhook';
      if(u.indexOf('openrouter')!==-1) return 'openrouter';
      if(u.indexOf(':11434')!==-1) return 'ollama';
      if(u.indexOf('lmstudio')!==-1||u.indexOf(':1234')!==-1) return 'lmstudio';
      if(u.indexOf('groq')!==-1) return 'groq';
      if(u.indexOf('azure')!==-1) return 'azure';
      if(u.indexOf(':8000')!==-1) return 'vllm';
      if(u.indexOf('openai.com')!==-1) return 'openai';
      if(u.indexOf('localhost')!==-1||u.indexOf('127.0.0.1')!==-1) return 'ollama';
      if(u==='') return 'ollama';
      return 'openai'
    }
    function llmApply(key){
      var s=llmSvc[key];if(!s) return;
      document.getElementById('cfg-provider').value=s.provider;
      document.getElementById('cfg-url').value=s.url;
      document.getElementById('cfg-key').value=s.keyPh;
      if(s.models.length>0) document.getElementById('cfg-model').value=s.models[0];
      else document.getElementById('cfg-model').value='';
      llmRefresh()
    }
    function llmDetectAndRefresh(){
      var cur=llmDetectCurrent();
      var s=llmSvc[cur];
      if(s) document.getElementById('cfg-provider').value=s.provider;
      llmRefresh()
    }
    function llmRefresh(){
      var cur=llmDetectCurrent(),s=llmSvc[cur],b=document.getElementById('cfg-svc-badge');
      var mg=document.getElementById('cfg-model-group'),kg=document.getElementById('cfg-key-group'),ug=document.getElementById('cfg-url-group');
      var hintBox=document.getElementById('cfg-model-hints'),keyHint=document.getElementById('cfg-key-hint'),presetBox=document.getElementById('cfg-presets');
      b.textContent=s?s.label:'';b.style.background=s?s.bg:'';b.style.color=s?s.fg:'';
      hintBox.innerHTML='';keyHint.textContent='';presetBox.innerHTML='';
      if(cur==='webhook'){
        mg.style.display='none';kg.style.display='none';
        document.getElementById('cfg-url-label').textContent='Webhook URL';
        document.getElementById('cfg-url').placeholder='https://your-endpoint.example.com/analyze';
      }else{
        mg.style.display='';kg.style.display='';
        document.getElementById('cfg-url-label').textContent='Base URL';
        if(s){
          document.getElementById('cfg-url').placeholder=s.url;
          document.getElementById('cfg-key').placeholder=s.keyPh||'Not required';
          keyHint.textContent=s.keyHint||'';
          document.getElementById('cfg-model').placeholder=s.models.length>0?s.models[0]:'model-name';
          s.models.forEach(function(m){
            var c=document.createElement('button');c.type='button';c.textContent=m;
            c.style.cssText='font-size:0.68rem;padding:2px 8px;border-radius:4px;border:1px solid var(--border);background:var(--surface2);color:var(--text3);cursor:pointer';
            c.onclick=function(){document.getElementById('cfg-model').value=m};
            hintBox.appendChild(c)
          })
        }
      }
      Object.keys(llmSvc).forEach(function(k){
        var sv=llmSvc[k];
        var btn=document.createElement('button');btn.type='button';btn.textContent=sv.label;
        var active=k===cur;
        btn.style.cssText='font-size:0.7rem;padding:4px 12px;border-radius:5px;cursor:pointer;font-weight:'+(active?'600':'400')+';border:1px solid '+(active?sv.fg:'var(--border)')+';background:'+(active?sv.bg:'transparent')+';color:'+(active?sv.fg:'var(--text3)');
        btn.onclick=function(){llmApply(k)};
        presetBox.appendChild(btn)
      })
    }
    document.addEventListener('DOMContentLoaded', llmRefresh);
    </script>
  </div>

  <div class="llm-card">
    <h3>Spending limits</h3>
    <div class="form-row" style="margin-bottom:10px">
      <div class="form-group" style="flex:1">
        <label>Daily limit (USD)</label>
        <input type="number" name="budget_daily" value="{{printf "%.2f" .Cfg.Budget.DailyLimitUSD}}" min="0" step="0.01" style="width:100%" placeholder="0 = no limit">
      </div>
      <div class="form-group" style="flex:1">
        <label>Monthly limit (USD)</label>
        <input type="number" name="budget_monthly" value="{{printf "%.2f" .Cfg.Budget.MonthlyLimitUSD}}" min="0" step="0.01" style="width:100%" placeholder="0 = no limit">
      </div>
    </div>
    <div class="form-group" style="margin-bottom:0">
      <label>When limit reached</label>
      <select name="budget_on_limit" style="width:100%;padding:8px 12px;border-radius:6px;border:1px solid var(--border);background:var(--surface2);color:var(--text);font-size:0.85rem">
        <option value="skip" {{if or (eq .Cfg.Budget.OnLimit "skip") (eq .Cfg.Budget.OnLimit "")}}selected{{end}}>Continue without LLM (deterministic only)</option>
        <option value="block" {{if eq .Cfg.Budget.OnLimit "block"}}selected{{end}}>Pause all analysis until reset</option>
      </select>
    </div>
    <input type="hidden" name="budget_warn" value="{{if gt .Cfg.Budget.WarnThreshold 0.0}}{{printf "%.0f" (divf .Cfg.Budget.WarnThreshold 0.01)}}{{else}}80{{end}}">

    <h3 style="margin-top:20px">Analysis triggers</h3>
    <p style="color:var(--text3);font-size:0.78rem;margin-bottom:10px">Which verdicts get sent to the LLM?</p>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
      <label style="display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:6px;border:1px solid {{if .Cfg.Analyze.Clean}}var(--success){{else}}var(--border){{end}};cursor:pointer;{{if .Cfg.Analyze.Clean}}background:rgba(34,197,94,0.06){{end}}">
        <span class="toggle"><input type="checkbox" name="analyze_clean" value="true" {{if .Cfg.Analyze.Clean}}checked{{end}}><span class="toggle-slider"></span></span>
        <div><div style="font-size:0.82rem;font-weight:500">Clean</div></div>
      </label>
      <label style="display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:6px;border:1px solid {{if .Cfg.Analyze.Flagged}}var(--warn){{else}}var(--border){{end}};cursor:pointer;{{if .Cfg.Analyze.Flagged}}background:rgba(210,153,34,0.06){{end}}">
        <span class="toggle"><input type="checkbox" name="analyze_flagged" value="true" {{if .Cfg.Analyze.Flagged}}checked{{end}}><span class="toggle-slider"></span></span>
        <div><div style="font-size:0.82rem;font-weight:500">Flagged</div></div>
      </label>
      <label style="display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:6px;border:1px solid {{if .Cfg.Analyze.Quarantined}}#fb923c{{else}}var(--border){{end}};cursor:pointer;{{if .Cfg.Analyze.Quarantined}}background:rgba(251,146,60,0.06){{end}}">
        <span class="toggle"><input type="checkbox" name="analyze_quarantined" value="true" {{if .Cfg.Analyze.Quarantined}}checked{{end}}><span class="toggle-slider"></span></span>
        <div><div style="font-size:0.82rem;font-weight:500">Quarantined</div></div>
      </label>
      <label style="display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:6px;border:1px solid {{if .Cfg.Analyze.Blocked}}var(--danger){{else}}var(--border){{end}};cursor:pointer;{{if .Cfg.Analyze.Blocked}}background:rgba(239,68,68,0.06){{end}}">
        <span class="toggle"><input type="checkbox" name="analyze_blocked" value="true" {{if .Cfg.Analyze.Blocked}}checked{{end}}><span class="toggle-slider"></span></span>
        <div><div style="font-size:0.82rem;font-weight:500">Blocked</div></div>
      </label>
    </div>
  </div>
</div>

<div class="llm-card" style="margin-bottom:16px">
  <h3>Auto-generate rules</h3>
  <div style="display:flex;gap:20px;margin-bottom:14px;flex-wrap:wrap">
    <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
      <span class="toggle"><input type="checkbox" name="rulegen_enabled" value="true" {{if .Cfg.RuleGen.Enabled}}checked{{end}}><span class="toggle-slider"></span></span>
      <span style="font-size:0.85rem;color:var(--text2)">Enable rule generation</span>
    </label>
    <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
      <span class="toggle"><input type="checkbox" name="rulegen_approval" value="true" {{if .Cfg.RuleGen.RequireApproval}}checked{{end}}><span class="toggle-slider"></span></span>
      <span style="font-size:0.85rem;color:var(--text2)">Require human approval</span>
    </label>
  </div>
  <div class="form-row" style="margin-bottom:0">
    <div class="form-group" style="flex:2">
      <label>Output directory</label>
      <input type="text" name="rulegen_dir" value="{{.Cfg.RuleGen.OutputDir}}" placeholder="./llm-rules">
    </div>
    <div class="form-group" style="flex:1">
      <label>Min confidence</label>
      <input type="number" name="rulegen_confidence" value="{{printf "%.1f" .Cfg.RuleGen.MinConfidence}}" min="0" max="1" step="0.1" placeholder="0.8">
    </div>
  </div>
</div>

<div style="display:flex;justify-content:space-between;align-items:center;padding-top:4px;padding-bottom:16px">
  <button type="submit" class="btn">Save Configuration</button>
  <button type="submit" form="llm-disable-form" class="btn btn-sm btn-outline" style="font-size:0.75rem" onclick="return confirm('Disable AI analysis? Threat detection will rely on rules only.')">Disable AI Analysis</button>
</div>
</form>
<form method="POST" action="/dashboard/settings/llm" id="llm-disable-form" style="display:none">
  <input type="hidden" name="enabled" value="false">
  <input type="hidden" name="provider" value="{{.Cfg.Provider}}">
  <input type="hidden" name="model" value="{{.Cfg.Model}}">
</form>
</div>

{{end}}
` + layoutFoot))

var llmDetailTmpl = template.Must(template.New("llm-detail").Funcs(tmplFuncs).Parse(`
<div class="panel-header">
  <h3 style="font-size:0.95rem;font-weight:600">LLM Analysis Detail</h3>
  <button onclick="closePanel()" style="background:none;border:none;color:var(--text3);cursor:pointer;font-size:1.2rem">&times;</button>
</div>
<div style="padding:20px;font-size:0.85rem">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px">
    <span style="display:inline-block;min-width:48px;padding:6px 12px;border-radius:6px;font-family:var(--mono);font-weight:800;font-size:1.4rem;text-align:center;{{if ge .RiskScore 80.0}}background:rgba(239,68,68,0.15);color:var(--danger){{else if ge .RiskScore 50.0}}background:rgba(210,153,34,0.15);color:var(--warn){{else if gt .RiskScore 0.0}}background:rgba(34,197,94,0.1);color:var(--success){{else}}background:var(--surface2);color:var(--text3){{end}}">{{printf "%.0f" .RiskScore}}</span>
    <div>
      <div style="font-weight:600;margin-bottom:2px">Risk Score</div>
      <div style="color:var(--text3);font-size:0.78rem">Confidence: {{printf "%.0f" .Confidence}}%</div>
    </div>
    <span style="margin-left:auto;padding:4px 12px;border-radius:4px;font-size:0.78rem;font-weight:500;{{if eq .RecommendedAction "block"}}background:rgba(239,68,68,0.15);color:var(--danger){{else if eq .RecommendedAction "investigate"}}background:rgba(210,153,34,0.15);color:var(--warn){{else if eq .RecommendedAction "quarantine"}}background:rgba(251,146,60,0.15);color:#fb923c{{else}}background:var(--surface2);color:var(--text3){{end}}">{{.RecommendedAction}}</span>
  </div>

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px">
    <div style="background:var(--surface2);border-radius:8px;padding:12px">
      <div style="color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px">Flow</div>
      <div><span style="color:var(--accent-light);font-weight:600">{{.FromAgent}}</span> <span style="color:var(--text3)">→</span> <span style="font-weight:500">{{.ToAgent}}</span></div>
    </div>
    <div style="background:var(--surface2);border-radius:8px;padding:12px">
      <div style="color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px">Model</div>
      <div style="font-family:var(--mono);font-size:0.82rem">{{.Model}}</div>
    </div>
    <div style="background:var(--surface2);border-radius:8px;padding:12px">
      <div style="color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px">Latency</div>
      <div style="font-family:var(--mono)">{{latencySec .LatencyMs}}s</div>
    </div>
    <div style="background:var(--surface2);border-radius:8px;padding:12px">
      <div style="color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px">Tokens</div>
      <div style="font-family:var(--mono)">{{.TokensUsed}}</div>
    </div>
  </div>

  <div style="margin-bottom:16px">
    <div style="color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px">Threats ({{countJSONArray .ThreatsJSON}})</div>
    {{$threats := parseJSONArray .ThreatsJSON}}
    {{if $threats}}
    <div style="padding:4px 0">{{range $threats}}<span style="display:inline-block;padding:3px 10px;border-radius:5px;font-size:0.75rem;font-weight:500;margin:2px 4px 2px 0;background:rgba(239,68,68,0.1);color:var(--danger);border:1px solid rgba(239,68,68,0.2)">{{.}}</span>{{end}}</div>
    {{else}}
    <div style="color:var(--text3);font-size:0.82rem">None</div>
    {{end}}
  </div>

  <div style="margin-bottom:16px">
    <div style="color:var(--text3);font-size:0.7rem;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px">Intent</div>
    {{$intent := parseJSONMap .IntentJSON}}
    {{if $intent}}
    {{range $k, $v := $intent}}
    <div style="padding:6px 0;border-bottom:1px solid var(--border);font-size:0.82rem">
      <span style="color:var(--text3);text-transform:capitalize">{{$k}}:</span>
      <span style="color:var(--text)">{{$v}}</span>
    </div>
    {{end}}
    {{else}}
    <div style="color:var(--text3);font-size:0.82rem">No intent data</div>
    {{end}}
  </div>

  <div style="border-top:1px solid var(--border);padding-top:12px;margin-top:8px">
    <a href="/dashboard/llm/case/{{.ID}}" style="color:var(--accent);text-decoration:none;font-size:0.82rem;font-weight:500">View Full Case &rarr;</a>
  </div>
  </div>
</div>
`))

var llmCaseTmpl = template.Must(template.New("llm-case").Funcs(tmplFuncs).Parse(layoutHead + `
<style>` + ciCSS + `
/* Case page overrides */
.cs-layout{display:grid;grid-template-columns:1fr 340px;gap:24px;align-items:start}
.cs-main{min-width:0}
.cs-side{display:flex;flex-direction:column;gap:16px}

/* Verdict banner */
.cs-banner{display:flex;align-items:stretch;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-xl);overflow:hidden;margin-bottom:var(--sp-6)}
.cs-banner-score{display:flex;flex-direction:column;align-items:center;justify-content:center;min-width:90px;padding:20px 16px;flex-shrink:0}
.cs-banner-score .n{font-size:2rem;font-weight:700;font-family:var(--mono);line-height:1;letter-spacing:-0.03em}
.cs-banner-score .l{font-size:0.56rem;letter-spacing:0.8px;margin-top:5px;font-weight:600;text-transform:uppercase}
.cs-banner-body{flex:1;padding:18px 22px;display:flex;flex-direction:column;justify-content:center;border-left:1px solid var(--border);min-width:0}
.cs-banner-title{font-size:1rem;font-weight:600;margin:0 0 8px;line-height:1.45;color:var(--text);text-wrap:pretty}
.cs-banner-meta{display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:0.75rem;color:var(--text3)}
.cs-banner-meta .sep{color:var(--border)}
.cs-banner-action{display:flex;align-items:center;padding:0 22px;flex-shrink:0;border-left:1px solid var(--border)}

/* Action buttons */
.cs-actions{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:20px}
.cs-abtn{display:inline-flex;align-items:center;gap:6px;padding:8px 18px;border-radius:8px;font-size:0.78rem;font-weight:500;cursor:pointer;border:1px solid;transition:all 0.15s;text-decoration:none}
.cs-abtn-danger{background:rgba(239,68,68,0.08);color:#f85149;border-color:rgba(239,68,68,0.2)}
.cs-abtn-danger:hover{background:rgba(239,68,68,0.15);border-color:#f85149}
.cs-abtn-ghost{background:transparent;color:var(--text2);border-color:var(--border)}
.cs-abtn-ghost:hover{background:var(--surface2);border-color:var(--text3)}
.cs-abtn svg{width:14px;height:14px}
.cs-reviewed{display:inline-flex;align-items:center;gap:6px;padding:8px 18px;border-radius:8px;font-size:0.78rem;font-weight:600}
.cs-reviewed-ok{background:rgba(34,197,94,0.08);color:#3fb950}
.cs-reviewed-bad{background:rgba(239,68,68,0.08);color:#f85149}

/* Side panel cards */
.cs-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-xl);overflow:hidden}
.cs-card-hdr{padding:12px 16px;border-bottom:1px solid var(--border);font-size:0.68rem;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:0.6px}
.cs-card-body{padding:14px 16px}
.cs-row{display:flex;justify-content:space-between;align-items:baseline;padding:7px 0;border-bottom:1px solid rgba(255,255,255,0.04);font-size:0.78rem}
.cs-row:last-child{border-bottom:none}
.cs-row .k{color:var(--text3);font-size:0.75rem}
.cs-row .v{font-family:var(--mono);font-size:0.72rem;color:var(--text2);text-align:right}
.cs-conf-bar{height:4px;background:var(--surface2);border-radius:2px;margin-top:4px}
.cs-conf-fill{height:100%;border-radius:2px;transition:width 0.3s}

/* History pills in sidebar */
.cs-hist-grid{display:flex;flex-wrap:wrap;gap:4px;padding:4px 0}
.cs-hist-pill{display:inline-flex;align-items:center;gap:4px;padding:4px 10px;border-radius:6px;font-size:0.68rem;text-decoration:none;color:var(--text3);background:var(--surface2);transition:all 0.12s}
.cs-hist-pill:hover{color:var(--text);background:var(--bg3)}
.cs-hist-score{font-family:var(--mono);font-weight:700;font-size:0.65rem}

/* Threat cards */
.cs-thr-card{border:1px solid var(--border);border-radius:10px;overflow:hidden;margin-bottom:12px}
.cs-thr-card:last-child{margin-bottom:0}
.cs-thr-top{display:flex;align-items:flex-start;gap:12px;padding:14px 18px}
.cs-thr-num{width:26px;height:26px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:0.68rem;font-weight:700;font-family:var(--mono);flex-shrink:0;margin-top:1px}
.cs-thr-num-c{background:rgba(239,68,68,0.12);color:#f85149}
.cs-thr-num-h{background:rgba(251,146,60,0.12);color:#fb923c}
.cs-thr-num-m{background:rgba(210,153,34,0.1);color:#d29922}
.cs-thr-num-l{background:rgba(34,197,94,0.08);color:#3fb950}
.cs-thr-info{flex:1;min-width:0}
.cs-thr-type{font-family:var(--mono);font-size:0.72rem;font-weight:600;color:var(--text2);text-transform:uppercase;margin-bottom:3px}
.cs-thr-desc{font-size:0.82rem;color:var(--text);font-weight:500;line-height:1.5}
.cs-thr-ev{padding:var(--sp-3) var(--sp-5) var(--sp-4);background:rgba(255,255,255,0.015);border-top:1px solid var(--border);font-size:var(--text-sm);color:var(--text3);line-height:1.6;font-family:var(--mono)}
.cs-thr-rule{padding:var(--sp-2) var(--sp-5) var(--sp-3);border-top:1px solid var(--border);font-size:var(--text-sm);display:flex;align-items:center;gap:var(--sp-2);flex-wrap:wrap}

/* Intent diff */
.cs-intent{display:grid;grid-template-columns:1fr 1fr;gap:0;border:1px solid var(--border);border-radius:10px;overflow:hidden}
.cs-intent-side{padding:14px 18px}
.cs-intent-decl{border-right:1px solid var(--border)}
.cs-intent-act.cs-intent-warn{background:rgba(239,68,68,0.03)}
.cs-intent-lbl{font-size:0.58rem;font-weight:600;letter-spacing:0.6px;text-transform:uppercase;color:var(--text3);margin-bottom:8px;display:flex;align-items:center;gap:6px}
.cs-intent-lbl-warn{color:#f85149}
.cs-intent-txt{font-size:0.82rem;line-height:1.55;color:var(--text)}
.cs-intent-act .cs-intent-txt{font-weight:500}
.cs-intent-act.cs-intent-warn .cs-intent-txt{color:#f85149}

/* Evidence block */
.cs-evidence{background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:16px 18px;font-family:var(--mono);font-size:0.72rem;line-height:1.7;color:var(--text);white-space:pre-wrap;word-break:break-all;max-height:280px;overflow-y:auto}

/* Generated rule */
.cs-rule-block{background:var(--surface2);border:1px solid rgba(99,102,241,0.15);border-radius:10px;padding:14px 18px;font-family:var(--mono);font-size:0.72rem;line-height:1.7;color:var(--accent-light);white-space:pre-wrap}

@media(max-width:960px){.cs-layout{grid-template-columns:1fr}.cs-banner{flex-direction:column}.cs-banner-score{min-width:unset;padding:14px}.cs-banner-body{border-left:none;border-top:1px solid var(--border)}.cs-banner-action{border-left:none;border-top:1px solid var(--border);padding:14px 22px}.cs-intent{grid-template-columns:1fr}.cs-intent-decl{border-right:none;border-bottom:1px solid var(--border)}}
</style>

<p style="margin-bottom:18px"><a href="/dashboard/llm" class="ci-back">&larr; Threat Intel</a></p>

{{with .Analysis}}
<!-- Verdict banner -->
<div class="cs-banner">
  <div class="cs-banner-score" style="{{if ge .RiskScore 76.0}}background:rgba(239,68,68,0.08);color:#f85149{{else if ge .RiskScore 51.0}}background:rgba(251,146,60,0.08);color:#fb923c{{else if ge .RiskScore 31.0}}background:rgba(210,153,34,0.06);color:#d29922{{else if gt .RiskScore 10.0}}background:rgba(34,197,94,0.06);color:#3fb950{{else}}background:var(--surface2);color:var(--text3){{end}}">
    <div class="n">{{printf "%.0f" .RiskScore}}</div>
    <div class="l">{{if ge .RiskScore 76.0}}CRITICAL{{else if ge .RiskScore 51.0}}HIGH{{else if ge .RiskScore 31.0}}MEDIUM{{else if gt .RiskScore 10.0}}LOW{{else}}BENIGN{{end}}</div>
  </div>
  <div class="cs-banner-body">
    <h2 class="cs-banner-title">{{firstThreatSummary .ThreatsJSON .RiskScore}}{{if and (gt .Confidence 0.0) (lt .Confidence 30.0)}} <span style="font-size:var(--text-xs);color:var(--warn);font-weight:500">&#9888; Low confidence</span>{{end}}</h2>
    <div class="cs-banner-meta">
      {{if .FromAgent}}<a href="/dashboard/agents/{{.FromAgent}}" style="color:var(--accent-light);text-decoration:none;font-weight:500">{{.FromAgent}}</a> <span style="opacity:0.5">&rarr;</span> <a href="/dashboard/agents/{{.ToAgent}}" style="color:var(--text2);text-decoration:none">{{.ToAgent}}</a><span class="sep">&middot;</span>{{end}}
      <span>{{relativeTime .Timestamp}}</span>
      <span class="sep">&middot;</span>
      <span>{{printf "%.0f" .Confidence}}% confidence</span>
    </div>
  </div>
  <div class="cs-banner-action">
    <span class="ci-badge {{if eq .RecommendedAction "block"}}ci-badge-blk{{else if eq .RecommendedAction "investigate"}}ci-badge-inv{{else if eq .RecommendedAction "quarantine"}}ci-badge-qua{{else}}ci-badge-ok{{end}}" style="font-size:0.75rem;padding:6px 18px">{{.RecommendedAction}}</span>
  </div>
</div>

<!-- Action buttons -->
<div class="cs-actions">
  {{if or (eq .ReviewedStatus "false_positive") (eq .ReviewedStatus "confirmed")}}
    {{if eq .ReviewedStatus "false_positive"}}<span class="cs-reviewed cs-reviewed-ok">&#10003; Dismissed as false positive</span>
    {{else}}<span class="cs-reviewed cs-reviewed-bad">&#10003; Confirmed as real threat</span>{{end}}
  {{else}}
    <button class="cs-abtn cs-abtn-danger" hx-post="/dashboard/api/llm/{{.ID}}/confirm" hx-target="closest .cs-actions" hx-swap="innerHTML" hx-confirm="Confirm this as a real threat?"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg> Confirm threat</button>
    <button class="cs-abtn cs-abtn-ghost" hx-post="/dashboard/api/llm/{{.ID}}/dismiss" hx-target="closest .cs-actions" hx-swap="innerHTML" hx-confirm="Dismiss as false positive?">False positive</button>
    {{if and .FromAgent (not $.AgentSuspended)}}<form method="POST" action="/dashboard/agents/{{.FromAgent}}/suspend" style="display:contents"><button type="submit" class="cs-abtn cs-abtn-ghost" style="color:#f85149;border-color:rgba(239,68,68,0.2)" onclick="return confirm('Suspend agent {{.FromAgent}}?')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg> Suspend agent</button></form>{{end}}
    {{if $.AgentSuspended}}<span class="cs-abtn" style="color:#f85149;cursor:default;border-color:rgba(239,68,68,0.2)">Agent suspended</span>{{end}}
  {{end}}
</div>

<!-- Two-column layout -->
<div class="cs-layout">
  <!-- LEFT: Main content -->
  <div class="cs-main">

    <!-- Findings -->
    {{$threats := parseJSONArray .ThreatsJSON}}
    <div class="ci-s">
      <h3>Findings <span class="cnt">({{countJSONArray .ThreatsJSON}})</span></h3>
      {{if $threats}}
        {{range $i, $t := $threats}}
          {{$m := toMap $t}}
          {{if $m}}
          <div class="cs-thr-card">
            <div class="cs-thr-top">
              <span class="cs-thr-num {{with index $m "severity"}}cs-thr-num-{{if eq (toString .) "critical"}}c{{else if eq (toString .) "high"}}h{{else if eq (toString .) "medium"}}m{{else}}l{{end}}{{end}}">{{inc $i}}</span>
              <div class="cs-thr-info">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
                  <span class="cs-thr-type">{{with index $m "type"}}{{upper (toString .)}}{{else}}THREAT-{{inc $i}}{{end}}</span>
                  {{with index $m "severity"}}<span class="ci-sev ci-sev-{{if eq (toString .) "critical"}}c{{else if eq (toString .) "high"}}h{{else if eq (toString .) "medium"}}m{{else}}l{{end}}">{{upper (toString .)}}</span>{{end}}
                </div>
                <div class="cs-thr-desc">{{with index $m "description"}}{{.}}{{end}}</div>
              </div>
            </div>
            {{with index $m "evidence"}}<div class="cs-thr-ev">{{.}}</div>{{end}}
            {{with index $m "suggestion"}}{{$s := toMap .}}{{if $s}}
            <div class="cs-thr-rule">
              <span style="color:var(--text3);font-size:var(--text-xs)">Suggested rule:</span>
              <code>{{with index $s "name"}}{{.}}{{end}}</code>
              {{with index $s "pattern"}}<code style="color:var(--text3);font-size:var(--text-xs)">{{.}}</code>{{end}}
              <button class="a-cp" onclick="ciCopyText(this.closest('.cs-thr-rule').querySelector('code').textContent,this)">copy</button>
            </div>
            {{end}}{{end}}
          </div>
          {{else}}
          <div class="cs-thr-card"><div class="cs-thr-top"><span class="cs-thr-num cs-thr-num-m">{{inc $i}}</span><div class="cs-thr-info"><div class="cs-thr-desc">{{$t}}</div></div></div></div>
          {{end}}
        {{end}}
      {{else}}
      <div class="ci-benign">
        <svg aria-hidden="true" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
        No threats detected - message assessed as benign.
      </div>
      {{end}}
    </div>

    <!-- Intent Analysis -->
    {{$intent := parseJSONMap .IntentJSON}}
    {{if $intent}}
    <div class="ci-s">
      <h3>Intent Analysis {{with index $intent "alignment"}}{{$a := toString .}}<span style="display:inline-flex;align-items:center;gap:4px;font-family:var(--mono);font-size:0.72rem;font-weight:600;padding:2px 10px;border-radius:100px;{{if lt $a "0.5"}}background:rgba(239,68,68,0.1);color:#f85149{{else}}background:rgba(34,197,94,0.1);color:#3fb950{{end}}">{{if lt $a "0.5"}}&#10007;{{else}}&#10003;{{end}} {{$a}}</span>{{end}}</h3>
      <div class="cs-intent">
        <div class="cs-intent-side cs-intent-decl">
          <div class="cs-intent-lbl">Declared intent</div>
          <div class="cs-intent-txt">{{with index $intent "declared_intent"}}{{.}}{{else}}-{{end}}</div>
        </div>
        <div class="cs-intent-side cs-intent-act{{if ge $.Analysis.RiskScore 50.0}} cs-intent-warn{{end}}">
          <div class="cs-intent-lbl{{if ge $.Analysis.RiskScore 50.0}} cs-intent-lbl-warn{{end}}">Actual behavior</div>
          <div class="cs-intent-txt">{{with index $intent "actual_intent"}}{{.}}{{else}}-{{end}}</div>
        </div>
      </div>
      {{with index $intent "reason"}}
      <p style="font-size:0.75rem;line-height:1.55;color:var(--text3);margin-top:10px">{{.}}</p>
      {{end}}
    </div>
    {{end}}

    <!-- Intercepted content -->
    {{if $.ToolArgs}}
    <div class="ci-s">
      <h3>Intercepted Content</h3>
      <div class="cs-evidence">{{$.ToolArgs}}</div>
    </div>
    {{end}}

    <!-- Generated Rule -->
    {{if .RuleGenerated}}
    <div class="ci-s" style="border-color:rgba(99,102,241,0.15)">
      <h3 style="color:var(--accent-light)">Generated Rule</h3>
      <p style="font-size:0.78rem;color:var(--text2);margin-bottom:10px">Deterministic rule created from this analysis. Catches future matches in &lt;1ms.</p>
      <div class="cs-rule-block">{{.RuleGenerated}}</div>
    </div>
    {{end}}

  </div>

  <!-- RIGHT: Sidebar -->
  <div class="cs-side">

    <!-- Assessment card -->
    <div class="cs-card">
      <div class="cs-card-hdr">Assessment</div>
      <div class="cs-card-body">
        <div class="cs-row"><span class="k">Risk score</span><span class="v" style="font-weight:700;font-size:0.82rem;{{if ge .RiskScore 76.0}}color:#f85149{{else if ge .RiskScore 51.0}}color:#fb923c{{else if ge .RiskScore 31.0}}color:#d29922{{else}}color:#3fb950{{end}}">{{printf "%.0f" .RiskScore}}</span></div>
        <div class="cs-row">
          <span class="k">Confidence</span>
          <span class="v">{{printf "%.0f" .Confidence}}%</span>
        </div>
        <div class="cs-conf-bar"><div class="cs-conf-fill" style="width:{{printf "%.0f" .Confidence}}%;background:{{if ge .Confidence 80.0}}#3fb950{{else if ge .Confidence 50.0}}#d29922{{else}}#f85149{{end}}"></div></div>
        <div class="cs-row" style="margin-top:6px"><span class="k">Latency</span><span class="v">{{latencySec .LatencyMs}}s</span></div>
        <div class="cs-row"><span class="k">Model</span><span class="v" style="font-size:0.68rem">{{.Model}}</span></div>
        <div class="cs-row"><span class="k">Tokens</span><span class="v">{{.TokensUsed}}</span></div>
      </div>
    </div>

    <!-- Quick links -->
    <div class="cs-card">
      <div class="cs-card-hdr">Related</div>
      <div class="cs-card-body" style="display:flex;flex-direction:column;gap:2px">
        {{if .FromAgent}}<a href="/dashboard/agents/{{.FromAgent}}" class="cs-row" style="text-decoration:none;color:inherit;border-radius:6px;padding:8px 10px;margin:-4px -10px;transition:background 0.1s"><span class="k">Agent</span><span class="v" style="color:var(--accent-light)">{{.FromAgent}}</span></a>{{end}}
        <a href="/dashboard/events?q={{.MessageID}}" class="cs-row" style="text-decoration:none;color:inherit;border-radius:6px;padding:8px 10px;margin:-4px -10px;transition:background 0.1s"><span class="k">Event</span><span class="v" style="color:var(--accent-light)">View &rarr;</span></a>
        <div class="cs-row"><span class="k">Message ID</span><span class="v" style="font-size:0.58rem;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{{.MessageID}}">{{.MessageID}}</span></div>
      </div>
    </div>

    <!-- Agent history -->
    {{if $.AgentHistory}}
    <div class="cs-card">
      <div class="cs-card-hdr">Agent History ({{.FromAgent}})</div>
      <div class="cs-card-body">
        <div class="cs-hist-grid">
          {{range $.AgentHistory}}
          <a href="/dashboard/llm/case/{{.ID}}" class="cs-hist-pill">
            <span class="cs-hist-score" style="{{if ge .RiskScore 76.0}}color:#f85149{{else if ge .RiskScore 51.0}}color:#fb923c{{else if ge .RiskScore 31.0}}color:#d29922{{else}}color:var(--text3){{end}}">{{printf "%.0f" .RiskScore}}</span>
            <span>{{relativeTime .Timestamp}}</span>
          </a>
          {{end}}
        </div>
      </div>
    </div>
    {{end}}

  </div>
</div>

<script>
function ciCopyText(text, btn) {
  navigator.clipboard.writeText(text).then(function() {
    var orig = btn.textContent;
    btn.textContent = 'copied';
    btn.style.color = 'var(--success)';
    setTimeout(function() { btn.textContent = orig; btn.style.color = ''; }, 1200);
  });
}
</script>
{{end}}
` + layoutFoot))

// --- Events page (merged audit log + quarantine) ---

var eventsTmpl = template.Must(template.New("events").Funcs(tmplFuncs).Parse(layoutHead + `
<p class="page-desc">All intercepted messages. Click any row for full details. <span class="sse-indicator" id="sse-status"><span class="sse-dot" id="sse-dot"></span> <span id="sse-label">connecting</span></span></p>

<div class="filter-bar">
  <select id="filter-agent">
    <option value="">All Agents</option>
    {{range .AgentNames}}<option value="{{.}}" {{if eq . $.FilterAgent}}selected{{end}}>{{.}}</option>{{end}}
  </select>
  <input type="date" id="filter-since" value="{{.FilterSince}}" title="From date">
  <span class="sep">to</span>
  <input type="date" id="filter-until" value="{{.FilterUntil}}" title="Until date">
  <button class="btn btn-sm" onclick="clearEventFilters()">Clear</button>
  <span class="spacer"></span>
  <select id="export-redaction" title="Redaction level" onchange="updateExportLinks()">
    <option value="">Full (admin)</option>
    <option value="analyst">Analyst (redacted matches)</option>
    <option value="external">External (metadata only)</option>
  </select>
  <a id="export-csv" class="btn btn-sm" download>CSV</a>
  <a id="export-json" class="btn btn-sm" download>JSON</a>
</div>
<script>
function buildExportURL(format) {
  var agent = document.getElementById('filter-agent').value;
  var since = document.getElementById('filter-since').value;
  var until = document.getElementById('filter-until').value;
  var redaction = document.getElementById('export-redaction').value;
  var url = '/dashboard/api/export/' + format + '?_=1';
  if (agent) url += '&agent=' + encodeURIComponent(agent);
  if (since) url += '&since=' + encodeURIComponent(since + 'T00:00:00Z');
  if (until) url += '&until=' + encodeURIComponent(until + 'T23:59:59Z');
  if (redaction) url += '&redaction=' + encodeURIComponent(redaction);
  return url;
}
function updateExportLinks() {
  var csv = document.getElementById('export-csv');
  var json = document.getElementById('export-json');
  if (csv) csv.href = buildExportURL('csv');
  if (json) json.href = buildExportURL('json');
}
function applyEventFilters() {
  var agent = document.getElementById('filter-agent').value;
  var since = document.getElementById('filter-since').value;
  var until = document.getElementById('filter-until').value;
  var tab = '{{.Tab}}';
  var url = '/dashboard/events?tab=' + tab;
  if (agent) url += '&agent=' + encodeURIComponent(agent);
  if (since) url += '&since=' + encodeURIComponent(since + 'T00:00:00Z');
  if (until) url += '&until=' + encodeURIComponent(until + 'T23:59:59Z');
  window.location = url;
}
function clearEventFilters() {
  window.location = '/dashboard/events?tab={{.Tab}}';
}
document.getElementById('filter-agent').addEventListener('change', applyEventFilters);
document.getElementById('filter-since').addEventListener('change', applyEventFilters);
document.getElementById('filter-until').addEventListener('change', applyEventFilters);
updateExportLinks();
</script>

<div class="tabs" data-tab-group="events">
  <a href="/dashboard/events?tab=all{{if .FilterAgent}}&agent={{.FilterAgent}}{{end}}{{if .FilterSince}}&since={{.FilterSince}}{{end}}{{if .FilterUntil}}&until={{.FilterUntil}}{{end}}" class="tab {{if eq .Tab "all"}}active{{end}}">All Events</a>
  <a href="/dashboard/events?tab=quarantine{{if .FilterAgent}}&agent={{.FilterAgent}}{{end}}{{if .FilterSince}}&since={{.FilterSince}}{{end}}{{if .FilterUntil}}&until={{.FilterUntil}}{{end}}" class="tab {{if eq .Tab "quarantine"}}active{{end}}">Quarantine{{if .QPending}} <span class="pending-badge">{{.QPending}}</span>{{end}}</a>
  <a href="/dashboard/events?tab=blocked{{if .FilterAgent}}&agent={{.FilterAgent}}{{end}}{{if .FilterSince}}&since={{.FilterSince}}{{end}}{{if .FilterUntil}}&until={{.FilterUntil}}{{end}}" class="tab {{if eq .Tab "blocked"}}active{{end}}">Blocked</a>
</div>

<!-- All Events -->
<div class="tab-content {{if eq .Tab "all"}}active{{end}}" data-tab-content="events" data-tab-name="all">
  <div class="search-bar">
    <span class="search-icon">&#x1F50D;</span>
    <input type="text" placeholder="Search events by agent, rule, or content hash..."
           hx-get="/dashboard/api/search" hx-trigger="keyup changed delay:300ms" hx-target="#search-results" hx-indicator="#events-search-loading" name="q">
    <span id="events-search-loading" class="htmx-indicator"><span class="loading-spinner"></span></span>
  </div>

  <div id="search-results">
  {{if .Entries}}
  <table>
    <thead><tr><th>Time</th><th>From</th><th>To</th><th>Status</th></tr></thead>
    <tbody id="events-body">
    {{range .Entries}}
    <tr class="ev-row clickable{{if hasRules .RulesTriggered}} has-rules{{end}}" hx-get="/dashboard/api/event/{{.ID}}" hx-target="#panel-content" hx-swap="innerHTML" ondblclick="event.preventDefault();event.stopPropagation();window.location='/dashboard/events/{{.ID}}'">
      <td data-ts="{{.Timestamp}}">{{.Timestamp}}</td>
      <td>{{agentCell .FromAgent}}</td>
      <td>{{if .ToolName}}{{toolDot .ToolName}}{{else}}{{agentCell .ToAgent}}{{end}}</td>
      <td><span class="badge-{{.Status}}">{{.Status}}</span>{{if ne .PolicyDecision "allowed"}} <span style="font-family:var(--sans);font-size:var(--text-xs);color:var(--text3);margin-left:4px">{{humanDecision .PolicyDecision}}</span>{{end}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  <div class="pager">
    <span id="ev-pager-info"></span>
    <div class="pager-btns">
      <button id="ev-prev" class="pager-btn" onclick="evPage(-1)" disabled>&larr; Prev</button>
      <button id="ev-next" class="pager-btn" onclick="evPage(1)">Next &rarr;</button>
    </div>
  </div>
  <script>
  var evCur=1,evSize=30;
  function evRender(){
    var rows=document.querySelectorAll('.ev-row');
    var total=rows.length;
    var start=(evCur-1)*evSize,end=Math.min(start+evSize,total);
    rows.forEach(function(r,i){r.style.display=(i>=start&&i<end)?'':'none';});
    document.getElementById('ev-pager-info').textContent=total?'Showing '+(start+1)+'\u2013'+end+' of '+total:'';
    document.getElementById('ev-prev').disabled=evCur<=1;
    document.getElementById('ev-next').disabled=end>=total;
  }
  function evPage(d){evCur+=d;evRender();}
  evRender();
  </script>
  {{else}}
  <div class="empty">No events in this view. Use your MCP tools normally and events will appear here in real-time.</div>
  {{end}}
  </div>
</div>

<!-- Quarantine -->
<div class="tab-content {{if eq .Tab "quarantine"}}active{{end}}" data-tab-content="events" data-tab-name="quarantine">
  {{if .QStats}}
  <div class="stats grid-4" style="margin-bottom:20px">
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

  <div class="filter-bar">
    <a href="/dashboard/events?tab=quarantine&status=pending" class="toggle-btn {{if eq .QStatusFilter "pending"}}active{{end}}">Pending</a>
    <a href="/dashboard/events?tab=quarantine&status=approved" class="toggle-btn {{if eq .QStatusFilter "approved"}}active{{end}}">Approved</a>
    <a href="/dashboard/events?tab=quarantine&status=rejected" class="toggle-btn {{if eq .QStatusFilter "rejected"}}active{{end}}">Rejected</a>
    <a href="/dashboard/events?tab=quarantine&status=" class="toggle-btn {{if eq .QStatusFilter ""}}active{{end}}">All</a>
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
          <button class="btn btn-sm btn-success" hx-post="/dashboard/api/quarantine/{{.ID}}/approve" hx-target="#q-row-{{.ID}}" hx-swap="outerHTML">Approve</button>
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
  <div class="empty">No quarantined messages{{if .QStatusFilter}} with status "{{.QStatusFilter}}"{{end}}.{{if not .RequireSig}} Currently in observe mode - messages are scanned but not held. Switch to enforce mode to enable quarantine.{{end}}</div>
  {{end}}
</div>

<!-- Blocked -->
<div class="tab-content {{if eq .Tab "blocked"}}active{{end}}" data-tab-content="events" data-tab-name="blocked">
  {{if .BlockedEntries}}
  <table>
    <thead><tr><th>Time</th><th>From</th><th>To</th><th>Status</th></tr></thead>
    <tbody>
    {{range .BlockedEntries}}
    <tr class="blk-row clickable has-rules" hx-get="/dashboard/api/event/{{.ID}}" hx-target="#panel-content" hx-swap="innerHTML" ondblclick="event.preventDefault();event.stopPropagation();window.location='/dashboard/events/{{.ID}}'">
      <td data-ts="{{.Timestamp}}">{{.Timestamp}}</td>
      <td>{{agentCell .FromAgent}}</td>
      <td>{{if .ToolName}}{{toolDot .ToolName}}{{else}}{{agentCell .ToAgent}}{{end}}</td>
      <td><span class="badge-{{.Status}}">{{.Status}}</span> <span style="font-family:var(--sans);font-size:var(--text-xs);color:var(--text3);margin-left:4px">{{humanDecision .PolicyDecision}}</span></td>
    </tr>
    {{end}}
    </tbody>
  </table>
  <div class="pager">
    <span id="blk-pager-info"></span>
    <div class="pager-btns">
      <button id="blk-prev" class="pager-btn" onclick="blkPage(-1)" disabled>&larr; Prev</button>
      <button id="blk-next" class="pager-btn" onclick="blkPage(1)">Next &rarr;</button>
    </div>
  </div>
  <script>
  var blkCur=1,blkSize=30;
  function blkRender(){
    var rows=document.querySelectorAll('.blk-row');
    var total=rows.length;
    var start=(blkCur-1)*blkSize,end=Math.min(start+blkSize,total);
    rows.forEach(function(r,i){r.style.display=(i>=start&&i<end)?'':'none';});
    document.getElementById('blk-pager-info').textContent=total?'Showing '+(start+1)+'\u2013'+end+' of '+total:'';
    document.getElementById('blk-prev').disabled=blkCur<=1;
    document.getElementById('blk-next').disabled=end>=total;
  }
  function blkPage(d){blkCur+=d;blkRender();}
  blkRender();
  </script>
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
      var toolColors = {Bash:'#d29922',Write:'#c084fc',Edit:'#818cf8',Read:'#22d3ee',Glob:'#2dd4bf',Grep:'#2dd4bf',WebFetch:'#f472b6',WebSearch:'#f472b6',Agent:'#a78bfa'};
      var toCell;
      if (ev.tool_name) {
        var tc = toolColors[ev.tool_name] || '#6e7681';
        toCell = '<span style="display:inline-flex;align-items:center;gap:5px"><span style="width:6px;height:6px;border-radius:50%;background:'+tc+';flex-shrink:0"></span>'+ev.tool_name+'</span>';
      } else {
        toCell = agentCellHTML(ev.to_agent||'');
      }
      var hasRules = ev.rules_triggered && ev.rules_triggered !== '[]' && ev.rules_triggered !== 'null';
      var row = document.createElement('tr');
      row.className = 'ev-row clickable new-event' + (hasRules ? ' has-rules' : '');
      row.setAttribute('hx-get', '/dashboard/api/event/' + ev.id);
      row.setAttribute('hx-target', '#panel-content');
      row.setAttribute('hx-swap', 'innerHTML');
      row.ondblclick = function(evt){evt.preventDefault();evt.stopPropagation();window.location='/dashboard/events/'+ev.id;};
      var decExtra='';
      if(ev.policy_decision&&ev.policy_decision!=='allowed'){
        var labels={'content_blocked':'Blocked — dangerous content','content_quarantined':'Quarantined','signature_required':'Rejected — unsigned','acl_denied':'Rejected — ACL denied'};
        decExtra=' <span style="font-family:var(--sans);font-size:var(--text-xs);color:var(--text3);margin-left:4px">'+(labels[ev.policy_decision]||ev.policy_decision)+'</span>';
      }
      row.innerHTML = '<td data-ts="' + ev.timestamp + '">' + ev.timestamp + '</td><td>' + agentCellHTML(ev.from_agent||'') + '</td><td>' + toCell + '</td><td><span class="badge-' + ev.status + '">' + ev.status + '</span>'+decExtra+'</td>';
      tbody.insertBefore(row, tbody.firstChild);
      htmx.process(row);
      if(typeof humanizeTimestamps==='function')humanizeTimestamps();
    } catch(err) {}
  };
})();
</script>
` + layoutFoot))

var graphTmpl = template.Must(template.New("graph").Funcs(tmplFuncs).Parse(layoutHead + `
<p class="page-desc">Red nodes have high threat scores. Shadow edges indicate traffic outside ACL policy. Data covers the last {{.Range}}.</p>

<div style="display:flex;gap:8px;margin-bottom:16px">
  {{range $v := .Ranges}}<a href="/dashboard/graph?range={{$v}}" class="btn btn-sm{{if eq $v $.Range}} active{{end}}" style="{{if eq $v $.Range}}background:var(--accent-dim);color:#fff;border-color:var(--accent){{end}}">{{$v}}</a>{{end}}
</div>

<div class="stats">
  <div class="stat"><div class="label">Nodes</div><div class="value">{{.Graph.TotalNodes}}</div></div>
  <div class="stat"><div class="label" data-tooltip="Connections with observed traffic between agents">Active Edges</div><div class="value">{{.Graph.TotalEdges}}</div></div>
  <div class="stat"><div class="label" data-tooltip="Traffic between agents not defined in ACL policy — may indicate misconfiguration">Shadow Edges</div><div class="value{{if .Graph.ShadowEdges}} warn{{end}}">{{len .Graph.ShadowEdges}}</div></div>
  <div class="stat"><div class="label" data-tooltip="ACL entries with no observed traffic — consider tightening permissions">Unused ACL</div><div class="value{{if .Graph.UnusedACL}} warn{{end}}">{{len .Graph.UnusedACL}}</div></div>
</div>

{{if and .Graph.ShadowEdges .RequireSig}}
<div class="alert-banner warn">
  <strong>{{len .Graph.ShadowEdges}} unregistered route{{if gt (len .Graph.ShadowEdges) 1}}s{{end}}</strong> — Traffic observed between agents without explicit ACL rules. Configure ACLs in Settings or agent profiles.
</div>
{{end}}

<div class="card" style="padding:0;overflow:hidden">
  <div style="display:flex;min-height:480px;height:calc(100vh - 340px)">
    <div style="flex:1;position:relative;overflow:hidden">
      <div id="graph-container" style="width:100%;height:100%;background:var(--bg);position:relative;overflow:hidden"></div>
      <div style="position:absolute;bottom:12px;left:16px;display:flex;gap:16px;font-size:0.7rem;color:var(--text3)">
        <span><svg width="18" height="10"><line x1="0" y1="5" x2="18" y2="5" stroke="#5eead4" stroke-width="2"/></svg> Orchestration</span>
        <span><svg width="18" height="10"><line x1="0" y1="5" x2="18" y2="5" stroke="#a78bfa" stroke-width="1" stroke-dasharray="3 3" stroke-opacity="0.5"/></svg> Tool call</span>
      </div>
    </div>
    <div style="width:340px;border-left:1px solid var(--border);background:var(--surface2);flex-shrink:0;overflow-y:auto;font-size:0.8rem">
      <div style="padding:16px 20px;border-bottom:1px solid var(--border)">
        <h3 style="font-size:0.95rem;font-weight:700;margin-bottom:14px">Overview</h3>
        <div id="gw-stats">
          <div style="display:flex;justify-content:space-between;padding:7px 10px;border:1px solid var(--border);border-radius:6px;margin-bottom:4px"><span style="color:var(--text3)">Agents</span><span id="gs-agents" style="font-weight:700;font-family:var(--mono)">--</span></div>
          <div style="display:flex;justify-content:space-between;padding:7px 10px;border:1px solid var(--border);border-radius:6px;margin-bottom:4px"><span style="color:var(--text3)">Tools</span><span id="gs-tools" style="font-weight:700;font-family:var(--mono)">--</span></div>
          <div style="display:flex;justify-content:space-between;padding:7px 10px;border:1px solid var(--border);border-radius:6px;margin-bottom:4px"><span style="color:var(--text3)">Messages scanned</span><span id="gs-messages" style="font-weight:700;font-family:var(--mono)">--</span></div>
          <div style="display:flex;justify-content:space-between;padding:7px 10px;border:1px solid var(--border);border-radius:6px;margin-bottom:4px"><span style="color:var(--text3)">Policy blocks</span><span id="gs-blocks" style="font-weight:700;font-family:var(--mono);color:#f85149">--</span></div>
          <div style="display:flex;justify-content:space-between;padding:7px 10px;border:1px solid var(--border);border-radius:6px;margin-bottom:4px"><span style="color:var(--text3)">Audit entries</span><span id="gs-audit" style="font-weight:700;font-family:var(--mono)">--</span></div>
        </div>
      </div>
      <div style="padding:16px 20px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
          <span style="font-size:0.7rem;color:var(--text3);letter-spacing:0.05em;font-weight:600">EVENT LOG</span>
          <span id="gw-event-count" style="font-size:0.7rem;color:var(--text3)"></span>
        </div>
        <div id="gw-events" style="font-size:0.75rem;font-family:var(--mono)"></div>
      </div>
    </div>
  </div>
</div>

<div id="graph-tables">
<div class="grid-2" style="gap:20px">
  <div class="card">
    <h2>Node Threat Scores</h2>
    <p style="color:var(--text3);font-size:0.78rem;margin-bottom:12px">Higher scores mean more blocked or quarantined messages originating from this agent.</p>
    {{if .Graph.Nodes}}
    <table>
      <thead><tr><th>Agent</th><th data-tooltip="Score based on ratio of blocked and quarantined messages">Threat</th><th>Sent</th><th>Recv</th><th data-tooltip="Agent's role in the communication network based on traffic patterns">Role</th></tr></thead>
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
        <td style="color:var(--text3)">{{if eq .Betweenness -1.0}}—{{else if gt .Betweenness 0.3}}Hub{{else if and (gt .TotalSent 0) (eq .TotalRecv 0)}}Producer{{else if and (eq .TotalSent 0) (gt .TotalRecv 0)}}Consumer{{else}}Peer{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">No agents detected in this time range</p>{{end}}
  </div>

  <div class="card">
    <h2>Edge Health</h2>
    <p style="color:var(--text3);font-size:0.78rem;margin-bottom:12px">Percentage of messages on each connection that were delivered successfully.</p>
    {{if .Graph.Edges}}
    <table>
      <thead><tr><th>From</th><th>To</th><th>Total</th><th data-tooltip="Ratio of delivered messages to total — lower scores indicate more blocked or quarantined traffic">Health</th></tr></thead>
      <tbody>
      {{range .Graph.Edges}}
      <tr class="clickable" hx-get="/dashboard/api/graph/edge?from={{.From}}&amp;to={{.To}}&amp;range={{$.Range}}" hx-target="#panel-content" hx-swap="innerHTML">
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
    {{else}}<p class="empty">No traffic in this time range</p>{{end}}
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
    <tbody id="acl-tbody">
    {{range .Graph.UnusedACL}}
    <tr class="acl-row"><td>{{.From}}</td><td>{{.To}}</td><td><span style="color:var(--text3)">no traffic</span></td></tr>
    {{end}}
    </tbody>
  </table>
  {{if gt (len .Graph.UnusedACL) 10}}
  <button id="acl-toggle" onclick="(function(){var rows=document.querySelectorAll('.acl-row');var btn=document.getElementById('acl-toggle');if(btn.dataset.open==='1'){rows.forEach(function(r,i){r.style.display=i>=10?'none':''});btn.textContent='Show all ('+rows.length+')';btn.dataset.open='0'}else{rows.forEach(function(r){r.style.display=''});btn.textContent='Show less';btn.dataset.open='1'}})()" data-open="0" style="margin-top:8px;background:none;border:1px solid var(--border);color:var(--accent-light);padding:6px 16px;border-radius:6px;cursor:pointer;font-size:0.78rem">Show all ({{len .Graph.UnusedACL}})</button>
  <script>document.querySelectorAll('.acl-row').forEach(function(r,i){if(i>=10)r.style.display='none'});</script>
  {{end}}
</div>
{{end}}
</div><!-- end graph-tables -->

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
    var NR = 18, OR = 26, TR = 10, PAD = 50;
    var cx = W / 2, cy = H / 2;
    // 3-column layout: ORCHESTRATOR | AGENTS | TOOLS
    // Agent sub-columns expand when there are many agents
    var agentCols = 1;
    var totalAgents = (data.nodes||[]).filter(function(n){return !n.is_tool && !n.is_orch && n.name!=='gateway';}).length;
    if (totalAgents > 12) agentCols = 3;
    else if (totalAgents > 6) agentCols = 2;

    var COL1 = W * 0.10; // orchestrator
    var COL_GW = W * 0.22; // gateway checkpoint
    var agentZoneStart = W * 0.36;
    var agentZoneEnd = W * 0.68;
    var COL2 = (agentZoneStart + agentZoneEnd) / 2; // center (used for header)
    var COL3 = W * 0.82; // tools
    var NS = 'http://www.w3.org/2000/svg';

    // ── Build edge latency map from raw data ──
    var latencyMap = {};
    (data.edges || []).forEach(function(e) {
      latencyMap[e.from+'>'+e.to] = e.avg_latency_ms || 0;
    });

    // ── Build node + link arrays ──
    var nodes = data.nodes.map(function(n) {
      return {name:n.name, isTool:false, isOrch:n.name==='claude-code', threat:n.threat_score, sent:n.total_sent||0, recv:n.total_recv||0, betweenness:n.betweenness!=null?n.betweenness:-1, x:cx, y:cy, _g:null};
    });
    var nodeIdx = {};
    nodes.forEach(function(n,i){ nodeIdx[n.name]=i; });

    var links = (data.edges||[]).filter(function(e){
      return nodeIdx[e.from]!==undefined && nodeIdx[e.to]!==undefined;
    }).map(function(e){
      return {from:nodeIdx[e.from], to:nodeIdx[e.to], health:e.health_score, total:e.total, latency:e.avg_latency_ms||0, fromName:e.from, toName:e.to, isTool:false};
    });

    (data.tool_nodes||[]).forEach(function(tn){
      nodeIdx[tn.name]=nodes.length;
      nodes.push({name:tn.name, isTool:true, isOrch:false, toolTotal:tn.total, threat:0, sent:0, recv:0, betweenness:-1, x:cx, y:cy, _g:null});
    });
    (data.tool_edges||[]).forEach(function(te){
      var ai=nodeIdx[te.agent], ti=nodeIdx[te.tool];
      if(ai!==undefined&&ti!==undefined) links.push({from:ai, to:ti, health:100, total:te.total, latency:0, fromName:te.agent, toName:te.tool, isTool:true});
    });

    // ── Columnar layout: ORCHESTRATOR → AGENTS → TOOLS ──
    // Separate agents from gateway
    var agentNodes=[], gwIdx=-1;
    nodes.forEach(function(n,i){
      if(n.isOrch) return;
      if(n.isTool) return;
      if(n.name==='gateway'){ gwIdx=i; return; }
      agentNodes.push(i);
    });

    // Position orchestrator (column 1)
    if(nodeIdx['claude-code']!==undefined){
      nodes[nodeIdx['claude-code']].x=COL1;
      nodes[nodeIdx['claude-code']].y=H*0.50;
    }
    // Position gateway checkpoint (between col 1 and col 2)
    if(gwIdx>=0){
      nodes[gwIdx].x=COL_GW;
      nodes[gwIdx].y=H*0.50;
    }
    // Position agents in sub-columns (1, 2, or 3 cols depending on count)
    var perCol=Math.ceil(agentNodes.length/agentCols);
    var subColWidth=(agentZoneEnd-agentZoneStart)/(agentCols);
    agentNodes.forEach(function(idx,i){
      var col=Math.floor(i/perCol);
      var row=i%perCol;
      var colCount=Math.min(perCol, agentNodes.length-col*perCol);
      var spacing=Math.min(80, (H-PAD*2)/(colCount+1));
      var startY=(H-(colCount-1)*spacing)/2;
      nodes[idx].x=agentZoneStart+subColWidth*(col+0.5);
      nodes[idx].y=startY+row*spacing;
    });
    // Position tool nodes vertically in column 3
    var toolNodes=[];
    nodes.forEach(function(n,i){ if(n.isTool) toolNodes.push(i); });
    var toolSpacing=Math.min(60, (H-PAD*2)/(toolNodes.length+1));
    var toolStartY=(H-(toolNodes.length-1)*toolSpacing)/2;
    toolNodes.forEach(function(idx,i){
      nodes[idx].x=COL3;
      nodes[idx].y=toolStartY+i*toolSpacing;
    });
    function nodeRadius(n){return n.isTool?TR+4:(n.isOrch?OR+4:NR+4);}

    // ── SVG setup ──
    var svg=document.createElementNS(NS,'svg');
    svg.setAttribute('width',W); svg.setAttribute('height',H);
    svg.setAttribute('viewBox','0 0 '+W+' '+H);
    svg.style.width='100%'; svg.style.height='100%';

    var defs=document.createElementNS(NS,'defs');
    var edgeColors={ok:'#5eead4',warn:'#d29922',bad:'#f85149'};
    ['ok','warn','bad'].forEach(function(k){
      var m=document.createElementNS(NS,'marker');
      m.setAttribute('id','arr-'+k); m.setAttribute('viewBox','0 0 8 6');
      m.setAttribute('refX','8'); m.setAttribute('refY','3');
      m.setAttribute('markerWidth','6'); m.setAttribute('markerHeight','5');
      m.setAttribute('orient','auto');
      var p=document.createElementNS(NS,'path');
      p.setAttribute('d','M0,0.5 L7,3 L0,5.5'); p.setAttribute('fill',edgeColors[k]);
      m.appendChild(p); defs.appendChild(m);
    });
    // Glow filter
    var glow=document.createElementNS(NS,'filter');
    glow.setAttribute('id','glow'); glow.setAttribute('x','-50%'); glow.setAttribute('y','-50%');
    glow.setAttribute('width','200%'); glow.setAttribute('height','200%');
    var gb=document.createElementNS(NS,'feGaussianBlur'); gb.setAttribute('stdDeviation','4'); gb.setAttribute('result','blur');
    glow.appendChild(gb);
    var fm=document.createElementNS(NS,'feMerge');
    var mn1=document.createElementNS(NS,'feMergeNode'); mn1.setAttribute('in','blur');
    var mn2=document.createElementNS(NS,'feMergeNode'); mn2.setAttribute('in','SourceGraphic');
    fm.appendChild(mn1); fm.appendChild(mn2); glow.appendChild(fm); defs.appendChild(glow);
    // Orchestrator gradient
    var orchGrad=document.createElementNS(NS,'radialGradient'); orchGrad.setAttribute('id','orchFill');
    var s1=document.createElementNS(NS,'stop'); s1.setAttribute('offset','0%'); s1.setAttribute('stop-color','#a78bfa'); s1.setAttribute('stop-opacity','0.25');
    var s2=document.createElementNS(NS,'stop'); s2.setAttribute('offset','100%'); s2.setAttribute('stop-color','#7c3aed'); s2.setAttribute('stop-opacity','0.08');
    orchGrad.appendChild(s1); orchGrad.appendChild(s2); defs.appendChild(orchGrad);
    svg.appendChild(defs);

    var style=document.createElementNS(NS,'style');
    style.textContent='@keyframes orchPulse{0%,100%{opacity:0.7}50%{opacity:1}}.orch-hex{animation:orchPulse 3s ease-in-out infinite}.graph-dim{opacity:0.18!important;transition:opacity 0.3s}.graph-bright{opacity:1!important;transition:opacity 0.3s}';
    svg.appendChild(style);

    // Column headers
    var headerFont='font-size:9px;fill:#52525b;font-family:ui-monospace,SFMono-Regular,monospace;letter-spacing:0.08em';
    ['ORCHESTRATOR','AGENTS','TOOLS'].forEach(function(label,ci){
      var hx=[COL1,COL2,COL3][ci];
      var ht=document.createElementNS(NS,'text');
      ht.setAttribute('x',hx); ht.setAttribute('y',24);
      ht.setAttribute('text-anchor','middle');
      ht.setAttribute('style',headerFont);
      ht.textContent=label;
      svg.appendChild(ht);
    });

    // Column separator lines
    [COL_GW+(agentZoneStart-COL_GW)*0.5, agentZoneEnd+(COL3-agentZoneEnd)*0.5].forEach(function(sx){
      var sep=document.createElementNS(NS,'line');
      sep.setAttribute('x1',sx); sep.setAttribute('y1',38);
      sep.setAttribute('x2',sx); sep.setAttribute('y2',H-10);
      sep.setAttribute('stroke','#2a2a2e'); sep.setAttribute('stroke-width','1');
      sep.setAttribute('stroke-dasharray','2 4');
      svg.appendChild(sep);
    });

    // ── Edges ──
    var lineEls=[], particles=[];
    var edgePairs={};
    links.forEach(function(e){ var key=Math.min(e.from,e.to)+'-'+Math.max(e.from,e.to); edgePairs[key]=(edgePairs[key]||0)+1; });
    var edgePairCount={};
    var maxTotal=1;
    links.forEach(function(e){ if(!e.isTool&&e.total>maxTotal) maxTotal=e.total; });

    links.forEach(function(e){
      var hk, strokeColor, baseW, co=0;

      if(e.isTool){
        // Tool edges: dashed purple lines
        hk='ok'; strokeColor='#a78bfa'; baseW=1.2;
      } else {
        hk=e.health>=70?'ok':(e.health>=40?'warn':'bad');
        strokeColor=edgeColors[hk];
        var key=Math.min(e.from,e.to)+'-'+Math.max(e.from,e.to);
        var pairTotal=edgePairs[key]||1;
        edgePairCount[key]=(edgePairCount[key]||0)+1;
        if(pairTotal>1) co=(edgePairCount[key]%2===0?1:-1)*18;
        baseW=Math.min(3,0.8+(e.total/maxTotal)*2.2);
      }

      var lineEl;
      if(co!==0){ lineEl=document.createElementNS(NS,'path'); lineEl.setAttribute('fill','none'); }
      else { lineEl=document.createElementNS(NS,'line'); }
      lineEl.setAttribute('stroke',strokeColor);
      lineEl.setAttribute('stroke-width',baseW);
      lineEl.setAttribute('stroke-opacity',e.isTool?'0.5':'0.4');
      if(e.isTool) lineEl.setAttribute('stroke-dasharray','4 3');
      if(!e.isTool) lineEl.setAttribute('marker-end','url(#arr-'+hk+')');
      lineEl.style.cursor='pointer';
      lineEl.setAttribute('data-edge','1');
      lineEl.setAttribute('data-from',e.fromName);
      lineEl.setAttribute('data-to',e.toName);
      svg.appendChild(lineEl);

      // Latency info available on hover/sidebar — no inline labels to keep graph clean

      // Particles
      var numP=e.isTool?1:Math.min(3,Math.max(1,Math.ceil(e.total/maxTotal*3)));
      for(var pi=0;pi<numP;pi++){
        var dot=document.createElementNS(NS,'circle');
        dot.setAttribute('r',e.isTool?'1.8':'2.5');
        dot.setAttribute('fill',strokeColor);
        dot.setAttribute('opacity',e.isTool?'0.5':'0.6');
        dot.setAttribute('data-edge','1');
        dot.setAttribute('data-from',e.fromName);
        dot.setAttribute('data-to',e.toName);
        svg.appendChild(dot);
        particles.push({dot:dot, link:e, co:co, t:pi/numP, speed:e.isTool?0.001+Math.random()*0.001:0.0015+Math.random()*0.002});
      }
      lineEls.push({el:lineEl, link:e, curved:co!==0, co:co, baseW:baseW, hk:hk, isTool:e.isTool});
    });

    function edgeEndpoints(le){
      var s=nodes[le.link.from],t=nodes[le.link.to];
      var dx=t.x-s.x, dy=t.y-s.y, d=Math.sqrt(dx*dx+dy*dy)||1;
      var tr=nodeRadius(t);
      return {sx:s.x,sy:s.y,ex:t.x-(dx/d)*tr,ey:t.y-(dy/d)*tr,dx:dx,dy:dy,d:d};
    }

    function updateEdges(){
      lineEls.forEach(function(le){
        var ep=edgeEndpoints(le);
        if(le.curved){
          var mx=(ep.sx+ep.ex)/2+(-ep.dy/ep.d)*le.co;
          var my=(ep.sy+ep.ey)/2+(ep.dx/ep.d)*le.co;
          le.el.setAttribute('d','M'+ep.sx+','+ep.sy+' Q'+mx+','+my+' '+ep.ex+','+ep.ey);
        } else {
          le.el.setAttribute('x1',ep.sx); le.el.setAttribute('y1',ep.sy);
          le.el.setAttribute('x2',ep.ex); le.el.setAttribute('y2',ep.ey);
        }
      });
    }
    updateEdges();

    // Particle animation (pauses when tab hidden to save CPU)
    var tabVisible=true, animId=null;
    document.addEventListener('visibilitychange',function(){
      tabVisible=!document.hidden;
      if(tabVisible&&!animId) animId=requestAnimationFrame(animParticles);
    });
    function animParticles(){
      if(!tabVisible){animId=null;return;}
      particles.forEach(function(p){
        p.t+=p.speed; if(p.t>1) p.t-=1;
        var s=nodes[p.link.from],t=nodes[p.link.to];
        var dx=t.x-s.x,dy=t.y-s.y,d=Math.sqrt(dx*dx+dy*dy)||1;
        var tr=nodeRadius(t);
        var ex=t.x-(dx/d)*tr, ey=t.y-(dy/d)*tr;
        var tt=p.t, x, y;
        if(p.co!==0){
          var mx=(s.x+ex)/2+(-dy/d)*p.co, my=(s.y+ey)/2+(dx/d)*p.co;
          var u=1-tt;
          x=u*u*s.x+2*u*tt*mx+tt*tt*ex; y=u*u*s.y+2*u*tt*my+tt*tt*ey;
        } else { x=s.x+(ex-s.x)*tt; y=s.y+(ey-s.y)*tt; }
        p.dot.setAttribute('cx',x); p.dot.setAttribute('cy',y);
      });
      animId=requestAnimationFrame(animParticles);
    }
    animId=requestAnimationFrame(animParticles);

    // ── Focus/Dim state ──
    var focusedNode=null;

    function getConnectedNames(nodeName){
      var connected={};
      connected[nodeName]=true;
      // Upstream: trace back from clicked node to orchestrator
      var upstream={};upstream[nodeName]=true;
      var ch=true;
      while(ch){ ch=false; links.forEach(function(l){
        if(!l.isTool&&upstream[l.toName]&&!upstream[l.fromName]){ upstream[l.fromName]=true;connected[l.fromName]=true;ch=true; }
      });}
      // Downstream: trace forward from clicked node to tools
      ch=true;
      var downstream={};downstream[nodeName]=true;
      while(ch){ ch=false; links.forEach(function(l){
        if(downstream[l.fromName]&&!downstream[l.toName]){ downstream[l.toName]=true;connected[l.toName]=true;ch=true; }
      });}
      return connected;
    }

    function focusNode(n){
      if(focusedNode===n.name){ unfocus(); return; }
      focusedNode=n.name;
      var connected=getConnectedNames(n.name);
      nodes.forEach(function(nd){
        if(nd._g){
          if(connected[nd.name]) nd._g.classList.remove('graph-dim'), nd._g.classList.add('graph-bright');
          else nd._g.classList.add('graph-dim'), nd._g.classList.remove('graph-bright');
        }
      });
      svg.querySelectorAll('[data-edge]').forEach(function(el2){
        var ef=el2.getAttribute('data-from'), et=el2.getAttribute('data-to');
        if(connected[ef]&&connected[et]) el2.classList.remove('graph-dim'), el2.classList.add('graph-bright');
        else el2.classList.add('graph-dim'), el2.classList.remove('graph-bright');
      });
    }

    function unfocus(){
      focusedNode=null;
      nodes.forEach(function(nd){ if(nd._g){ nd._g.classList.remove('graph-dim','graph-bright'); }});
      svg.querySelectorAll('[data-edge]').forEach(function(el2){ el2.classList.remove('graph-dim','graph-bright'); });
    }

    // polling moved to separate script block below

    // Click background to unfocus
    svg.addEventListener('click',function(ev){ if(ev.target===svg) unfocus(); });

    // ── Nodes ──
    var nodeLayer=document.createElementNS(NS,'g');
    function hexPts(hx,hy,r){
      var pts=[];
      for(var hi=0;hi<6;hi++){var a=Math.PI/6+(Math.PI/3)*hi; pts.push((hx+r*Math.cos(a)).toFixed(1)+','+(hy+r*Math.sin(a)).toFixed(1));}
      return pts.join(' ');
    }

    nodes.forEach(function(n,i){
      var g=document.createElementNS(NS,'g');
      g.style.cursor='pointer';
      n._g=g;

      var shape, fo, labelY, textLen;
      var nameLen=Math.min(n.name.length,22);

      if(n.isTool){
        shape=document.createElementNS(NS,'rect');
        shape.setAttribute('x',n.x-TR-2); shape.setAttribute('y',n.y-TR-2);
        shape.setAttribute('width',(TR+2)*2); shape.setAttribute('height',(TR+2)*2);
        shape.setAttribute('rx','4');
        shape.setAttribute('fill','rgba(139,92,246,0.06)');
        shape.setAttribute('stroke','#7c3aed'); shape.setAttribute('stroke-width','1');
        shape.setAttribute('stroke-opacity','0.5');
        fo=document.createElementNS(NS,'foreignObject');
        fo.setAttribute('x',n.x-TR); fo.setAttribute('y',n.y-TR);
        fo.setAttribute('width',TR*2); fo.setAttribute('height',TR*2);
        var toolDiv=document.createElement('div');
        toolDiv.style.cssText='width:100%;height:100%;display:flex;align-items:center;justify-content:center;color:#a78bfa;font-family:ui-monospace,SFMono-Regular,monospace;font-size:10px;font-weight:600';
        toolDiv.textContent=n.name.charAt(0).toUpperCase();
        fo.appendChild(toolDiv);
        labelY=n.y+TR+11; textLen=nameLen*4.5+6;

      } else if(n.isOrch){
        shape=document.createElementNS(NS,'polygon');
        shape.setAttribute('points',hexPts(n.x,n.y,OR+3));
        shape.setAttribute('fill','url(#orchFill)');
        shape.setAttribute('stroke','#a78bfa'); shape.setAttribute('stroke-width','2.5');
        shape.setAttribute('filter','url(#glow)');
        shape.classList.add('orch-hex');
        var innerHex=document.createElementNS(NS,'polygon');
        innerHex.setAttribute('points',hexPts(n.x,n.y,OR-5));
        innerHex.setAttribute('fill','rgba(139,92,246,0.15)');
        innerHex.setAttribute('stroke','#c4b5fd'); innerHex.setAttribute('stroke-width','1');
        innerHex.setAttribute('stroke-opacity','0.4');
        fo=document.createElementNS(NS,'foreignObject');
        fo.setAttribute('x',n.x-14); fo.setAttribute('y',n.y-14);
        fo.setAttribute('width',28); fo.setAttribute('height',28);
        var orchIcon=document.createElement('div');
        orchIcon.style.cssText='width:100%;height:100%;display:flex;align-items:center;justify-content:center;color:#c4b5fd;font-size:16px;font-weight:700;font-family:ui-monospace,SFMono-Regular,monospace';
        orchIcon.textContent='\u2B21';
        fo.appendChild(orchIcon);
        n._innerHex=innerHex;
        labelY=n.y+OR+16; textLen=nameLen*5.8+10;

      } else {
        var ringColor=n.threat>60?'#f85149':(n.threat>30?'#d29922':'#3fb950');
        shape=document.createElementNS(NS,'circle');
        shape.setAttribute('cx',n.x); shape.setAttribute('cy',n.y); shape.setAttribute('r',NR+2);
        shape.setAttribute('fill','none');
        shape.setAttribute('stroke',ringColor); shape.setAttribute('stroke-width','1.5');
        shape.setAttribute('stroke-opacity','0.6');
        fo=document.createElementNS(NS,'foreignObject');
        fo.setAttribute('x',n.x-NR); fo.setAttribute('y',n.y-NR);
        fo.setAttribute('width',NR*2); fo.setAttribute('height',NR*2);
        var avDiv=document.createElement('div');
        avDiv.innerHTML=agentAvatar(n.name,NR*2);
        fo.appendChild(avDiv);
        labelY=n.y+NR+14; textLen=nameLen*5.8+10;

        // Status dot (small indicator at top-right of node)
        var statusDot=document.createElementNS(NS,'circle');
        statusDot.setAttribute('cx',n.x+NR-2); statusDot.setAttribute('cy',n.y-NR+2);
        statusDot.setAttribute('r','4');
        statusDot.setAttribute('fill',ringColor);
        statusDot.setAttribute('stroke','#0d1117'); statusDot.setAttribute('stroke-width','1.5');
        n._statusDot=statusDot;
      }

      // Label
      var labelBg=document.createElementNS(NS,'rect');
      labelBg.setAttribute('x',n.x-textLen/2); labelBg.setAttribute('y',labelY-9);
      labelBg.setAttribute('width',textLen); labelBg.setAttribute('height',n.isOrch?26:14);
      labelBg.setAttribute('rx','3');
      labelBg.setAttribute('fill','#0d1117'); labelBg.setAttribute('fill-opacity','0.9');

      var label=document.createElementNS(NS,'text');
      label.setAttribute('x',n.x); label.setAttribute('y',labelY);
      label.setAttribute('text-anchor','middle');
      label.setAttribute('fill',n.isTool?'#a78bfa':'#e4e4e7');
      label.setAttribute('font-size',n.isTool?'8.5':(n.isOrch?'12':'9.5'));
      label.setAttribute('font-weight',n.isOrch?'600':'500');
      label.setAttribute('font-family','ui-monospace,SFMono-Regular,SF Mono,Menlo,monospace');
      var maxLen=n.isOrch?22:16;
      var displayName=n.name==='gateway'?'oktsec':(n.name.length>maxLen?n.name.substring(0,maxLen-1)+'\u2026':n.name);
      label.textContent=displayName;

      // Orchestrator subtitle
      var subLabel=null;
      if(n.isOrch){
        subLabel=document.createElementNS(NS,'text');
        subLabel.setAttribute('x',n.x); subLabel.setAttribute('y',labelY+12);
        subLabel.setAttribute('text-anchor','middle');
        subLabel.setAttribute('fill','#6e7681');
        subLabel.setAttribute('font-size','9');
        subLabel.setAttribute('font-family','ui-monospace,SFMono-Regular,SF Mono,Menlo,monospace');
        subLabel.textContent='orchestrator';
      }

      g.appendChild(shape);
      if(n._innerHex) g.appendChild(n._innerHex);
      g.appendChild(fo); g.appendChild(labelBg); g.appendChild(label);
      if(subLabel) g.appendChild(subLabel);
      if(n._statusDot) g.appendChild(n._statusDot);
      n._ring=shape; n._fo=fo; n._label=label; n._labelBg=labelBg; n._subLabel=subLabel;

      var didDrag=false;
      g.addEventListener('click',function(ev){
        ev.stopPropagation();
        if(didDrag){didDrag=false;return;}
        if(n.isTool) return;
        focusNode(n);
      });

      // Drag support
      var dragging=false;
      fo.addEventListener('mousedown',function(ev){dragging=true;ev.preventDefault();});
      svg.addEventListener('mousemove',function(ev){
        if(!dragging)return;
        didDrag=true;
        var rect=svg.getBoundingClientRect();
        n.x=Math.max(PAD,Math.min(W-PAD,ev.clientX-rect.left));
        n.y=Math.max(PAD,Math.min(H-PAD,ev.clientY-rect.top));
        if(n.isTool){
          shape.setAttribute('x',n.x-TR-2); shape.setAttribute('y',n.y-TR-2);
          fo.setAttribute('x',n.x-TR); fo.setAttribute('y',n.y-TR);
        } else if(n.isOrch){
          shape.setAttribute('points',hexPts(n.x,n.y,OR+3));
          if(n._innerHex) n._innerHex.setAttribute('points',hexPts(n.x,n.y,OR-5));
          fo.setAttribute('x',n.x-14); fo.setAttribute('y',n.y-14);
        } else {
          shape.setAttribute('cx',n.x); shape.setAttribute('cy',n.y);
          fo.setAttribute('x',n.x-NR); fo.setAttribute('y',n.y-NR);
          if(n._statusDot){ n._statusDot.setAttribute('cx',n.x+NR-2); n._statusDot.setAttribute('cy',n.y-NR+2); }
        }
        var ly=n.isTool?n.y+TR+11:(n.isOrch?n.y+OR+16:n.y+NR+14);
        label.setAttribute('x',n.x); label.setAttribute('y',ly);
        labelBg.setAttribute('x',n.x-textLen/2); labelBg.setAttribute('y',ly-9);
        if(n._subLabel){ n._subLabel.setAttribute('x',n.x); n._subLabel.setAttribute('y',ly+12); }
        updateEdges();
      });
      svg.addEventListener('mouseup',function(){
        if(dragging&&!didDrag) didDrag=false;
        dragging=false;
      });

      nodeLayer.appendChild(g);
    });
    svg.appendChild(nodeLayer);
    el.appendChild(svg);
  }
})();
</script>
<script>
(function(){
  var _prevEv='',_prevTb='';
  function _nc(){return '_t='+Date.now();}
  function pollGraph(){
    fetch('/dashboard/api/graph/stats?'+_nc(),{credentials:'same-origin',cache:'no-store'}).then(function(r){return r.json()}).then(function(d){
      var g=function(id){return document.getElementById(id)};
      if(g('gs-agents'))g('gs-agents').textContent=d.agents;
      if(g('gs-tools'))g('gs-tools').textContent=d.tools;
      if(g('gs-messages'))g('gs-messages').textContent=d.messages.toLocaleString();
      if(g('gs-blocks'))g('gs-blocks').textContent=d.blocks;
      if(g('gs-audit'))g('gs-audit').textContent=d.messages.toLocaleString();
      var ec=document.getElementById('gw-event-count');
      if(ec)ec.textContent=d.messages.toLocaleString()+' EVENTS';
    }).catch(function(){});
    fetch('/dashboard/api/graph/events?'+_nc(),{credentials:'same-origin',cache:'no-store'}).then(function(r){return r.text()}).then(function(h){
      var t=h.trim();
      if(t!==_prevEv){_prevEv=t;var el=document.getElementById('gw-events');if(el){el.innerHTML=t;el.querySelectorAll('[data-ts]').forEach(function(e){var ts=e.getAttribute('data-ts');if(ts&&typeof _relTime==='function')e.textContent=_relTime(ts);});}}
    }).catch(function(){});
    fetch('/dashboard/api/graph/tables?range={{.Range}}&'+_nc(),{credentials:'same-origin',cache:'no-store'}).then(function(r){return r.text()}).then(function(h){
      var t=h.trim();
      if(t!==_prevTb){_prevTb=t;var el=document.getElementById('graph-tables');if(el)el.innerHTML=t;}
    }).catch(function(){});
  }
  pollGraph();
  function schedulePoll(){
    setTimeout(function(){
      if(!document.hidden) pollGraph();
      schedulePoll();
    },15000);
  }
  schedulePoll();
  document.addEventListener('visibilitychange',function(){
    if(!document.hidden) pollGraph();
  });
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

var gatewayTmpl = template.Must(template.New("gateway").Funcs(tmplFuncs).Parse(layoutHead + `
<style>
.gw-tabs{display:flex;gap:0;border-bottom:2px solid var(--border);margin-bottom:var(--sp-5)}
.gw-tab{padding:10px var(--sp-5);font-size:var(--text-sm);font-weight:500;color:var(--text3);cursor:pointer;border:none;background:none;border-bottom:2px solid transparent;margin-bottom:-2px;transition:color var(--ease-default),border-color var(--ease-default)}
.gw-tab:hover{color:var(--text2)}
.gw-tab.active{color:var(--text);border-bottom-color:var(--accent);font-weight:600}
.gw-panel{display:none}
.gw-panel.active{display:block}
</style>
<p class="page-desc">The MCP gateway fronts backend MCP servers, applying security scanning and per-agent tool allowlists to every tool call.</p>

<div class="gw-tabs" role="tablist">
  <button class="gw-tab {{if ne .Tab "discovery"}}active{{end}}" onclick="gwTab('config')">Configuration</button>
  <button class="gw-tab {{if eq .Tab "discovery"}}active{{end}}" onclick="gwTab('discovery')">Discovery{{if .Discovered}} <span style="font-size:0.68rem;color:var(--text3)">({{len .Discovered}})</span>{{end}}</button>
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
  <p class="desc">
    The gateway runs as a separate process (<code style="background:var(--surface);padding:2px 8px;border-radius:4px;font-family:var(--mono);font-size:0.75rem;color:var(--accent-light)">oktsec gateway</code>). This dashboard manages its configuration.
  </p>
  <div style="display:flex;gap:24px;margin-bottom:12px">
    <div>
      <span style="color:var(--text3);font-size:0.72rem;text-transform:uppercase;letter-spacing:1px">Health</span>
      <div style="margin-top:6px" id="gateway-health" hx-get="/dashboard/api/gateway/health" hx-trigger="load" hx-swap="innerHTML">
        <span style="color:var(--text3);font-size:0.85rem">checking...</span>
      </div>
    </div>
    <div>
      <span style="color:var(--text3);font-size:0.72rem;text-transform:uppercase;letter-spacing:1px">Listen</span>
      <div style="font-size:1rem;font-weight:600;margin-top:4px;font-family:var(--mono)">{{if .Gateway.Bind}}{{.Gateway.Bind}}{{else}}127.0.0.1{{end}}:{{if .Gateway.Port}}{{.Gateway.Port}}{{else}}9090{{end}}</div>
    </div>
    <div>
      <span style="color:var(--text3);font-size:0.72rem;text-transform:uppercase;letter-spacing:1px">Endpoint</span>
      <div style="font-size:1rem;font-weight:600;margin-top:4px;font-family:var(--mono)">{{if .Gateway.EndpointPath}}{{.Gateway.EndpointPath}}{{else}}/mcp{{end}}</div>
    </div>
    <div>
      <span style="color:var(--text3);font-size:0.72rem;text-transform:uppercase;letter-spacing:1px">Backends</span>
      <div style="font-size:1rem;font-weight:600;margin-top:4px">{{len .Servers}}</div>
    </div>
  </div>
</div>

<div class="card">
  <h2>Configuration</h2>
  <p class="desc">
    Controls whether the gateway is active and how it processes MCP traffic. Changes are saved to <code style="background:var(--surface);padding:2px 6px;border-radius:4px;font-size:var(--text-sm);font-family:var(--mono);color:var(--accent-light)">oktsec.yaml</code> and take effect on next gateway start.
  </p>
  <form method="POST" action="/dashboard/gateway/settings">
    <div style="display:flex;gap:32px;margin-bottom:20px">
      <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
        <span class="toggle"><input type="checkbox" name="enabled" value="true" {{if .Gateway.Enabled}}checked{{end}}><span class="toggle-slider"></span></span>
        <span style="font-size:0.85rem;color:var(--text2)">Gateway enabled</span>
      </label>
      <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
        <span class="toggle"><input type="checkbox" name="scan_responses" value="true" {{if .Gateway.ScanResponses}}checked{{end}}><span class="toggle-slider"></span></span>
        <span style="font-size:0.85rem;color:var(--text2)">Scan backend responses</span>
      </label>
    </div>
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
    <button type="submit" class="btn btn-sm">Save Configuration</button>
  </form>
</div>

<div class="card">
  <h2>Backend MCP Servers</h2>
  <p class="desc">
    Each backend server exposes MCP tools that agents can call through the gateway. The gateway auto-discovers tools from each server and applies security policies.
  </p>
  {{if .Servers}}
  <table>
    <thead><tr><th>Name</th><th>Transport</th><th>Target</th><th></th></tr></thead>
    <tbody>
    {{range .Servers}}
    <tr id="server-row-{{.Name}}" class="clickable" onclick="window.location='/dashboard/gateway/servers/{{.Name}}'">
      <td style="font-weight:600"><a href="/dashboard/gateway/servers/{{.Name}}" style="color:var(--accent-light);text-decoration:none">{{.Name}}</a></td>
      <td><span class="badge-{{if eq .Transport "stdio"}}delivered{{else}}quarantined{{end}}" style="font-size:0.7rem">{{.Transport}}</span></td>
      <td style="color:var(--text3);font-family:var(--mono);font-size:0.8rem">{{if eq .Transport "stdio"}}{{.Command}}{{else}}{{.URL}}{{end}}</td>
      <td style="text-align:right" onclick="event.stopPropagation()"><button class="btn btn-sm btn-danger" hx-delete="/dashboard/gateway/servers/{{.Name}}" hx-confirm="Delete server {{.Name}}?" hx-target="#server-row-{{.Name}}" hx-swap="outerHTML swap:200ms">delete</button></td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}
  <div class="empty">No MCP servers configured. Add one below to get started.</div>
  {{end}}

  <form method="POST" action="/dashboard/gateway/servers" class="inline-add">
    <div class="form-group" style="min-width:150px">
      <label>Name</label>
      <input type="text" name="name" required pattern="[a-zA-Z0-9][a-zA-Z0-9_-]*" placeholder="e.g. my-server">
    </div>
    <div class="form-group" style="min-width:100px;flex:0.5">
      <label>Transport</label>
      <select name="transport" onchange="var s=this.value;document.getElementById('stdio-fields').style.display=s==='stdio'?'':'none';document.getElementById('http-fields').style.display=s==='http'?'':'none'">
        <option value="stdio">stdio</option>
        <option value="http">http</option>
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
    <button type="submit" class="btn">Add</button>
  </form>
  <p style="color:var(--text3);font-size:0.72rem;margin-top:8px">Configure args, env vars, and headers from the server detail page.</p>
</div>
</div><!-- /gw-config -->

<div id="gw-discovery" class="gw-panel {{if eq .Tab "discovery"}}active{{end}}">
<div class="card">
  <h2>Discovered MCP Servers</h2>
  <p class="desc">
    Servers found in local AI client configurations (Claude Desktop, Cursor, VS Code, Cline, Windsurf, etc.).
  </p>
  {{if .Discovered}}
  <p style="color:var(--text3);font-size:0.78rem;margin-bottom:12px">Found {{len .Discovered}} unique server(s).</p>
  <table>
    <thead><tr><th>Name</th><th>Client(s)</th><th>Command</th></tr></thead>
    <tbody>
    {{range .Discovered}}
    <tr>
      <td><strong>{{.Name}}</strong></td>
      <td>{{.Client}}</td>
      <td><code style="background:var(--surface);padding:2px 8px;border-radius:4px;font-family:var(--mono);font-size:0.82rem">{{truncate .Command 80}}</code></td>
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
      <button type="button" class="btn btn-sm btn-danger" hx-delete="/dashboard/gateway/servers/{{.Name}}" hx-confirm="Delete server {{.Name}}? This cannot be undone." hx-swap="none" onclick="setTimeout(function(){window.location='/dashboard/gateway'},300)">Delete Server</button>
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
    <tr class="clickable" onclick="window.location='/dashboard/agents/{{.Name}}'">
      <td style="font-weight:600"><a href="/dashboard/agents/{{.Name}}" style="color:var(--accent-light);text-decoration:none">{{.Name}}</a></td>
      <td>{{range $i, $t := .AllowedTools}}{{if $i}} {{end}}<span class="acl-target">{{$t}}</span>{{end}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
</div>
{{end}}
` + layoutFoot))

// --- Rule detail full page ---

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
  {{if eq .Detail.Severity "critical"}}<span class="sev-critical">critical</span>
  {{else if eq .Detail.Severity "high"}}<span class="sev-high">high</span>
  {{else if eq .Detail.Severity "medium"}}<span class="sev-medium">medium</span>
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

