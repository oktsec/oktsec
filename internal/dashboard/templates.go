package dashboard

import (
	"encoding/json"
	"fmt"
	"html/template"
	"strconv"
	"strings"
	"time"
)

// categoryOverrides pins the canonical casing for acronym-heavy category
// names that a generic title-caser mangles. "Mcp" / "Openclaw" look
// unprofessional on customer-facing pages, and these names show up in the
// Rules catalog and in the Settings drawer where VCs see them first.
var categoryOverrides = map[string]string{
	"mcp":             "MCP",
	"mcp_attack":      "MCP Attack",
	"mcp_config":      "MCP Config",
	"openclaw":        "OpenClaw",
	"openclaw_config": "OpenClaw Config",
	"inter_agent":     "Inter-Agent",
	"ipi":             "IPI",
	"iap":             "IAP",
	"oclaw":           "OCLAW",
	"ce":              "CE",
	"tc":              "TC",
	"pii":             "PII",
	"api":             "API",
	"llm":             "LLM",
	"rce":             "RCE",
	"ssrf":            "SSRF",
	"xss":             "XSS",
	"sql":             "SQL",
	"jwt":             "JWT",
	"oauth":           "OAuth",
	"cors":            "CORS",
	"tls":             "TLS",
	"csrf":            "CSRF",
	"acl":             "ACL",
	"ai":              "AI",
}

// normalizedKey lets categoryOverrides match regardless of whether the
// caller hands us snake_case ("inter_agent"), kebab-case ("inter-agent"),
// or just the raw word. Without this the same category ID reaches the UI
// formatted differently depending on the source.
func normalizedKey(s string) string {
	return strings.ReplaceAll(strings.ToLower(s), "-", "_")
}

// snakeToTitle converts snake_case to Title Case, preserving canonical
// capitalization for well-known acronyms (MCP, OpenClaw, IPI, …). Without
// this, the UI ships strings like "Mcp Attack" and "Openclaw Config" which
// read as unpolished to a security buyer.
// maskWebhookURL hides the secret path of a webhook URL, showing only
// scheme + host + last 4 chars. e.g. "https://hooks.slack.com/services/...QUDb"
func maskWebhookURL(rawURL string) string {
	idx := strings.Index(rawURL, "://")
	if idx == -1 {
		if len(rawURL) > 8 {
			return rawURL[:4] + "..." + rawURL[len(rawURL)-4:]
		}
		return "****"
	}
	rest := rawURL[idx+3:]
	slashIdx := strings.Index(rest, "/")
	if slashIdx == -1 {
		return rawURL
	}
	host := rest[:slashIdx]
	suffix := rest[slashIdx:]
	if len(suffix) > 4 {
		return rawURL[:idx+3] + host + "/..." + suffix[len(suffix)-4:]
	}
	return rawURL[:idx+3] + host + "/..."
}

func snakeToTitle(s string) string {
	if v, ok := categoryOverrides[normalizedKey(s)]; ok {
		return v
	}
	words := strings.Split(s, "_")
	for i, w := range words {
		if len(w) == 0 {
			continue
		}
		if v, ok := categoryOverrides[normalizedKey(w)]; ok {
			words[i] = v
			continue
		}
		words[i] = strings.ToUpper(w[:1]) + w[1:]
	}
	return strings.Join(words, " ")
}

// kebabToTitle converts kebab-case to Title Case with the same acronym
// overrides as snakeToTitle.
func kebabToTitle(s string) string {
	if v, ok := categoryOverrides[normalizedKey(s)]; ok {
		return v
	}
	words := strings.FieldsFunc(s, func(r rune) bool { return r == '-' || r == '_' })
	for i, w := range words {
		if len(w) == 0 {
			continue
		}
		if v, ok := categoryOverrides[normalizedKey(w)]; ok {
			words[i] = v
			continue
		}
		words[i] = strings.ToUpper(w[:1]) + w[1:]
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
			"Bash": "#d29922", "Write": "#c084fc", "Edit": "#58a6ff",
			"Read": "#22d3ee", "Glob": "#2dd4bf", "Grep": "#2dd4bf",
			"WebFetch": "#f472b6", "WebSearch": "#f472b6", "Agent": "#bc8cff",
		}
		c := "#6e7681"
		if v, ok := colors[toolName]; ok {
			c = v
		}
		return template.HTML(fmt.Sprintf(`<span style="display:inline-flex;align-items:center;gap:5px"><span style="width:6px;height:6px;border-radius:50%%;background:%s;flex-shrink:0"></span>%s</span>`, c, template.HTMLEscapeString(toolName)))
	},
	"hasRules":    func(s string) bool { return s != "" && s != "[]" && s != "null" },
	"maskWebhookURL": maskWebhookURL,
	"seq": func(n int) []int {
		s := make([]int, n)
		for i := range s {
			s[i] = i
		}
		return s
	},
	"listContains": func(list []string, s string) bool {
		for _, v := range list {
			if v == s {
				return true
			}
		}
		return false
	},
	"fmtDate": func(ts string) string {
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			return t.Local().Format("Jan 02 15:04")
		}
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			return t.Local().Format("Jan 02 15:04")
		}
		if len(ts) > 16 {
			return ts[:16]
		}
		return ts
	},
	"split":    strings.Split,
	"mdToHTML": simpleMarkdownToHTML,
	"pageTitle": func(active string) string {
		titles := map[string]string{
			"events":    "Events",
			"sessions":  "Sessions",
			"audit":     "Security Posture",
			"llm":       "AI Analysis",
			"discovery": "Discovery",
			"overview":  "Overview",
			"agents":    "Agents",
			"rules":     "Rules",
			"graph":     "Graph",
			"gateway":   "Gateway",
			"settings":  "Settings",
			"alerts":    "Notifications",
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
	"add":      func(a, b int) int { return a + b },
	"isFixable": func(checkID string) bool { _, ok := fixableChecks[checkID]; return ok },
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
  color-scheme:dark;
  /* Canvas & Surfaces */
  --bg:#0d1117;--surface:#161b22;--surface2:#21262d;--border:#30363d;--border-muted:#21262d;
  /* Text - WCAG AA validated */
  --text:#e6edf3;--text2:#8b949e;--text3:#6e7681;--text-on-emphasis:#ffffff;
  /* Accent / Info */
  --accent:#58a6ff;--accent-light:#58a6ff;--accent-dim:#1f6feb;--accent-muted:rgba(56,139,253,0.15);--accent-border:rgba(56,139,253,0.30);
  /* Semantic */
  --danger:#f85149;--danger-emphasis:#da3633;--danger-muted:rgba(248,81,73,0.15);--danger-border:rgba(248,81,73,0.30);
  --success:#3fb950;--success-emphasis:#238636;--success-muted:rgba(63,185,80,0.15);--success-border:rgba(63,185,80,0.30);
  --warn:#d29922;--warn-emphasis:#9e6a03;--warn-muted:rgba(210,153,34,0.15);--warn-border:rgba(210,153,34,0.30);
  /* Purple (agent/session identity) */
  --purple:#bc8cff;--purple-emphasis:#8b5cf6;--purple-muted:rgba(188,140,255,0.15);--purple-border:rgba(188,140,255,0.30);
  /* Typography */
  --mono:ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,'Liberation Mono',monospace;
  --sans:'Inter',system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans',Helvetica,Arial,sans-serif;
}
@font-face{font-family:'Inter';src:url('/dashboard/static/fonts/Inter.woff2') format('woff2');font-weight:100 900;font-style:normal;font-display:swap}
@keyframes fadeIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
body{font-family:var(--sans);background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;-webkit-font-smoothing:antialiased}
.backdrop{display:none}
.login-card{position:relative;z-index:1;background:#161b22;border:1px solid #30363d;border-radius:12px;padding:48px 40px;max-width:400px;width:100%;text-align:center;box-shadow:0 8px 24px rgba(0,0,0,0.4);animation:fadeIn 0.4s ease-out}
.icon{margin-bottom:20px}
.icon svg{width:48px;height:48px;color:var(--accent)}
.logo{font-family:var(--mono);font-size:1.5rem;font-weight:700;letter-spacing:-0.3px;margin-bottom:8px;color:var(--text)}
.subtitle{color:var(--text2);font-size:0.85rem;margin-bottom:32px}
.help{color:var(--text3);font-size:0.78rem;margin-bottom:24px;line-height:1.6}
.help code{background:#21262d;padding:2px 6px;border-radius:4px;font-family:var(--mono);font-size:0.75rem;color:#e6edf3;border:1px solid #30363d}
input[type=text]{
  width:100%;padding:12px 16px;background:#0d1117;border:1px solid #30363d;
  border-radius:8px;color:var(--text);font-family:var(--mono);font-size:1.2rem;
  text-align:center;letter-spacing:4px;outline:none;transition:border-color 0.15s,box-shadow 0.15s;
}
input[type=text]:focus{border-color:#58a6ff;box-shadow:0 0 0 3px rgba(56,139,253,0.15)}
input[type=text]::placeholder{letter-spacing:0;font-size:0.85rem;color:var(--text3)}
button{
  width:100%;padding:12px 16px;margin-top:16px;background:#1f6feb;color:#fff;
  border:1px solid rgba(56,139,253,0.30);border-radius:8px;font-size:1rem;font-weight:600;cursor:pointer;
  transition:background 0.15s,transform 0.1s;
}
button:hover{background:#388bfd}
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
  <p class="help">Enter the access code shown in your terminal.<br>Run <code>oktsec run</code> to get a code.<br><small style="color:#8b949e">Code changes each time the server restarts.</small></p>
  <form method="POST" action="/dashboard/login" autocomplete="off">
    <label for="login-code" class="sr-only">Access code</label>
    <input type="text" id="login-code" name="code" placeholder="00000000" maxlength="8" pattern="\d{8}" inputmode="numeric" autofocus required>
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
  --accent:#58a6ff;--accent-light:#58a6ff;--accent-dim:#1f6feb;
  --mono:ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,'Liberation Mono',monospace;
  --sans:'Inter',system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans',Helvetica,Arial,sans-serif;
}
@keyframes fadeIn{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
@keyframes pulse{0%,100%{opacity:0.15}50%{opacity:0.25}}
body{font-family:var(--sans);background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;overflow:hidden}
.backdrop{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);width:800px;height:800px;background:radial-gradient(circle,transparent 0%,transparent 65%);pointer-events:none;animation:pulse 6s ease-in-out infinite}
.container{position:relative;z-index:1;text-align:center;animation:fadeIn 0.6s ease-out}
.logo{font-family:var(--mono);font-size:4.5rem;font-weight:700;letter-spacing:-2px;margin-bottom:12px;background:linear-gradient(135deg,var(--text) 0%,var(--accent-light) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.tagline{color:var(--text3);font-size:1rem;letter-spacing:0.5px;margin-bottom:40px}
.links{display:flex;gap:16px;justify-content:center;flex-wrap:wrap}
.links a{display:inline-flex;align-items:center;gap:8px;padding:10px 22px;border-radius:8px;font-size:0.88rem;font-weight:500;text-decoration:none;transition:background 0.2s,transform 0.1s,box-shadow 0.2s}
.links a:active{transform:scale(0.98)}
.primary{background:var(--accent);color:#fff}
.primary:hover{background:var(--accent-dim);box-shadow:0 4px 12px rgba(56,139,253,0.25)}
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
  --accent:#58a6ff;--accent-light:#58a6ff;--accent-dim:#1f6feb;
  --mono:ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,'Liberation Mono',monospace;
  --sans:'Inter',system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans',Helvetica,Arial,sans-serif;
}
@keyframes fadeIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
body{font-family:var(--sans);background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center}
.backdrop{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);width:600px;height:600px;background:radial-gradient(circle,transparent 0%,transparent 70%);pointer-events:none;z-index:0}
.card{position:relative;z-index:1;background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:48px 40px;max-width:420px;width:100%;text-align:center;box-shadow:0 1px 2px rgba(0,0,0,0.3),0 4px 16px rgba(0,0,0,0.2);animation:fadeIn 0.4s ease-out}
.icon{margin-bottom:20px}
.icon svg{width:48px;height:48px;color:var(--accent);opacity:0.8}
.code{font-family:var(--mono);font-size:4rem;font-weight:700;letter-spacing:-2px;color:var(--accent);line-height:1;margin-bottom:8px}
.title{font-size:1.25rem;font-weight:600;margin-bottom:12px}
.desc{color:var(--text3);font-size:0.85rem;line-height:1.6;margin-bottom:32px}
.back{display:inline-block;padding:10px 24px;background:var(--accent);color:#fff;border:none;border-radius:8px;font-size:0.9rem;font-weight:600;text-decoration:none;cursor:pointer;transition:background 0.2s,transform 0.1s,box-shadow 0.2s}
.back:hover{background:var(--accent-dim);box-shadow:0 4px 12px rgba(56,139,253,0.25)}
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
<link rel="stylesheet" href="/dashboard/static/dashboard.css?v=20260320">
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
    <a href="/dashboard/sessions" class="sidebar-item {{if eq .Active "sessions"}}active{{end}}">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
      Sessions
    </a>
    <a href="/dashboard/alerts" class="sidebar-item {{if eq .Active "alerts"}}active{{end}}">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
      Notifications
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
  </div>
  <div class="sidebar-section">
    <div class="sidebar-section-label">Analyze</div>
    <a href="/dashboard/audit" class="sidebar-item {{if eq .Active "audit"}}active{{end}}">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/></svg>
      Security Posture
    </a>
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
  <button id="redact-toggle" class="topbar-btn" onclick="toggleRedactPaths()" title="Mask file paths in displayed content">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
    <span id="redact-label">Mask paths</span>
  </button>
  <a href="/dashboard/settings" class="mode-pill {{if .RequireSig}}enforce{{else}}observe{{end}}" data-tooltip="{{if .RequireSig}}Enforce mode — signatures required, unsigned messages rejected{{else}}Observe mode — signatures optional, content enforcement still active. Click to configure.{{end}}"><span class="dot"></span>{{if .RequireSig}}enforce{{else}}observe{{end}}</a>
  <form method="POST" action="/dashboard/logout" style="margin-left:10px;display:inline"><button type="submit" class="topbar-logout">Logout</button></form>
</div>
<main>`

const layoutFoot = `</main>

<!-- Slide-in panel -->
<div class="panel-overlay" id="panel-overlay" onclick="closePanel()"></div>
<div class="panel" id="detail-panel" role="dialog" aria-modal="true" aria-label="Detail panel">
  <div id="panel-loading" class="htmx-indicator" style="text-align:center;padding:40px"><span class="loading-spinner" style="width:24px;height:24px"></span></div>
  <div id="panel-content"></div>
</div>

<script>
function toggleSidebar() {
  document.querySelector('.sidebar').classList.toggle('mobile-open');
  document.querySelector('.sidebar-overlay').classList.toggle('open');
}

var _panelPrevFocus=null;
function openPanel(html) {
  _panelPrevFocus=document.activeElement;
  document.getElementById('panel-content').innerHTML = html;
  document.getElementById('detail-panel').classList.add('open');
  document.getElementById('panel-overlay').classList.add('open');
  var fc=document.querySelector('#detail-panel .panel-close,#detail-panel button,#detail-panel a');
  if(fc)fc.focus();
}
function closePanel() {
  document.getElementById('detail-panel').classList.remove('open');
  document.getElementById('panel-overlay').classList.remove('open');
  if(_panelPrevFocus)_panelPrevFocus.focus();
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

// Path redaction — hides full file paths, home dirs, usernames from displayed content.
// Useful for screenshots, demos, compliance. Data in audit trail is NOT modified.
var _redactOn = localStorage.getItem('oktsec-redact') === '1';
function _redactStr(s) {
  // /Users/foo/Documents/bar/baz.txt -> ~/.../baz.txt
  // /home/foo/projects/bar/main.go -> ~/.../main.go
  // C:\Users\foo\Documents\bar -> ~\...\bar
  s = s.replace(/\/Users\/[^\/\s"',]+\/[^"'\s,}]*/g, function(m) {
    var parts = m.split('/'); return '~/.../' + parts[parts.length - 1];
  });
  s = s.replace(/\/home\/[^\/\s"',]+\/[^"'\s,}]*/g, function(m) {
    var parts = m.split('/'); return '~/.../' + parts[parts.length - 1];
  });
  s = s.replace(/[A-Z]:\\Users\\[^\\"\s,]+\\[^"'\s,}]*/g, function(m) {
    var parts = m.split('\\'); return '~\\...\\' + parts[parts.length - 1];
  });
  return s;
}
function _applyRedaction() {
  if (!_redactOn) return;
  // Session trace tool inputs
  document.querySelectorAll('.st-content').forEach(function(el) {
    if (!el.dataset.orig) el.dataset.orig = el.textContent;
    el.textContent = _redactStr(el.dataset.orig);
  });
  // Event detail panel
  var edp = document.getElementById('ed-content-pretty');
  if (edp) {
    if (!edp.dataset.origHtml) edp.dataset.origHtml = edp.innerHTML;
    edp.innerHTML = _redactStr(edp.dataset.origHtml);
  }
  // Event full page
  var epp = document.getElementById('ep-content-pretty');
  if (epp) {
    if (!epp.dataset.origHtml) epp.dataset.origHtml = epp.innerHTML;
    epp.innerHTML = _redactStr(epp.dataset.origHtml);
  }
  // Quarantine preview
  document.querySelectorAll('.q-preview').forEach(function(el) {
    if (!el.dataset.orig) el.dataset.orig = el.textContent;
    el.textContent = _redactStr(el.dataset.orig);
  });
}
function _removeRedaction() {
  document.querySelectorAll('.st-content').forEach(function(el) {
    if (el.dataset.orig) el.textContent = el.dataset.orig;
  });
  var edp = document.getElementById('ed-content-pretty');
  if (edp && edp.dataset.origHtml) edp.innerHTML = edp.dataset.origHtml;
  var epp = document.getElementById('ep-content-pretty');
  if (epp && epp.dataset.origHtml) epp.innerHTML = epp.dataset.origHtml;
  document.querySelectorAll('.q-preview').forEach(function(el) {
    if (el.dataset.orig) el.textContent = el.dataset.orig;
  });
}
function toggleRedactPaths() {
  _redactOn = !_redactOn;
  localStorage.setItem('oktsec-redact', _redactOn ? '1' : '0');
  var btn = document.getElementById('redact-toggle');
  if (btn) btn.classList.toggle('active', _redactOn);
  if (_redactOn) _applyRedaction(); else _removeRedaction();
}
// Init on page load
(function() {
  var btn = document.getElementById('redact-toggle');
  if (btn) btn.classList.toggle('active', _redactOn);
  if (_redactOn) setTimeout(_applyRedaction, 100);
})();
// Re-apply after HTMX content loads
document.body.addEventListener('htmx:afterSettle', function() { if (_redactOn) setTimeout(_applyRedaction, 50); });

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
function _esc(s){if(!s)return'';var d=document.createElement('div');d.textContent=s;return d.innerHTML;}
function agentCellHTML(name){if(!name)return'';return '<span class="agent-cell">'+agentAvatar(_esc(name),20)+' '+_esc(name)+'</span>';}

// Custom confirm modal (replaces ALL confirm dialogs)
(function(){
  var overlay=document.createElement('div');
  overlay.className='modal-overlay';
  overlay.setAttribute('aria-hidden','true');
  overlay.hidden=true;
  overlay.innerHTML='<div class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title" aria-describedby="modal-msg"><div class="modal-title" id="modal-title">Confirm</div><div class="modal-msg" id="modal-msg"></div><div class="modal-actions"><button class="btn btn-outline" id="modal-cancel">Cancel</button><button class="btn" id="modal-ok">Confirm</button></div></div>';
  document.body.appendChild(overlay);
  if('inert' in overlay)overlay.inert=true;
  var pendingResolve=null,_modalTrigger=null;
  function closeModal(result){
    overlay.classList.remove('open');
    overlay.setAttribute('aria-hidden','true');
    overlay.hidden=true;
    if('inert' in overlay)overlay.inert=true;
    if(_modalTrigger){_modalTrigger.focus();_modalTrigger=null;}
    if(pendingResolve){pendingResolve(result);pendingResolve=null;}
  }
  document.getElementById('modal-cancel').onclick=function(){closeModal(false)};
  overlay.onclick=function(e){if(e.target===overlay)closeModal(false)};
  document.addEventListener('keydown',function(e){if(e.key==='Escape'&&overlay.classList.contains('open'))closeModal(false)});
  document.getElementById('modal-ok').onclick=function(){closeModal(true)};
  // Focus trap: Tab cycles within modal buttons
  overlay.addEventListener('keydown',function(e){
    if(e.key!=='Tab')return;
    var focusable=overlay.querySelectorAll('button:not([disabled])');
    if(focusable.length===0)return;
    var first=focusable[0],last=focusable[focusable.length-1];
    if(e.shiftKey){if(document.activeElement===first){e.preventDefault();last.focus();}}
    else{if(document.activeElement===last){e.preventDefault();first.focus();}}
  });
  function showModal(msg){
    _modalTrigger=document.activeElement;
    document.getElementById('modal-msg').textContent=msg;
    var isDestructive=msg.toLowerCase().indexOf('delete')>-1||msg.toLowerCase().indexOf('suspend')>-1||msg.toLowerCase().indexOf('revoke')>-1;
    var okBtn=document.getElementById('modal-ok');
    okBtn.className=isDestructive?'btn btn-danger':'btn';
    okBtn.textContent=isDestructive?'Confirm':'OK';
    overlay.hidden=false;
    overlay.removeAttribute('aria-hidden');
    if('inert' in overlay)overlay.inert=false;
    overlay.classList.add('open');
    document.getElementById('modal-cancel').focus();
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
      if(ok){if(typeof e.detail.issueRequest==='function'){e.detail.issueRequest(true)}else{e.detail.issueRequest=true;htmx.trigger(e.detail.elt,'confirmed')}}
    });
  });
})();

// Toast notification system
(function(){
  var container=document.createElement('div');
  container.className='toast-container';
  container.setAttribute('aria-live','polite');
  container.setAttribute('role','status');
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

