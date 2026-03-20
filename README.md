<p align="center">
  <strong>Oktsec</strong> — Runtime security for AI agent tool calls
</p>

<p align="center">
  <a href="https://github.com/oktsec/oktsec/actions/workflows/ci.yml"><img src="https://github.com/oktsec/oktsec/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://goreportcard.com/report/github.com/oktsec/oktsec"><img src="https://goreportcard.com/badge/github.com/oktsec/oktsec" alt="Go Report Card"></a>
  <a href="https://pkg.go.dev/github.com/oktsec/oktsec"><img src="https://pkg.go.dev/badge/github.com/oktsec/oktsec.svg" alt="Go Reference"></a>
  <a href="https://github.com/oktsec/oktsec/releases"><img src="https://img.shields.io/github/v/release/oktsec/oktsec" alt="GitHub Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
</p>

<p align="center">
  <a href="#installation">Installation</a> &middot;
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#hooks">Hooks</a> &middot;
  <a href="#mcp-gateway">Gateway</a> &middot;
  <a href="#threat-intel">Threat Intel</a> &middot;
  <a href="#openclaw-support">OpenClaw</a> &middot;
  <a href="#dashboard">Dashboard</a> &middot;
  <a href="#detection-rules">Rules</a> &middot;
  <a href="#configuration">Config</a>
</p>

---

See everything your AI agents execute. Monitors MCP tool calls and CLI operations in real-time - intercept, detect, block, audit. **217 detection rules** across 16 categories. Tamper-evident audit trail. Optional LLM threat intelligence. Discovers and secures **17 MCP clients** automatically. Deterministic 10-stage pipeline. Single binary. Built on the [official MCP SDK](https://github.com/modelcontextprotocol/go-sdk). Aligned with the [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/).

## What it does

Oktsec sits between AI agents and enforces a 10-stage security pipeline:

1. **Rate limiting** — Per-agent sliding-window throttling prevents message flooding (ASI02, ASI10).
2. **Identity** — Ed25519 signatures verify every message sender. No valid signature, no processing (ASI03).
3. **Agent suspension** — Suspended agents are immediately rejected, no further processing (ASI10).
4. **Policy** — YAML-based ACLs control which agent can message which. Default-deny mode rejects unknown senders (ASI03).
5. **Content scanning** — 217 detection rules catch prompt injection, credential leaks, PII exposure, data exfiltration, MCP attacks, tool-call threats, supply chain risks, and more (ASI01, ASI02, ASI05).
6. **Intent validation** — Declared intent vs actual content alignment check. Detects agents that say one thing and do another (ASI01).
7. **BlockedContent enforcement** — Per-agent category-based content blocking escalates verdicts when findings match blocked categories (ASI02).
8. **Multi-message escalation** — Agents with repeated blocks get their verdicts escalated automatically (ASI01, ASI10).
9. **Audit** — Every message is logged to SQLite with content hash, sender verification status, policy decision, and triggered rules. Hash-chained with Ed25519 proxy signatures for tamper evidence.
10. **Anomaly detection** — Background risk scoring with automatic alerts and optional auto-suspension (ASI10).

```
Agent A → sign → POST /v1/message → [Oktsec] → rate limit → verify → suspend → ACL → scan → intent → blocked content → escalation → deliver/block/quarantine → audit → anomaly
```

### Supported platforms

Auto-discovers MCP server configurations from **17 clients**:

| Client | Protocol | Notes |
|--------|----------|-------|
| Claude Desktop | MCP (stdio) | Wrap + scan |
| Cursor | MCP (stdio) | Wrap + scan |
| VS Code | MCP (stdio) | Wrap + scan |
| Cline | MCP (stdio) | Wrap + scan |
| Windsurf | MCP (stdio) | Wrap + scan |
| Claude Code | MCP (gateway) + hooks | Gateway routing + tool-call interception |
| Zed | MCP (stdio) | Wrap + scan |
| Amp | MCP (stdio) | Wrap + scan |
| Gemini CLI | MCP (stdio) | Wrap + scan |
| Copilot CLI | MCP (stdio) | Wrap + scan |
| Amazon Q | MCP (stdio) | Wrap + scan |
| Roo Code | MCP (stdio) | Wrap + scan |
| Kilo Code | MCP (stdio) | Wrap + scan |
| BoltAI | MCP (stdio) | Wrap + scan |
| JetBrains | MCP (stdio) | Wrap + scan |
| OpenCode | MCP (stdio) | Wrap + scan |
| **OpenClaw** | **WebSocket** | **Scan only** ([details](#openclaw-support)) |

Additionally detects and audits [NanoClaw](#nanoclaw-support) mount allowlist configurations.

## Installation

### Quick install

```bash
curl -fsSL https://raw.githubusercontent.com/oktsec/oktsec/main/install.sh | bash
```

Installs the latest binary to `~/.local/bin`. Customize with environment variables:

```bash
VERSION=v0.11.0 curl -fsSL https://raw.githubusercontent.com/oktsec/oktsec/main/install.sh | bash
INSTALL_DIR=/usr/local/bin curl -fsSL https://raw.githubusercontent.com/oktsec/oktsec/main/install.sh | bash
```

### Pre-built binaries

Download from the [releases page](https://github.com/oktsec/oktsec/releases).

### From source

```bash
go install github.com/oktsec/oktsec/cmd/oktsec@latest
```

### Docker

```bash
docker pull ghcr.io/oktsec/oktsec:latest
docker run -p 8080:8080 ghcr.io/oktsec/oktsec
```

With config and key persistence:

```bash
docker run -p 8080:8080 \
  -v ./oktsec.yaml:/home/oktsec/oktsec.yaml \
  -v ./keys:/home/oktsec/keys \
  -v oktsec-data:/home/oktsec/data \
  ghcr.io/oktsec/oktsec serve --config /home/oktsec/oktsec.yaml
```

Docker Compose (recommended for multi-agent setups):

```bash
docker compose up -d
```

See [`docker-compose.yml`](docker-compose.yml) for the full example.

For using Oktsec alongside **Docker Sandboxes** (isolated micro VMs for AI agents), see the dedicated guide: [Oktsec + Docker Sandboxes](guides/docker-sandboxes.md). Oktsec supports forward proxy mode (`forward_proxy.enabled: true`) for use with Docker Sandbox's `--network-proxy` flag — all outbound HTTP traffic is scanned transparently.

## Quick start

### One-command setup (recommended)

```bash
oktsec run
```

That's it. If no config exists, `oktsec run` auto-discovers all MCP clients on your machine, generates a config with sensible defaults, creates Ed25519 keypairs, wraps every MCP server through the security proxy, connects Claude Code via gateway + hooks, and starts the proxy + gateway + dashboard. If a config already exists, it just starts serving. All state lives in `~/.oktsec/` (config, keys, database, secrets).

Oktsec starts in **observe mode** — it logs everything but blocks nothing. Review activity in the dashboard at `http://127.0.0.1:8080/dashboard` using the access code shown in your terminal. Restart your MCP clients (Claude Desktop, Cursor, etc.) to activate.

To enable **enforcement mode** (block malicious requests with JSON-RPC errors):

```bash
oktsec run --enforce
# or for a single server:
oktsec proxy --enforce --agent filesystem -- npx @mcp/server-filesystem /data
```

Check deployment health at any time:

```bash
oktsec doctor
```

### Step-by-step setup (if you prefer control)

```bash
oktsec discover                    # See what's installed
oktsec wrap claude-desktop         # Wrap one client at a time
oktsec run                         # Auto-setup (if needed) + start proxy + dashboard
```

### Manual setup

```bash
# Generate agent keypairs
oktsec keygen --agent research-agent --agent analysis-agent --out ./keys/

# Create config
cat > oktsec.yaml <<EOF
version: "1"
server:
  port: 8080
identity:
  keys_dir: ./keys
  require_signature: true
agents:
  research-agent:
    can_message: [analysis-agent]
  analysis-agent:
    can_message: [research-agent]
EOF

# Start the proxy
oktsec serve
```

### Send a message

Messages must be signed with the sender's Ed25519 private key. The signature covers `from + to + content + timestamp`:

```bash
curl -X POST http://localhost:8080/v1/message \
  -H "Content-Type: application/json" \
  -d '{
    "from": "research-agent",
    "to": "analysis-agent",
    "content": "Summarize the quarterly report",
    "signature": "<base64-ed25519-signature>",
    "timestamp": "2026-02-22T10:00:00Z"
  }'
```

Response:
```json
{
  "status": "delivered",
  "message_id": "550e8400-e29b-41d4-a716-446655440000",
  "policy_decision": "allow",
  "rules_triggered": [],
  "verified_sender": true
}
```

## Hooks

Oktsec intercepts tool calls from any MCP client that supports HTTP hooks — not just MCP traffic. Every `Read`, `Write`, `Bash`, `WebSearch`, and any other tool call passes through the 217-rule security pipeline before execution.

```
Claude Code (any tool call)
    │
    ├── PreToolUse → POST /hooks/event → 217 rules → allow/block
    │
    ├── Tool executes (if allowed)
    │
    └── PostToolUse → POST /hooks/event → audit log
```

`oktsec run` configures hooks automatically for Claude Code. For other clients, point HTTP hooks at:

```
POST http://127.0.0.1:9090/hooks/event
```

Headers:
- `X-Oktsec-Agent: <agent-name>` — Agent identity
- `X-Oktsec-Client: <client-name>` — Client identifier

The hooks handler runs the same scanner as the proxy pipeline and logs every tool call to the audit trail. In enforcement mode, blocked tool calls return an error before execution.

### Why hooks matter

MCP stdio wrapping intercepts only MCP tool calls. Hooks intercept **everything** — file reads, shell commands, web searches, code edits — any tool the client exposes. This gives full visibility into agent behavior regardless of protocol.

## MCP gateway

Oktsec can run as a **Streamable HTTP MCP gateway** that fronts one or more backend MCP servers, intercepting every `tools/call` with the full security pipeline. Built on the [official MCP SDK](https://github.com/modelcontextprotocol/go-sdk) (v1, Tier 1).

```bash
oktsec gateway --config ./oktsec.yaml
```

The gateway sits between your agents and their MCP servers:

```
Agent  ──►  Oktsec Gateway  ──►  Backend MCP Server(s)
             │
             ├─ Rate limit
             ├─ Agent ACL check
             ├─ Content scan (217 rules)
             ├─ Tool policies (spend limits, rate limits, approval)
             ├─ Rule overrides
             ├─ Verdict (allow/block/quarantine)
             ├─ Audit log
             └─ Webhook notification
```

Configure backend MCP servers in `oktsec.yaml`:

```yaml
gateway:
  enabled: true
  port: 9090
  endpoint_path: /mcp
  scan_responses: true    # also scan what backends return

mcp_servers:
  filesystem:
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
  github:
    transport: http
    url: https://api.github.com/mcp
```

Features:
- **Tool discovery** — Automatically discovers and exposes tools from all backends
- **Tool namespacing** — Conflicting tool names get prefixed (`backend_toolname`)
- **Per-agent tool allowlists** — Restrict which tools each agent can access
- **Per-tool policies** — Spending limits, rate limits, and approval thresholds per tool
- **Response scanning** — Optionally scan backend responses before returning to the agent
- **Auto-port** — Falls back to adjacent ports if the configured one is busy
- **Embedded mode** — `oktsec run` starts proxy + gateway in a single process

### Tool policies

Define per-tool spending limits, rate limits, and approval thresholds:

```yaml
agents:
  finance-agent:
    tool_policies:
      create_payment:
        max_amount: 10000
        daily_limit: 50000
        require_approval_above: 5000
        rate_limit: 10     # max calls per minute
      read_transactions:
        rate_limit: 100
```

### Egress policies

Control outbound network access per agent and per tool. Inspired by NVIDIA NemoClaw's policy model.

```yaml
agents:
  research-agent:
    egress:
      integrations: ["github", "slack"]    # Auto-load domain allowlists
      allowed_domains: ["arxiv.org"]       # Additional domains
      blocked_domains: ["evil.com"]        # Always blocked
      tool_restrictions:
        WebFetch: ["arxiv.org", "api.github.com"]  # WebFetch limited
        Bash: []                                     # No egress for Bash
```

16 built-in integration presets: Slack, GitHub, Telegram, Discord, Jira, Linear, Notion, Stripe, OpenAI, Anthropic, Supabase, Firebase, npm, PyPI, Docker, Hugging Face. Configure from the dashboard agent detail page or YAML.

## Threat Intel

Optional async LLM analysis layer on top of the deterministic pipeline. Connects to any provider: Claude, OpenAI, Gemini, Ollama, OpenRouter, Groq, Together, or any OpenAI-compatible endpoint.

When the pipeline detects something suspicious — a content scan with findings, an intent mismatch, a pattern of escalation — the triage module samples the message and enqueues it for background analysis. The selected model generates a case that appears in the dashboard. The operator reviews it, dismisses it, or confirms it. If confirmed, the system proposes a new detection rule that can be approved or rejected from the rules panel.

Key design constraint: **never blocks, never makes verdict decisions.** The deterministic pipeline handles all real-time decisions. The LLM layer only generates investigation cases for human review.

```yaml
llm:
  enabled: true
  provider: openai          # openai, claude, webhook
  model: gpt-4o-mini        # any model the provider supports
  api_key_env: OPENAI_API_KEY
  triage:
    sample_rate: 0.05        # sample 5% of flagged messages
  budget:
    daily_limit: 20          # USD
    monthly_limit: 500
```

Features:
- **Multi-provider** — OpenAI-compatible (Ollama, Groq, Together, Azure, LM Studio, vLLM), Anthropic Claude, custom webhook
- **Fallback provider** — Secondary LLM on primary failure
- **Budget controls** — Daily and monthly spending caps with hard limits
- **Triage pre-filter** — Sample rate, sensitive keyword detection, new agent pair detection
- **Rule generation** — LLM proposes rules with pattern, category, severity for human approval

## OpenClaw support

[OpenClaw](https://github.com/openclaw/openclaw) is the largest AI agent platform (300K+ users, 140K GitHub stars). It gives agents access to filesystem, shell, email, calendar, browser, and messaging channels (WhatsApp, Telegram, Slack, Discord). CrowdStrike documents it as "a powerful AI backdoor agent capable of taking orders from adversaries." Every DM is a prompt injection vector.

**OpenClaw does not use MCP.** It has its own WebSocket gateway (`ws://127.0.0.1:18789`) and JSON5 config at `~/.openclaw/openclaw.json`. Oktsec detects, parses, and analyzes OpenClaw installations with a dedicated scanner.

### Scan an OpenClaw installation

```bash
oktsec scan-openclaw
oktsec scan-openclaw --path ~/.openclaw/openclaw.json
```

Output:
```
Scanning OpenClaw installation: /home/user/.openclaw/openclaw.json

  Risk Level: CRITICAL

  [!] tools.profile is "full" with no deny list — agents have unrestricted tool access
  [!] gateway.bind is "0.0.0.0" — WebSocket gateway exposed to network
  [!] dmPolicy is "open" — any external message can reach agents (prompt injection vector)
  [!] messaging channels configured (slack, telegram) — each is a prompt injection attack surface
  [!] no agents have sandbox enabled — all agents run with full host access

────────────────────────────────────────────────────────────

Summary:
  Config risk:     CRITICAL
  Risk factors:    5
  Workspace files: 2 scanned
  Content issues:  3 finding(s)
```

### Risk checks

The risk assessor checks 7 patterns:

| Check | Severity | Trigger |
|-------|----------|---------|
| Full tool profile | Critical | `tools.profile == "full"` without deny list |
| Exec without sandbox | Critical | `exec`/`shell` in tools.allow, no sandboxed agents |
| Path traversal in $include | Critical | `..` in `$include` paths |
| Exposed gateway | High | `gateway.bind` is `0.0.0.0`, `lan`, or `::` |
| Open DM policy | High | `dmPolicy == "open"` |
| No sandbox | High | No agents have `sandbox: true` |
| Messaging channels | Medium | Any channels configured (attack surface) |

### OpenClaw detection rules

7 dedicated rules in the `openclaw-config` category:

| Rule | Severity | Description |
|------|----------|-------------|
| `OCLAW-001` | Critical | Full tool profile without restrictions |
| `OCLAW-002` | High | Gateway exposed to network |
| `OCLAW-003` | High | Open DM policy |
| `OCLAW-004` | Critical | Exec/shell tool without sandbox |
| `OCLAW-005` | Critical | Path traversal in `$include` |
| `OCLAW-006` | High | Gateway missing authentication |
| `OCLAW-007` | High | Hardcoded credentials in config |

### Why wrap doesn't work for OpenClaw

MCP clients use stdio — oktsec can wrap the command and intercept JSON-RPC traffic. OpenClaw uses a WebSocket gateway, so the wrapping model doesn't apply. Running `oktsec wrap openclaw` returns a clear error pointing to `scan-openclaw` instead.

## NanoClaw support

[NanoClaw](https://github.com/nanoclaw/nanoclaw) is a lightweight alternative to OpenClaw focused on filesystem access for AI agents. It uses a mount allowlist (`~/.config/nanoclaw/mount-allowlist.json`) to control which directories agents can read and write.

Oktsec auto-detects NanoClaw installations and audits them for security misconfigurations:

```bash
oktsec discover    # Detects NanoClaw automatically
oktsec audit       # Includes NanoClaw checks
```

### NanoClaw checks

6 checks in the deployment audit:

| Check | Severity | Trigger |
|-------|----------|---------|
| NC-MNT-001 | Critical | Mount allowlist missing or unparseable |
| NC-MNT-002 | High | `nonMainReadOnly` is false (write access to all mounts) |
| NC-MNT-003 | Critical | Dangerous root paths (`/`, `~`, `$HOME`) in allowlist |
| NC-MNT-004 | Medium | No blocked file patterns configured |
| NC-SEC-001 | High | Allowlist file has loose permissions |
| NC-MNT-005 | High | `allowReadWrite` on sensitive paths (`/etc`, `/var`, `~`) |

## Onboarding flow

### Discover

Scans your machine for MCP server configurations, OpenClaw, and NanoClaw installations:

```bash
oktsec discover
```

Output:
```
Found 2 MCP configuration(s):

  Cursor  /home/user/.cursor/mcp.json
    ├── filesystem           npx -y @mcp/server-filesystem /data
    ├── database             node ./db-server.js
    └── github               npx -y @mcp/server-github

  OpenClaw  /home/user/.openclaw/openclaw.json
    ├── openclaw-gateway     openclaw gateway 0.0.0.0
    ├── assistant            openclaw agent assistant
    └── channel-slack        openclaw channel slack

  OpenClaw risk: CRITICAL
    [!] tools.profile is "full" with no deny list — agents have unrestricted tool access
    [!] no agents have sandbox enabled — all agents run with full host access

  Run 'oktsec scan-openclaw' for full analysis.

  NanoClaw  ~/.config/nanoclaw/mount-allowlist.json
    └── mount-allowlist   6 paths configured

Total: 6 MCP servers across 3 clients

Run 'oktsec run' to generate configuration and start observing.
```

Supported clients: Claude Desktop, Cursor, VS Code, Cline, Windsurf, Claude Code, Zed, Amp, Gemini CLI, Copilot CLI, Amazon Q, Roo Code, Kilo Code, BoltAI, JetBrains, OpenCode, OpenClaw.

### Init

`oktsec run` auto-generates config and Ed25519 keypairs for each discovered server on first launch. For manual control:

```bash
oktsec run                         # Auto-generates config at ~/.oktsec/config.yaml if missing
oktsec run --config ./oktsec.yaml  # Use a specific config path
```

Each server is auto-classified by risk level based on its capabilities:
- **Critical** — database, postgres, mysql, sqlite, mongo, redis
- **High** — filesystem, git, github, browser, puppeteer, playwright, openclaw
- **Medium** — slack, discord, email, messaging
- **Unknown** — everything else (defaults to observe)

### Wrap / Unwrap

Modifies MCP client configs to route server traffic through `oktsec proxy`:

```bash
oktsec wrap cursor                # Observe mode (log only)
oktsec wrap --enforce cursor      # Enforcement mode (block malicious requests)
oktsec unwrap cursor              # Restore original client config
```

Before wrap:
```json
{ "command": "npx", "args": ["-y", "@mcp/server-filesystem", "/data"] }
```

After wrap:
```json
{ "command": "oktsec", "args": ["proxy", "--agent", "filesystem", "--", "npx", "-y", "@mcp/server-filesystem", "/data"] }
```

With `--enforce`:
```json
{ "command": "oktsec", "args": ["proxy", "--agent", "filesystem", "--enforce", "--", "npx", "-y", "@mcp/server-filesystem", "/data"] }
```

### Stdio proxy

The `proxy` command wraps an MCP server process, intercepting its JSON-RPC 2.0 stdio traffic. Every message is scanned through the Aguara engine and logged to the audit trail:

```bash
oktsec proxy --agent filesystem -- npx @mcp/server-filesystem /data
oktsec proxy --enforce --agent database -- node ./db-server.js
```

In **observe mode** (default), all messages are forwarded regardless of scan results. In **enforcement mode** (`--enforce`), blocked client→server requests are not forwarded — instead, a JSON-RPC 2.0 error response is injected back to the client:

```json
{"jsonrpc":"2.0","id":42,"error":{"code":-32600,"message":"blocked by oktsec: IAP-001"}}
```

Server→client responses are always forwarded (observe-only). This is what `oktsec wrap` configures automatically for each server.

## Deployment audit

The `audit` command checks your oktsec deployment and any detected agent platforms for security misconfigurations. It runs checks across Oktsec, OpenClaw, NanoClaw, and discovered MCP servers, and outputs a health score with remediation guidance:

```bash
oktsec audit
oktsec audit --json
oktsec audit --sarif    # SARIF v2.1.0 for CI integration
```

Output:
```
Deployment Security Audit
═════════════════════════

  Health Score: 72 / 100 (Grade: C)

  Oktsec (16 checks)
  ──────────────────
  [CRITICAL] require_signature is false — messages accepted without verification
             Fix: Set identity.require_signature: true in oktsec.yaml

  [HIGH]     default_policy is "allow" — unknown agents can send messages
             Fix: Set default_policy: deny in oktsec.yaml

  OpenClaw (18 checks)
  ────────────────────
  [CRITICAL] tools.profile is "full" with no deny list
             Fix: openclaw config set tools.profile restricted

  Summary: 2 critical, 3 high, 1 medium, 35 passed
```

The `status` command provides a quick health summary:

```bash
oktsec status
```

## MCP server mode

Oktsec can run as an MCP tool server, giving AI agents direct access to security operations:

```bash
oktsec mcp --config ./oktsec.yaml
```

Add to your MCP client config:
```json
{
  "mcpServers": {
    "oktsec": {
      "command": "oktsec",
      "args": ["mcp", "--config", "./oktsec.yaml"]
    }
  }
}
```

Available tools (6):

| Tool | Description |
|---|---|
| `scan_message` | Scan content for prompt injection, credential leaks, PII, and 217 threat patterns |
| `list_agents` | List all agents with their ACLs and content restrictions |
| `audit_query` | Query the audit log with filters (status, agent, limit) |
| `get_policy` | Get the security policy for a specific agent |
| `verify_agent` | Verify an Ed25519 signature from an agent using their registered public key |
| `review_quarantine` | List, inspect, approve, or reject quarantined messages |

## Dashboard

Real-time web UI for monitoring agent activity. Protected by a GitHub-style local access code.

```bash
oktsec run
```

```
  oktsec
  ────────────────────────────────────────
  API:        http://127.0.0.1:8080/v1/message
  Dashboard:  http://127.0.0.1:8080/dashboard
  Health:     http://127.0.0.1:8080/health
  ────────────────────────────────────────
  Access code:  48291057
  ────────────────────────────────────────
  Mode: observe  |  Agents: 6
```

The access code is generated fresh each time the server starts. Sessions expire after 8 hours. The server binds to `127.0.0.1` by default (localhost only). Use `--bind 0.0.0.0` to expose it on the network.

### Pages

- **Overview** — Hero stats, pipeline health bar, live event feed (SSE) alongside security status, activity sparkline, top threats and agent risk.
- **Events** — Audit log with latency and rules columns, tab filters (All / Quarantine / Blocked), search, event detail with pipeline summary bar, JSON syntax highlighting, full audit chain.
- **Notifications** — Webhook channel CRUD, alert configuration summary, alert history with delivery status.
- **Agents** — Card grid with risk scores, message counts, key status. Add Agent form at top. Detail page with communication partners, recent messages, LLM threat intelligence, tool policies.
- **Rules** — Category card grid with severity breakdown, drill-down to individual rules, per-rule enforcement overrides, per-category webhook triggers, custom rule creation, LLM-suggested rules.
- **Rule Detail** — Patterns, examples, inline test sandbox, enforcement override.
- **Security Posture** — Deployment audit: health score and grade, per-product findings (Oktsec, OpenClaw, MCP Servers), AI-enhanced analysis banner, remediation guidance, SARIF export.
- **Graph** — Agent communication topology with deterministic layout, node threat scores (betweenness centrality), edge health, shadow edge detection.
- **AI Analysis** — LLM threat cases with confirm/dismiss workflow, triage configuration, provider test connection, budget tracking, rule generation.
- **Gateway** — Backend MCP server CRUD, gateway configuration, tool discovery, health checks.
- **Settings** — Single-page layout with Security (mode, policy, server info), Protection (quarantine, behavior monitoring, rate limiting, intent validation), and Advanced (egress proxy) sections.
- **Sessions** — Session inventory with search, threat filters, and trace timeline.

### Sessions

Track and analyze agent sessions across time. Sessions are grouped by MCP session ID with aggregated stats.

- **Session inventory** — `/dashboard/sessions` page with search, threat filter (All / With threats / Clean), JSON/CSV export
- **Session trace** — Timeline of tool calls per session with 2-column layout: timeline left, AI analysis right
- **AI session analysis** — One-click analysis via Claude or OpenAI. Identifies threat actors, assesses risk level, recommends specific actions with links to dashboard pages. Persisted as audit evidence with model name and timestamp
- **Agent sessions** — Agent detail page shows related sessions with risk scores

### Quarantine queue

Messages triggering high-severity rules are held for human review. Quarantined messages return HTTP 202 with a `quarantine_id`. Reviewers can approve or reject from the dashboard, CLI, or MCP tool. Items auto-expire after a configurable period.

```bash
oktsec quarantine list                         # List pending items
oktsec quarantine detail <id>                  # View full content and triggered rules
oktsec quarantine approve <id> --reviewer ops  # Approve and deliver
oktsec quarantine reject <id> --reviewer ops   # Reject permanently
```

## Agent identity

Every agent gets an Ed25519 keypair:

```bash
oktsec keygen --agent my-agent --out ./keys/
# Creates: keys/my-agent.key (private, stays with the agent)
#          keys/my-agent.pub (public, copied to the proxy)
```

The proxy loads all `.pub` files from the configured `keys_dir` at startup. When a message arrives:

1. Look up the sender's public key
2. Verify the signature covers `from + to + content + timestamp`
3. If invalid: reject (403), no further processing
4. If valid: continue to ACL check and content scan

Signing is ~50us, verification is ~120us.

### Key management

```bash
oktsec keys list                                # List all registered keypairs
oktsec keys rotate --agent my-agent             # Generate new keypair, revoke old
oktsec keys revoke --agent my-agent             # Revoke without replacement
```

### Gradual onboarding

Set `require_signature: false` to deploy Oktsec as a content scanner first. Messages without signatures are accepted but logged as `verified_sender: false`. Enable signatures when ready.

## Configuration

Config resolution (first match wins):

1. `--config` flag (explicit path)
2. `$OKTSEC_CONFIG` environment variable
3. `./oktsec.yaml` (backward compatibility)
4. `~/.oktsec/config.yaml` (default)

```yaml
version: "1"

server:
  port: 8080
  bind: 127.0.0.1         # Default: localhost only
  log_level: info          # debug, info, warn, error
  require_intent: false    # Enable intent validation (stage 6)

identity:
  keys_dir: ./keys         # Directory with .pub files
  require_signature: true  # Reject unsigned messages

default_policy: deny       # "allow" (default) or "deny" — reject unknown senders

custom_rules_dir: ./custom-rules  # Directory for org-specific YAML detection rules

agents:
  research-agent:
    can_message: [analysis-agent]        # ACL: allowed recipients
    blocked_content: [credentials, pii]  # Content categories to always block for this agent
    allowed_tools: [read_file, search]   # MCP tool allowlist (empty = all allowed)
    description: "Research and data gathering"
    tags: [research, data]
    tool_policies:
      create_payment:
        max_amount: 10000                # Max single-call amount
        daily_limit: 50000               # Max daily aggregate
        require_approval_above: 5000     # Quarantine if above threshold
        rate_limit: 10                   # Max calls per minute
  analysis-agent:
    can_message: [research-agent, reporting-agent]
    suspended: false                     # Set to true to reject all messages

quarantine:
  enabled: true
  expiry_hours: 24         # Auto-expire pending items
  retention_days: 30       # Auto-purge audit entries older than N days (0 = keep forever)

rate_limit:
  per_agent: 100           # Max messages per window (0 = disabled)
  window: 60               # Window size in seconds

anomaly:
  check_interval: 60       # Seconds between risk checks
  risk_threshold: 50       # Risk score (0-100) to trigger alert
  min_messages: 5          # Minimum messages before evaluating risk
  auto_suspend: false      # Suspend agent when threshold exceeded

forward_proxy:
  enabled: false
  scan_requests: true        # Scan outgoing request bodies
  scan_responses: false      # Scan upstream response bodies
  max_body_size: 1048576     # 1 MB
  allowed_domains: []        # Whitelist (empty = all allowed)
  blocked_domains: []        # Blacklist (takes precedence)

gateway:
  enabled: true
  port: 9090
  endpoint_path: /mcp
  scan_responses: true       # Scan backend responses

mcp_servers:
  filesystem:
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]

llm:
  enabled: false
  provider: openai           # openai, claude, webhook
  model: gpt-4o-mini
  api_key_env: OPENAI_API_KEY
  triage:
    sample_rate: 0.05
  budget:
    daily_limit: 20
    monthly_limit: 500

rules:                       # Per-rule enforcement overrides
  - id: block-relay-injection
    severity: critical
    action: block           # block, quarantine, allow-and-flag, ignore
    notify: [slack-security] # Named channels or raw URLs
    template: "🚨 *{{RULE}}* — {{RULE_NAME}}\n• *Severity:* {{SEVERITY}} | *Category:* {{CATEGORY}}\n• *Agents:* {{FROM}} → {{TO}}\n• *Match:* '{{MATCH}}'"

category_webhooks:           # Default webhooks for entire categories (rules inherit these)
  - category: credential-leak
    notify: [slack-security]
  - category: prompt-injection
    notify: [slack-security]

webhooks:
  - name: slack-security    # Named channel (referenced in rules.notify)
    url: https://hooks.slack.com/services/xxx
    events: [blocked, quarantined, agent_risk_elevated]
```

Validate your config:
```bash
oktsec verify --config oktsec.yaml
```

## Detection rules

Oktsec includes **217 detection rules** across 16 categories:

| Source | Count | Categories |
|--------|-------|------------|
| [Aguara](https://github.com/garagon/aguara) | 178 | prompt-injection, credential-leak, exfiltration, command-execution, mcp-attack, mcp-config, supply-chain, ssrf-cloud, indirect-injection, unicode-attack, third-party-content, external-download |
| Inter-agent protocol (IAP) | 15 | inter-agent |
| Tool-call (TC) | 10 | tool-call |
| OpenClaw (OCLAW) | 15 | openclaw-config |

### Inter-agent protocol rules

| Rule | Severity | Description |
|------|----------|-------------|
| `IAP-001` | Critical | Relay injection (agent-to-agent hijacking) |
| `IAP-002` | High | PII in agent messages |
| `IAP-003` | Critical | Credentials in agent messages |
| `IAP-004` | High | System prompt extraction via agent |
| `IAP-005` | High | Privilege escalation between agents |
| `IAP-006` | High | Data exfiltration via agent relay |
| `IAP-007` | Critical | Tool description prompt injection |
| `IAP-008` | Critical | Tool description data exfiltration |
| `IAP-009` | High | Tool description privilege escalation |
| `IAP-010` | High | Tool description shadowing |
| `IAP-011` | Critical | Tool description hidden commands |
| `IAP-012` | High | Tool name typosquatting |
| `IAP-013` | High | Authority impersonation with urgent action |
| `IAP-014` | Critical | Sensitive data transfer to external endpoint |
| `IAP-015` | High | Elevated privilege request for production |

### Tool-call rules

| Rule | Severity | Description |
|------|----------|-------------|
| `TC-001` | Critical | Path traversal in tool arguments |
| `TC-002` | High | Sensitive file access attempt |
| `TC-003` | Critical | Write to system directory |
| `TC-004` | Critical | SSRF via fetch tool |
| `TC-005` | Critical | Shell injection in tool arguments |
| `TC-006` | High | Credential pattern in tool content |
| `TC-007` | Medium | Bulk directory enumeration |
| `TC-008` | High | Suspicious URL pattern in fetch |
| `TC-009` | High | Scope escape via absolute path |
| `TC-010` | Medium | Excessive file content in write |

### OpenClaw rules

15 rules in the `openclaw-config` category (OCLAW-001 through OCLAW-015), covering full tool profiles, exposed gateways, open DM policies, exec without sandbox, path traversal, missing authentication, hardcoded credentials, and more.

```bash
oktsec rules                     # List all 217 rules
oktsec rules --explain IAP-001   # Explain a specific rule
oktsec rules --explain TC-001    # Explain a tool-call rule
oktsec rules --explain OCLAW-001 # Explain an OpenClaw rule
```

Additionally, the [deployment audit](#deployment-audit) runs 41 deeper checks (18 for OpenClaw, 7 for NanoClaw, 16 for Oktsec) that analyze config structure, permissions, and runtime settings.

## Audit log

Every message is logged to SQLite (`oktsec.db`) with:
- Content hash (SHA-256)
- Signature verification status
- Public key fingerprint
- Policy decision
- Rules triggered
- Latency
- Hash chain link (tamper-evident)

```bash
oktsec logs                          # Last 50 entries
oktsec logs --status blocked         # Only blocked messages
oktsec logs --unverified             # Messages without valid signature
oktsec logs --agent research-agent   # Filter by agent
oktsec logs --since 1h              # Last hour
```

### Performance

Analytics queries use a 24-hour time window with covering indexes. All dashboard queries complete in under 10ms regardless of total database size.

| Metric | Value |
|--------|-------|
| Write throughput | ~90K inserts/sec (batched) |
| Query latency | <6ms (at 1M+ rows) |
| DB size | ~400 MB per 1M entries |

## Observability

### Prometheus metrics

Oktsec exposes Prometheus metrics at `GET /metrics`:

| Metric | Type | Description |
|--------|------|-------------|
| `messages_total` | Counter | Messages processed (by verdict, agent) |
| `message_latency` | Histogram | Pipeline processing latency |
| `rules_triggered` | Counter | Rule matches (by rule_id) |
| `llm_analysis_total` | Counter | LLM analyses performed (by provider) |
| `llm_analysis_latency` | Histogram | LLM response latency |
| `llm_tokens_used` | Counter | Token consumption (by provider) |
| `llm_budget_spent` | Counter | Spending tracking (by provider) |
| `llm_queue_depth` | Gauge | Current analysis queue length |

### SARIF export

Export deployment audit findings in SARIF v2.1.0 for CI integration:

```bash
oktsec audit --sarif > results.sarif
```

### CSV / JSON export

Export audit trail from the dashboard or CLI:

```bash
# From dashboard: GET /dashboard/api/export/csv
# From dashboard: GET /dashboard/api/export/json
```

## CLI reference

```
oktsec run [--port N] [--bind ADDR] [--enforce] [--skip-wrap]  # Auto-setup + serve (recommended)
oktsec doctor                                            # Check deployment health (config, secrets, DB, keys, port, rules)
oktsec discover                                          # Scan for MCP servers, OpenClaw, NanoClaw
oktsec wrap [--enforce] [--all | <client>]               # Route MCP client(s) through oktsec proxy
oktsec unwrap <client>                                   # Restore original client config
oktsec connect <server>                                  # Register MCP server with gateway
oktsec disconnect <server>                               # Unregister MCP server from gateway
oktsec scan-openclaw [--path ~/.openclaw/openclaw.json]  # Analyze OpenClaw installation
oktsec proxy [--enforce] --agent <name> -- <cmd> [args]  # Stdio proxy for single MCP server
oktsec serve [--config oktsec.yaml] [--port 8080] [--bind 127.0.0.1]  # Start proxy + dashboard
oktsec gateway [--config oktsec.yaml]                    # Start gateway (standalone)
oktsec mcp [--config oktsec.yaml]                        # Run as MCP tool server
oktsec keygen --agent <name> [--agent <name>...] --out <dir>
oktsec keys list|rotate|revoke [--agent <name>]
oktsec verify [--config oktsec.yaml]                     # Validate config file
oktsec logs [--status <status>] [--agent <name>] [--unverified] [--since <duration>]
oktsec rules [--explain <rule-id>]
oktsec quarantine list|detail|approve|reject [--status <status>] [<id>]
oktsec agent list                                        # List agents with status
oktsec agent suspend <name>                              # Suspend an agent
oktsec agent unsuspend <name>                            # Unsuspend an agent
oktsec audit [--json] [--sarif]                          # Deployment security audit (41 checks)
oktsec status                                            # Health score, detected products, top issues
oktsec enforce [on|off]                                  # Toggle enforce/observe mode
oktsec env [list|set|unset]                              # Manage environment variables
oktsec version
```

## API

### `POST /v1/message`

Send a message through the proxy.

| Field | Type | Required | Description |
|---|---|---|---|
| `from` | string | yes | Sender agent name |
| `to` | string | yes | Recipient agent name |
| `content` | string | yes | Message content |
| `signature` | string | no* | Base64 Ed25519 signature |
| `timestamp` | string | no | RFC3339 timestamp |
| `metadata` | object | no | Arbitrary key-value pairs |

*Required when `require_signature: true`

### `GET /v1/quarantine/{id}`

Poll quarantine status for a held message.

### `POST /hooks/event`

Submit a tool-call event for scanning. Used by MCP client hooks.

### `GET /health`

Returns `{"status": "ok", "version": "0.11.0"}`.

### `GET /metrics`

Prometheus metrics endpoint.

### `GET /dashboard`

Web UI for monitoring agent activity. Protected by access code shown at startup.

## Go SDK

The `sdk` package provides a Go client for sending messages through the oktsec proxy:

```go
import "github.com/oktsec/oktsec/sdk"

// Without signing (observe mode)
c := sdk.NewClient("http://localhost:8080", "my-agent", nil)
resp, err := c.SendMessage(ctx, "recipient", "hello")
// resp.Status: "delivered", resp.PolicyDecision: "allow", resp.RulesTriggered: [...]

// With Ed25519 signing
kp, _ := sdk.LoadKeypair("./keys", "my-agent")
c := sdk.NewClient("http://localhost:8080", "my-agent", kp.PrivateKey)
resp, err := c.SendMessage(ctx, "recipient", "hello")

// With metadata
resp, err := c.SendMessageWithMetadata(ctx, "recipient", "hello", map[string]string{
    "task_id": "abc-123",
})

// Health check
health, err := c.Health(ctx)
```

Install: `go get github.com/oktsec/oktsec/sdk`

### Python SDK

Published on [PyPI](https://pypi.org/project/oktsec/) as `oktsec`:

```bash
pip install oktsec
```

```python
from oktsec import OktsecClient

client = OktsecClient("http://localhost:8080", "my-agent")
resp = await client.send_message("recipient", "hello")

# With Ed25519 signing
client = OktsecClient("http://localhost:8080", "my-agent", key_path="./keys/my-agent.key")
```

## OWASP Top 10 for Agentic Applications

Oktsec is aligned with the [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/):

| # | Category | Coverage | How |
|---|----------|----------|-----|
| ASI01 | Excessive Agency / Goal Hijack | **Strong** | Multi-message verdict escalation, content scanning, intent validation, LLM threat analysis |
| ASI02 | Tool Misuse | **Strong** | Stdio enforcement, BlockedContent per-agent, rate limiting, tool-call rules, tool policies |
| ASI03 | Privilege Escalation | **Strong** | Ed25519 identity, default-deny policy, ACLs, per-agent tool allowlists |
| ASI04 | Supply Chain | Partial | Architecture limit (proxy, not package scanner) |
| ASI05 | Unsafe Code Execution | **Strong** | Stdio enforcement blocks tool calls, tool-call rules (TC-001–TC-010), hooks interception |
| ASI07 | Inter-Agent Communication | **Strong** | Signed messages, ACLs, content scanning, hash-chained audit trail, graph analysis |
| ASI10 | Rogue Agents | **Strong** | Agent suspension, rate limiting, anomaly detection, auto-suspend, LLM triage |

## Built on

- **[Aguara](https://github.com/garagon/aguara)** — Security scanner for AI agent skills (178 detection rules, context-aware scanning, Aho-Corasick pattern matching, tool exemptions, scan profiles)
- **[MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk)** — Official Tier 1 Go SDK for Model Context Protocol (v1, Linux Foundation governance, semver stability)
- **Go stdlib** — `crypto/ed25519`, `net/http`, `log/slog`, `crypto/sha256`
- **[modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite)** — Pure Go SQLite (no CGO)
- **[prometheus/client_golang](https://github.com/prometheus/client_golang)** — Prometheus metrics

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and pull request process.

For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
