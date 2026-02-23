<p align="center">
  <strong>Oktsec</strong> — Security proxy for AI agent communication
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
  <a href="#openclaw-support">OpenClaw</a> &middot;
  <a href="#dashboard">Dashboard</a> &middot;
  <a href="#detection-rules">Rules</a> &middot;
  <a href="#configuration">Config</a>
</p>

---

Identity verification, policy enforcement, content scanning, and audit trail for AI agent messaging. Supports MCP clients and OpenClaw. No LLM. Single binary. **151 detection rules.** Aligned with the [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/).

## What it does

Oktsec sits between AI agents and enforces a multi-layer security pipeline:

1. **Rate limiting** — Per-agent sliding-window throttling prevents message flooding (ASI02, ASI10).
2. **Identity** — Ed25519 signatures verify every message sender. No valid signature, no processing (ASI03).
3. **Agent suspension** — Suspended agents are immediately rejected, no further processing (ASI10).
4. **Policy** — YAML-based ACLs control which agent can message which. Default-deny mode rejects unknown senders (ASI03).
5. **Content scanning** — 151 detection rules catch prompt injection, credential leaks, PII exposure, data exfiltration, MCP attacks, supply chain risks, and more (ASI01, ASI02, ASI05).
6. **BlockedContent enforcement** — Per-agent category-based content blocking escalates verdicts when findings match blocked categories (ASI02).
7. **Multi-message escalation** — Agents with repeated blocks get their verdicts escalated automatically (ASI01, ASI10).
8. **Audit** — Every message is logged to SQLite with content hash, sender verification status, policy decision, and triggered rules.
9. **Anomaly detection** — Background risk scoring with automatic alerts and optional auto-suspension (ASI10).

```
Agent A → sign → POST /v1/message → [Oktsec] → rate limit → verify → suspend check → ACL → scan → blocked content → escalation → deliver/block/quarantine → audit → anomaly check
```

### Supported platforms

| Platform | Protocol | Discovery | Wrap | Scan |
|----------|----------|-----------|------|------|
| Claude Desktop | MCP (stdio) | yes | yes | yes |
| Cursor | MCP (stdio) | yes | yes | yes |
| VS Code | MCP (stdio) | yes | yes | yes |
| Cline | MCP (stdio) | yes | yes | yes |
| Windsurf | MCP (stdio) | yes | yes | yes |
| **OpenClaw** | **WebSocket** | **yes** | **n/a** | **yes** |

## Installation

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

## Quick start

### Automatic setup (recommended)

Oktsec discovers your existing MCP servers and OpenClaw installations, generates a config, and wraps MCP clients with security monitoring:

```bash
# 1. Discover all agent platforms on this machine
oktsec discover

# 2. Auto-generate config + keypairs
oktsec init

# 3. Wrap your MCP client so traffic routes through oktsec
oktsec wrap cursor          # or: claude-desktop, vscode, cline, windsurf

# 4. Start the proxy with dashboard
oktsec serve
```

Oktsec starts in **observe mode** — it logs everything but blocks nothing. Review activity in the dashboard at `http://127.0.0.1:8080/dashboard` using the access code shown in your terminal.

To enable **enforcement mode** (block malicious requests with JSON-RPC errors):

```bash
oktsec wrap --enforce cursor
# or for a single server:
oktsec proxy --enforce --agent filesystem -- npx @mcp/server-filesystem /data
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

## Onboarding flow

### Discover

Scans your machine for MCP server configurations and OpenClaw installations:

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

Total: 6 MCP servers across 2 clients

Run 'oktsec init' to generate configuration and start observing.
```

Supported clients: Claude Desktop, Cursor, VS Code, Cline, Windsurf, OpenClaw.

### Init

Auto-generates an `oktsec.yaml` config and Ed25519 keypairs for each discovered server:

```bash
oktsec init
oktsec init --keys ./keys --config ./oktsec.yaml
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

Available tools:

| Tool | Description |
|---|---|
| `scan_message` | Scan content for prompt injection, credential leaks, PII, and 150+ threat patterns |
| `list_agents` | List all agents with their ACLs and content restrictions |
| `audit_query` | Query the audit log with filters (status, agent, limit) |
| `get_policy` | Get the security policy for a specific agent |
| `review_quarantine` | List, inspect, approve, or reject quarantined messages |

## Dashboard

Real-time web UI for monitoring agent activity. Protected by a GitHub-style local access code.

```bash
oktsec serve
```

```
  ┌──────────────────────────────────────┐
  │           OKTSEC v0.3.0              │
  │   Security Proxy for AI Agents       │
  ├──────────────────────────────────────┤
  │  API:       http://127.0.0.1:8080   │
  │  Dashboard: http://127.0.0.1:8080/dashboard │
  │  Health:    http://127.0.0.1:8080/health    │
  ├──────────────────────────────────────┤
  │  Access code: 48291057               │
  └──────────────────────────────────────┘
```

The access code is generated fresh each time the server starts. Sessions expire after 24 hours. The server binds to `127.0.0.1` by default (localhost only). Use `--bind 0.0.0.0` to expose it on the network.

### Pages

- **Overview** — Stats grid (total, blocked, quarantined, flagged), top triggered rules, agent risk scores, hourly activity chart
- **Events** — Unified audit log and quarantine view with live SSE streaming, tab filters (All / Quarantine / Blocked), human-readable event detail panels with clickable rule cards
- **Rules** — Category card grid with drill-down to individual rules, inline enable/disable toggles. 14 categories including `openclaw-config`
- **Agents** — Agent CRUD, ACLs, content restrictions, Ed25519 keygen per agent
- **Settings** — Security mode (enforce/observe), key management with revocation, quarantine config

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

```yaml
version: "1"

server:
  port: 8080
  bind: 127.0.0.1         # Default: localhost only
  log_level: info          # debug, info, warn, error

identity:
  keys_dir: ./keys         # Directory with .pub files
  require_signature: true  # Reject unsigned messages

default_policy: deny       # "allow" (default) or "deny" — reject unknown senders

agents:
  research-agent:
    can_message: [analysis-agent]        # ACL: allowed recipients
    blocked_content: [credentials, pii]  # Content categories to always block for this agent
    description: "Research and data gathering"
    tags: [research, data]
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

rules:
  - id: block-relay-injection
    severity: critical
    action: block           # block, quarantine, allow-and-flag, ignore
    notify: [webhook]

webhooks:
  - url: https://hooks.slack.com/services/xxx
    events: [blocked, quarantined, agent_risk_elevated]
```

Validate your config:
```bash
oktsec verify --config oktsec.yaml
```

## Detection rules

Oktsec includes **151 detection rules** across 14 categories:

| Source | Count | Categories |
|--------|-------|------------|
| [Aguara](https://github.com/garagon/aguara) | 138 | prompt-injection, credential-leak, exfiltration, command-execution, mcp-attack, mcp-config, supply-chain, ssrf-cloud, indirect-injection, unicode-attack, third-party-content, external-download |
| Inter-agent protocol (IAP) | 6 | inter-agent |
| OpenClaw (OCLAW) | 7 | openclaw-config |

### Inter-agent protocol rules

| Rule | Severity | Description |
|------|----------|-------------|
| `IAP-001` | Critical | Relay injection (agent-to-agent hijacking) |
| `IAP-002` | High | PII in agent messages |
| `IAP-003` | Critical | Credentials in agent messages |
| `IAP-004` | High | System prompt extraction via agent |
| `IAP-005` | High | Privilege escalation between agents |
| `IAP-006` | High | Data exfiltration via agent relay |

### OpenClaw rules

| Rule | Severity | Description |
|------|----------|-------------|
| `OCLAW-001` | Critical | Full tool profile without restrictions |
| `OCLAW-002` | High | Gateway exposed to network |
| `OCLAW-003` | High | Open DM policy |
| `OCLAW-004` | Critical | Exec/shell tool without sandbox |
| `OCLAW-005` | Critical | Path traversal in `$include` |
| `OCLAW-006` | High | Gateway missing authentication |
| `OCLAW-007` | High | Hardcoded credentials in config |

```bash
oktsec rules                     # List all 151 rules
oktsec rules --explain IAP-001   # Explain a specific rule
```

## Audit log

Every message is logged to SQLite (`oktsec.db`) with:
- Content hash (SHA-256)
- Signature verification status
- Public key fingerprint
- Policy decision
- Rules triggered
- Latency

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

## CLI reference

```
oktsec discover                                          # Scan for MCP servers + OpenClaw
oktsec init [--keys ./keys] [--config oktsec.yaml]       # Auto-generate config + keypairs
oktsec wrap [--enforce] <client>                         # Route MCP client through oktsec proxy
oktsec unwrap <client>                                   # Restore original client config
oktsec scan-openclaw [--path ~/.openclaw/openclaw.json]  # Analyze OpenClaw installation
oktsec proxy [--enforce] --agent <name> -- <cmd> [args]  # Stdio proxy for single MCP server
oktsec serve [--config oktsec.yaml] [--port 8080] [--bind 127.0.0.1]
oktsec mcp [--config oktsec.yaml]                        # Run as MCP tool server
oktsec keygen --agent <name> [--agent <name>...] --out <dir>
oktsec keys list|rotate|revoke [--agent <name>]
oktsec verify [--config oktsec.yaml]
oktsec logs [--status <status>] [--agent <name>] [--unverified] [--since <duration>]
oktsec rules [--explain <rule-id>]
oktsec quarantine list|detail|approve|reject [--status <status>] [<id>]
oktsec agent list                                        # List agents with status
oktsec agent suspend <name>                              # Suspend an agent
oktsec agent unsuspend <name>                            # Unsuspend an agent
oktsec status                                            # Show proxy status
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

### `GET /health`

Returns `{"status": "ok", "version": "0.3.0"}`.

### `GET /dashboard`

Web UI for monitoring agent activity. Protected by access code shown at startup.

## OWASP Top 10 for Agentic Applications

Oktsec is aligned with the [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/):

| # | Category | Coverage | How |
|---|----------|----------|-----|
| ASI01 | Excessive Agency / Goal Hijack | Partial | Multi-message verdict escalation, content scanning |
| ASI02 | Tool Misuse | **Strong** | Stdio enforcement, BlockedContent per-agent, rate limiting |
| ASI03 | Privilege Escalation | **Strong** | Ed25519 identity, default-deny policy, ACLs |
| ASI04 | Supply Chain | Weak | Architecture limit (proxy, not package scanner) |
| ASI05 | Unsafe Code Execution | Partial | Stdio enforcement blocks tool calls (e.g. exec) |
| ASI07 | Inter-Agent Communication | **Strong** | Signed messages, ACLs, content scanning, audit trail |
| ASI10 | Rogue Agents | **Strong** | Agent suspension, rate limiting, anomaly detection, auto-suspend |

## Built on

- **[Aguara](https://github.com/garagon/aguara)** — Security scanner for AI agent skills (138 detection rules, pattern matching, taint tracking, NLP injection detection)
- **[mcp-go](https://github.com/mark3labs/mcp-go)** — Go SDK for Model Context Protocol
- **Go stdlib** — `crypto/ed25519`, `net/http`, `log/slog`, `crypto/sha256`
- **[modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite)** — Pure Go SQLite (no CGO)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and pull request process.

For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
