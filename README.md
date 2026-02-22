<p align="center">
  <strong>Oktsec</strong> — Security proxy for inter-agent communication
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
  <a href="#dashboard">Dashboard</a> &middot;
  <a href="#detection-rules">Rules</a> &middot;
  <a href="#configuration">Config</a> &middot;
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

---

Identity verification, policy enforcement, and audit trail for AI agent messaging.
No LLM. Single binary.

## What it does

Oktsec sits between AI agents and enforces three layers of security:

1. **Identity** — Ed25519 signatures verify every message sender. No valid signature, no processing.
2. **Policy** — YAML-based ACLs control which agent can message which. Unauthorized routes are blocked.
3. **Audit** — Every message is logged to SQLite with content hash, sender verification status, and policy decision.

Messages are also scanned against 144 detection rules (138 from [Aguara](https://github.com/garagon/aguara) + 6 inter-agent protocol rules) to catch prompt injection, credential leaks, PII exposure, and data exfiltration.

```
Agent A → sign → POST /v1/message → [Oktsec] → verify → ACL → scan → deliver/block → audit
```

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

Oktsec discovers your existing MCP servers, generates a config, and wraps them with security monitoring — in three commands:

```bash
# 1. Discover → auto-generates config + keypairs
oktsec init

# 2. Wrap your MCP client so traffic routes through oktsec
oktsec wrap cursor          # or: claude-desktop, vscode, cline, windsurf

# 3. Start the proxy with dashboard
oktsec serve
```

That's it. Oktsec starts in **observe mode** — it logs everything but blocks nothing. You can review activity in the dashboard at `http://127.0.0.1:8080/dashboard` using the access code shown in your terminal.

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

## Onboarding flow

### Discover

Scans your machine for MCP server configurations across supported clients:

```bash
oktsec discover
```

Supported clients: Claude Desktop, Cursor, VS Code, Cline, Windsurf.

Output:
```
MCP Servers Found:
cursor
  ├── filesystem   npx -y @modelcontextprotocol/server-filesystem /data
  ├── database     node ./db-server.js
  └── github       npx -y @modelcontextprotocol/server-github
```

### Init

Auto-generates an `oktsec.yaml` config and Ed25519 keypairs for each discovered server:

```bash
oktsec init
oktsec init --keys ./keys --config ./oktsec.yaml
```

Each server is auto-classified by risk level based on its capabilities:
- **Critical** — database, postgres, mysql, sqlite, mongo, redis
- **High** — filesystem, git, github, browser, puppeteer, playwright
- **Medium** — slack, discord, email, messaging
- **Unknown** — everything else (defaults to observe)

### Wrap / Unwrap

Modifies MCP client configs to route server traffic through `oktsec proxy`:

```bash
oktsec wrap cursor          # Backs up config, rewrites to use oktsec proxy
oktsec unwrap cursor        # Restores the original config from .bak
```

Before wrap:
```json
{ "command": "npx", "args": ["-y", "@mcp/server-filesystem", "/data"] }
```

After wrap:
```json
{ "command": "oktsec", "args": ["proxy", "--agent", "filesystem", "--", "npx", "-y", "@mcp/server-filesystem", "/data"] }
```

### Stdio proxy

The `proxy` command wraps an MCP server process, intercepting its JSON-RPC 2.0 stdio traffic. Every message is scanned through the Aguara engine and logged to the audit trail:

```bash
oktsec proxy --agent filesystem -- npx @mcp/server-filesystem /data
oktsec proxy --agent database -- node ./db-server.js
```

This is what `oktsec wrap` configures automatically for each server.

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
| `scan_message` | Scan content for prompt injection, credential leaks, PII, and 140+ threat patterns |
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
  │           OKTSEC v0.2.0              │
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
- **Rules** — Category card grid with drill-down to individual rules, inline enable/disable toggles
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

agents:
  research-agent:
    can_message: [analysis-agent]        # ACL: allowed recipients
    blocked_content: [credentials, pii]  # Content categories to block
    description: "Research and data gathering"
    tags: [research, data]
  analysis-agent:
    can_message: [research-agent, reporting-agent]

quarantine:
  enabled: true
  expiry_hours: 24         # Auto-expire pending items
  retention_days: 30       # Auto-purge audit entries older than N days (0 = keep forever)

rules:
  - id: block-relay-injection
    severity: critical
    action: block           # block, quarantine, allow-and-flag, ignore
    notify: [webhook]

webhooks:
  - url: https://hooks.slack.com/services/xxx
    events: [blocked, quarantined]
```

Validate your config:
```bash
oktsec verify --config oktsec.yaml
```

## Detection rules

Oktsec includes 144 detection rules:

- **138 rules from Aguara** — prompt injection, credential leaks, SSRF, supply chain, exfiltration, MCP attacks, unicode tricks, and more
- **6 inter-agent protocol (IAP) rules**:

| Rule | Description |
|------|-------------|
| `IAP-001` | Relay injection (agent-to-agent hijacking) |
| `IAP-002` | PII in agent messages |
| `IAP-003` | Credentials in agent messages |
| `IAP-004` | System prompt extraction via agent |
| `IAP-005` | Privilege escalation between agents |
| `IAP-006` | Data exfiltration via agent relay |

```bash
oktsec rules                     # List all rules
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
oktsec discover                                          # Scan for MCP servers
oktsec init [--keys ./keys] [--config oktsec.yaml]       # Auto-generate config + keypairs
oktsec wrap <client>                                     # Route client through oktsec proxy
oktsec unwrap <client>                                   # Restore original client config
oktsec proxy --agent <name> -- <command> [args...]       # Stdio proxy for single MCP server
oktsec serve [--config oktsec.yaml] [--port 8080] [--bind 127.0.0.1]
oktsec mcp [--config oktsec.yaml]                        # Run as MCP tool server
oktsec keygen --agent <name> [--agent <name>...] --out <dir>
oktsec keys list|rotate|revoke [--agent <name>]
oktsec verify [--config oktsec.yaml]
oktsec logs [--status <status>] [--agent <name>] [--unverified] [--since <duration>]
oktsec rules [--explain <rule-id>]
oktsec quarantine list|detail|approve|reject [--status <status>] [<id>]
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

Returns `{"status": "ok", "version": "0.2.0"}`.

### `GET /dashboard`

Web UI for monitoring agent activity. Protected by access code shown at startup.

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
