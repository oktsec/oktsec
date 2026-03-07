# AGENTS.md - Oktsec Reference for AI Agents

Oktsec is a security proxy and MCP gateway for AI agent-to-agent communication. It sits between agents and their MCP servers, scanning messages and tool calls for prompt injection, credential leaks, command execution, and other threats. Single Go binary, no LLM, deterministic. Built on the [official MCP SDK](https://github.com/modelcontextprotocol/go-sdk).

## Quick Start

```bash
# Install
curl -fsSL https://raw.githubusercontent.com/oktsec/oktsec/main/install.sh | bash

# One-command setup (discovers, configures, wraps all MCP servers)
oktsec setup

# Start the dashboard
oktsec serve
```

Or install from source:

```bash
go install github.com/oktsec/oktsec@latest
```

## How It Works

Every message goes through this pipeline:

```
Rate limit -> Identity verification -> Suspension check -> ACL check -> Content scan -> Blocked content filter -> History escalation -> Verdict -> Audit log
```

Verdicts: `clean` (deliver), `flag` (deliver + log), `quarantine` (hold for human review), `block` (reject).

## Operational Modes

| Mode | Command | Use Case |
|------|---------|----------|
| HTTP proxy | `oktsec serve` | Agent-to-agent API, dashboard |
| Stdio proxy | `oktsec proxy` | Wrap individual MCP servers |
| MCP gateway | `oktsec gateway` | Front multiple backend MCP servers |
| MCP tool server | `oktsec mcp` | Expose security tools to AI agents |

## MCP Gateway Mode

Run `oktsec gateway` to intercept all MCP tool calls to backend servers. The same security pipeline runs on every `tools/call`. Configure backends in `oktsec.yaml`:

```yaml
mcp_servers:
  filesystem:
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
```

The gateway auto-discovers tools from all backends, applies per-agent allowlists, and can optionally scan backend responses.

## Sending a Message

`POST /v1/message` with JSON body:

```json
{
  "from": "coordinator",
  "to": "researcher",
  "content": "Scan the target system for open ports",
  "timestamp": "2026-02-23T15:00:00Z",
  "signature": "<base64 Ed25519 signature>"
}
```

### Signing

The signature covers the canonical payload `from\nto\ncontent\ntimestamp` using Ed25519. The private key is a raw 64-byte Ed25519 key stored in PEM format (type `OKTSEC ED25519 PRIVATE KEY`).

```
payload = "coordinator\nresearcher\nScan the target system\n2026-02-23T15:00:00Z"
signature = base64(ed25519.Sign(privateKey, payload))
```

If `require_signature: false` in config, the signature field is optional. Messages are still scanned for content threats.

### Response

```json
{
  "status": "delivered",
  "message_id": "uuid",
  "policy_decision": "allow",
  "rules_triggered": [],
  "verified_sender": true
}
```

## Policy Decisions

| Decision | Meaning | HTTP |
|---|---|---|
| `allow` | Clean content, delivered | 200 |
| `content_flagged` | Medium-severity finding, delivered | 200 |
| `content_quarantined` | High-severity finding, held for review | 202 |
| `content_blocked` | Critical-severity finding, rejected | 403 |
| `identity_rejected` | Bad signature or unknown agent | 403 |
| `signature_required` | Unsigned message, signatures enforced | 401 |
| `acl_denied` | Sender not authorized to message recipient | 403 |
| `agent_suspended` | Sender is suspended | 403 |
| `recipient_suspended` | Recipient is suspended | 403 |

## Config Schema (oktsec.yaml)

```yaml
version: "1"

server:
  port: 8080              # auto-increments if in use (up to +10)
  bind: "127.0.0.1"
  log_level: "info"       # debug | info | warn | error

identity:
  keys_dir: "./keys"
  require_signature: true

default_policy: "allow"   # "allow" | "deny" (reject unknown agents)

agents:
  coordinator:
    can_message: ["researcher", "reporter"]  # ["*"] = any agent
    blocked_content: []                       # Aguara categories that force block
    allowed_tools: []                         # MCP tool names allowed via stdio proxy (empty = all)
    suspended: false
    description: "Orchestrator agent"
    egress:                                   # per-agent outbound traffic controls (optional)
      allowed_domains: [api.google.com]       # additive to global forward_proxy.allowed_domains
      blocked_domains: [pastebin.com]         # additive to global; global blocklist always wins
      scan_requests: true                     # null = inherit global; explicit overrides
      blocked_categories: [credentials, pii]  # DLP: block outbound content matching these categories
      rate_limit: 100                         # per-agent egress rate limit (0 = disabled)
      rate_window: 60                         # seconds

mcp_servers:              # backend MCP servers (gateway mode)
  filesystem:
    transport: stdio      # "stdio" or "http"
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]

rules:                    # per-rule enforcement overrides
  - id: "IAP-001"
    action: "block"       # block | quarantine | allow-and-flag | ignore

webhooks:
  - url: "https://hooks.example.com/oktsec"
    events: ["blocked"]   # empty = all events

quarantine:
  enabled: true
  expiry_hours: 24

rate_limit:
  per_agent: 20           # 0 = disabled
  window: 60              # seconds

anomaly:
  risk_threshold: 50      # 0 = disabled; 0-100
  min_messages: 5
  auto_suspend: false
```

## CLI Commands

All commands accept `--config <path>` (default: `oktsec.yaml`).

| Command | Purpose |
|---|---|
| `setup` | One-command onboarding: discover + init + wrap all |
| `serve` | Start proxy server + dashboard (`--port`, `--bind`) |
| `gateway` | Start MCP gateway fronting backend servers |
| `proxy --agent <name> -- <cmd>` | Wrap a single MCP server with stdio interception (`--enforce`) |
| `keygen --agent <name>` | Generate Ed25519 keypair |
| `verify` | Validate config file |
| `status` | Show proxy status and audit stats |
| `logs` | Query audit log (`--status`, `--agent`, `--since`, `--limit`, `--live`) |
| `rules` | List detection rules (`--explain <id>` for details) |
| `agent list` | List agents with status |
| `agent suspend <name>` | Suspend an agent |
| `agent unsuspend <name>` | Unsuspend an agent |
| `quarantine list` | List quarantined messages (`--status pending\|approved\|rejected\|expired`) |
| `quarantine approve <id>` | Approve quarantined message |
| `quarantine reject <id>` | Reject quarantined message |
| `quarantine detail <id>` | Show quarantine item details |
| `enforce` | Show current mode |
| `enforce on` | Enable signature enforcement |
| `enforce off` | Disable signature enforcement |
| `keys list` | List all agent keypairs |
| `keys rotate --agent <name>` | Rotate keypair (old key revoked) |
| `keys revoke --agent <name>` | Revoke keypair |
| `discover` | Scan for MCP server configs on the machine |
| `init` | Generate config and keys from discovered MCP servers |
| `wrap <client>` | Route client's MCP servers through oktsec proxy (`--enforce`, `--all`) |
| `unwrap <client>` | Restore original MCP config |
| `scan-openclaw` | Analyze OpenClaw installation security |
| `mcp` | Start oktsec as an MCP server (stdio) |
| `version` | Print version info |

Supported wrap/unwrap clients: `claude-desktop`, `cursor`, `vscode`, `cline`, `windsurf`, `amp`, `gemini-cli`, `copilot-cli`, `amazon-q`, `roo-code`, `kilo-code`, `boltai`, `jetbrains`.

## MCP Tools

When running as an MCP server (`oktsec mcp`), these tools are available:

| Tool | Parameters | Description |
|---|---|---|
| `scan_message` | `content` (required), `from`, `to` | Scan content for threats. Returns verdict + findings. |
| `list_agents` | none | List agents with ACL rules. |
| `audit_query` | `status`, `agent`, `limit` | Query the audit log. |
| `get_policy` | `agent` (required) | Get security policy for an agent. |
| `verify_agent` | `agent`, `from`, `to`, `content`, `timestamp`, `signature` (all required) | Verify an Ed25519 signature. |
| `review_quarantine` | `action` (required: list/detail/approve/reject), `id`, `limit`, `status` | Manage quarantined messages. |

All tools except `review_quarantine` are read-only.

## Tool Allowlist (Stdio Proxy)

When `allowed_tools` is set for an agent in config, only listed MCP tools are permitted in `tools/call` requests. Any unlisted tool is blocked with a JSON-RPC error:

```json
{"jsonrpc":"2.0","id":5,"error":{"code":-32600,"message":"blocked by oktsec: tool_allowlist:exec_command"}}
```

Config example:
```yaml
agents:
  filesystem:
    allowed_tools: ["read_file", "list_dir", "search_files"]
```

Empty list (or omitted) means all tools are allowed. The check runs before content scanning (cheapest check first).

## Verdict Escalation

1. **Severity mapping**: critical = block, high = quarantine, medium = flag, low = clean
2. **Blocked content**: if finding category matches agent's `blocked_content` list, escalate to block
3. **History**: 3+ blocks/quarantines in the last hour + flagged content = escalate to quarantine. 5+ = escalate to block.
4. **Rule overrides**: per-rule `action` in config can force any verdict

## Detection Rules

175 built-in rules across 14 categories. Key inter-agent rules:

| ID | Name | Severity |
|---|---|---|
| IAP-001 | Inter-agent relay injection | critical |
| IAP-002 | PII in agent message | high |
| IAP-003 | Credential in agent message | critical |
| IAP-004 | System prompt extraction via agent | high |
| IAP-005 | Privilege escalation between agents | high |
| IAP-006 | Data exfiltration via agent relay | high |

Categories include: `prompt-injection`, `command-execution`, `credential-leak`, `exfiltration`, `ssrf-cloud`, `supply-chain`, `mcp-attack`, `mcp-config`, `inter-agent`, `unicode-attack`, and more.

Use `oktsec rules` to list all rules. Use `oktsec rules --explain <id>` for pattern details.

## Python SDK

```bash
pip install oktsec  # coming soon -- install from sdk/python/ for now
```

```python
from oktsec import OktsecClient

client = OktsecClient(base_url="http://127.0.0.1:8080")

# Send a message
result = client.send_message(
    from_agent="coordinator",
    to_agent="researcher",
    content="Analyze the latest threat report",
)

# With Ed25519 signing
from oktsec import load_keypair
keypair = load_keypair("./keys", "coordinator")
client = OktsecClient(base_url="http://127.0.0.1:8080", keypair=keypair)
```

Async support via `AsyncOktsecClient` (httpx-based).

## Agent CRUD API

Manage agents programmatically without editing `oktsec.yaml`:

### List agents
```
GET /v1/agents → [{"name": "coordinator", "description": "...", "can_message": [...], "suspended": false, "has_key": true}, ...]
```

### Get agent
```
GET /v1/agents/{name} → {"name": "coordinator", "description": "...", ...}
```

### Create agent
```
POST /v1/agents
{"name": "new-agent", "description": "My agent", "can_message": ["other"], "tags": ["prod"]}
→ 201 Created
```

### Update agent (partial)
```
PUT /v1/agents/{name}
{"description": "Updated", "suspended": true}
→ 200 OK (only provided fields are changed)
```

### Delete agent
```
DELETE /v1/agents/{name} → 204 No Content
```

### Rotate keys
```
POST /v1/agents/{name}/keys → {"status": "rotated", "agent": "name", "fingerprint": "sha256:..."}
```
Revokes the old key and generates a new Ed25519 keypair.

### Toggle suspension
```
POST /v1/agents/{name}/suspend → {"agent": "name", "suspended": "true"}
```

All endpoints return JSON. Changes are persisted to `oktsec.yaml` automatically.

## Health Check

```
GET /health -> {"status": "ok", "version": "0.8.0"}
```

## Prometheus Metrics

```
GET /metrics
```

Available metric families: `oktsec_messages_total`, `oktsec_message_latency_seconds`, `oktsec_rules_triggered_total`, `oktsec_rate_limit_hits_total`, `oktsec_quarantine_pending`, `oktsec_signature_verified_total`.

## Webhook Events

Events: `message_blocked`, `message_quarantined`, `agent_risk_elevated`.

Payload:
```json
{
  "event": "message_blocked",
  "message_id": "uuid",
  "from": "researcher",
  "to": "coordinator",
  "severity": "critical",
  "rule": "IAP-001",
  "timestamp": "2026-02-23T15:00:00Z"
}
```

## Per-Agent Egress Control

When the forward proxy is enabled, agents identify themselves via `X-Oktsec-Agent: <agent_name>` header on proxy requests. This enables per-agent outbound traffic policies.

**Merge rules:**
- Per-agent `allowed_domains` is additive to global `forward_proxy.allowed_domains`
- Per-agent `blocked_domains` is additive to global `forward_proxy.blocked_domains`
- Global `blocked_domains` always wins (cannot be overridden per-agent)
- `scan_requests`/`scan_responses`: null inherits global, explicit value overrides
- No `egress` block = fall back to global settings entirely

**DLP category blocking:** After scanning outbound content, findings are checked against the agent's `blocked_categories`. If any finding matches, the request is blocked. Reuses the same Aguara rule categories as inbound content scanning.

The `X-Oktsec-Agent` header is stripped before forwarding upstream (never leaked to destination).

## Delegation Chains

Agents can delegate messaging authority to other agents using cryptographically signed delegation tokens. Inspired by Verifiable Intent's 3-layer delegation model.

```go
// Create a delegation from parent to child, valid for 24h
token := identity.CreateDelegation(parentPrivKey, "parent", "child", []string{"target-a", "target-b"}, 24*time.Hour)

// Verify: checks signature, expiry, and scope
result := identity.VerifyDelegation(parentPubKey, token, "target-a")
// result.Valid == true
```

Canonical signing payload: `delegator\ndelegate\nscope_csv\nissuedAt\nexpiresAt`

When a delegate sends a message, the handler can verify the chain: delegate's key signed the message, delegator's key signed the delegation, and ACL uses the delegator's permissions.

## Scoped Constraints

ACL entries can include constraints beyond simple allow/deny:

```yaml
agents:
  researcher:
    can_message:
      - target: coder
        constraints:
          - type: rate
            max_messages: 50
            window_secs: 3600
          - type: ttl
            expires_at: "2026-04-01T00:00:00Z"
      - target: coordinator   # no constraints = unrestricted
```

Constraint types:
- `rate` — max N messages per window to a specific target
- `ttl` — permission expires at a given timestamp

Backward compatible: plain string entries in `can_message` still work as unrestricted permissions.

## Intent Declaration

Agents can declare what they intend to do via the `intent` field:

```json
{
  "from": "researcher",
  "to": "coder",
  "content": "Please review PR #92",
  "intent": "code_review",
  "timestamp": "2026-03-06T12:00:00Z"
}
```

The proxy validates intent against content using deterministic pattern matching (no LLM). Known categories: `code_review`, `deploy`, `debug`, `monitoring`, `testing`, `documentation`, `security`, `data`. A mismatch between declared intent and content triggers a flag.

## Selective Disclosure (Audit Redaction)

Audit log exports support three redaction levels:

- `full` — all fields visible (admin only)
- `analyst` — content hashes visible, matched content in findings redacted to `[REDACTED]`
- `external` — only status, timestamp, agents, and policy decision

```
GET /v1/audit?redaction=analyst
```

## Verifiable Audit Trail

Audit entries form a tamper-evident hash chain. Each entry includes:
- `prev_hash` — SHA-256 of the previous entry's hash
- `entry_hash` — SHA-256 of `prev_hash + id + timestamp + from + to + content_hash + status`
- `proxy_signature` — Ed25519 signature of `entry_hash` by the proxy's key

Verify chain integrity:
```
oktsec verify --audit
GET /v1/audit/verify
```

## MCP Gateway Tool Constraints

Per-agent tool constraints go beyond simple allowlists:

```yaml
agents:
  researcher:
    tool_constraints:
      - tool: read_file
        parameters:
          path:
            allowed_patterns: ["/data/*", "/public/*"]
            blocked_patterns: ["/secrets/*", "*.env"]
        max_response_bytes: 1048576
      - tool: write_file
        cooldown_secs: 10
    tool_chain_rules:
      - if: get_credentials
        then: [send_email, http_request]
        cooldown_secs: 300
```

Features:
- **Parameter constraints**: allowed/blocked glob patterns, max length
- **Tool cooldowns**: minimum interval between calls to the same tool
- **Chain rules**: calling tool A blocks tools B and C for N seconds (prevents credential exfiltration)

## Rate Limiting

When `rate_limit.per_agent > 0`, each agent is limited to N messages per window (sliding window). Exceeding the limit returns HTTP 429. Rate limiting runs before identity verification (cheapest check first).

## Anomaly Detection

When `anomaly.risk_threshold > 0`, a background loop scores each agent:

```
risk_score = (blocked * 3 + quarantined * 2) / total * 100
```

If score exceeds threshold and agent has `min_messages` or more total messages, fires `agent_risk_elevated` webhook. If `auto_suspend: true`, the agent is automatically suspended.
