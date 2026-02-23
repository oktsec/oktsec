# AGENTS.md - Oktsec Reference for AI Agents

Oktsec is a security proxy for AI agent-to-agent communication. It sits between agents, scanning messages for prompt injection, credential leaks, command execution, and other threats. Single Go binary, no LLM, deterministic.

## Quick Start

```bash
# Install
go install github.com/oktsec/oktsec@latest

# Generate keys for your agents
oktsec keygen --agent coordinator --agent researcher --out ./keys

# Create config (or auto-detect from installed MCP clients)
oktsec init

# Start the proxy
oktsec serve
```

## How It Works

Every message goes through this pipeline:

```
Rate limit -> Identity verification -> Suspension check -> ACL check -> Content scan -> Blocked content filter -> History escalation -> Verdict -> Audit log
```

Verdicts: `clean` (deliver), `flag` (deliver + log), `quarantine` (hold for human review), `block` (reject).

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
| `serve` | Start proxy server (`--port`, `--bind`) |
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
| `wrap <client>` | Route client's MCP servers through oktsec proxy (`--enforce`) |
| `unwrap <client>` | Restore original MCP config |
| `proxy --agent <name> -- <cmd>` | Wrap a single MCP server with stdio interception (`--enforce`) |
| `scan-openclaw` | Analyze OpenClaw installation security |
| `mcp` | Start oktsec as an MCP server (stdio) |
| `version` | Print version info |

Supported wrap/unwrap clients: `claude-desktop`, `cursor`, `vscode`, `cline`, `windsurf`.

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

151 built-in rules across 14 categories. Key inter-agent rules:

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

## Health Check

```
GET /health -> {"status": "ok", "version": "0.4.0"}
```

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

## Rate Limiting

When `rate_limit.per_agent > 0`, each agent is limited to N messages per window (sliding window). Exceeding the limit returns HTTP 429. Rate limiting runs before identity verification (cheapest check first).

## Anomaly Detection

When `anomaly.risk_threshold > 0`, a background loop scores each agent every `check_interval` seconds:

```
risk_score = (blocked * 3 + quarantined * 2) / total * 100
```

If score exceeds threshold and agent has `min_messages` or more total messages, fires `agent_risk_elevated` webhook. If `auto_suspend: true`, the agent is automatically suspended.
