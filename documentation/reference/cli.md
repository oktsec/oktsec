# CLI Reference

All commands accept the global flag `--config <path>`. Config is resolved using a 4-step cascade:

1. `--config` flag (explicit path)
2. `$OKTSEC_CONFIG` environment variable
3. `./oktsec.yaml` (current directory)
4. `~/.oktsec/config.yaml` (centralized home directory)

```bash
oktsec [command] [flags]
```

---

## Primary Commands

### `run`

The unified command for running Oktsec. If no config exists, performs auto-setup (discovery, config generation, key creation, wrapping) before starting the server.

```bash
oktsec run
oktsec run --port 9090 --bind 0.0.0.0
oktsec run --config /path/to/config.yaml
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--port` | int | config value | Override server port |
| `--bind` | string | config value | Override bind address |
| `--config` | string | resolved via cascade | Config file path |
| `--enforce` | bool | `false` | Start in enforcement mode (block malicious requests) |

What `run` does:

1. Resolves config using the 4-step cascade
2. If no config exists: discovers MCP clients, generates config and keypairs, wraps servers
3. Starts the proxy server with dashboard, API, gateway (if configured), and Prometheus metrics
4. Prints access code and endpoints

### `doctor`

Run 7 health checks to verify your Oktsec installation.

```bash
oktsec doctor
```

Checks:

| # | Check | What it verifies |
|---|-------|------------------|
| 1 | Home directory | `~/.oktsec/` exists with correct permissions |
| 2 | Config | Config file is valid and loadable |
| 3 | Secrets | `.env` file exists with `OKTSEC_API_KEY` |
| 4 | Database | SQLite database is accessible |
| 5 | Keys | Ed25519 keypairs exist for all configured agents |
| 6 | Port | Configured port is available |
| 7 | Rules | Detection rules load without errors |

---

## Setup & Onboarding

### `setup` (deprecated)

!!! warning "Deprecated"
    Use `oktsec run` instead. The `setup` command still works but prints a deprecation notice.

One-command onboarding: discover all MCP servers, generate config and keypairs, wrap everything.

```bash
oktsec setup
oktsec setup --enforce
oktsec setup --skip-wrap
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--keys` | string | `./keys` | Directory for generated keypairs |
| `--config` | string | `oktsec.yaml` | Output config file path |
| `--enforce` | bool | `false` | Start in enforcement mode (block malicious requests) |
| `--skip-wrap` | bool | `false` | Generate config only, don't modify client configs |

What `setup` does:

1. Scans for MCP clients on the machine
2. Generates `oktsec.yaml` with one agent per MCP server
3. Generates Ed25519 keypairs for each agent
4. Wraps all MCP servers through `oktsec proxy`
5. Prints next steps

### `discover`

Scan the machine for MCP server configurations.

```bash
oktsec discover
```

Checks 17 clients: Claude Desktop, Cursor, VS Code, Cline, Windsurf, Claude Code, Amp, Gemini CLI, Copilot CLI, Amazon Q, Roo Code, Kilo Code, BoltAI, JetBrains, and more.

Also detects OpenClaw installations and runs a risk assessment.

### `init` (deprecated)

!!! warning "Deprecated"
    Use `oktsec run` instead. The `init` command still works but prints a deprecation notice.

Generate config and keypairs from discovered servers without wrapping.

```bash
oktsec init
oktsec init --keys ./keys --config ./oktsec.yaml
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--keys` | string | `./keys` | Directory for generated keypairs |
| `--config` | string | `oktsec.yaml` | Output config file path |

Each server is auto-classified by risk level:

| Risk | Triggers |
|------|----------|
| Critical | database, postgres, mysql, sqlite, mongo, redis, sql |
| High | filesystem, git, github, browser, puppeteer, playwright |
| Medium | slack, discord, email, messaging |
| Unknown | Everything else |

### `wrap`

Route MCP client servers through `oktsec proxy`. Creates a `.bak` backup of the original config.

```bash
oktsec wrap claude-desktop
oktsec wrap --all
oktsec wrap --enforce --all
oktsec wrap --enforce cursor
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--enforce` | bool | `false` | Enable enforcement mode (block malicious requests) |
| `--all` | bool | `false` | Wrap all discovered clients at once |

Supported clients: `claude-desktop`, `cursor`, `vscode`, `cline`, `windsurf`, `amp`, `gemini-cli`, `copilot-cli`, `amazon-q`, `roo-code`, `kilo-code`, `boltai`, `jetbrains`.

!!! note
    Restart your MCP clients after wrapping to activate the proxy.

### `unwrap`

Restore the original MCP config from the `.bak` backup created by `wrap`.

```bash
oktsec unwrap claude-desktop
oktsec unwrap cursor
```

---

## Server Modes

### `serve` (deprecated)

!!! warning "Deprecated"
    Use `oktsec run` instead. The `serve` command still works but prints a deprecation notice.

Start the proxy server with dashboard, API, and Prometheus metrics.

```bash
oktsec serve
oktsec serve --port 9090 --bind 0.0.0.0
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--port` | int | config value | Override server port |
| `--bind` | string | config value | Override bind address |

Endpoints served:

| Path | Description |
|------|-------------|
| `/v1/message` | Message API |
| `/v1/agents` | Agent CRUD API |
| `/dashboard` | Web UI |
| `/health` | Health check |
| `/metrics` | Prometheus metrics |

An 8-digit access code is printed at startup for dashboard authentication. Sessions expire after 8 hours.

### `gateway`

Start the MCP security gateway fronting backend servers.

```bash
oktsec gateway
oktsec gateway --port 9090
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--port` | int | config value | Override gateway port |
| `--bind` | string | config value | Override bind address |

Requires at least one entry in `mcp_servers` config.

### `proxy`

Wrap an MCP server's stdio with security interception.

```bash
oktsec proxy --agent filesystem -- npx @mcp/server-filesystem /data
oktsec proxy --enforce --agent database -- node ./db-server.js
oktsec proxy --enforce --inspect-responses --agent fs -- npx @mcp/server-filesystem /tmp
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--agent` | string | **required** | Agent name for this MCP server |
| `--enforce` | bool | `false` | Block malicious requests instead of observe-only |
| `--inspect-responses` | bool | `false` | Also scan server responses (requires `--enforce`) |

In observe mode, all messages are forwarded regardless of scan results. In enforcement mode, blocked tool calls return a JSON-RPC error:

```json
{"jsonrpc":"2.0","id":42,"error":{"code":-32600,"message":"blocked by oktsec: IAP-001"}}
```

### `mcp`

Start oktsec as an MCP tool server (stdio transport). Add to your MCP client config:

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

Exposes 6 security tools: `scan_message`, `list_agents`, `audit_query`, `get_policy`, `verify_agent`, `review_quarantine`.

---

## Identity & Keys

### `keygen`

Generate Ed25519 keypairs.

```bash
oktsec keygen --agent research-agent
oktsec keygen --agent agent-a --agent agent-b --out ./keys/
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--agent` | []string | **required** | Agent name(s) to generate keys for. Repeatable |
| `--out` | string | `./keys` | Output directory |

### `keys list`

List all registered keypairs with fingerprints and status (active/revoked).

```bash
oktsec keys list
```

### `keys rotate`

Rotate an agent's keypair. Moves the old key to `keys/revoked/` and generates a new one. Records the revocation in the audit trail.

```bash
oktsec keys rotate --agent my-agent
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--agent` | string | **required** | Agent name to rotate |

### `keys revoke`

Revoke an agent's keypair without generating a replacement. Messages signed with revoked keys are rejected.

```bash
oktsec keys revoke --agent compromised-agent
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--agent` | string | **required** | Agent name to revoke |

---

## Agent Management

### `agent list`

List all configured agents with status, ACLs, and blocked content categories.

```bash
oktsec agent list
```

### `agent suspend`

Suspend an agent — all messages from/to this agent are immediately rejected.

```bash
oktsec agent suspend malicious-agent
```

### `agent unsuspend`

Unsuspend an agent — messages are processed normally again.

```bash
oktsec agent unsuspend rehabilitated-agent
```

---

## Audit & Monitoring

### `logs`

Query the audit log.

```bash
oktsec logs
oktsec logs --status blocked
oktsec logs --agent researcher --since 1h
oktsec logs --unverified --limit 100
oktsec logs --live
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--status` | string | `""` | Filter: `delivered`, `blocked`, `quarantined`, `rejected` |
| `--agent` | string | `""` | Filter by agent name |
| `--unverified` | bool | `false` | Show only unsigned/unverified messages |
| `--since` | string | `""` | Duration filter (e.g., `1h`, `30m`, `24h`) |
| `--limit` | int | `50` | Max entries to return |
| `--live` | bool | `false` | Stream new entries in real-time (polls every 1s) |

Output columns: `TIME`, `FROM`, `TO`, `STATUS`, `DECISION`, `VERIFIED`, `LATENCY`.

### `status`

Show proxy status, configuration summary, health score, and audit statistics.

```bash
oktsec status
```

Displays: mode, agent count, signature status, port, keys loaded, health score (0-100 with letter grade), message statistics, and top issues.

### `audit`

Run 41 deployment security checks across Oktsec, OpenClaw, and NanoClaw. Returns non-zero exit code if critical or high findings exist.

```bash
oktsec audit
oktsec audit --json
oktsec audit --sarif
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--json` | bool | `false` | Output as JSON |
| `--sarif` | bool | `false` | Output as SARIF v2.1.0 (for CI/CD integration) |

---

## Quarantine

### `quarantine list`

List quarantined messages.

```bash
oktsec quarantine list
oktsec quarantine list --status approved
oktsec quarantine list --limit 10
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--status` | string | `pending` | Filter: `pending`, `approved`, `rejected`, `expired` |
| `--limit` | int | `50` | Max items to return |

### `quarantine detail`

Show full details of a quarantined item, including content and triggered rules.

```bash
oktsec quarantine detail <id>
```

### `quarantine approve`

Approve a quarantined message for delivery.

```bash
oktsec quarantine approve <id>
oktsec quarantine approve <id> --reviewer "security-team"
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--reviewer` | string | `cli` | Name of the reviewer |

### `quarantine reject`

Permanently reject a quarantined message.

```bash
oktsec quarantine reject <id>
oktsec quarantine reject <id> --reviewer "security-team"
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--reviewer` | string | `cli` | Name of the reviewer |

---

## Rules & Config

### `rules`

List all loaded detection rules or explain a specific rule.

```bash
oktsec rules                     # List all 230 rules
oktsec rules --explain IAP-001   # Show rule patterns and details
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--explain` | string | `""` | Show detailed info for a specific rule ID |

### `verify`

Validate the config file syntax and constraints.

```bash
oktsec verify
oktsec verify --config /path/to/oktsec.yaml
```

### `enforce`

Toggle between enforce and observe mode.

```bash
oktsec enforce           # Show current mode
oktsec enforce on        # Switch to enforce (require_signature: true)
oktsec enforce off       # Switch to observe (require_signature: false)
```

After toggling, restart the proxy or send `SIGHUP` to apply.

---

## Other

### `scan-openclaw`

Analyze an OpenClaw installation for security risks. Scans config and workspace files (`SOUL.md`, `AGENTS.md`, `TOOLS.md`, `USER.md`) with the Aguara engine.

```bash
oktsec scan-openclaw
oktsec scan-openclaw --path ~/.openclaw/openclaw.json
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--path` | string | auto-detected | Path to `openclaw.json` |

### `version`

Print version, Go version, and OS/architecture.

```bash
oktsec version
```

```
oktsec v1.0.0
  go:   go1.23.4
  os:   darwin/arm64
```
