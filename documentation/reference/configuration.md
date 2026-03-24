# Configuration Reference

Oktsec is configured via YAML. All commands accept `--config <path>` to specify the config file explicitly.

## Config resolution cascade

When no explicit `--config` flag is provided, Oktsec resolves the config file using this 4-step cascade (first match wins):

| Priority | Source | Path |
|----------|--------|------|
| 1 | `--config` flag | Explicit path passed on the command line |
| 2 | `$OKTSEC_CONFIG` env var | Path from the environment variable |
| 3 | Working directory | `./oktsec.yaml` |
| 4 | Home directory | `~/.oktsec/config.yaml` |

## Centralized home directory

Oktsec stores all state in `~/.oktsec/`:

```
~/.oktsec/
  config.yaml    # Main configuration
  .env           # Secrets (API keys)
  keys/          # Ed25519 keypairs
  oktsec.db      # SQLite audit database
```

The `oktsec run` command creates this directory structure automatically on first run. Run `oktsec doctor` to verify it.

## Secrets separation

Sensitive values are stored in `~/.oktsec/.env`, separate from the main config:

```bash
OKTSEC_API_KEY=oks_a1b2c3d4e5f6...
```

This file is auto-generated on first run with a random `OKTSEC_API_KEY`. Keeping secrets out of the YAML config makes it safe to commit `config.yaml` to version control.

## Config backup

When Oktsec writes to the config file (e.g., via dashboard settings or `oktsec wrap`), it creates a `.bak` backup of the previous version in the same directory before writing.

---

## Minimal config

```yaml
version: "1"

server:
  port: 8080

identity:
  keys_dir: "./keys"
  require_signature: false   # observe mode

agents:
  coordinator:
    can_message: ["researcher", "coder"]
  researcher:
    can_message: ["coordinator"]
  coder:
    can_message: ["coordinator"]
```

This is enough to start. The security pipeline runs with defaults for everything not specified.

---

## Full schema

Every field, its type, default, and behavior.

### `server`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `port` | int | `8080` | HTTP port. Auto-increments up to +10 if in use |
| `bind` | string | `127.0.0.1` | Bind address. Use `0.0.0.0` for network access |
| `log_level` | string | `info` | Log verbosity: `debug`, `info`, `warn`, `error` |

### `identity`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `keys_dir` | string | `./keys` | Directory containing `.pub` and `.key` files |
| `require_signature` | bool | `true` | Reject unsigned messages (enforce mode). Set `false` for observe mode |

!!! tip "Observe vs enforce"
    `require_signature: false` = **observe mode** — logs everything, blocks nothing. This is the recommended starting mode. Set `true` when ready to enforce identity verification.

### `default_policy`

| Value | Behavior |
|-------|----------|
| `allow` (default) | Accept messages from unknown agents |
| `deny` | Reject messages from agents not listed in `agents` |

### `db_path`

| Type | Default | Description |
|------|---------|-------------|
| string | `oktsec.db` | SQLite database for audit trail and quarantine. Resolved to absolute path at load time. Use `:memory:` for in-memory (testing only) |

### `custom_rules_dir`

| Type | Default | Description |
|------|---------|-------------|
| string | `""` | Directory for org-specific YAML detection rules. Loaded alongside the 230 built-in rules |

---

## `agents`

Map of agent name to configuration. Agent names must match `^[a-zA-Z0-9][a-zA-Z0-9_-]*$`.

```yaml
agents:
  coordinator:
    description: "Orchestrator agent"
    can_message: ["researcher", "reporter"]
    blocked_content: [credentials, pii]
    allowed_tools: []
    suspended: false
    location: "us-east-1"
    tags: ["prod", "critical"]
    egress:
      allowed_domains: [api.google.com]
      blocked_domains: [pastebin.com]
      scan_requests: true
      blocked_categories: [credentials]
      rate_limit: 100
      rate_window: 60
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `can_message` | []string | `[]` | Agents this agent can message. `["*"]` = any agent. An agent **cannot** list itself |
| `blocked_content` | []string | `[]` | Aguara categories that force `block` verdict for this agent |
| `allowed_tools` | []string | `[]` | MCP tool names this agent can call. Empty = all tools allowed |
| `suspended` | bool | `false` | Immediately block all messages from/to this agent |
| `description` | string | `""` | Human-readable description |
| `created_by` | string | `""` | Who created the agent (set by API) |
| `created_at` | string | `""` | Creation timestamp (set by API) |
| `location` | string | `""` | Deployment location tag |
| `tags` | []string | `[]` | Arbitrary tags for filtering |
| `egress` | object | `null` | Per-agent outbound controls (see below) |

### `agents.*.egress`

Per-agent outbound traffic controls. Omit entirely to use global `forward_proxy` settings.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allowed_domains` | []string | `[]` | Only these domains are reachable. **Additive** with global `allowed_domains` |
| `blocked_domains` | []string | `[]` | Block these domains. **Additive** with global `blocked_domains` |
| `scan_requests` | bool* | `null` | Scan outbound bodies. `null` = inherit global setting |
| `scan_responses` | bool* | `null` | Scan inbound responses. `null` = inherit global setting |
| `blocked_categories` | []string | `[]` | DLP: block outbound content matching these Aguara categories |
| `rate_limit` | int | `0` | Max outbound requests per window (0 = no agent-specific limit) |
| `rate_window` | int | `60` | Window size in seconds |

*Uses pointer semantics: `null`/omitted inherits from global, explicit `true`/`false` overrides.

---

## `gateway`

MCP gateway mode — fronts multiple backend MCP servers through a single endpoint.

```yaml
gateway:
  enabled: true
  port: 9090
  bind: "127.0.0.1"
  endpoint_path: "/mcp"
  scan_responses: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable the gateway |
| `port` | int | `9090` | Gateway HTTP port. Auto-increments up to +10 if in use |
| `bind` | string | `127.0.0.1` | Bind address |
| `endpoint_path` | string | `/mcp` | MCP endpoint path |
| `scan_responses` | bool | `false` | Scan backend responses before passing to agents |

---

## `mcp_servers`

Backend MCP servers for gateway mode. Map of server name to config.

=== "stdio"

    ```yaml
    mcp_servers:
      filesystem:
        transport: stdio
        command: npx
        args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
        env:
          NODE_ENV: production
    ```

=== "http"

    ```yaml
    mcp_servers:
      github:
        transport: http
        url: https://api.github.com/mcp
        headers:
          Authorization: "Bearer ghp_xxx"
    ```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `transport` | string | yes | `stdio` or `http` |
| `command` | string | stdio only | Command to launch |
| `args` | []string | no | Command arguments |
| `env` | map | no | Environment variables (stdio only) |
| `url` | string | http only | Remote MCP server URL |
| `headers` | map | no | HTTP headers (http only) |

---

## `forward_proxy`

HTTP forward proxy for outbound agent traffic. Used with Docker Sandbox or any agent that routes through `HTTP_PROXY`.

```yaml
forward_proxy:
  enabled: true
  scan_requests: true
  scan_responses: false
  max_body_size: 1048576
  allowed_domains: []
  blocked_domains:
    - pastebin.com
    - transfer.sh
    - file.io
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable the forward proxy |
| `scan_requests` | bool | `true` | Scan outbound request bodies with Aguara |
| `scan_responses` | bool | `false` | Scan inbound response bodies |
| `max_body_size` | int64 | `1048576` | Max body size to scan (bytes). Bodies larger than this are passed through unscanned |
| `allowed_domains` | []string | `[]` | Global domain allowlist. Empty = all domains allowed |
| `blocked_domains` | []string | `[]` | Global domain blocklist. **Takes precedence** over allowlist |

!!! warning "Open proxy protection"
    Validation rejects configs where `forward_proxy.enabled: true` but neither `allowed_domains` nor `blocked_domains` are set. This prevents accidentally running an open proxy.

---

## `quarantine`

```yaml
quarantine:
  enabled: true
  expiry_hours: 24
  retention_days: 30
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable the quarantine queue |
| `expiry_hours` | int | `24` | Auto-expire pending items after this many hours |
| `retention_days` | int | `0` | Auto-purge audit entries older than N days. `0` = keep forever |

---

## `rate_limit`

Global per-agent message rate limiting.

```yaml
rate_limit:
  per_agent: 20
  window: 60
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `per_agent` | int | `0` | Max messages per agent per window. `0` = disabled |
| `window` | int | `60` | Window size in seconds |

---

## `anomaly`

Automatic risk-based alerting and optional auto-suspension.

```yaml
anomaly:
  check_interval: 60
  risk_threshold: 50
  min_messages: 5
  auto_suspend: false
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `check_interval` | int | `60` | Seconds between anomaly checks |
| `risk_threshold` | float64 | `0` | Risk score (0-100) to trigger alert. `0` = disabled |
| `min_messages` | int | `0` | Minimum messages before evaluating risk |
| `auto_suspend` | bool | `false` | Automatically suspend agents exceeding the threshold |

---

## `rules`

Per-rule enforcement overrides. Override the default severity-based verdict for any detection rule.

```yaml
rules:
  - id: "IAP-001"
    severity: "critical"
    action: "block"
    notify: [slack-security]
    template: |
      *{{RULE}}* — {{RULE_NAME}}
      Severity: {{SEVERITY}} | Agents: {{FROM}} -> {{TO}}
      Match: `{{MATCH}}`
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Rule ID (e.g., `IAP-001`, `PI-001`) |
| `severity` | string | no | Override severity |
| `action` | string | yes | `block`, `quarantine`, `allow-and-flag`, or `ignore` |
| `notify` | []string | no | Named webhook channels or raw URLs |
| `template` | string | no | Custom webhook body template |

!!! info "Duplicate detection"
    Validation rejects configs with duplicate rule IDs in the `rules` list.

---

## `category_webhooks`

Default notification channels for all rules in a category. Rules with explicit `notify` take precedence.

```yaml
category_webhooks:
  - category: credential-leak
    notify: [slack-security]
  - category: prompt-injection
    notify: [slack-security, discord-alerts]
```

---

## `webhooks`

Named notification endpoints referenced by `notify` in rules and category webhooks.

```yaml
webhooks:
  - name: slack-security
    url: https://hooks.slack.com/services/T00/B00/xxx
    events: [blocked, quarantined]
  - name: discord-alerts
    url: https://discord.com/api/webhooks/xxx
    events: [blocked]
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | no | Friendly name for referencing in `notify` |
| `url` | string | yes | Webhook endpoint URL |
| `events` | []string | yes | Events to send: `blocked`, `quarantined`, `rejected` |

---

## Template variables

Available in `rules[].template`:

| Variable | Description |
|----------|-------------|
| `{{RULE}}` | Rule ID (e.g., `IAP-001`) |
| `{{RULE_NAME}}` | Rule name |
| `{{SEVERITY}}` | Severity level |
| `{{CATEGORY}}` | Rule category |
| `{{FROM}}` | Sender agent |
| `{{TO}}` | Recipient agent |
| `{{MATCH}}` | Matched content snippet |
| `{{ACTION}}` | Verdict taken |

---

## Validation

```bash
oktsec verify --config oktsec.yaml
```

Validation checks:

- Port in range 1-65535
- `keys_dir` set when `require_signature: true`
- `default_policy` is `allow` or `deny`
- No agent lists itself in `can_message`
- No duplicate rule overrides
- Rule actions are valid (`block`, `quarantine`, `allow-and-flag`, `ignore`)
- Gateway port valid and MCP server transports correct
- Forward proxy not enabled without domain policies (open proxy prevention)
- `max_body_size` non-negative

---

## Environment-specific examples

=== "Development"

    ```yaml
    version: "1"
    server:
      port: 8080
      log_level: debug
    identity:
      keys_dir: ./keys
      require_signature: false    # observe mode
    agents:
      my-agent:
        can_message: ["*"]
    ```

=== "Staging"

    ```yaml
    version: "1"
    server:
      port: 8080
      log_level: info
    identity:
      keys_dir: ./keys
      require_signature: true     # enforce mode
    default_policy: deny
    agents:
      coordinator:
        can_message: [researcher, coder]
        blocked_content: [credentials]
      researcher:
        can_message: [coordinator]
        allowed_tools: [read_file, search_files]
        blocked_content: [credentials, pii]
      coder:
        can_message: [coordinator]
        allowed_tools: [read_file, write_file, list_dir]
        blocked_content: [credentials]
    rate_limit:
      per_agent: 50
      window: 60
    ```

=== "Production"

    ```yaml
    version: "1"
    server:
      port: 8080
      bind: "127.0.0.1"
      log_level: warn
    identity:
      keys_dir: /etc/oktsec/keys
      require_signature: true
    default_policy: deny
    db_path: /var/lib/oktsec/oktsec.db
    agents:
      coordinator:
        can_message: [researcher, coder, reporter]
        blocked_content: [credentials, pii]
      researcher:
        can_message: [coordinator]
        allowed_tools: [read_file, search_files]
        blocked_content: [credentials, pii, exfiltration]
        egress:
          allowed_domains: [api.arxiv.org, api.semanticscholar.org]
          blocked_categories: [credentials, pii]
          rate_limit: 200
      coder:
        can_message: [coordinator]
        allowed_tools: [read_file, write_file, list_dir]
        blocked_content: [credentials, exfiltration]
        egress:
          allowed_domains: [api.github.com, registry.npmjs.org]
          rate_limit: 100
    forward_proxy:
      enabled: true
      scan_requests: true
      blocked_domains: [pastebin.com, transfer.sh, file.io]
    quarantine:
      enabled: true
      expiry_hours: 24
      retention_days: 90
    rate_limit:
      per_agent: 20
      window: 60
    anomaly:
      check_interval: 60
      risk_threshold: 70
      min_messages: 10
      auto_suspend: true
    rules:
      - id: IAP-001
        action: block
        notify: [slack-security]
      - id: IAP-003
        action: block
        notify: [slack-security]
      - id: IAP-007
        action: block
        notify: [slack-security]
    category_webhooks:
      - category: credential-leak
        notify: [slack-security]
    webhooks:
      - name: slack-security
        url: https://hooks.slack.com/services/T00/B00/xxx
        events: [blocked, quarantined]
    ```
