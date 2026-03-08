# Securing OpenClaw with Oktsec

OpenClaw agents call MCP tools, relay instructions between agents, and make autonomous decisions. Oktsec intercepts every tool call and agent message, scanning for prompt injection, credential leaks, data exfiltration, and 172 other threat patterns.

This guide gets you from zero to secured in under 5 minutes.

---

## Architecture

```
OpenClaw Agent  -->  Oktsec Gateway  -->  MCP Server(s)
                      |
                      +-- Rate limit
                      +-- Tool allowlist
                      +-- Tool policies (spending limits, rate limits)
                      +-- Content scan (175 rules)
                      +-- Audit log
                      +-- Dashboard
```

Oktsec runs as an **MCP gateway** between your OpenClaw agents and their MCP servers. Your agents connect to the gateway instead of connecting to MCP servers directly. Every tool call passes through the security pipeline.

---

## Quick setup

### 1. Install oktsec

=== "macOS / Linux"

    ```bash
    curl -fsSL https://raw.githubusercontent.com/oktsec/oktsec/main/install.sh | bash
    ```

=== "Go"

    ```bash
    go install github.com/oktsec/oktsec/cmd/oktsec@latest
    ```

=== "Docker"

    ```bash
    docker pull ghcr.io/oktsec/oktsec:latest
    ```

### 2. Create the config

Create `oktsec.yaml` in your project directory:

```yaml
version: "1"

server:
  port: 8080

identity:
  keys_dir: ./keys
  require_signature: false  # start without signatures

gateway:
  enabled: true
  port: 9090
  endpoint_path: /mcp
  scan_responses: true

# Point to your existing MCP servers
mcp_servers:
  filesystem:
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]

  # Add your other MCP servers here:
  # database:
  #   transport: stdio
  #   command: node
  #   args: ["./db-server.js"]
  #
  # github:
  #   transport: http
  #   url: https://api.github.com/mcp
  #   headers:
  #     Authorization: "Bearer ghp_xxx"

# Define your OpenClaw agents
agents:
  researcher:
    can_message: [planner]
    allowed_tools: [filesystem_read_file, filesystem_search_files]
    blocked_content: [credentials]

  coder:
    can_message: [planner, reviewer]
    allowed_tools: [filesystem_read_file, filesystem_write_file, filesystem_list_dir]
    blocked_content: [credentials, exfiltration]

  planner:
    can_message: [researcher, coder, reviewer]

  reviewer:
    can_message: [planner]
    allowed_tools: [filesystem_read_file, filesystem_search_files]
```

### 3. Start oktsec

```bash
oktsec serve
```

You'll see:

```
  oktsec proxy + gateway
  ────────────────────────────────────
  API:        http://127.0.0.1:8080/v1/message
  Gateway:    http://127.0.0.1:9090/mcp
  Dashboard:  http://127.0.0.1:8080/dashboard
  ────────────────────────────────────
  Access code:  48291057
  ────────────────────────────────────
```

### 4. Point OpenClaw to the gateway

In your OpenClaw config, replace your MCP server entries with the oktsec gateway:

=== "OpenClaw JSON config"

    ```json
    {
      "mcpServers": {
        "oktsec-gateway": {
          "url": "http://127.0.0.1:9090/mcp",
          "headers": {
            "X-Oktsec-Agent": "researcher"
          }
        }
      }
    }
    ```

    Each agent should send its name in the `X-Oktsec-Agent` header. This is how oktsec identifies which agent is making the tool call and applies the correct ACLs and tool policies.

=== "OpenClaw Python SDK"

    ```python
    from openclaw import Agent

    agent = Agent(
        name="researcher",
        mcp_servers={
            "oktsec-gateway": {
                "url": "http://127.0.0.1:9090/mcp",
                "headers": {
                    "X-Oktsec-Agent": "researcher"
                }
            }
        }
    )
    ```

=== "Environment variable"

    ```bash
    export MCP_SERVER_URL="http://127.0.0.1:9090/mcp"
    export MCP_HEADERS='{"X-Oktsec-Agent": "researcher"}'
    ```

That's it. Your OpenClaw agents now route all tool calls through oktsec.

### 5. Open the dashboard

Open `http://127.0.0.1:8080/dashboard` and enter the access code from the terminal. You'll see every tool call flowing through in real time.

---

## What gets enforced

Once connected, oktsec applies these checks to every tool call:

| Check | What happens |
|-------|-------------|
| **Rate limit** | Agent exceeding per-hour limit gets rejected |
| **Tool allowlist** | Calls to tools not in `allowed_tools` are blocked |
| **Tool policies** | Spending limits, daily caps, approval thresholds enforced |
| **Content scan** | 175 rules scan tool arguments for prompt injection, credentials, exfiltration |
| **Response scan** | Backend responses scanned before returning to agent |
| **Blocked content** | Per-agent category enforcement (e.g., block all `credentials` for researcher) |
| **Poisoned tools** | Tool descriptions scanned at startup - poisoned tools removed automatically |
| **Audit log** | Every call logged with agent, tool, verdict, latency |

---

## Per-agent tool policies

Control how much your agents can spend and how fast they can call tools:

```yaml
agents:
  shopping-agent:
    allowed_tools: [create_virtual_card, get_balance]
    tool_policies:
      create_virtual_card:
        max_amount: 100            # max $100 per call
        daily_limit: 500           # max $500/day
        require_approval_above: 50 # human review if > $50
        rate_limit: 10             # max 10 calls/hour
```

When an amount exceeds `require_approval_above`, the tool call is **quarantined** - held for human review in the dashboard. The agent sees an error; the call doesn't reach the backend until a human approves it.

---

## Multi-agent OpenClaw setup

For a typical OpenClaw multi-agent pipeline, each agent needs its own identity:

```yaml
agents:
  planner:
    can_message: [researcher, coder, reviewer]
    description: "Task decomposition and coordination"

  researcher:
    can_message: [planner]
    allowed_tools: [filesystem_read_file, filesystem_search_files, web_search]
    blocked_content: [credentials]
    description: "Web research and data gathering"

  coder:
    can_message: [planner, reviewer]
    allowed_tools: [filesystem_read_file, filesystem_write_file, filesystem_list_dir]
    blocked_content: [credentials, exfiltration, command-execution]
    description: "Code generation"

  reviewer:
    can_message: [planner]
    allowed_tools: [filesystem_read_file, filesystem_search_files]
    description: "Code review"
```

Each agent connects to the same gateway but sends a different `X-Oktsec-Agent` header:

```json
{
  "mcpServers": {
    "oktsec-gateway": {
      "url": "http://127.0.0.1:9090/mcp",
      "headers": {
        "X-Oktsec-Agent": "coder"
      }
    }
  }
}
```

Key security properties:

- **Researcher** can only read files and search - no write, no shell access
- **Coder** can read/write files but credentials and exfiltration patterns are blocked
- **Reviewer** is read-only
- **Planner** can coordinate but each subordinate agent is restricted independently
- Any agent trying to call a tool not in its allowlist gets an immediate error

---

## Deployment audit

Oktsec includes 18 security checks specifically for OpenClaw deployments:

```bash
oktsec audit --product openclaw
```

```
  OpenClaw Deployment Audit
  ─────────────────────────
  Score: 72/100 (C)

  PASS  OC-001  TLS enabled on MCP connections
  FAIL  OC-002  Default admin credentials not changed
  PASS  OC-003  Agent isolation configured
  WARN  OC-007  No rate limiting on tool calls
  ...

  18 checks · 12 pass · 4 warn · 2 fail
```

Use `--format sarif` to integrate with GitHub Actions code scanning.

---

## Observe vs enforce

By default, oktsec runs in **observe mode** - it logs everything but allows all tool calls through. This is useful for seeing what your agents do before locking things down.

When ready to enforce:

1. Review the dashboard to see which rules trigger on normal traffic
2. Adjust `allowed_tools` and `blocked_content` per agent
3. Switch to enforcement by removing `require_signature: false` or setting rule actions to `block`

```yaml
rules:
  - id: IAP-001   # relay injection
    action: block
  - id: IAP-007   # tool description injection
    action: block
  - id: CL-001    # credential leak
    action: block
```

---

## Common questions

**Do I need to change my OpenClaw code?**

No. You only change the MCP server URL your agents connect to. Point them to `http://127.0.0.1:9090/mcp` instead of the MCP servers directly. No SDK changes, no code changes.

**Does oktsec add latency?**

Content scanning takes ~8ms per tool call. Rate limiting and ACL checks are sub-microsecond. Total overhead is typically under 10ms.

**Can I use oktsec with other MCP clients at the same time?**

Yes. Run `oktsec setup` to auto-wrap Claude Desktop, Cursor, VS Code, etc. Those use stdio proxy mode. OpenClaw uses gateway mode. Both share the same dashboard and audit trail.

**What happens when a tool call is blocked?**

The agent receives a JSON-RPC error:

```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "error": {
    "code": -32600,
    "message": "blocked by oktsec: content_blocked (2 rules triggered)"
  }
}
```

The original tool call never reaches the backend MCP server.

**How do I add more MCP servers?**

Add them to `mcp_servers` in `oktsec.yaml` and restart. The gateway auto-discovers tools from all backends:

```yaml
mcp_servers:
  filesystem:
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
  slack:
    transport: http
    url: https://mcp.slack.com/v1
    headers:
      Authorization: "Bearer xoxb-xxx"
```

If two backends have a tool with the same name, oktsec namespaces them: `filesystem_read_file`, `slack_read_file`.

---

## Next steps

- [Dashboard guide](dashboard.md) - monitoring and managing security from the web UI
- [Detection rules reference](../reference/rules.md) - all 175 rules with examples
- [Per-agent egress control](egress.md) - restrict outbound HTTP traffic per agent
- [Configuration reference](../reference/configuration.md) - full YAML schema
