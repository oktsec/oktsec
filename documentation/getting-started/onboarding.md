# Onboarding Flow

## Discover

Scans your machine for MCP server configurations, OpenClaw, and NanoClaw installations:

```bash
oktsec discover
```

Output:

```
Found 2 MCP configuration(s):

  Cursor  /home/user/.cursor/mcp.json
    +-- filesystem           npx -y @mcp/server-filesystem /data
    +-- database             node ./db-server.js
    +-- github               npx -y @mcp/server-github

  Claude Desktop  /home/user/.config/claude/claude_desktop_config.json
    +-- filesystem           npx -y @mcp/server-filesystem /data

Total: 4 MCP servers across 2 clients
```

Supported clients: Claude Desktop, Cursor, VS Code, Cline, Windsurf, Amp, Gemini CLI, Copilot CLI, Amazon Q, Roo Code, Kilo Code, BoltAI, JetBrains.

## Init

Auto-generates `oktsec.yaml` and Ed25519 keypairs for each discovered server:

```bash
oktsec init
oktsec init --keys ./keys --config ./oktsec.yaml
```

Each server is auto-classified by risk level:

- **Critical** — database, postgres, mysql, sqlite, mongo, redis
- **High** — filesystem, git, github, browser, puppeteer, playwright
- **Medium** — slack, discord, email, messaging
- **Unknown** — everything else (defaults to observe)

## Wrap / Unwrap

Modifies MCP client configs to route server traffic through `oktsec proxy`:

```bash
oktsec wrap cursor                # Observe mode (log only)
oktsec wrap --enforce cursor      # Enforcement mode (block malicious)
oktsec wrap --all                 # Wrap all discovered clients
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

!!! note
    Restart your MCP clients (Claude Desktop, Cursor, etc.) after wrapping to activate the proxy.

## Stdio Proxy

The `proxy` command wraps an MCP server process, intercepting its JSON-RPC 2.0 stdio traffic:

```bash
oktsec proxy --agent filesystem -- npx @mcp/server-filesystem /data
oktsec proxy --enforce --agent database -- node ./db-server.js
```

In **observe mode** (default), all messages are forwarded regardless of scan results. In **enforcement mode** (`--enforce`), blocked requests return a JSON-RPC error:

```json
{"jsonrpc":"2.0","id":42,"error":{"code":-32600,"message":"blocked by oktsec: IAP-001"}}
```

## Tool Allowlist

When `allowed_tools` is set for an agent, only listed MCP tools are permitted:

```yaml
agents:
  filesystem:
    allowed_tools: ["read_file", "list_dir", "search_files"]
```

Any unlisted tool is blocked with a JSON-RPC error. Empty list means all tools are allowed.
