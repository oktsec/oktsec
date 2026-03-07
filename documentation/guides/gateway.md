# MCP Gateway

Oktsec can run as a **Streamable HTTP MCP gateway** that fronts one or more backend MCP servers, intercepting every `tools/call` with the full security pipeline.

```
Agent  -->  Oktsec Gateway  -->  Backend MCP Server(s)
             |
             +-- Rate limit
             +-- Agent ACL check
             +-- Content scan (175 rules)
             +-- Rule overrides
             +-- Verdict (allow/block/quarantine)
             +-- Audit log
             +-- Webhook notification
```

## Setup

```bash
oktsec gateway --config ./oktsec.yaml
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
    headers:
      Authorization: "Bearer ghp_xxx"
```

## Features

### Tool discovery

The gateway automatically discovers and exposes tools from all backends. When a client connects, it sees a unified list of all available tools.

### Tool namespacing

If two backends expose a tool with the same name, the gateway prefixes with the backend name: `backend_toolname`.

### Per-agent tool allowlists

Restrict which tools each agent can access:

```yaml
agents:
  researcher:
    allowed_tools: ["filesystem_read_file", "filesystem_search_files"]
  admin:
    allowed_tools: []  # empty = all tools allowed
```

### Response scanning

With `scan_responses: true`, the gateway also scans what backends return before passing it back to the agent.

### Auto-port

If the configured gateway port is busy, it falls back to adjacent ports (up to +10).

## Transport types

### stdio

Launches the MCP server as a subprocess:

```yaml
mcp_servers:
  filesystem:
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    env:
      NODE_ENV: production
```

### http

Connects to a remote MCP server over HTTP:

```yaml
mcp_servers:
  remote:
    transport: http
    url: https://mcp.example.com/v1
    headers:
      Authorization: "Bearer token"
```

## Dashboard integration

When running `oktsec serve` with `gateway.enabled: true`, the gateway is managed from the dashboard. You can create, edit, delete, and monitor backend MCP servers from the Gateway page.
