# Quick Start: Secure Your MCP Servers in 2 Minutes

## One-command setup

```bash
# Install
curl -fsSL https://raw.githubusercontent.com/oktsec/oktsec/main/install.sh | bash

# Setup — discovers, configures, and wraps all MCP servers
oktsec setup
```

That's it. Oktsec will:

1. Scan for all MCP clients on your machine (Claude Desktop, Cursor, VS Code, Cline, Windsurf, and 12 more)
2. Find every MCP server configured in those clients
3. Generate `oktsec.yaml` with sensible defaults (observe mode — logs everything, blocks nothing)
4. Generate Ed25519 keypairs for each agent
5. Wrap every discovered MCP server through the oktsec security proxy
6. Tell you what to do next

## What happens after setup

Restart your MCP clients (Claude Desktop, Cursor, etc.) to activate the proxy. Then start the dashboard:

```bash
oktsec serve
```

Open `http://127.0.0.1:8080/dashboard` and enter the access code shown in the terminal.

Every MCP tool call now flows through oktsec's 9-stage security pipeline with 175 detection rules — scanning for prompt injection, credential leaks, PII exposure, data exfiltration, and more.

## Watch live

```bash
oktsec logs --live
```

## Switch to enforcement mode

By default, oktsec starts in **observe mode**: it logs everything but blocks nothing. When you're ready to enforce:

```bash
oktsec wrap --all --enforce
```

Restart your MCP clients. Malicious requests will now be blocked instead of just logged.

## Undo everything

```bash
oktsec unwrap claude-desktop   # Restore one client
oktsec unwrap cursor           # Restore another
```

## Step-by-step (if you prefer control)

```bash
# 1. See what's installed
oktsec discover

# 2. Generate config and keys (no wrapping)
oktsec setup --skip-wrap

# 3. Review the generated config
cat oktsec.yaml

# 4. Wrap a specific client
oktsec wrap claude-desktop

# 5. Or wrap everything at once
oktsec wrap --all
```

## Setup flags

| Flag | Default | Description |
|------|---------|-------------|
| `--enforce` | false | Start in enforcement mode (block malicious requests) |
| `--skip-wrap` | false | Generate config only, don't modify client configs |
| `--keys` | `./keys` | Directory for generated Ed25519 keypairs |
| `--config` | `oktsec.yaml` | Output config file path |

## Supported clients

These clients can be auto-discovered and wrapped:

| Client | Wrap | Discovery |
|--------|------|-----------|
| Claude Desktop | yes | yes |
| Cursor | yes | yes |
| VS Code | yes | yes |
| Cline | yes | yes |
| Windsurf | yes | yes |
| Amp | yes | yes |
| Gemini CLI | yes | yes |
| Copilot CLI | yes | yes |
| Amazon Q | yes | yes |
| Roo Code | yes | yes |
| Kilo Code | yes | yes |
| BoltAI | yes | yes |
| JetBrains | yes | yes |
| Claude Code | discovery only | yes |
| OpenCode | discovery only | yes |
| Zed | discovery only | yes |
| OpenClaw | discovery only | yes |

Clients marked "discovery only" use non-standard config formats or protocols and cannot be auto-wrapped. Use `oktsec gateway` for those.

## Audit trail

All proxy instances and the dashboard share the same SQLite audit database at `~/.oktsec/oktsec.db`. This means:

- MCP tool calls scanned by `oktsec proxy` appear in the dashboard
- `oktsec logs` shows activity from all wrapped servers
- No data is lost between proxy restarts

## Next steps

- [Add oktsec to a multi-agent system](multi-agent-integration.md) *(coming soon)*
- [Deploy the MCP gateway for your team](gateway-setup.md) *(coming soon)*
- [Configure detection rules and enforcement](../README.md#detection-rules)
