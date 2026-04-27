<h1 align="center">Oktsec</h1>

<p align="center">
  <strong>Runtime security for AI agents.</strong>
</p>

<p align="center">
  Oktsec runs locally between AI agents and the tools they execute. For surfaces routed through it — MCP calls, shell/file/browser actions, agent-to-agent messages, and outbound requests — Oktsec applies policy before those actions become production changes.
</p>

<p align="center">
  <a href="https://github.com/oktsec/oktsec/actions/workflows/ci.yml"><img src="https://github.com/oktsec/oktsec/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://goreportcard.com/report/github.com/oktsec/oktsec"><img src="https://goreportcard.com/badge/github.com/oktsec/oktsec" alt="Go Report Card"></a>
  <a href="https://pkg.go.dev/github.com/oktsec/oktsec"><img src="https://pkg.go.dev/badge/github.com/oktsec/oktsec.svg" alt="Go Reference"></a>
  <a href="https://github.com/oktsec/oktsec/releases"><img src="https://img.shields.io/github/v/release/oktsec/oktsec" alt="GitHub Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#why-oktsec">Why Oktsec</a> &middot;
  <a href="#how-it-works">Architecture</a> &middot;
  <a href="#dashboard">Dashboard</a> &middot;
  <a href="#how-it-compares">Compare</a> &middot;
  <a href="https://oktsec.com/docs">Docs</a>
</p>

---

<p align="center">
  <img src="documentation/assets/screenshots/dashboard-overview.png" alt="Oktsec dashboard - Overview" width="820">
</p>

---

- **See** every tool call routed through Oktsec in a real-time dashboard.
- **Control** which agents can call which tools and services.
- **Block or quarantine** risky actions before execution.
- **Prove what happened** with tamper-evident, hash-chained audit logs.
- **Keep it local**: one Go binary, no cloud dependency, Apache 2.0.

Latest: v0.15 adds tamper-evident audit chain v2, Redis-backed distributed rate limiting, key rotation with version pinning, and OpenTelemetry tracing. See [CHANGELOG](CHANGELOG.md).

## Quick start

```bash
# Install
curl -fsSL https://raw.githubusercontent.com/oktsec/oktsec/main/install.sh | bash

# Or inspect the script first
curl -fsSL https://raw.githubusercontent.com/oktsec/oktsec/main/install.sh -o install.sh
less install.sh && sh install.sh

# Or build from source (Go 1.25+)
go install github.com/oktsec/oktsec/cmd/oktsec@latest
```

```bash
# Start
oktsec run
```

Open `http://127.0.0.1:8080/dashboard` with the access code printed in your terminal.

**What `oktsec run` does:**

- Discovers local AI/MCP clients (Claude Desktop, Cursor, VS Code, Claude Code, etc.)
- Writes config under `~/.oktsec/`
- Creates Ed25519 keypairs for each discovered server
- Starts in **observe mode** by default (logs routed activity, blocks nothing)
- Shows a local dashboard with an access code
- Does not send message content, keys, or audit logs to Oktsec
- Can be reverted with `oktsec unwrap <client>`

To enable **enforcement mode** (block risky tool calls):

```bash
oktsec run --enforce
```

Check deployment health:

```bash
oktsec doctor
```

Local-first. No message content leaves your machine. Anonymous install telemetry (version + OS + arch, no user data) can be disabled with `OKTSEC_NO_TELEMETRY=1` or `telemetry.disabled: true` in config.

## Why Oktsec

AI agents don't just chat. They run shells, write to disks, transfer funds, hit internal APIs and spawn sub-agents. Every tool call can become a production action when agents can read files, write code, call APIs, or run commands — and most stacks have no default oversight: no rate limit on how fast Claude can `rm -rf`, no signature on who issued the command, no audit trail that survives a tampered log, no backpressure when prompt injection slips through.

Traditional security tools sit at the network edge (WAFs) or the model boundary (prompt classifiers). Neither sees the agent-to-tool decision point where actual actions happen. Oktsec runs in that path.

**Why now:**

- AI agents are moving from chat to tool execution.
- MCP standardizes tool access across clients.
- Developers are exposing filesystem, shell, browser and internal APIs to agents.
- Existing security sits at network/prompt boundaries, not agent-to-tool runtime.

## Who uses Oktsec

- **Developers** running Claude Desktop, Cursor, Claude Code or MCP servers locally.
- **Security teams** that need visibility into AI agent tool calls before allowing them on work machines.
- **Platform teams** exposing internal APIs, databases or filesystem tools to agents.
- **Agent framework builders** that need signed agent-to-agent communication and audit logs.

### Common use cases

- Observe every tool call routed through Oktsec from Claude Code, Cursor or Claude Desktop.
- Block shell, file and network actions that match risky patterns.
- Audit which agent accessed which tool and why.
- Add policy before exposing internal MCP servers to agents.
- Keep AI agent security local and self-hosted.

### Choose your path

| Role | Start here |
|------|-----------|
| Local developer | `oktsec run` |
| Security team | `oktsec audit` then `oktsec run --enforce` |
| MCP platform | Configure `gateway.enabled: true` |
| Agent-to-agent systems | Use `/v1/message` with Ed25519 signing |

## Threat model

Oktsec assumes agent inputs are untrusted. A malicious webpage, email, Slack message, tool description, MCP server or sub-agent can try to make an agent execute a risky action. Oktsec intercepts at the moment an agent tries to use a tool.

| Mode | What happens | Use when |
|------|-------------|----------|
| Observe | Log and alert, do not block | First install, tuning |
| Enforce | Block/quarantine risky calls | Production protection |

### What Oktsec is not

- Not an LLM firewall for prompts alone.
- Not a replacement for OS sandboxing, EDR or cloud IAM.
- Not a SaaS proxy; it runs locally by default.
- Not an autonomous decision-maker; LLM analysis is async and human-reviewed.

### Data handling

Oktsec stores data locally in SQLite under `~/.oktsec/`. No message content, keys or audit logs are sent to Oktsec. Optional LLM analysis sends selected cases only to the provider you configure.

## How it works

Every message and tool call routed through Oktsec passes through a deterministic 10-stage security pipeline:

1. **Rate limiting** - Per-agent sliding-window throttling prevents flooding.
2. **Identity** - Ed25519 signatures verify every message sender.
3. **Agent suspension** - Suspended agents are immediately rejected.
4. **Policy** - YAML ACLs control which agent can reach which. Default-deny mode available.
5. **Content scanning** - 268 detection rules catch prompt injection, credential leaks, PII, exfiltration, MCP attacks, tool-call threats, and supply chain risks.
6. **Intent validation** - Declared intent vs actual content alignment check.
7. **Blocked content** - Per-agent category-based content blocking.
8. **Multi-message escalation** - Repeated blocks escalate verdicts automatically.
9. **Audit** - Hash-chained log with Ed25519 proxy signatures for tamper evidence.
10. **Anomaly detection** - Background risk scoring with alerts and optional auto-suspension.

```
Agent A -> sign -> POST /v1/message -> [Oktsec] -> rate limit -> verify -> suspend -> ACL -> scan -> intent -> blocked content -> escalation -> deliver/block/quarantine -> audit -> anomaly
```

No LLM on the hot path. Every verdict is deterministic.

### Supported clients

Auto-discovers MCP server configurations from **17 clients**:

| Client | Protocol | Notes |
|--------|----------|-------|
| Claude Desktop | MCP (stdio) | Wrap + scan |
| Cursor | MCP (stdio) | Wrap + scan |
| VS Code | MCP (stdio) | Wrap + scan |
| Cline | MCP (stdio) | Wrap + scan |
| Windsurf | MCP (stdio) | Wrap + scan |
| Claude Code | MCP (gateway) + hooks | Gateway routing + tool-call interception |
| Zed | MCP (stdio) | Wrap + scan |
| Amp | MCP (stdio) | Wrap + scan |
| Gemini CLI | MCP (stdio) | Wrap + scan |
| Copilot CLI | MCP (stdio) | Wrap + scan |
| Amazon Q | MCP (stdio) | Wrap + scan |
| Roo Code | MCP (stdio) | Wrap + scan |
| Kilo Code | MCP (stdio) | Wrap + scan |
| BoltAI | MCP (stdio) | Wrap + scan |
| JetBrains | MCP (stdio) | Wrap + scan |
| OpenCode | MCP (stdio) | Wrap + scan |
| OpenClaw | WebSocket | Scan only ([details](#openclaw-support)) |

Additionally detects and audits [NanoClaw](#nanoclaw-support) mount allowlist configurations.

## Hooks

For clients with configured HTTP hooks, Oktsec can receive pre-action events for supported tools such as `Read`, `Write`, `Bash`, `WebSearch`, and `Edit`. Pre-action hook events are scanned through the full security pipeline (current release: 268 detection rules) before execution. Post-action events provide observed audit evidence after the action.

```
Claude Code (configured tool call)
    |
    +-- PreToolUse  -> POST /hooks/event -> security pipeline -> allow/block
    |
    +-- Tool executes (if allowed)
    |
    +-- PostToolUse -> POST /hooks/event -> audit log (observed)
```

`oktsec run` configures supported Claude Code hooks automatically. Other clients must expose compatible hooks and be pointed at `POST http://127.0.0.1:9090/hooks/event`.

MCP stdio wrapping intercepts only MCP tool calls. Hooks can cover client-exposed file, shell, web, edit, and agent tools when the client emits compatible hook events; coverage depends on which hooks the client actually fires and how the operator configures them.

## MCP gateway

Streamable HTTP MCP gateway that fronts one or more backend MCP servers, intercepting every `tools/call` with the full security pipeline. Built on the [official MCP SDK](https://github.com/modelcontextprotocol/go-sdk) (v1, Tier 1).

```
Agent  ->  Oktsec Gateway  ->  Backend MCP Server(s)
             |
             +- Rate limit, ACL, content scan
             +- Tool policies (spend limits, rate limits, approval)
             +- Verdict (allow/block/quarantine)
             +- Audit log + webhook notification
```

```yaml
gateway:
  enabled: true
  port: 9090
  scan_responses: true

mcp_servers:
  filesystem:
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
  github:
    transport: http
    url: https://api.github.com/mcp
```

Features: tool discovery, tool namespacing, per-agent tool allowlists, per-tool policies (spending limits, rate limits, approval thresholds), response scanning, auto-port fallback, and embedded mode via `oktsec run`.

### Tool policies

```yaml
agents:
  finance-agent:
    tool_policies:
      create_payment:
        max_amount: 10000
        daily_limit: 50000
        require_approval_above: 5000
        rate_limit: 10     # max calls per minute
```

### Egress policies

Control outbound network access per agent and per tool:

```yaml
agents:
  research-agent:
    egress:
      integrations: ["github", "slack"]    # 16 built-in presets
      allowed_domains: ["arxiv.org"]
      blocked_domains: ["evil.com"]
      tool_restrictions:
        WebFetch: ["arxiv.org", "api.github.com"]
        Bash: []                             # No egress for Bash
```

## Dashboard

Real-time web UI for monitoring agent activity. Protected by a GitHub-style local access code.

<p align="center">
  <img src="documentation/assets/screenshots/dashboard-events.png" alt="Events - live feed of agent messages and tool calls" width="820">
</p>

**11 primary pages:** Overview (hero stats, pipeline health, coverage matrix, live feed), Events (audit log with search and quarantine tab), Sessions (session inventory and trace timeline), Notifications (webhook CRUD, alert history), Agents (card grid with risk scores, agent detail with tool policies), Rules (268 rules across categories, per-rule overrides, custom rules, LLM-suggested rules), Security Posture (deployment audit, health score, SARIF export), AI Analysis (async LLM cases, triage config, budget tracking), Graph (agent topology with threat scoring), Gateway (backend CRUD, tool discovery, health checks), Settings (security mode, protection config, rate limiting). Drill-down routes include rule detail, session detail, custom rules, category detail, and coverage activity drawers.

### What you see after five minutes

- Which agents are active and what tools they called.
- Which detection rules fired and what was blocked or quarantined.
- Agent risk scores based on communication patterns.
- Audit chain integrity verification.
- Session traces with AI-powered threat analysis.

### Quarantine queue

Messages triggering high-severity rules are held for human review. Quarantined messages return HTTP 202 with a `quarantine_id`. Reviewers can approve or reject from the dashboard, CLI, or MCP tool. Items auto-expire after a configurable period.

## Detection rules

<p align="center">
  <img src="documentation/assets/screenshots/dashboard-rules.png" alt="Rules catalog - detection rules across categories" width="820">
</p>

Current release: **268 detection rules** across categories:

| Source | Count | Categories |
|--------|-------|------------|
| [Aguara](https://github.com/garagon/aguara) built-in | 189 | prompt-injection, credential-leak, exfiltration, command-execution, mcp-attack, mcp-config, supply-chain, supply-chain-exfil, ssrf-cloud, indirect-injection, unicode-attack, third-party-content, external-download |
| Inter-agent protocol (IAP) | 17 | inter-agent (includes CVE exploit transfer) |
| IPI Arena (IPI) | 13 | inter-agent (from [arXiv:2603.15714](https://arxiv.org/abs/2603.15714)) |
| Container escape (CE) | 12 | container-escape (from [SandboxEscapeBench](https://arxiv.org/abs/2603.02277)) |
| Tool-call (TC) | 11 | tool-call (path traversal, shell injection, persistence) |
| Memory poisoning (MEM) | 8 | memory-poisoning (dotfile writes, settings hijack, alias injection) |
| Overeager detection (OE) | 3 | overeager (credential exploration, safety bypass) |
| OpenClaw (OCLAW) | 15 | openclaw-config |

```bash
oktsec rules                     # List all 268 rules
oktsec rules --explain CE-004    # Explain any rule
```

## Threat intel

Optional async LLM analysis layer. Connects to any provider: Claude, OpenAI, Gemini, Ollama, OpenRouter, Groq, Together, or any OpenAI-compatible endpoint.

When the pipeline detects something suspicious, the triage module samples the case for background analysis. The LLM generates an investigation case for human review. If confirmed, it proposes a detection rule for approval.

**Never blocks, never makes verdict decisions.** The deterministic pipeline handles all real-time decisions. The LLM layer only generates investigation cases for human review.

## Agent identity

Every agent gets an Ed25519 keypair. The proxy verifies signatures covering `from + to + content + timestamp`. Signing is ~50us, verification is ~120us.

```bash
oktsec keygen --agent my-agent --out ./keys/
oktsec keys list                                # List all registered keypairs
oktsec keys rotate --agent my-agent             # Generate new keypair, revoke old
```

Set `require_signature: false` to deploy as a content scanner first. Enable signatures when ready.

## Deployment audit

49 checks across Oktsec (18), OpenClaw (18), NanoClaw (7), and MCP servers (6). Outputs a health score with remediation guidance.

```bash
oktsec audit
oktsec audit --sarif    # SARIF v2.1.0 for CI integration
```

```
Deployment Security Audit
=========================

  Health Score: 72 / 100 (Grade: C)

  Oktsec (18 checks)
  ------------------
  [CRITICAL] require_signature is false
             Fix: Set identity.require_signature: true in oktsec.yaml

  Summary: 2 critical, 3 high, 1 medium, 43 passed
```

## Observability

Prometheus metrics at `GET /metrics` (messages, latency, rules triggered, LLM usage, budget tracking). SARIF export for CI integration. CSV/JSON export from the dashboard.

## OpenClaw support

[OpenClaw](https://github.com/openclaw/openclaw) is a popular AI agent platform that gives agents access to filesystem, shell, email, calendar, browser, and messaging channels. It does not use MCP - it has its own WebSocket gateway. Oktsec detects, parses, and analyzes OpenClaw installations with a dedicated scanner and 15 detection rules.

```bash
oktsec scan-openclaw
```

## NanoClaw support

[NanoClaw](https://github.com/nanoclaw/nanoclaw) is a lightweight agent platform focused on filesystem access. Oktsec auto-detects installations and audits them with 7 checks covering mount allowlists, write permissions, and sensitive paths.

## Configuration

Config resolution: `--config` flag, `$OKTSEC_CONFIG`, `./oktsec.yaml`, `~/.oktsec/config.yaml`.

```yaml
version: "1"

server:
  port: 8080
  bind: 127.0.0.1

identity:
  keys_dir: ./keys
  require_signature: true

default_policy: deny    # recommended for enforcement

agents:
  research-agent:
    can_message: [analysis-agent]
    blocked_content: [credentials, pii]
    allowed_tools: [read_file, search]
    tool_policies:
      create_payment:
        max_amount: 10000
        require_approval_above: 5000
```

Validate: `oktsec verify --config oktsec.yaml`

Full configuration reference in the [docs](https://oktsec.com/docs/configuration).

## SDKs

### Go

```go
import "github.com/oktsec/oktsec/sdk"

c := sdk.NewClient("http://localhost:8080", "my-agent", nil)
resp, err := c.SendMessage(ctx, "recipient", "hello")
```

Install: `go get github.com/oktsec/oktsec/sdk`

### Python

Published on [PyPI](https://pypi.org/project/oktsec/) as `oktsec`:

```bash
pip install oktsec
```

```python
from oktsec import OktsecClient

client = OktsecClient("http://localhost:8080", "my-agent")
resp = await client.send_message("recipient", "hello")
```

## OWASP Agentic Top 10

| # | Category | How Oktsec covers it |
|---|----------|-----|
| ASI01 | Excessive Agency / Goal Hijack | Multi-message escalation, content scanning, intent validation, LLM triage |
| ASI02 | Tool Misuse | Stdio enforcement, per-agent content blocking, rate limiting, tool-call rules, tool policies |
| ASI03 | Privilege Escalation | Ed25519 identity, default-deny policy, ACLs, per-agent tool allowlists |
| ASI04 | Supply Chain | Dependency auditing (OSV.dev), egress sandboxing, rug-pull detection |
| ASI05 | Unsafe Code Execution | Stdio enforcement, tool-call rules (TC-001 to TC-011), hooks interception |
| ASI07 | Inter-Agent Communication | Signed messages, ACLs, content scanning, hash-chained audit trail, graph analysis |
| ASI10 | Rogue Agents | Agent suspension, rate limiting, anomaly detection, auto-suspend |

## How it compares

Oktsec lives at the **runtime execution layer** - the tool calls and messages agents emit *while* they run. Adjacent projects protect different layers.

| Capability | Oktsec | Prompt classifiers (Lakera, PromptArmor) | WAFs (Cloudflare, AWS) |
|---|---|---|---|
| Agent-to-agent message control | Yes | No | No |
| MCP tool-call interception | 10-stage pipeline | No | No |
| Deterministic hot path (no LLM) | Yes | LLM-based | Regex |
| Ed25519 identity + tamper-evident audit | Yes | No | No |
| On-prem single binary (Apache 2.0) | Yes | SaaS | SaaS |

**Different layer, complementary.** A typical deployment runs a WAF at the edge, a prompt classifier at the LLM boundary, and Oktsec at the agent-to-tool boundary where actual actions happen.

## Recommended rollout

1. Run in observe mode for one day.
2. Review Events and Security Posture in the dashboard.
3. Add agent and tool allowlists.
4. Enable enforce mode for high-risk tools.
5. Export audit/SARIF into your security workflow.

## Built on

- **[Aguara](https://github.com/garagon/aguara)** - Security scanner for AI agent skills and supply chain threats (189 detection rules)
- **[MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk)** - Official Tier 1 Go SDK for Model Context Protocol
- **Go stdlib** - `crypto/ed25519`, `net/http`, `log/slog`, `crypto/sha256`
- **[modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite)** - Pure Go SQLite (no CGO)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and pull request process.

For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## Get in touch

- **Star this repo** if agent security matters to your team.
- **Production deployment / enterprise questions**: gus@oktsec.com
- **Security disclosure**: see [SECURITY.md](SECURITY.md)
- **Issues & feature requests**: [GitHub Issues](https://github.com/oktsec/oktsec/issues)

## License

Apache License 2.0. See [LICENSE](LICENSE).
