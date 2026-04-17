# Architecture

## Overview

Oktsec is a single Go binary with no CGO dependencies. It operates in four modes, all sharing the same security pipeline.

```mermaid
graph TB
    subgraph "oktsec binary"
        serve["serve<br>(HTTP proxy)"]
        proxy["proxy<br>(stdio)"]
        gateway["gateway<br>(MCP)"]
        mcp["mcp<br>(tool server)"]
    end

    serve --> pipeline
    proxy --> pipeline
    gateway --> pipeline
    mcp --> pipeline

    subgraph pipeline["Security Pipeline"]
        direction LR
        rl[Rate Limit] --> id[Identity<br>Ed25519]
        id --> acl[ACL]
        acl --> scan[Content Scan<br>Aguara 268 rules]
        scan --> audit[(Audit Log<br>SQLite)]
    end
```

## Package layout

```
cmd/oktsec/commands/     Cobra CLI entry point
internal/
  proxy/                 HTTP proxy, stdio wrapper, forward proxy, agent CRUD API
  gateway/               MCP gateway fronting backend servers
  engine/                Aguara detection engine wrapper
  audit/                 SQLite audit trail + quarantine queue
  identity/              Ed25519 keypair management
  config/                YAML config loading/validation
  policy/                ACL evaluator
  dashboard/             HTMX web UI (server-rendered)
  mcp/                   MCP tool server (6 security tools)
  discover/              Auto-discovers MCP clients on the machine
  auditcheck/            41 deployment audit checks (SARIF output)
  graph/                 Agent topology + threat scoring
  mcputil/               Shared MCP utilities
  safefile/              SSRF/symlink-safe file I/O
rules/                   Detection rule YAML files (embedded via embed.go)
sdk/                     Go SDK client
sdk/python/              Python SDK
```

## Security pipeline detail

The pipeline in `internal/proxy/handler.go` runs checks from cheapest to most expensive. If any check fails, the message is rejected immediately — no further processing.

```mermaid
flowchart TD
    msg[Incoming Message] --> rl{Rate limit?}
    rl -->|exceeded| r429[429 Too Many Requests]
    rl -->|ok| sig{Valid signature?}
    sig -->|invalid| r403a[403 identity_rejected]
    sig -->|missing + required| r401[401 signature_required]
    sig -->|ok / not required| sus{Agent suspended?}
    sus -->|yes| r403b[403 agent_suspended]
    sus -->|no| acl{ACL allows?}
    acl -->|no| r403c[403 acl_denied]
    acl -->|yes| scan[Aguara Scan<br>268 rules]
    scan --> bc[Blocked Content<br>per-agent categories]
    bc --> split[Split Injection<br>multi-message scan]
    split --> override[Rule Overrides<br>from config]
    override --> hist[History Escalation<br>3+ blocks in 1h]
    hist --> verdict{Verdict}
    verdict -->|clean| v200[200 delivered]
    verdict -->|flag| v200f[200 content_flagged]
    verdict -->|quarantine| v202[202 quarantined]
    verdict -->|block| v403[403 content_blocked]

    scan --> audit[(Audit Log)]
    v200 --> audit
    v200f --> audit
    v202 --> audit
    v403 --> audit
    v403 --> webhook[Webhook Alert]
    v202 --> webhook
```

## Data flow by mode

### HTTP proxy (`serve`)

The main mode. Agents send JSON messages via REST API. Dashboard and agent CRUD API are co-hosted.

```mermaid
flowchart LR
    agent[Agent] -->|POST /v1/message| proxy[Oktsec Server]
    proxy --> pipeline[Security Pipeline]
    pipeline --> db[(SQLite)]
    proxy -->|/dashboard| dash[HTMX Dashboard]
    proxy -->|/v1/agents| api[Agent CRUD API]
    proxy -->|/metrics| prom[Prometheus]
```

### Stdio proxy (`proxy`)

Wraps an MCP server process. Sits between the MCP client and server, intercepting JSON-RPC 2.0 messages on stdin/stdout.

```mermaid
flowchart LR
    client[MCP Client] <-->|stdin/stdout| oktsec[oktsec proxy]
    oktsec <-->|stdin/stdout| server[MCP Server]
    oktsec --> scan[Aguara Scan]
    oktsec --> db[(Audit Log)]
```

### MCP gateway (`gateway`)

Fronts multiple backend MCP servers through a single Streamable HTTP endpoint. Auto-discovers tools from all backends.

```mermaid
flowchart LR
    agent[Agent] -->|HTTP /mcp| gw[Oktsec Gateway]
    gw --> scan[Security Pipeline]
    gw -->|stdio| fs[Filesystem Server]
    gw -->|stdio| db_srv[Database Server]
    gw -->|HTTP| gh[GitHub MCP]
    scan --> audit[(Audit Log)]
```

### Forward proxy (egress)

HTTP forward proxy for outbound agent traffic. Supports per-agent domain policies and DLP scanning.

```mermaid
flowchart LR
    agent[Agent] -->|HTTP/CONNECT| fp[Forward Proxy]
    fp --> header{X-Oktsec-Agent?}
    header -->|yes| agent_policy[Per-Agent Policy]
    header -->|no| global[Global Policy]
    agent_policy --> domain{Domain allowed?}
    global --> domain
    domain -->|no| block[403 Blocked]
    domain -->|yes| scan[Content Scan]
    scan --> internet[Internet]
    fp --> audit[(Audit Log)]
```

## Key design decisions

**No CGO**
:   All dependencies are pure Go. Cross-compilation to Linux, macOS, Windows on amd64 and arm64 works out of the box. The SQLite driver is `modernc.org/sqlite` (pure Go translation of SQLite C code).

**Official MCP SDK**
:   Uses `modelcontextprotocol/go-sdk` (Tier 1, Linux Foundation governance, semver stability). Migrated from community `mark3labs/mcp-go` for long-term support.

**Embedded rules**
:   Detection rules are compiled into the binary via `rules/embed.go`. No external files to deploy or manage. Custom rules can be loaded from a directory at runtime.

**Cheapest checks first**
:   The pipeline runs rate limiting (~1ns) before signature verification (~120us) before content scanning (~8ms). This minimizes wasted CPU on rejected messages.

**Batched audit writes**
:   The SQLite audit store batches inserts for ~90K writes/sec throughput. Queries use 24-hour time windows with covering indexes for <6ms latency at 1M+ rows.

## Performance

| Metric | Value |
|--------|-------|
| Audit write throughput | ~90K inserts/sec (batched) |
| Handler throughput (clean) | ~52 msg/sec per core |
| Handler throughput (malicious) | ~127 msg/sec per core |
| Signature verification | ~120us |
| Query latency at 1M rows | <6ms |
| Binary size | ~30 MB |
| Memory at idle | ~25 MB |
