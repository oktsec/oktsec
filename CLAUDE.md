# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Oktsec is a security proxy and MCP gateway for AI agent-to-agent communication. Single Go binary, no LLM, deterministic. It intercepts messages and MCP tool calls, running them through a security pipeline: rate limit -> identity verification (Ed25519) -> suspension check -> ACL check -> content scan (175 rules via Aguara engine) -> blocked content filter -> verdict escalation -> audit log -> anomaly detection.

Verdicts: `clean` (deliver), `flag` (deliver + warn), `quarantine` (hold for human), `block` (reject).

Four operational modes: HTTP proxy server (`serve`), stdio proxy (`proxy`), MCP gateway (`gateway`), MCP tool server (`mcp`).

## Build & Development Commands

```bash
make build                                   # Build binary with version injection
make test                                    # All tests, race detector enabled
make lint                                    # golangci-lint v2
make vet                                     # go vet
make fmt                                     # gofmt
go test -race -count=1 ./internal/audit/     # Single package
go test -v -race -count=1 ./internal/proxy/  # Single package, verbose
make integration-test                        # Integration tests (proxy package, -tags=integration)
make bench                                   # Scaling benchmark (cmd/bench)
make run ARGS="serve"                        # Run with args
```

Pre-PR checklist: `make build && make test && make lint && make vet`

## Architecture

### Package Layout

- **`cmd/oktsec/commands/`** -- Cobra CLI commands. `root.go` is the entry point. Each file is one command (serve, gateway, proxy, keygen, audit, etc.).
- **`internal/proxy/`** -- Core HTTP proxy server and stdio wrapper. `handler.go` implements the full security pipeline. `stdio.go` intercepts JSON-RPC 2.0 traffic for MCP servers. `forward.go` handles CONNECT tunneling for Docker Sandbox integration. `middleware.go` sets security headers (CSP, X-Frame-Options, etc.).
- **`internal/gateway/`** -- MCP gateway that fronts multiple backend MCP servers. Auto-discovers tools from backends, applies per-agent tool allowlists, namespaces conflicting tool names. `verdict.go` has shared verdict helpers.
- **`internal/engine/`** -- Wraps the Aguara detection engine. `scanner.go` runs content scanning and redacts credentials from findings. Thread-safe with mutex-protected cache.
- **`internal/audit/`** -- SQLite-backed audit trail and quarantine queue. Batched writes (~90K inserts/sec). Supports time-windowed analytics.
- **`internal/identity/`** -- Ed25519 keypair management. PEM format with type `OKTSEC ED25519 PRIVATE KEY`. Canonical signing payload: `from\nto\ncontent\ntimestamp`. `keystore.go` manages runtime key loading with hot-reload via SIGHUP.
- **`internal/config/`** -- YAML config loading/validation. Config file: `oktsec.yaml`.
- **`internal/policy/`** -- ACL evaluator: can sender message recipient? Supports default-deny.
- **`internal/dashboard/`** -- Web UI with HTMX. Server-rendered templates. `handlers.go` and `templates.go` are large generated files. Auth via access codes. Self-hosted assets (no external CDN).
- **`internal/mcp/`** -- MCP tool server exposing 6 security tools (scan_message, list_agents, audit_query, etc.).
- **`internal/discover/`** -- Auto-discovers MCP server configs from 17 clients (Claude Desktop, Cursor, VS Code, Cline, Windsurf, Amp, Gemini CLI, etc.).
- **`internal/auditcheck/`** -- 41 deployment security audit checks (oktsec, OpenClaw, NanoClaw) with remediation guidance. SARIF output support.
- **`internal/graph/`** -- Agent communication topology, threat scoring via betweenness centrality.
- **`internal/mcputil/`** -- MCP utilities and helpers shared between gateway and proxy.
- **`internal/safefile/`** -- Secure file I/O (SSRF, symlink, file-size hardening).
- **`rules/`** -- Detection rule YAML files embedded via `embed.go`. `default.yaml` (148 Aguara rules), `openclaw.yaml` (15 rules). Inter-agent rules use `IAP-` prefix.
- **`sdk/`** -- Go SDK (`sdk/client.go`) and Python SDK (`sdk/python/`). Python SDK uses hatchling build system.

### Key Design Constraints

- **No CGO** -- All dependencies are pure Go for clean cross-compilation.
- **Official MCP SDK** -- Uses `modelcontextprotocol/go-sdk` (migrated from community `mark3labs/mcp-go`).
- **Embedded rules** -- Detection rules are embedded in the binary via `rules/embed.go`.
- **Dashboard templates** -- `internal/dashboard/templates.go` is auto-generated (~153KB). Don't edit manually; edit the template source.
- **Self-hosted dashboard assets** -- All CSS, JS (htmx), and fonts are served from the binary. No external CDN references in CSP.

### Security Pipeline Flow (handler.go)

The pipeline in `internal/proxy/handler.go` runs checks from cheapest to most expensive:
1. Rate limit check (in-memory sliding window)
2. Identity verification (Ed25519 signature)
3. Agent suspension check
4. ACL evaluation
5. Content scan (Aguara engine, 175 rules)
6. Blocked content filter (per-agent category enforcement)
7. Verdict escalation (history-based: 3+ blocks in 1h -> escalate)
8. Audit log write
9. Anomaly detection (background scoring)

### Adding Detection Rules

Add rules to `rules/default.yaml` following the Aguara YAML schema. Use `IAP-` prefix for inter-agent rules. Include `true_positive` and `false_positive` examples.

## Testing Patterns

- **Unit tests** use `_test.go` suffix in the same package. Test files named `coverage_test.go` contain supplementary coverage tests.
- **Integration tests** use `-tags=integration` build tag (proxy package).
- Dashboard tests are the slowest (~90s with race detector) due to template parsing per test.
- Gateway lifecycle functions (NewGateway, Start, Shutdown) require real MCP connections -- hard to unit test. Coverage gap documented in `DOCS/engineering/next-steps-post-v0.8.md`.
- Use `newGatewayForTest()` or `newTestGateway()` helpers instead of `NewGateway()` in gateway tests.
- Dashboard routes use Go 1.22+ ServeMux patterns (`GET /dashboard/rules/{category}`, `POST /dashboard/api/rule/{id}/toggle`).
- Quarantine HTTP status is 202 (Accepted), not 200.
- `parseExportLimit` max is 50000.

## Internal Docs

Internal development docs live in `DOCS/` (gitignored). Structure:
- `DOCS/strategy/` -- Business strategy, gateway design, investor materials
- `DOCS/product/` -- Product status reports, quick-start guide
- `DOCS/engineering/` -- Quality audits, roadmap, next steps

## Current State (v0.8.0)

- **30K LOC Go** | ~400 tests | 21 packages | 38 PRs merged
- **175 detection rules** (148 Aguara + 15 OpenClaw + 12 inter-agent)
- **Python SDK** in `sdk/python/` (hatchling, not yet published to PyPI)
- **Prometheus metrics** at `/metrics` (6 metric families)
- **17 MCP client** auto-discovery, 13 wrappable
- **CODEOWNERS** at `.github/CODEOWNERS`
- **CSP header** -- self-only policy, no external domains


## Communication Rules
- Never include `Co-Authored-By: Claude` in commits to this repository.
- Never include "Generated with Claude Code" in PR descriptions.
- Never use em dashes (-) in LinkedIn posts or external communications. Use hyphens (-) instead.
- All commits and PRs are authored entirely under garagon's name.
