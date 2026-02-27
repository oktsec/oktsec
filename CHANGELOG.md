# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- **MCP gateway mode**: Streamable HTTP MCP gateway that fronts backend MCP servers, intercepting every `tools/call` with the full security pipeline. Supports stdio and HTTP backend transports, tool discovery, automatic namespacing, per-agent tool allowlists, response scanning, and auto-port fallback. New `oktsec gateway` command.

### Changed

- **MCP SDK migration**: Replaced `mark3labs/mcp-go` (community, v0.44) with `modelcontextprotocol/go-sdk` (official Tier 1, v1.4.0). All MCP server, client, and transport code now uses the official SDK with semver stability guarantees and Linux Foundation governance.
- **Documentation**: Added MCP gateway section to README, updated dependency references, added gateway configuration examples.

## [0.5.0] - 2026-02-24

### Added

- **Policy as code**: Per-rule action overrides in `oktsec.yaml`. Configure `block`, `quarantine`, `allow-and-flag`, or `ignore` per rule ID. Per-rule webhook notifications with configurable URLs. Plain-text webhook templates with tag substitution (`{{RULE}}`, `{{SEVERITY}}`, `{{FROM}}`, `{{TO}}`, etc.) — system wraps in Slack-compatible JSON automatically. Dashboard enforcement tab with create/edit/delete, rule descriptions, expandable webhook and template previews.
- **HTTP forward proxy**: New `forward_proxy` mode for Docker Sandbox integration. Supports HTTP CONNECT tunneling so containerized agents route traffic through oktsec for scanning.
- **OpenClaw security rules OCLAW-008 to OCLAW-015**: Sandbox disabled, path traversal in mounts, missing auth on gateway, hardcoded credentials in env, gateway exposed without TLS, open DM with external agents, exec without resource limits, UI proxy without auth. Plus `ScanContentAs()` API for scanning content as a specific agent identity.
- **`oktsec audit` command**: 41-check deployment security auditor covering Oktsec (16 checks), OpenClaw (18 checks), and NanoClaw (7 checks). Health score with A-F grading, severity breakdown, actionable remediation commands. SARIF output (`--format sarif`) for GitHub code scanning integration.
- **`oktsec status` command**: One-line health score + top 3 issues for quick checks.
- **`internal/auditcheck` package**: Extracted audit checks from CLI into a shared library used by both CLI and dashboard. Finding enrichment with `ConfigPath` and `Remediation` fields.
- **Dashboard audit page**: Redesigned with stat strip (score/grade, severity breakdown), critical alert strip, per-product cards with icon/config/docs, expandable findings with inline remediation, and copy-to-clipboard.
- **Dashboard security hardening**: Session cookie `SameSite=Strict`, `HttpOnly`, `Secure` flags. CSRF protection on state-changing routes. X-Frame-Options and X-Content-Type-Options headers.
- **Audit store test coverage**: 9 new test functions covering key revocation, query stats, hourly stats, top rules, edge rules, agent risk scoring, quarantine lifecycle, hub broadcast.
- **Package documentation**: godoc-compliant package doc comments on all 9 internal packages.

### Changed

- **Dashboard CSS**: Severity labels simplified to text-only. Button glow effects removed. Card border-radius standardized to 10px.
- **CI pipeline**: Added `make integration-test` step to GitHub Actions workflow.
- **Detection rules**: 159 total (138 Aguara + 6 IAP + 15 OpenClaw).
- CLI `audit` and `status` commands now delegate to `internal/auditcheck` instead of inline check functions.

### Fixed

- **Forward proxy**: Wrapper applied outside middleware chain to prevent hijack conflicts with dashboard routes.

## [0.4.1] - 2026-02-23

### Added

- **Per-agent tool allowlist**: New `allowed_tools` config field restricts which MCP tools an agent can invoke via `tools/call` requests in the stdio proxy. Unlisted tools are blocked with a JSON-RPC error. Empty list means all tools allowed (ASI05).
- **MCP tool tests**: 19 tests covering all 6 MCP tools (`scan_message`, `list_agents`, `audit_query`, `get_policy`, `verify_agent`, `review_quarantine`).
- Documented tool allowlist in AGENTS.md with config example and JSON-RPC error format.

### Fixed

- **Flaky SQLITE_BUSY in tests**: Replaced `time.Sleep` with deterministic `Store.Flush()` that waits for async write channel to drain. Fixes intermittent CI failures on slow runners.

---

## [0.4.0] - 2026-02-23

OWASP agentic hardening release. Aligned with [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/). All changes are backward-compatible.

### Added

- **Default-deny policy**: New `default_policy: deny` config option rejects messages from unknown senders not listed in the agents map. Defaults to `allow` for backward compatibility (ASI03).
- **Agent suspension**: Agents can be suspended via CLI (`oktsec agent suspend <name>`) or dashboard toggle. Suspended agents have all messages rejected immediately — both as sender and recipient. New `suspended` field in agent config (ASI10).
- **`oktsec agent` command**: New subcommands `suspend`, `unsuspend`, and `list` for managing agent lifecycle from the CLI.
- **Enforcement mode for stdio proxy**: New `--enforce` flag on `oktsec proxy` and `oktsec wrap`. When enabled, malicious client→server requests are blocked and a JSON-RPC 2.0 error response is injected back to the MCP client (`{"jsonrpc":"2.0","id":<id>,"error":{"code":-32600,"message":"blocked by oktsec: <rule>"}}`). Server→client responses are always forwarded. Notifications are silently dropped when blocked. Without `--enforce`, behavior is observe-only (backward compatible) (ASI02, ASI05).
- **BlockedContent enforcement**: The `blocked_content` agent config field (previously dead code) is now enforced. When a scan finding's category matches an entry in the agent's `blocked_content` list, the verdict is escalated to block (ASI02).
- **Category field in FindingSummary**: Scan findings now include the Aguara rule category, enabling per-agent category-based filtering.
- **Per-agent rate limiting**: New `rate_limit` config section with `per_agent` (max messages per window) and `window` (seconds). Uses a sliding-window counter. Returns HTTP 429 when exceeded. Checked before any expensive operations. Disabled when `per_agent` is 0 (ASI02, ASI10).
- **Anomaly detection loop**: Background goroutine periodically queries `QueryAgentRisk()` and fires `agent_risk_elevated` webhook events when an agent's risk score exceeds the configured threshold. Configurable via `anomaly.check_interval`, `anomaly.risk_threshold`, `anomaly.min_messages`. Optional `anomaly.auto_suspend` automatically suspends high-risk agents (ASI10).
- **Multi-message verdict escalation**: Before applying the final verdict, the handler queries the last hour of audit entries for the sender. If 3+ recent blocks exist and the current verdict is flag → escalates to quarantine. If 5+ recent blocks and current verdict is quarantine → escalates to block. Uses the existing `idx_audit_ts_agent_status` index (ASI01).
- **Dashboard suspend toggle**: New `POST /dashboard/agents/{name}/suspend` route toggles agent suspension from the dashboard UI.
- **New decision labels**: Dashboard event detail now shows human-readable labels for `agent_suspended`, `recipient_suspended`, and `identity_rejected` policy decisions.

### Changed

- Handler pipeline expanded from 4 steps to 7: rate limit → identity → suspension → ACL → scan → blocked content → escalation → verdict.
- Stdio proxy refactored: split into `proxyClientToServer()` (can block + inject errors) and `proxyServerToClient()` (observe-only, always forwards). Mutex-protected stdout writes for concurrent goroutine safety.
- `FindingSummary` struct now includes `Category` field (populated from Aguara's `Finding.Category`).
- `NewStdioProxy()` signature updated to accept `enforce bool` parameter.

### OWASP Coverage

| Category | Before | After |
|----------|--------|-------|
| ASI01 - Goal Hijack | Partial | **Partial+** |
| ASI02 - Tool Misuse | Partial | **Strong** |
| ASI03 - Identity/Privilege | Strong | **Strong+** |
| ASI05 - Code Execution | Weak | **Partial** |
| ASI10 - Rogue Agents | Partial | **Strong** |

## [0.3.0] - 2026-02-22

### Added

- **OpenClaw detection**: Discover and analyze OpenClaw AI agent installations. OpenClaw uses a WebSocket gateway and JSON5 config (`~/.openclaw/openclaw.json`) instead of MCP — oktsec now parses both.
- **`oktsec scan-openclaw`**: New command that assesses OpenClaw config risk (7 checks) and scans workspace files (SOUL.md, AGENTS.md, TOOLS.md, USER.md) with the Aguara engine.
- **7 OCLAW detection rules** (OCLAW-001 through OCLAW-007) in new `openclaw-config` category:
  - OCLAW-001: Full tool profile without restrictions (critical)
  - OCLAW-002: Gateway exposed to network (high)
  - OCLAW-003: Open DM policy (high)
  - OCLAW-004: Exec/shell tool without sandbox (critical)
  - OCLAW-005: Path traversal in `$include` (critical)
  - OCLAW-006: Gateway missing authentication (high)
  - OCLAW-007: Hardcoded credentials in config (high)
- **`oktsec discover`** now detects OpenClaw installations and prints risk summary when found.
- **`oktsec wrap openclaw`** returns a clear error explaining the WebSocket architecture difference and points to `scan-openclaw`.
- **Dashboard** shows `openclaw-config` category on the rules page.
- **JSON5 support**: Config parser strips `//` and `/* */` comments from OpenClaw configs.
- **Risk assessor**: `discover.AssessOpenClawRisk()` checks 7 patterns: full tool profiles, exposed gateways, open DM policies, unsandboxed agents, path traversal in includes, exec tools, and messaging channel attack surface.

### Changed

- `oktsec init` now assigns risk level "high" to OpenClaw-sourced agents.
- Discovery fallback text updated to include OpenClaw.
- Total rule count: 151 (138 Aguara + 6 IAP + 7 OCLAW).

## [0.2.0] - 2026-02-22

### Added

- **Quarantine Queue**: Messages triggering high-severity rules are held for human review instead of being silently delivered. Quarantined messages return HTTP 202 with a `quarantine_id` for status polling. Reviewers can approve (delivers the message) or reject from dashboard, CLI, or MCP tool.
- **Dashboard v2**: Complete redesign with 5-tab navigation (Overview, Events, Rules, Agents, Settings).
  - **Events page**: Unified audit log and quarantine view with live SSE streaming, tab filters (All / Quarantine / Blocked), and human-readable event detail panels with clickable rule cards.
  - **Rules page**: Category card grid replacing the flat rule list. Click a category to drill into individual rules with inline enable/disable toggles.
  - **Settings page**: Security mode (enforce/observe), agent key management with revocation, quarantine configuration, server info.
  - **Analytics on Overview**: Top triggered rules, agent risk scores, severity distribution, hourly activity chart.
- **Agent CRUD**: Create, edit, and delete agents from the dashboard. Generate Ed25519 keypairs per agent. Agent metadata fields: description, creator, location, tags.
- **Brute-force protection**: Dashboard login rate-limited to 5 attempts per 15 minutes per IP (in-memory, no external dependencies).
- **MCP tool `review_quarantine`**: AI agents can list, inspect, approve, or reject quarantine items programmatically.
- **CLI `oktsec quarantine`**: Subcommands for `list`, `detail`, `approve`, `reject` with table output.
- **Log retention**: Configurable `retention_days` auto-purges audit entries older than N days. Runs alongside quarantine expiry in the background.

### Changed

- **Analytics queries use 24-hour time window**: `QueryTopRules`, `QueryAgentRisk`, and `QueryHourlyStats` now scan only the last 24 hours instead of the full table. Reduces query time from ~1,000ms to ~6ms at 1M rows.
- **Composite index** `(timestamp, from_agent, status)` added for covering index scans on analytics queries.
- **ANALYZE on startup**: SQLite query planner statistics are updated on every server start for optimal index usage.
- **RFC3339 timestamp comparisons**: All time-window queries use Go-computed RFC3339 cutoffs instead of SQLite's `datetime()` function, ensuring correct index utilization.
- Quarantine verdict now returns HTTP 202 Accepted (was 200 OK).
- Legacy dashboard URLs (`/dashboard/logs`, `/dashboard/identity`, `/dashboard/analytics`, `/dashboard/quarantine`) redirect to new locations with 301.

### Performance

| Query (at 1M rows) | Before | After |
|---------------------|--------|-------|
| Top rules           | 1,061 ms | 5.9 ms |
| Agent risk          | 980 ms | 1.6 ms |
| Hourly stats        | 55 ms | 1.4 ms |
| Write throughput    | — | ~90K inserts/sec (batched) |

## [0.1.0] - 2026-02-20

### Added

- Initial release: HTTP proxy, Ed25519 identity, YAML policy, SQLite audit trail.
- 144 detection rules (138 Aguara + 6 inter-agent protocol).
- Dashboard v1 with real-time log viewer.
- MCP integration (`scan_message`, `query_audit`).
- CLI: `serve`, `keygen`, `verify`, `logs`, `rules`, `version`.
- Auto-discovery of existing MCP servers (`oktsec init`).
