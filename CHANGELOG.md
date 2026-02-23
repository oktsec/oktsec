# Changelog

All notable changes to this project will be documented in this file.

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
