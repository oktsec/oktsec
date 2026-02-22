# Changelog

All notable changes to this project will be documented in this file.

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
