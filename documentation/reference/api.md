# API Reference

All API endpoints are served by `oktsec serve` on the configured port (default: `8080`).

---

## Message API

### `POST /v1/message`

Send a message through the security pipeline.

**Request:**

```bash
curl -X POST http://localhost:8080/v1/message \
  -H "Content-Type: application/json" \
  -d '{
    "from": "coordinator",
    "to": "researcher",
    "content": "Analyze the latest threat report",
    "metadata": {"task_id": "abc-123"}
  }'
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `from` | string | yes | Sender agent name |
| `to` | string | yes | Recipient agent name |
| `content` | string | yes | Message content |
| `signature` | string | conditional | Base64-encoded Ed25519 signature. Required when `require_signature: true` |
| `timestamp` | string | no | RFC 3339 timestamp. Auto-generated if omitted |
| `metadata` | object | no | Arbitrary key-value pairs passed through to the audit log |

**Signing payload:**

The signature covers the canonical string `from\nto\ncontent\ntimestamp` using Ed25519:

```
coordinator\nresearcher\nAnalyze the latest threat report\n2026-03-06T10:00:00Z
```

**Response (200 — delivered):**

```json
{
  "status": "delivered",
  "message_id": "550e8400-e29b-41d4-a716-446655440000",
  "policy_decision": "allow",
  "rules_triggered": [],
  "verified_sender": true,
  "quarantine_id": "",
  "expires_at": ""
}
```

**Response (202 — quarantined):**

```json
{
  "status": "quarantined",
  "message_id": "550e8400-e29b-41d4-a716-446655440001",
  "policy_decision": "content_quarantined",
  "rules_triggered": [
    {"rule_id": "IAP-002", "name": "PII in agent messages", "severity": "high"}
  ],
  "quarantine_id": "q-abc123",
  "expires_at": "2026-03-07T10:00:00Z"
}
```

**Response (403 — blocked):**

```json
{
  "status": "blocked",
  "message_id": "550e8400-e29b-41d4-a716-446655440002",
  "policy_decision": "content_blocked",
  "rules_triggered": [
    {"rule_id": "IAP-001", "name": "Relay injection", "severity": "critical"}
  ]
}
```

### Policy decisions

| Decision | HTTP | Meaning |
|----------|------|---------|
| `allow` | 200 | Clean content, delivered |
| `content_flagged` | 200 | Medium-severity finding, delivered with warning |
| `content_quarantined` | 202 | High-severity, held for human review |
| `content_blocked` | 403 | Critical-severity, rejected |
| `identity_rejected` | 403 | Invalid signature or unknown agent (enforce mode) |
| `signature_required` | 401 | Unsigned message when signatures are enforced |
| `acl_denied` | 403 | Sender not authorized to message recipient |
| `agent_suspended` | 403 | Sender is suspended |
| `recipient_suspended` | 403 | Recipient is suspended |

### Pipeline order

The pipeline runs checks from cheapest to most expensive. If any check fails, subsequent checks are skipped:

1. Rate limit (~1ns)
2. Identity verification (~120us)
3. Suspension check
4. ACL evaluation
5. Content scan — 230 rules (~8ms)
6. Blocked content filter (per-agent categories)
7. Split injection detection (multi-message scan)
8. Rule overrides (from config)
9. History escalation (3+ blocks in 1h)
10. Audit log write
11. Anomaly detection (background)

---

## Agent CRUD API

### `GET /v1/agents`

List all agents.

```bash
curl http://localhost:8080/v1/agents
```

```json
[
  {
    "name": "coordinator",
    "description": "Orchestrator",
    "can_message": ["researcher", "coder"],
    "suspended": false,
    "has_key": true,
    "tags": ["prod"],
    "location": "us-east-1"
  }
]
```

### `GET /v1/agents/{name}`

Get agent details. Returns `404` if not found.

```bash
curl http://localhost:8080/v1/agents/coordinator
```

### `POST /v1/agents`

Create a new agent.

```bash
curl -X POST http://localhost:8080/v1/agents \
  -H "Content-Type: application/json" \
  -d '{
    "name": "new-agent",
    "description": "Research assistant",
    "can_message": ["coordinator"],
    "blocked_content": ["credentials"],
    "allowed_tools": ["read_file", "search_files"],
    "location": "us-east-1",
    "tags": ["staging"]
  }'
```

| Status | Meaning |
|--------|---------|
| 201 | Agent created |
| 400 | Invalid name (must match `^[a-zA-Z0-9][a-zA-Z0-9_-]*$`) |
| 409 | Agent already exists |

### `PUT /v1/agents/{name}`

Partial update — only provided fields are changed.

```bash
curl -X PUT http://localhost:8080/v1/agents/researcher \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Updated description",
    "blocked_content": ["credentials", "pii"]
  }'
```

Uses pointer fields internally (`*string`, `*bool`) so omitted fields are preserved.

### `DELETE /v1/agents/{name}`

Delete an agent and persist to config.

| Status | Meaning |
|--------|---------|
| 204 | Deleted |
| 404 | Not found |

### `POST /v1/agents/{name}/keys`

Rotate the agent's Ed25519 keypair. Revokes the old key and generates a new one.

```bash
curl -X POST http://localhost:8080/v1/agents/researcher/keys
```

```json
{
  "status": "rotated",
  "agent": "researcher",
  "fingerprint": "sha256:abc123..."
}
```

### `POST /v1/agents/{name}/suspend`

Toggle suspension state.

```bash
curl -X POST http://localhost:8080/v1/agents/researcher/suspend
```

```json
{
  "agent": "researcher",
  "suspended": "true"
}
```

---

## Quarantine API

### `GET /v1/quarantine/{id}`

Get the status and details of a quarantined message.

```bash
curl http://localhost:8080/v1/quarantine/q-abc123
```

---

## Health & Monitoring

### `GET /health`

```json
{"status": "ok", "version": "1.0.0"}
```

### `GET /metrics`

Prometheus-format metrics.

| Metric | Type | Description |
|--------|------|-------------|
| `oktsec_messages_total` | counter | Total messages processed, by verdict |
| `oktsec_message_latency_seconds` | histogram | End-to-end pipeline latency |
| `oktsec_rules_triggered_total` | counter | Detection rule triggers, by rule ID |
| `oktsec_rate_limit_hits_total` | counter | Rate limit rejections |
| `oktsec_quarantine_pending` | gauge | Current pending quarantine items |
| `oktsec_signature_verified_total` | counter | Signature verification results |

Example Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: oktsec
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: /metrics
```

---

## Dashboard endpoints

The dashboard is served at `/dashboard` with SSE for live updates. These are internal endpoints used by the HTMX UI:

| Path | Method | Description |
|------|--------|-------------|
| `/dashboard` | GET | Overview page |
| `/dashboard/login` | GET/POST | Access code authentication |
| `/dashboard/events` | GET | Events page with SSE streaming |
| `/dashboard/rules` | GET | Rule categories |
| `/dashboard/rules/{category}` | GET | Rules in a category |
| `/dashboard/rules/detail/{id}` | GET | Rule detail page |
| `/dashboard/agents` | GET | Agent list |
| `/dashboard/agents/{name}` | GET | Agent detail |
| `/dashboard/graph` | GET | Communication topology |
| `/dashboard/settings` | GET | Settings page |
| `/dashboard/audit` | GET | Security audit |
| `/dashboard/discovery` | GET | MCP client discovery |

---

## Webhook events

Oktsec sends webhook notifications for configured events.

**Event types:** `message_blocked`, `message_quarantined`, `agent_risk_elevated`, `rule_triggered`.

**Payload:**

```json
{
  "event": "message_blocked",
  "message_id": "550e8400-e29b-41d4-a716-446655440000",
  "from": "researcher",
  "to": "coordinator",
  "severity": "critical",
  "rule": "IAP-001",
  "rule_name": "Relay injection",
  "category": "inter-agent",
  "timestamp": "2026-03-06T15:00:00Z"
}
```

---

## MCP Tools

When running as an MCP server (`oktsec mcp`), these tools are available:

### `scan_message`

Scan content for security threats.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `content` | string | yes | Content to scan |
| `from` | string | no | Sender agent name |
| `to` | string | no | Recipient agent name |

Returns verdict (`clean`, `flag`, `quarantine`, `block`) and triggered rules.

### `list_agents`

List all configured agents with ACLs and status. No parameters.

### `audit_query`

Query the audit log.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `status` | string | no | Filter by status |
| `agent` | string | no | Filter by agent |
| `limit` | int | no | Max entries |

### `get_policy`

Get the security policy for a specific agent.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `agent` | string | yes | Agent name |

### `verify_agent`

Verify an Ed25519 signature.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `agent` | string | yes | Agent name |
| `from` | string | yes | Sender |
| `to` | string | yes | Recipient |
| `content` | string | yes | Message content |
| `timestamp` | string | yes | RFC 3339 timestamp |
| `signature` | string | yes | Base64 Ed25519 signature |

### `review_quarantine`

Manage quarantined messages.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `action` | string | yes | `list`, `detail`, `approve`, or `reject` |
| `id` | string | conditional | Quarantine item ID (for detail/approve/reject) |
| `limit` | int | no | Max items for list action |
| `status` | string | no | Filter for list action |
