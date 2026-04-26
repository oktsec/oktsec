# Generic MCP HTTP Client with Bearer Token

This guide shows how to connect any MCP HTTP client to the Oktsec gateway using a bearer token, without relying on the legacy `X-Oktsec-Agent` header. The bearer token is the recommended path for new integrations and the only path supported in enterprise deployments.

## When to use this

- Your client cannot set arbitrary HTTP headers (so the legacy `X-Oktsec-Agent` path is not an option).
- You are deploying Oktsec in enterprise mode and need authenticated identity on every request.
- You want one identity contract that works the same for any MCP HTTP client (Claude Code, Codex, Cursor, custom agents, internal services).

## Concepts

### Principal vs. reported actor

Oktsec separates **principal** (the authenticated identity used for every policy decision) from **reported actor** (display-only metadata supplied by the client, payload, or hook):

- `Principal` drives ACL, rate limit, suspension, tool allowlist, delegation, and every blocking decision.
- `ReportedActor` is shown in the dashboard alongside the principal so an analyst can see, for example, that the principal `local-codex` was acting on behalf of a sub-agent named `review-subagent`.

A reported actor never overrides the principal. A spoofed `X-Oktsec-Agent: admin` header cannot grant admin policy when a bearer token says the request belongs to `local-codex`.

### Local vs. enterprise

Oktsec ships two deployment profiles. Each surface (gateway, hooks, forward proxy) honors them the same way:

| Profile | Default behavior | Use when |
|---|---|---|
| `local` | Auth optional. The legacy `X-Oktsec-Agent` header from `127.0.0.1` is accepted as `trusted_local` identity for backwards compatibility. | Single-developer setup on a laptop. |
| `enterprise` | Auth required. The loopback header is **never** accepted as principal — only as reported-actor metadata. | Anything exposed beyond loopback, fleet/team rollouts, regulated workloads. |

Local mode stays permissive on purpose: existing setups using `X-Oktsec-Agent` keep working without config changes. Enterprise mode fails closed: missing or invalid identity returns `401 Unauthorized` before any policy code runs.

You can force fail-closed behavior on a local laptop with:

```yaml
deployment:
  require_surface_auth: true
```

This lets you test the enterprise contract end-to-end without flipping the whole profile.

### `X-Oktsec-Agent` is legacy

The `X-Oktsec-Agent` header is supported as a backwards-compatibility path for local profile only:

- Accepted as principal **only** when (1) profile is `local`, (2) the request originates from the loopback interface, and (3) `gateway.trusted_loopback_headers` is on (default in local profile when no `auth_methods` override is set).
- In enterprise mode the header is downgraded to a low-confidence reported actor and never grants policy authority.
- Bearer tokens always win: if both a valid `Authorization: Bearer …` and `X-Oktsec-Agent` are present, the token's principal is used and the header surfaces as a reported actor only.

For new integrations and enterprise deployments, use a bearer token.

## Configure a principal and a token

A principal is an identity Oktsec recognizes. Tokens are bound to one principal and stored as salted SHA-256 hashes — the raw secret is never persisted.

### 1. Create the token with the CLI

```bash
oktsec tokens create --principal local-codex --type gateway_bearer --expires 30d
```

The first time you create a token for a principal, Oktsec auto-creates the principal entry with `kind: agent` and reports it explicitly:

```
Created principal "local-codex" with kind=agent.
Created token "gw-local-codex-2026-04-26-a1b2c3" for principal "local-codex".
Expires at 2026-05-26T00:00:00Z.

Raw token (shown once, copy it now):

  okt_gw_a1b2c3d4...

Use it in your MCP client's Authorization header:

  Authorization: Bearer okt_gw_a1b2c3d4...

The hash has been saved to your config. The raw value above will not be displayed again.
Reload the gateway (SIGHUP) for the new token to take effect immediately.
```

`--expires` accepts Go duration syntax (`24h`, `90m`) and the shortcuts `7d`, `30d`, `2w`, `1y`. Omit it for a non-expiring token.

`--token-id` is optional; the CLI generates `<type-prefix>-<principal>-<date>-<random>` so two tokens on the same day do not collide. Pass `--token-id <id>` if you want a specific name.

The raw value is the only thing the CLI ever prints. Copy it into your client immediately — there is no way to recover it later. The config keeps only the salted SHA-256 hash.

Token types:

- `gateway_bearer` — used for the MCP HTTP gateway (this guide).
- `proxy_basic` — used for the HTTP forward proxy (separate surface, separate token).
- `hook_bearer` — used by authenticated hook adapters.

A leaked `gateway_bearer` token cannot authenticate to the forward proxy, and vice versa.

### 2. Inspect existing tokens

```bash
oktsec tokens list
oktsec tokens list --principal local-codex
```

Output is a table with the token id, type, status (`active` / `expired` / `revoked`), creation date, and expiry. The hash and raw value are never displayed.

### 3. Decide auth strictness

For local development, the defaults are fine — bearer tokens authenticate as principal, the legacy header still works for any client that hasn't migrated.

For enterprise:

```yaml
deployment:
  profile: enterprise

gateway:
  bind: "0.0.0.0"
  require_auth: true
  auth_methods:
    - bearer_token
    # - mtls       # reserved for a future release
  trusted_loopback_headers: false  # never trust the header in enterprise
```

`require_auth` is a per-surface override (`auto` | `true` | `false`). `auto` (or unset) follows the deployment profile. Explicit `true`/`false` always wins.

## Use the bearer token from a client

The MCP client makes its `tools/call` requests against the gateway endpoint with the standard `Authorization: Bearer …` header:

```bash
curl -X POST http://127.0.0.1:9090/mcp \
  -H "Authorization: Bearer okt_gw_<your_raw_token_here>" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}'
```

For an MCP client SDK that supports bearer auth (the official `@modelcontextprotocol/sdk` does), pass the token as the `headers.Authorization` value when constructing the transport. The gateway treats the request the same regardless of which SDK or runtime sent it — that is the point of being surface-agnostic.

### Optional: declare the reported actor

If your client wants the dashboard to show a sub-agent name (e.g. `review-subagent`) alongside the principal, set the reported-actor header. It is display-only and never affects policy:

```bash
curl ... \
  -H "Authorization: Bearer okt_gw_..." \
  -H "X-Oktsec-Reported-Actor: review-subagent" \
  ...
```

Or include `_oktsec_agent` in the tool arguments — the gateway strips it from the upstream payload and stores it as the reported actor.

## Verify it worked

A successful call returns the tool's result. The audit row carries the resolved identity provenance:

```sql
SELECT from_agent, auth_method, principal_trust_level, reported_actor
FROM audit_log
ORDER BY timestamp DESC
LIMIT 1;
```

Expected:

| from_agent | auth_method | principal_trust_level | reported_actor |
|---|---|---|---|
| `local-codex` | `bearer_token` | `authenticated` | `review-subagent` (or empty) |

A 401 response means either the token did not match any active principal, the token was revoked or expired, or `require_auth` is on and no `Authorization` header was sent. The response includes a `WWW-Authenticate: Bearer realm="oktsec gateway"` hint.

## Token rotation and revocation

Rotate by creating a new token, distributing the new raw value to the client, then revoking the old one:

```bash
# New token (raw value printed once)
oktsec tokens create --principal local-codex --type gateway_bearer --expires 30d

# Old token: keep the audit trail row, mark it revoked
oktsec tokens revoke --principal local-codex --token gw-local-codex-2026-04-20-abc123
```

`revoke` sets `revoked_at` on the token row but leaves it in the config so audit history is preserved. Revoked tokens stop authenticating immediately on the next request — the resolver revalidates each token's active state on every lookup, not just at config load time.

Reload the gateway (SIGHUP) so it picks up the rebuilt principal store.

## Related

- [MCP Gateway](gateway.md) — gateway configuration, backends, and tool routing.
- [Egress](egress.md) — HTTP forward proxy with proxy-token auth (separate surface, same identity contract).
