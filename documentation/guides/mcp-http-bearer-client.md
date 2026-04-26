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

> **Coming next**: `oktsec tokens create` will generate the raw token, hash it, and append the principal to your config in one command. Until that lands, generate the hash manually as shown below.

### 1. Generate a raw token and hash

Pick a 32-byte random secret with the `okt_gw_` prefix and produce the storage hash. Any tool that produces SHA-256 with a salt works; the format is `sha256:<hex_salt>:<hex_digest>`.

For a one-off, paste this into a Python REPL:

```python
import secrets, hashlib

raw  = "okt_gw_" + secrets.token_hex(32)
salt = secrets.token_bytes(16)
hash_ = "sha256:" + salt.hex() + ":" + hashlib.sha256(salt + raw.encode()).hexdigest()

print("RAW (show once, then discard):", raw)
print("HASH (paste into config):", hash_)
```

Save the raw value somewhere safe and paste **only the hash** into config.

### 2. Add the principal to `oktsec.yaml`

```yaml
identity:
  principals:
    - id: local-codex
      display_name: Codex local agent
      kind: agent
      allowed_surfaces:
        - mcp_http
      tokens:
        - id: gw-local-codex
          type: gateway_bearer
          hash: "sha256:<paste_hex_salt>:<paste_hex_digest>"
          created_at: "2026-04-26T00:00:00Z"
          # Optional fields:
          # expires_at: "2027-04-26T00:00:00Z"
          # revoked_at: "2026-05-15T00:00:00Z"
```

Token types:

- `gateway_bearer` — used for the MCP HTTP gateway (this guide).
- `proxy_basic` — used for the HTTP forward proxy (separate surface, separate token).
- `hook_bearer` — used by authenticated hook adapters.

A leaked `gateway_bearer` token cannot authenticate to the forward proxy, and vice versa.

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

Until the CLI lands, rotate by appending a new token to the principal's `tokens:` list, distributing the new raw value to the client, then setting `revoked_at` on the old entry. Revoked tokens stop authenticating immediately on the next request — the resolver revalidates each token's active state on every lookup, not just at config load time.

```yaml
tokens:
  - id: gw-local-codex
    type: gateway_bearer
    hash: "sha256:..."
    created_at: "2026-04-26T00:00:00Z"
    revoked_at: "2026-05-15T00:00:00Z"   # this token no longer works
  - id: gw-local-codex-2
    type: gateway_bearer
    hash: "sha256:..."                    # new hash, new raw value to the client
    created_at: "2026-05-15T00:00:00Z"
```

Reload the gateway (SIGHUP) for the rebuild to pick up the changes.

## Related

- [MCP Gateway](gateway.md) — gateway configuration, backends, and tool routing.
- [Egress](egress.md) — HTTP forward proxy with proxy-token auth (separate surface, same identity contract).
