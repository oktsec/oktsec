# Plan: Per-Agent Egress Control for oktsec

## Context

Feedback from Rodri: oktsec should control what **goes out** from AI agents — like AWS GuardDuty but for the AI agent ecosystem. Currently oktsec only inspects **inbound** agent-to-agent messages. The forward proxy (`forward_proxy` config) has global domain filtering and content scanning, but it's the same rules for all agents. There's no per-agent egress policy, no DLP, and no way to know *which* agent is making an outbound request.

## What exists today

The forward proxy in `internal/proxy/forward.go` already handles:
- HTTP CONNECT tunneling (HTTPS) and plain HTTP forwarding
- Global `allowed_domains` / `blocked_domains`
- Request body scanning via Aguara (`scan_requests` flag)
- Response body scanning via Aguara (`scan_responses` flag)
- Rate limiting by remote IP address
- Audit logging of proxy events

But it's all **global** — every agent gets the same rules, and agents are identified only by `r.RemoteAddr` (raw IP).

## Design

### Agent identification

Agents identify themselves via `X-Oktsec-Agent: <agent_name>` header on proxy requests. This header is:
- Read by the forward proxy before policy evaluation
- Stripped before forwarding upstream (never leaked to destination)
- Optional — requests without it fall back to global rules (backward compatible)

Same trust model as the existing `/v1/message` endpoint where `from` is self-declared in JSON body. For Docker sandbox deployments the network boundary provides isolation.

### Per-agent egress config

New `egress` field on the `Agent` struct:

```yaml
agents:
  researcher:
    can_message: [coordinator]
    egress:
      allowed_domains: [api.google.com, arxiv.org]
      blocked_domains: [pastebin.com]
      scan_requests: true
      blocked_categories: [credentials, pii]
      rate_limit: 100
      rate_window: 60

  coder:
    can_message: [coordinator]
    egress:
      allowed_domains: [api.github.com, registry.npmjs.org]
      blocked_categories: [credentials]
      rate_limit: 50
```

**Merge rules:**
- Per-agent `allowed_domains` is **additive** to global `forward_proxy.allowed_domains`
- Per-agent `blocked_domains` is **additive** to global `forward_proxy.blocked_domains`
- Global `blocked_domains` always wins (cannot be overridden per-agent)
- `scan_requests`/`scan_responses` use `*bool` — nil inherits global, explicit overrides
- No `egress` block = fall back to global settings entirely

### DLP category blocking

After scanning outbound content with Aguara, check findings against the agent's `blocked_categories`. If any finding matches, block the request. Reuses the same pattern as `applyBlockedContent()` in `handler.go` for inbound messages.

## Files to modify

### `internal/config/config.go` — MODIFY
- Add `EgressPolicy` struct with `AllowedDomains`, `BlockedDomains`, `ScanRequests *bool`, `ScanResponses *bool`, `BlockedCategories`, `RateLimit`, `RateWindow`
- Add `Egress *EgressPolicy` field to `Agent` struct (pointer, omitempty — nil = no config)
- Extend `Validate()` with egress field checks

### `internal/proxy/forward.go` — MODIFY
- Add `egressEval *EgressEvaluator` and `agentLimiters map[string]*RateLimiter` fields to `ForwardProxy`
- Update `NewForwardProxy` signature to accept `agents map[string]config.Agent`
- Add `extractAgent(r *http.Request) string` — reads + strips `X-Oktsec-Agent` header
- Modify `handleConnect()`: extract agent → resolve policy → per-agent domain check + rate limit → log agent name
- Modify `handleHTTP()`: extract agent → resolve policy → per-agent domain check + rate limit + scan flags + DLP category check → log agent name
- Update `logProxyEntry()` to use agent name when available, fall back to `r.RemoteAddr`

### `internal/proxy/egress.go` — NEW (~120 LOC)
- `EgressEvaluator` struct: merges global `ForwardProxyConfig` + per-agent `EgressPolicy`
- `ResolveAgent(name string) *ResolvedEgressPolicy` — produces merged policy
- `ResolvedEgressPolicy` struct with `DomainAllowed(host string) bool`
- `categoryBlocked(category string, blocked []string) bool` helper

### `internal/proxy/server.go` — MODIFY
- Pass `cfg.Agents` to `NewForwardProxy` constructor (line ~117)

### `internal/proxy/egress_test.go` — NEW
- Policy resolution: no egress → global defaults
- Additive domain merging
- Global blocklist precedence
- Boolean flag inheritance (*bool nil vs explicit)
- Rate limit inheritance
- DomainAllowed with merged policies

### `internal/proxy/forward_test.go` — MODIFY
- Update `newTestForwardProxy` helper to accept optional agents
- Add per-agent egress integration tests (domain allow/block, rate limits, DLP category block, header stripping)

### `internal/config/config_test.go` — MODIFY
- YAML round-trip with egress config
- Backward compatibility (old YAML without egress)
- Validation of egress fields

## Implementation order

1. Add `EgressPolicy` struct + `Egress` field to config, extend `Validate()` — `config.go`
2. Add config tests — `config_test.go`
3. Create `egress.go` with `EgressEvaluator` + `ResolvedEgressPolicy`
4. Create `egress_test.go`
5. Modify `forward.go`: agent extraction, per-agent policy in `handleConnect`/`handleHTTP`
6. Wire agents into `NewForwardProxy` in `server.go`
7. Update `forward_test.go` with per-agent integration tests

## Verification

```bash
cd /Users/dev/Documents/Personales/Cybersecurity/oktsec

# Unit + integration tests
make test

# Manual: start with per-agent egress config
./oktsec serve --config testdata/egress-test.yaml

# Agent with allowlist can reach its domains
curl -x http://localhost:8081 -H "X-Oktsec-Agent: researcher" http://api.google.com/test

# Agent cannot reach domains outside its allowlist
curl -x http://localhost:8081 -H "X-Oktsec-Agent: researcher" http://evil.com/exfil

# Unknown agent falls back to global rules
curl -x http://localhost:8081 http://api.anthropic.com/test

# Verify agent header is not forwarded upstream
# (check with a request-echo server like tero)
```

## Not in scope (future)

- **HMAC-signed agent headers** — prevent impersonation with `X-Oktsec-Signature: HMAC-SHA256(agent:timestamp, secret)`. Useful for shared-network deployments without Docker isolation.
- **Egress-specific Aguara rules** — new rule category for detecting prompt leaking, PII in outbound content. Currently reuses existing Aguara rules which already cover credentials and exfiltration patterns.
- **Dashboard egress tab** — per-agent outbound traffic visualization, top destinations, blocked attempts.
