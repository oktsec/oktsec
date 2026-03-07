# Per-Agent Egress Control

Oktsec controls what goes out from AI agents — like AWS GuardDuty but for the AI agent ecosystem.

## Overview

The forward proxy scans all outbound HTTP traffic. With per-agent egress control, each agent gets its own outbound policy: domain allowlists, blocklists, DLP category blocking, and rate limiting.

## Agent identification

Agents identify themselves via the `X-Oktsec-Agent` header on proxy requests:

```bash
curl -x http://localhost:8081 \
  -H "X-Oktsec-Agent: researcher" \
  http://api.google.com/test
```

The header is:

- Read by the forward proxy before policy evaluation
- **Stripped before forwarding upstream** (never leaked to destination)
- Optional — requests without it fall back to global rules

## Configuration

### Global settings

```yaml
forward_proxy:
  enabled: true
  scan_requests: true
  scan_responses: false
  max_body_size: 1048576     # 1 MB
  allowed_domains: []        # empty = all allowed
  blocked_domains:
    - pastebin.com
    - evil.com
```

### Per-agent egress policy

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

## Merge rules

| Setting | Behavior |
|---------|----------|
| `allowed_domains` | Per-agent is **additive** to global |
| `blocked_domains` | Per-agent is **additive** to global |
| Global `blocked_domains` | **Always wins** (cannot be overridden per-agent) |
| `scan_requests` / `scan_responses` | `null` = inherit global; explicit value overrides |
| No `egress` block | Falls back to global settings entirely |

## DLP category blocking

After scanning outbound content with Aguara, findings are checked against the agent's `blocked_categories`. If any finding matches, the request is blocked.

This reuses the same Aguara rule categories as inbound content scanning: `credentials`, `pii`, `prompt-injection`, `exfiltration`, `command-execution`, etc.

```yaml
agents:
  data-agent:
    egress:
      blocked_categories: [credentials, pii]
```

## Per-agent rate limiting

Each agent can have its own egress rate limit, independent of the global rate limiter:

```yaml
agents:
  scraper:
    egress:
      rate_limit: 50      # max 50 requests per window
      rate_window: 60     # 60 second window
```

## Examples

### Agent restricted to specific APIs

```yaml
agents:
  research-bot:
    egress:
      allowed_domains: [api.arxiv.org, api.semanticscholar.org]
      blocked_categories: [credentials]
      rate_limit: 200
```

This agent can only reach arxiv and semantic scholar. Any outbound content containing credentials is blocked.

### Agent with no restrictions (inherits global)

```yaml
agents:
  admin-bot:
    can_message: ["*"]
    # no egress block = uses global forward_proxy settings
```

### Verify header stripping

The `X-Oktsec-Agent` header is never forwarded to the destination. You can verify this with a request echo service.
