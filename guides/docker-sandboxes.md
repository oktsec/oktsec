# Oktsec + Docker Sandboxes

Docker Sandboxes provide isolated micro VMs for AI agents with a configurable network proxy. Oktsec complements this by inspecting the content that flows between agents. Docker isolates the runtime; Oktsec inspects the messages.

## What each layer does

| Concern | Docker Sandbox | Oktsec |
|---------|---------------|--------|
| Process isolation | Yes (micro VM) | No |
| Filesystem isolation | Yes | No |
| Network filtering | Proxy-level allow/deny | No |
| Message content scanning | No | Yes (151 rules) |
| Identity verification | No | Yes (Ed25519) |
| Agent-to-agent ACLs | No | Yes |
| Audit trail | No | Yes (SQLite) |
| Prompt injection detection | No | Yes |
| Credential leak detection | No | Yes |

Docker Sandboxes answer: "Can this agent access the network/filesystem?"
Oktsec answers: "Is the content this agent is sending/receiving safe?"

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Host machine                         │
│                                                         │
│  ┌───────────────────┐       ┌───────────────────┐      │
│  │  Docker Sandbox A  │       │  Docker Sandbox B  │     │
│  │  ┌─────────────┐  │       │  ┌─────────────┐  │     │
│  │  │   Agent A    │  │       │  │   Agent B    │  │     │
│  │  └──────┬──────┘  │       │  └──────▲──────┘  │     │
│  │         │ POST    │       │         │ deliver  │     │
│  └─────────┼─────────┘       └─────────┼─────────┘     │
│            │                           │                │
│            ▼                           │                │
│  ┌──────────────────────────────────────────────┐      │
│  │              Docker Network Proxy             │      │
│  └──────────────────────┬───────────────────────┘      │
│                         │                               │
│                         ▼                               │
│  ┌──────────────────────────────────────────────┐      │
│  │                   Oktsec                      │      │
│  │                                               │      │
│  │  rate limit → verify → ACL → scan → deliver   │      │
│  │                                               │      │
│  │  151 rules · Ed25519 · audit trail            │      │
│  └──────────────────────────────────────────────┘      │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

Each sandbox's network proxy routes outbound traffic through Oktsec. Agents inside sandboxes send messages to Oktsec's `/v1/message` endpoint. Oktsec scans, verifies, and routes (or blocks) before the message reaches the destination sandbox.

## Setup

### 1. Start Oktsec

Run Oktsec on the host or as a container on the same Docker network:

```bash
# Option A: host
oktsec serve --config oktsec.yaml --bind 0.0.0.0

# Option B: container
docker compose up -d
```

If using a container, ensure Oktsec is on a Docker network reachable by the sandboxes.

### 2. Create sandboxes with network proxy

When creating a Docker Sandbox, configure the network proxy to route traffic through Oktsec:

```bash
docker sandbox create \
  --network-proxy http://host.docker.internal:8080 \
  --name agent-a

docker sandbox create \
  --network-proxy http://host.docker.internal:8080 \
  --name agent-b
```

The `--network-proxy` flag tells the sandbox to route outbound HTTP through the specified proxy. All agent-to-agent traffic passes through Oktsec.

### 3. Configure agents to use Oktsec

Inside each sandbox, configure the agent to send messages to Oktsec's endpoint:

```bash
# From inside the sandbox, the agent sends messages through the proxy
curl -X POST http://host.docker.internal:8080/v1/message \
  -H "Content-Type: application/json" \
  -d '{
    "from": "agent-a",
    "to": "agent-b",
    "content": "Analyze the dataset",
    "signature": "<base64-ed25519-signature>",
    "timestamp": "2026-02-23T10:00:00Z"
  }'
```

### 4. Verify

Check that messages flow through Oktsec:

```bash
# View recent audit entries
oktsec logs

# Check the dashboard
open http://127.0.0.1:8080/dashboard
```

## Example: OpenClaw agents in sandboxes

OpenClaw agents are high-risk targets — they have filesystem access, shell access, and messaging channels. Running them inside Docker Sandboxes with Oktsec adds two layers of protection.

### Oktsec config

```yaml
version: "1"

server:
  port: 8080
  bind: 0.0.0.0

identity:
  keys_dir: ./keys
  require_signature: false    # Start in observe mode

agents:
  openclaw-assistant:
    can_message: [openclaw-researcher]
    blocked_content: [credentials, pii, exfiltration]
  openclaw-researcher:
    can_message: [openclaw-assistant]
    blocked_content: [credentials, command-execution]

quarantine:
  enabled: true
  expiry_hours: 24
```

### Start the stack

```bash
# 1. Start Oktsec
docker compose up -d

# 2. Create sandboxed environments for each OpenClaw agent
docker sandbox create \
  --network-proxy http://host.docker.internal:8080 \
  --name openclaw-assistant

docker sandbox create \
  --network-proxy http://host.docker.internal:8080 \
  --name openclaw-researcher

# 3. Run OpenClaw inside each sandbox
docker sandbox exec openclaw-assistant -- openclaw start assistant
docker sandbox exec openclaw-researcher -- openclaw start researcher
```

### What happens

1. OpenClaw agents start inside isolated micro VMs (no host filesystem/network access)
2. All outbound traffic routes through the Docker network proxy to Oktsec
3. Oktsec scans every message for prompt injection, credential leaks, PII, exfiltration
4. Suspicious messages are quarantined for human review
5. Everything is logged to the audit trail

## Defense in depth

| Layer | Protects against | Tool |
|-------|-----------------|------|
| 1. Docker Sandbox | Container escape, filesystem access, network pivoting | Docker |
| 2. Network proxy | Unauthorized outbound connections | Docker Sandbox proxy |
| 3. Identity verification | Agent impersonation | Oktsec (Ed25519) |
| 4. Policy enforcement | Unauthorized agent-to-agent communication | Oktsec (ACLs) |
| 5. Content scanning | Prompt injection, credential leaks, PII, exfiltration | Oktsec (151 rules) |
| 6. Audit trail | Post-incident forensics | Oktsec (SQLite) |

No single layer is sufficient. Docker Sandboxes without content inspection miss prompt injection. Oktsec without sandboxing can't prevent filesystem access. Use both.
