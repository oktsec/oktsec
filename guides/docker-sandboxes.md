# Oktsec + Docker Sandboxes

Docker Sandboxes provide isolated micro VMs for AI agents. Oktsec provides content inspection for agent-to-agent messages. They solve different problems and work together as complementary layers.

## What each layer does

| Concern | Docker Sandbox | Oktsec |
|---------|---------------|--------|
| Process isolation | Yes (micro VM) | No |
| Filesystem isolation | Yes | No |
| Network filtering | Proxy-level allow/deny | No |
| Credential proxying | Yes (API keys never in sandbox) | No |
| Message content scanning | No | Yes (151 rules) |
| Identity verification | No | Yes (Ed25519) |
| Agent-to-agent ACLs | No | Yes |
| Audit trail | No | Yes (SQLite) |
| Prompt injection detection | No | Yes |
| Credential leak detection | No | Yes |

Docker Sandboxes answer: "Can this agent access the network/filesystem?"
Oktsec answers: "Is the content this agent is sending/receiving safe?"

## How it works

Oktsec is a REST API service (`POST /v1/message`), not an HTTP forward proxy. Agents inside Docker Sandboxes must explicitly send inter-agent messages through Oktsec's endpoint. Oktsec does not transparently intercept network traffic.

```
┌─────────────────────────────────────────────────────────┐
│                    Host / Docker network                 │
│                                                         │
│  ┌───────────────────┐       ┌───────────────────┐      │
│  │  Docker Sandbox A  │       │  Docker Sandbox B  │     │
│  │  ┌─────────────┐  │       │  ┌─────────────┐  │     │
│  │  │   Agent A    │  │       │  │   Agent B    │  │     │
│  │  └──────┬──────┘  │       │  └──────▲──────┘  │     │
│  │         │         │       │         │         │     │
│  └─────────┼─────────┘       └─────────┼─────────┘     │
│            │ POST /v1/message          │ poll/receive   │
│            │                           │                │
│            ▼                           │                │
│  ┌──────────────────────────────────────────────┐      │
│  │                   Oktsec                      │      │
│  │                                               │      │
│  │  rate limit → verify → ACL → scan → verdict   │      │
│  │                                               │      │
│  │  151 rules · Ed25519 · audit trail            │      │
│  └──────────────────────────────────────────────┘      │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

Agent A sends a signed JSON message to Oktsec. Oktsec scans it, checks ACLs, and returns a verdict (delivered, blocked, or quarantined). Agent B receives the message only if Oktsec allows it.

## Setup

### 1. Start Oktsec

Run Oktsec on the host or as a container on the same Docker network:

```bash
# Option A: host
oktsec serve --config oktsec.yaml --bind 0.0.0.0

# Option B: container
docker compose up -d
```

If using a container, ensure Oktsec is on a Docker network reachable from the sandboxes.

### 2. Create sandboxes

Create isolated environments for each agent:

```bash
docker sandbox create --name agent-a shell ~/agent-a-workspace
docker sandbox create --name agent-b shell ~/agent-b-workspace
```

Each sandbox gets its own micro VM with filesystem isolation, credential proxying, and disposable state.

### 3. Configure agents to use Oktsec

Inside each sandbox, the agent sends inter-agent messages through Oktsec's API:

```bash
# From inside sandbox A, send a message to agent B
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

`host.docker.internal` resolves to the host machine from inside Docker containers and sandboxes.

### 4. Verify

Check that messages flow through Oktsec:

```bash
# View recent audit entries
oktsec logs

# Check the dashboard
open http://127.0.0.1:8080/dashboard
```

## Example: NanoClaw in sandbox + Oktsec

[NanoClaw](https://github.com/qwibitai/nanoclaw) is a Claude-powered WhatsApp assistant. It monitors messages 24/7 — every incoming DM is a potential prompt injection vector. Docker Sandboxes isolate its runtime; Oktsec inspects the content it processes.

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
  nanoclaw:
    can_message: [reviewer]
    blocked_content: [credentials, pii, exfiltration, command-execution]
  reviewer:
    can_message: [nanoclaw]

quarantine:
  enabled: true
  expiry_hours: 24
```

### Start the stack

```bash
# 1. Start Oktsec
docker compose up -d

# 2. Create a sandboxed environment for NanoClaw
mkdir -p ~/nanoclaw-workspace
docker sandbox create --name nanoclaw shell ~/nanoclaw-workspace

# 3. Enter the sandbox and install NanoClaw
docker sandbox run nanoclaw
# Inside the sandbox:
cd ~/workspace
git clone https://github.com/qwibitai/nanoclaw
cd nanoclaw
npm install

# 4. Configure NanoClaw to route inter-agent messages through Oktsec
# Set OKTSEC_URL=http://host.docker.internal:8080 in the agent config
npm start
```

### What each layer protects

- **Docker Sandbox** prevents NanoClaw from accessing the host filesystem, other processes, or network resources beyond what's explicitly allowed
- **Docker credential proxy** keeps API keys out of the sandbox (the real key is never inside the VM)
- **Oktsec** scans every inter-agent message for prompt injection, credential leaks, PII, and exfiltration before delivery

### What Oktsec does NOT do here

Oktsec does not intercept NanoClaw's WhatsApp traffic or API calls. It only inspects messages that agents explicitly send through the `/v1/message` endpoint. For NanoClaw, this means the agent must be configured to route inter-agent communication through Oktsec.

## Defense in depth

| Layer | Protects against | Tool |
|-------|-----------------|------|
| 1. Docker Sandbox | Container escape, filesystem access, network pivoting | Docker |
| 2. Docker credential proxy | API key theft from inside the sandbox | Docker |
| 3. Identity verification | Agent impersonation | Oktsec (Ed25519) |
| 4. Policy enforcement | Unauthorized agent-to-agent communication | Oktsec (ACLs) |
| 5. Content scanning | Prompt injection, credential leaks, PII, exfiltration | Oktsec (151 rules) |
| 6. Audit trail | Post-incident forensics | Oktsec (SQLite) |

No single layer is sufficient. Docker Sandboxes without content inspection miss prompt injection. Oktsec without sandboxing can't prevent filesystem access. Use both.

## Current limitations

- **No transparent proxy**: Oktsec is a REST API, not an HTTP forward proxy. It cannot be used with Docker Sandbox's `--network-proxy` flag to transparently intercept traffic. Agents must explicitly call `/v1/message`.
- **Agent integration required**: Each agent needs to be configured to send inter-agent messages through Oktsec. This is not automatic.
- **Inbound messages not scanned**: Messages arriving from external sources (WhatsApp DMs, Slack messages) reach the agent directly. Oktsec only scans messages that pass through its API.
