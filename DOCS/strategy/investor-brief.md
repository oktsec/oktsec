# Oktsec — Investor Brief

**February 2026**

---

## The Problem

AI agents are the fastest-growing software category in history. 3 million agents are deployed across large US/UK enterprises, with 80.9% of organizations actively running agents in production. But security hasn't kept up:

- **88%** of organizations report confirmed or suspected AI agent security incidents in the past year (Gravitee, Feb 2026)
- **1.5 million** AI agents operate with zero security oversight
- **45.6%** of teams still use shared API keys for agent-to-agent authentication
- Only **21.9%** treat AI agents as independent, identity-bearing entities
- Only **29%** feel prepared to secure agentic AI deployments (Cisco, Feb 2026)

The result: agents talk to agents, call tools, relay data, and make decisions — with no identity verification, no policy enforcement, no audit trail, and no content inspection between them.

In September 2025, the first fully autonomous AI-orchestrated cyberattack was documented. In early 2026, the OpenClaw crisis exposed 21K+ instances to malicious marketplace exploits. Forrester predicts an agentic AI deployment will cause a publicly disclosed breach leading to employee dismissals in 2026.

**The agent-to-agent communication channel is the new attack surface, and it's completely unprotected.**

---

## The Solution

**Oktsec is the security proxy for AI agent communication.** A single binary that sits between agents, enforcing identity, policy, and content security on every message — with no LLM dependency, no cloud service, and no code changes.

```
Agent A  ──→  Oktsec Proxy  ──→  Agent B
              (verify, scan,
               enforce, audit)
```

### What it does

| Layer | What Oktsec enforces |
|-------|---------------------|
| **Identity** | Ed25519 cryptographic signatures on every message. Each agent has a unique keypair. No shared API keys. |
| **Policy** | YAML-defined ACLs: who can talk to whom, which tools they can call, what content is blocked. Default-deny mode. |
| **Content scanning** | 159 detection rules (prompt injection, credential leaks, exfiltration, supply chain attacks, SSRF, MCP attacks). Zero false-positive tolerance. |
| **Per-rule enforcement** | Block, quarantine for human review, flag, or ignore — configurable per rule. |
| **Audit trail** | Every message logged with sender, receiver, content hash, rules triggered, policy decision, latency. SQLite, <6ms queries at 1M rows. |
| **Real-time dashboard** | 7-page web UI with live event stream, agent topology graph, threat scoring, quarantine review, deployment audit. |

### How it deploys

```bash
oktsec discover          # Auto-detect Claude, Cursor, VS Code, OpenClaw, NanoClaw
oktsec init              # Generate config + Ed25519 keys
oktsec wrap              # Redirect agents through the proxy (one command)
oktsec serve             # Start — takes effect immediately
```

No SDK integration required. No agent code changes. Works with any MCP-compatible client (Claude Desktop, Cursor, VS Code, Cline, Windsurf) and agent frameworks (OpenClaw, NanoClaw).

---

## Market Opportunity

### The market is forming now

| Metric | Value | Source |
|--------|-------|--------|
| Agentic AI market (2026) | $10.2B | Acumen Research |
| Agentic AI market (2035) | $260.7B (43.3% CAGR) | Acumen Research |
| AI in cybersecurity (2025) | $29.6B | Precedence Research |
| AI in cybersecurity (2035) | $167.8B | Precedence Research |
| AI security funding (2025) | $6.34B (3x YoY) | Software Strategies Blog |
| AI cybersecurity CAGR | 74% | Gartner |

### Standards are formalizing

- **OWASP Top 10 for Agentic Applications** — Released December 2025. Oktsec's detection engine covers 9 of 10 categories.
- **NIST AI Agent Threat Taxonomy** — In development, announced December 2025. Oktsec's 41-check deployment audit aligns with NIST CSF 2.0.
- **Gartner Agentic AI TRiSM** — New formal category (Trust, Risk, and Security Management for agentic AI). Gartner predicts 25% of enterprise breaches will trace to AI agent abuse by 2028.

### MCP adoption is explosive

| Metric | Value |
|--------|-------|
| MCP SDK monthly downloads | 97M+ |
| MCP servers available | 5,800+ |
| MCP server download growth | 100K (Nov 2024) to 8M+ (Apr 2025) |
| Companies connecting agents to MCP | 43% today, 96% within 12 months |

Every MCP connection is an unmonitored communication channel. Oktsec intercepts all of them.

---

## Competitive Landscape

### Recent M&A and funding signals demand

| Event | Amount | Date |
|-------|--------|------|
| 7AI Series A (record for cybersecurity) | $130M | Dec 2025 |
| Noma Security Series B | $100M | Jul 2025 |
| Zenity Series B | $38M | Oct 2024 |
| Proofpoint acquires Acuvity | Undisclosed | Feb 2026 |
| Check Point acquires Lakera | Undisclosed | Q4 2025 |

### How Oktsec is different

| Competitor approach | Oktsec approach |
|-------------------|-----------------|
| Cloud SaaS, needs API integration | **Single binary, zero-integration deployment** |
| LLM-based content inspection | **Deterministic rule engine (159 rules, no hallucination, no latency)** |
| Platform lock-in | **Works with any MCP client, any agent framework** |
| Identity via API keys or OAuth | **Ed25519 cryptographic identity per agent** |
| No agent-to-agent focus | **Purpose-built for inter-agent communication** |
| Monitoring/alerting only | **Inline enforcement: block, quarantine, policy-as-code** |

**Key insight:** Existing solutions (Zenity, Noma, 7AI) focus on *enterprise AI governance* — monitoring LLM usage, preventing data leaks to ChatGPT, governing copilot behavior. None of them address the **agent-to-agent communication channel** as a dedicated security boundary with cryptographic identity, content scanning, and inline policy enforcement.

Oktsec is not an AI governance platform. It's an **agent firewall** — the Cloudflare of agent-to-agent traffic.

---

## Product Maturity

### v0.5.0 — Production ready

| Dimension | Status |
|-----------|--------|
| Codebase | 20,790 LOC Go, single binary, no CGO, no external deps at runtime |
| Tests | 306 test functions, 24 test files, race-detector clean |
| Detection rules | 159 rules across 15 categories (prompt injection, credential leak, exfiltration, SSRF, supply chain, MCP attacks, etc.) |
| Deployment audit | 41 security checks across Oktsec, OpenClaw, and NanoClaw |
| Dashboard | 7-page real-time web UI (overview, events, rules, agents, topology graph, audit, settings) |
| CLI | 19 commands covering full lifecycle (discover, init, wrap, serve, audit, quarantine, keys, etc.) |
| Platform support | Claude Desktop, Cursor, VS Code, Cline, Windsurf, OpenClaw, NanoClaw |
| Performance | 90K audit inserts/sec, <6ms queries at 1M rows, <500ms startup |
| CI/CD | GitHub Actions (lint, test, vet), GoReleaser, multi-arch Docker (amd64/arm64) |
| SDK | Go client library with Ed25519 signing |
| MCP server mode | 6 tools for AI agents to query security state |

### Release velocity

| Version | Date | Delta |
|---------|------|-------|
| v0.1.0 | Feb 20 | Initial release |
| v0.2.0 | Feb 22 | +2 days |
| v0.3.0 | Feb 22 | Same day |
| v0.4.0 | Feb 23 | +1 day |
| v0.5.0 | Feb 24 | +1 day |

5 releases in 5 days. The product moves fast.

---

## Technical Architecture

```
┌─────────────────────────────────────────────────────┐
│                    oktsec proxy                      │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐   │
│  │ Identity  │  │ Policy   │  │ Content Scanner  │   │
│  │ Ed25519   │  │ ACLs     │  │ 159 rules        │   │
│  │ verify    │→ │ enforce  │→ │ (Aguara engine)  │   │
│  └──────────┘  └──────────┘  └──────────────────┘   │
│        │              │               │              │
│        ▼              ▼               ▼              │
│  ┌──────────────────────────────────────────────┐    │
│  │              Verdict Pipeline                 │    │
│  │  rate limit → identity → ACL → scan →         │    │
│  │  rule overrides → escalation → verdict        │    │
│  └──────────────────────────────────────────────┘    │
│        │                                             │
│        ▼                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐   │
│  │ Audit    │  │ Webhooks │  │ Dashboard        │   │
│  │ SQLite   │  │ Slack,   │  │ 7 pages, SSE     │   │
│  │ WAL mode │  │ Discord  │  │ real-time         │   │
│  └──────────┘  └──────────┘  └──────────────────┘   │
└─────────────────────────────────────────────────────┘
```

**Key design decisions:**
- **In-process scanner** — Aguara runs as a library, not a subprocess. Zero network latency for content inspection.
- **Deterministic rules** — No LLM in the security path. Every decision is explainable and reproducible.
- **Pure Go, no CGO** — Single static binary. Deploys anywhere without dependencies.
- **Observe mode** — Gradual rollout: log everything, block nothing. Switch to enforce when ready.

---

## Security Pipeline (8 steps)

Every message passes through:

1. **Rate limiting** — Per-agent sliding window (prevents resource exhaustion)
2. **Identity verification** — Ed25519 signature validation
3. **Suspension check** — Compromised agents blocked instantly
4. **ACL enforcement** — Who can talk to whom
5. **Content scanning** — 159 rules (prompt injection, credentials, exfiltration, SSRF, etc.)
6. **Per-rule policy overrides** — Block, quarantine, flag, or ignore per rule ID
7. **History-based escalation** — 3+ blocks triggers quarantine, 5+ triggers block
8. **Verdict** — deliver, block, quarantine, or flag

---

## OWASP Alignment

Oktsec maps directly to the **OWASP Top 10 for Agentic Applications** (Dec 2025):

| OWASP Risk | Oktsec Coverage |
|------------|----------------|
| A01: Prompt Injection | 17 detection rules (PI-001 through PI-017) |
| A02: Tool Misuse | Per-agent tool allowlist + 11 MCP attack rules |
| A03: Excessive Permissions | ACL enforcement, default-deny policy |
| A04: Goal Hijacking | Inter-agent relay injection detection (IAP-001) |
| A05: Memory Poisoning | Conversation history poisoning detection (PI-007) |
| A06: Broken Trust Boundaries | Ed25519 identity, per-agent ACLs |
| A07: Supply Chain | 14 supply chain rules, MCP config scanning |
| A08: Identity Spoofing | Cryptographic identity, key revocation |
| A09: Insufficient Logging | Full audit trail, real-time dashboard |
| A10: Inadequate Error Handling | Panic recovery, graceful degradation |

---

## Roadmap

### Q1 2026 — Foundation (DONE)

- [x] Core proxy with identity, policy, scanning, audit
- [x] Dashboard with real-time monitoring
- [x] Multi-platform support (5 MCP clients + 2 agent frameworks)
- [x] 159 detection rules
- [x] Policy-as-code (per-rule enforcement overrides)
- [x] Deployment audit (41 checks)
- [x] Go SDK + MCP server mode

### Q2 2026 — Enterprise Hardening

- [ ] **Prometheus/OpenTelemetry metrics** — /metrics endpoint for Grafana/Datadog integration
- [ ] **Rule analytics dashboard** — Which rules fire most, false positive rates, trend visualization
- [ ] **Webhook retry with exponential backoff** — Guaranteed delivery for Slack/PagerDuty/Opsgenie
- [ ] **Agent groups and role-based policies** — Apply rules to teams, not individual agents
- [ ] **Policy diff and rollback** — Track config changes, audit who changed what, one-click rollback
- [ ] **Python and TypeScript SDKs** — Expand beyond Go ecosystem
- [ ] **SARIF CI integration** — `oktsec audit --format sarif` already works; add GitHub Actions marketplace action

### Q3 2026 — Scale and Ecosystem

- [ ] **Multi-instance federation** — Shared audit trail across multiple proxy instances (distributed deployments)
- [ ] **Centralized management plane** — Single dashboard for fleet of proxies
- [ ] **Plugin system for custom scanners** — WASM-based rule extensions beyond regex
- [ ] **Slack/Teams bot** — Interactive quarantine review (approve/reject from chat)
- [ ] **API key authentication mode** — Simpler alternative to Ed25519 for rapid onboarding
- [ ] **SOC2/ISO 27001 documentation** — Compliance artifacts for enterprise procurement

### Q4 2026 — Platform

- [ ] **Hosted SaaS option** — Managed proxy with zero-setup deployment
- [ ] **Agent marketplace security scanning** — Vet third-party agents before deployment
- [ ] **Real-time threat intelligence feed** — Community-contributed detection rules
- [ ] **Runtime behavioral analysis** — Baseline agent behavior, detect anomalies beyond static rules
- [ ] **Enterprise SSO** — SAML/OIDC for dashboard access

---

## Why Now

Three forces converging:

1. **Adoption curve** — 3M agents deployed, 96% of companies connecting to MCP within 12 months. The infrastructure is being built right now.

2. **Regulatory pressure** — OWASP published the Top 10 for Agentic Applications in December 2025. NIST is building an AI agent threat taxonomy. Gartner predicts 25% of enterprise breaches from agent abuse by 2028. Compliance requirements are forming.

3. **No incumbent** — Every major cybersecurity vendor (Cisco, Check Point, Proofpoint, CyberArk) is scrambling to add AI agent security through acquisitions. But none have a purpose-built agent-to-agent security proxy. The agent communication channel — the most critical attack surface — remains unprotected.

Oktsec is the **first mover in agent-to-agent communication security** with a production-ready, zero-dependency solution shipping today.

---

## Open Source Strategy

Oktsec is **open source (Apache 2.0)**. This is a deliberate GTM strategy:

1. **Adoption** — Security teams evaluate tools hands-on. Open source eliminates procurement friction.
2. **Trust** — Security products that hide their code face skepticism. Transparency builds trust.
3. **Community** — Detection rules improve with community contributions. More eyes = better coverage.
4. **Enterprise upsell** — Open core model. Free: proxy + CLI + dashboard. Paid: managed SaaS, fleet management, SSO, SLA, support.

The playbook: **Snyk** (open source security scanner → $8.5B valuation), **Cloudflare** (free tier → enterprise platform), **HashiCorp** (open source infrastructure → $5.6B acquisition by IBM).

---

## Ecosystem & Integrations

| Integration | Type | Status |
|------------|------|--------|
| Claude Desktop | MCP client | Supported |
| Cursor | MCP client | Supported |
| VS Code | MCP client | Supported |
| Cline | MCP client | Supported |
| Windsurf | MCP client | Supported |
| OpenClaw | Agent framework | Supported (18 audit checks) |
| NanoClaw | Agent framework | Supported (7 audit checks) |
| Docker Sandbox | Container runtime | Forward proxy mode |
| Slack | Notifications | Webhook integration |
| Discord | Notifications | Webhook integration |
| GitHub Actions | CI/CD | SARIF output for code scanning |
| Aguara | Detection engine | In-process library (138 rules) |

---

## Contact

**Project:** github.com/oktsec/oktsec
**Organization:** github.com/oktsec
