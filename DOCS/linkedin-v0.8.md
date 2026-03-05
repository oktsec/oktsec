# LinkedIn Post - Oktsec v0.8.0

---

Just shipped Oktsec v0.8.0 - the biggest release yet.

Oktsec is an open-source security proxy for AI agent communication. It sits between your agents and their MCP servers, scanning every tool call and message for prompt injection, credential leaks, data exfiltration, and 170+ other threats. Single binary, no LLM, deterministic.

What's new in v0.8:

One-command setup. Run `oktsec setup` and it discovers every MCP server on your machine, generates a security config, and wraps all 13 supported clients (Claude Desktop, Cursor, VS Code, and more) in under 30 seconds. From install to first scanned message in 2 minutes.

Python SDK. Sync and async clients with Ed25519 signing. Most agent frameworks are Python - now they have a native client.

Prometheus metrics. Six metric families tracking verdicts, latency, rule triggers, and quarantine state. Plug into Grafana and you have real-time visibility into your agent security posture.

Mobile-ready dashboard. Full redesign with responsive layout, rule detail pages with inline testing, per-category webhook config, and a tabbed settings page for editing your entire security policy from the browser.

MCP gateway management. Add, edit, and monitor backend MCP servers directly from the dashboard. Health checks, tool inventory, and per-server configuration.

175 detection rules covering every OWASP Top 10 category for agentic applications: prompt injection, tool misuse, excessive permissions, goal hijacking, supply chain attacks, identity spoofing, and more.

The full security pipeline - rate limiting, Ed25519 identity, ACL enforcement, content scanning, quarantine, anomaly detection - runs on every message and tool call. No cloud dependency. No API keys to manage. No code changes to your agents.

If you're running MCP servers or building multi-agent systems, your agent communication channel is likely unprotected. That's what Oktsec fixes.

Apache 2.0. Try it: github.com/oktsec/oktsec

#cybersecurity #AI #agents #MCP #opensource #agenticsecurity

---

## Alt: Shorter version

Shipped Oktsec v0.8.0.

One command to secure every MCP server on your machine. 175 detection rules. Zero code changes.

What's new:
- `oktsec setup` - discovers and wraps all MCP clients in seconds
- Python SDK with Ed25519 signing
- Prometheus /metrics endpoint
- Mobile-ready dashboard with gateway management
- Full OWASP Top 10 agentic coverage

30K lines of Go. Single binary. No LLM in the security path.

Every tool call your agents make flows through a 9-stage pipeline: rate limit, identity verification, ACL, content scan, quarantine, anomaly detection.

Open source (Apache 2.0): github.com/oktsec/oktsec

#cybersecurity #AI #agents #MCP #opensource
