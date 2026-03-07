# Use Cases

Oktsec solves real security problems in AI agent deployments. These aren't theoretical — they're the attack patterns seen in production multi-agent systems.

---

## Who is this for?

<div class="grid" markdown>

<div class="card" markdown>

### :material-account-group: Multi-agent teams

You have agents coordinating work — a planner, a coder, a reviewer. You need to ensure they can't hijack each other or leak data across trust boundaries.

[Multi-Agent Pipeline :material-arrow-right:](multi-agent-pipeline.md)

</div>

<div class="card" markdown>

### :material-server-security: MCP server operators

You expose tools (filesystem, database, APIs) to AI agents via MCP. You need to control which agents access which tools, and scan every tool call.

[MCP Server Hardening :material-arrow-right:](mcp-hardening.md)

</div>

<div class="card" markdown>

### :material-shield-lock-outline: Security-conscious teams

Your agents make outbound HTTP requests. You need to ensure they don't exfiltrate credentials, PII, or sensitive data to unauthorized endpoints.

[Egress DLP :material-arrow-right:](egress-dlp.md)

</div>

</div>

---

## Common attack patterns Oktsec catches

| Attack | Rule | Verdict | What happens |
|--------|------|---------|-------------|
| Agent A tells Agent B to ignore its system prompt | IAP-001 (critical) | **Block** | Message rejected, webhook alert |
| Credentials embedded in agent messages | IAP-003 (critical) | **Block** | Message rejected, audit logged |
| Agent tries to extract another agent's system prompt | IAP-004 (high) | **Quarantine** | Held for human review |
| MCP tool description contains hidden instructions | IAP-007 (critical) | **Block** | Tool call rejected |
| Tool name typosquatting (`read_flie` vs `read_file`) | IAP-012 (high) | **Quarantine** | Tool call held for review |
| Outbound HTTP request contains API keys | Aguara credential rules | **Block** | Egress request blocked |
| Agent sends data to unauthorized domain | Per-agent egress policy | **Block** | Request blocked at forward proxy |
| Same agent triggers 5+ blocks in an hour | History escalation | **Block** | All future content auto-escalated |

---

## How teams deploy Oktsec

=== "Development"

    ```bash
    oktsec setup
    oktsec serve
    ```

    Zero config. Discovers your MCP servers, wraps them, starts in **observe mode**. Review activity in the dashboard before enabling enforcement.

=== "Staging"

    ```yaml
    # oktsec.yaml
    identity:
      require_signature: true
    default_policy: deny
    agents:
      planner:
        can_message: [coder, reviewer]
      coder:
        can_message: [planner]
        allowed_tools: [read_file, write_file, run_tests]
        blocked_content: [credentials]
      reviewer:
        can_message: [planner]
        allowed_tools: [read_file, search_files]
    ```

    Enforce signatures, default-deny unknown agents, restrict tool access and content categories per agent.

=== "Production"

    ```yaml
    identity:
      require_signature: true
    default_policy: deny
    rate_limit:
      per_agent: 100
      window: 60
    anomaly:
      risk_threshold: 50
      auto_suspend: true
    forward_proxy:
      enabled: true
      scan_requests: true
      blocked_domains: [pastebin.com, transfer.sh]
    webhooks:
      - name: slack-security
        url: https://hooks.slack.com/services/xxx
        events: [blocked, quarantined, agent_risk_elevated]
    ```

    Full enforcement with rate limiting, anomaly detection with auto-suspension, egress DLP, and Slack alerts on security events.
