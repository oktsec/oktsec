# Detection Rules

Oktsec includes **175 detection rules** across 15 categories, compiled into the binary. No external files to deploy.

## Rule sources

| Source | Count | Prefix | Description |
|--------|-------|--------|-------------|
| [Aguara](https://github.com/garagon/aguara) | 148 | `PI-`, `CL-`, `EX-`, `CE-`, etc. | Open-source detection engine for AI security threats |
| Inter-agent protocol | 12 | `IAP-` | Oktsec-specific rules for agent-to-agent attacks |
| OpenClaw config | 15 | `OCLAW-` | Configuration security checks for OpenClaw installations |

## Aguara categories

The 148 Aguara rules cover these categories:

| Category | Description | Example threat |
|----------|-------------|----------------|
| `prompt-injection` | Direct and indirect prompt injection | "Ignore previous instructions and..." |
| `credential-leak` | API keys, tokens, passwords in transit | AWS keys, GitHub tokens, SSH keys |
| `exfiltration` | Data exfiltration patterns | Encoding data in URLs, DNS tunneling patterns |
| `command-execution` | Shell command injection | `$(rm -rf /)`, backtick injection |
| `mcp-attack` | MCP protocol-level attacks | Malicious tool descriptions, server impersonation |
| `mcp-config` | MCP configuration weaknesses | Overly permissive tool access, missing auth |
| `supply-chain` | Dependency and package attacks | Typosquatting, malicious install scripts |
| `ssrf-cloud` | SSRF targeting cloud metadata | `http://169.254.169.254/latest/meta-data` |
| `indirect-injection` | Injection via external content | Poisoned documents, hidden instructions in HTML |
| `unicode-attack` | Unicode-based evasion techniques | Homoglyph attacks, invisible characters |
| `third-party-content` | Risks from third-party data | Untrusted API responses with embedded instructions |
| `external-download` | Suspicious download patterns | Binary downloads, script execution from URLs |

---

## Inter-agent protocol rules (IAP)

These 12 rules are specific to agent-to-agent communication — the unique attack surface that oktsec was built to protect.

### Agent message rules

| Rule | Severity | Description |
|------|----------|-------------|
| `IAP-001` | Critical | **Relay injection** — agent-to-agent hijacking via embedded instructions |
| `IAP-002` | High | **PII in agent messages** — SSNs, passport numbers, personal data in transit |
| `IAP-003` | Critical | **Credentials in agent messages** — API keys, tokens, passwords between agents |
| `IAP-004` | High | **System prompt extraction** — attempts to extract another agent's system prompt |
| `IAP-005` | High | **Privilege escalation** — an agent trying to gain elevated permissions |
| `IAP-006` | High | **Data exfiltration via relay** — using an agent as a proxy to leak data |

### Tool description rules

These catch attacks embedded in MCP tool descriptions — a vector where a compromised MCP server poisons tool metadata to hijack agents:

| Rule | Severity | Description |
|------|----------|-------------|
| `IAP-007` | Critical | **Tool description prompt injection** — hijacking instructions in tool descriptions |
| `IAP-008` | Critical | **Tool description data exfiltration** — exfil URLs embedded in tool descriptions |
| `IAP-009` | High | **Tool description privilege escalation** — privilege escalation in tool metadata |
| `IAP-010` | High | **Tool description shadowing** — a tool that mimics another tool's name/behavior |
| `IAP-011` | Critical | **Tool description hidden commands** — concealed execution instructions |
| `IAP-012` | High | **Tool name typosquatting** — tool names designed to confuse (`read_flie` vs `read_file`) |

---

## OpenClaw config rules (OCLAW)

15 rules for detecting security issues in OpenClaw installations.

| Rule | Severity | Description |
|------|----------|-------------|
| `OCLAW-001` | Critical | Full tool profile without restrictions |
| `OCLAW-002` | High | Gateway exposed to network |
| `OCLAW-003` | High | Open DM policy |
| `OCLAW-004` | Critical | Exec/shell tool without sandbox |
| `OCLAW-005` | Critical | Path traversal in `$include` |
| `OCLAW-006` | High | Gateway missing authentication |
| `OCLAW-007` | High | Hardcoded credentials in config |
| `OCLAW-008` | Critical | Dangerous security override flag |
| `OCLAW-009` | Critical | Sandbox mode disabled |
| `OCLAW-010` | High | Workspace-only restriction disabled |
| `OCLAW-011` | High | Wildcard in access allowlist |
| `OCLAW-012` | High | Dangerous tool grants |
| `OCLAW-013` | High | Sensitive file path in transit |
| `OCLAW-014` | Medium | mDNS full disclosure mode |
| `OCLAW-015` | High | Browser control host access |

---

## Verdict escalation

The pipeline maps findings to verdicts in four stages:

### 1. Severity mapping (default)

| Severity | Default verdict |
|----------|----------------|
| Critical | **block** (403) |
| High | **quarantine** (202) |
| Medium | **flag** (200, logged) |
| Low | **clean** (200) |

### 2. Blocked content (per-agent)

If a finding's category matches the agent's `blocked_content` list, the verdict is escalated to **block** regardless of severity:

```yaml
agents:
  researcher:
    blocked_content: [credentials, pii]
    # Any credentials or PII finding → block, even if medium severity
```

### 3. History escalation

Based on recent behavior within a 1-hour window:

| Condition | Escalation |
|-----------|------------|
| 3+ blocks/quarantines + new flagged content | Flag → **quarantine** |
| 5+ blocks/quarantines + new flagged content | Flag → **block** |

This catches agents that repeatedly probe boundaries with slightly-below-threshold content.

### 4. Rule overrides (config)

Per-rule `action` in config can force any verdict, overriding all other logic:

```yaml
rules:
  - id: "IAP-001"
    action: "block"       # always block, regardless of severity mapping
  - id: "PI-003"
    action: "ignore"      # disable this rule entirely
  - id: "CL-002"
    action: "allow-and-flag"  # deliver but log
```

Override actions:

| Action | Effect |
|--------|--------|
| `block` | Reject the message (403) |
| `quarantine` | Hold for human review (202) |
| `allow-and-flag` | Deliver but log as flagged (200) |
| `ignore` | Remove the finding entirely — rule is disabled |

---

## Category webhooks

Set default webhook channels for all rules in a category:

```yaml
category_webhooks:
  - category: credential-leak
    notify: [slack-security]
  - category: prompt-injection
    notify: [slack-security]
  - category: inter-agent
    notify: [slack-security, discord-alerts]
```

Rules with explicit `notify` take precedence over category-level webhooks.

---

## Custom rules

Add org-specific detection rules by setting `custom_rules_dir`:

```yaml
custom_rules_dir: ./custom-rules
```

Rules follow the [Aguara YAML schema](https://github.com/garagon/aguara). Example custom rule:

```yaml
id: ORG-001
name: "Internal API key pattern"
description: "Detects our org's internal API key format"
severity: critical
category: credentials
targets: ["*.md", "*.txt", "*.json"]
match_mode: any
patterns:
  - type: regex
    value: "(?i)orgkey_[a-z0-9]{32}"
examples:
  true_positive:
    - "Use this key: orgkey_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
  false_positive:
    - "The orgkey format is documented in the wiki"
```

Guidelines:

- Use `IAP-` prefix for inter-agent rules, org-specific prefix for custom rules
- Always include `true_positive` and `false_positive` examples
- Test with `oktsec rules --explain ORG-001` after adding

---

## CLI

```bash
oktsec rules                     # List all 175 rules with severity
oktsec rules --explain IAP-001   # Show rule patterns, examples, and description
```

### Inline testing (dashboard)

The dashboard Rules page includes an inline tester — paste any content and test it against a specific rule to see if it matches. Useful for tuning custom rules and verifying false positive/negative behavior.
