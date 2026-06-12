# AARM Alignment

[AARM (Autonomous Action Runtime Management)](https://aarm.dev) is the Cloud Security Alliance's open runtime security standard for autonomous AI agents. Oktsec's pipeline aligns with the AARM Core requirements (R1–R6).

## Decision vocabulary

AARM R4 requires the policy engine to be capable of five authorization decisions. Oktsec's verdicts map directly:

| Oktsec verdict | Audit status | AARM decision | Meaning |
|---|---|---|---|
| `clean` | `delivered` | **ALLOW** | The action proceeds unchanged. |
| `flag` | `delivered` | **ALLOW** (annotated) | The action proceeds; the receipt carries a warning. |
| `modify` | `modified` | **MODIFY** | Detected content is redacted in transit; the modified action proceeds. |
| `step_up` | `step_up` | **STEP_UP** | The action is held pending explicit additional approval (e.g. a spend over the tool policy's approval threshold). |
| `quarantine` | `quarantined` | **DEFER** | The action is held for human review of its content. |
| `block` | `blocked` | **DENY** | The action is rejected. |

### MODIFY: in-transit redaction

Listing scan categories under an agent's `redact_content` delivers messages with those detections redacted instead of blocking them. Block and quarantine always win over modify — redaction only applies to content that would otherwise deliver — so redacting a category whose findings block by default (for example `credential-leak`, which is critical) is paired with a per-rule override that lowers the verdict:

```yaml
rules:
  - id: CRED_002          # AWS access key
    action: allow-and-flag
agents:
  support-agent:
    blocked_content:
      - memory-poisoning
    redact_content:
      - credential-leak
```

A message carrying a detected AWS key is then delivered with the match replaced by `[REDACTED]`, the response carries the modified content (`modified_content`), and the receipt records `status: modified`, `policy_decision: content_redacted` and the findings. The receipt keeps the hash of the original content — what the sender signed — so the modification itself is evidenced. Use `oktsec rules list` to see each rule's category.

### STEP_UP: approval thresholds

A tool policy with `require_approval_above` produces a distinct `step_up` decision when the threshold is exceeded, instead of folding into quarantine:

```yaml
agents:
  payments-agent:
    tool_policies:
      transfer_funds:
        require_approval_above: 500
```

## Core requirements map

| Req | Requirement | Oktsec mechanism |
|---|---|---|
| R1 | Pre-execution interception | The MCP gateway, stdio proxy and HTTP proxy intercept every message and tool call before delivery. The hooks surface is observational telemetry and is not part of this claim. |
| R2 | Context accumulation | Declared intent per message, audit history, history-based verdict escalation, delegation chains and session tracking. |
| R3 | Policy evaluation with intent alignment | The pipeline validates declared intent against content (`require_intent: true` enforces declaration). |
| R4 | Five authorization decisions | The verdict vocabulary above. |
| R5 | Tamper-evident receipts | Every evaluated action writes a hash-chained audit entry (SHA-256) signed by the proxy's Ed25519 key, carrying decision, timestamp, findings and latency. |
| R6 | Identity binding | Agents sign messages with per-agent Ed25519 keys over a canonical payload; the receipt records the verification result and is itself proxy-signed. |
