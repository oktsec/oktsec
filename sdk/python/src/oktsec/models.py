"""Data models for the oktsec SDK."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FindingSummary:
    """A triggered detection rule."""

    rule_id: str
    name: str
    severity: str
    category: str = ""
    match: str = ""


@dataclass
class MessageRequest:
    """Request payload for POST /v1/message."""

    from_agent: str
    to: str
    content: str
    timestamp: str
    signature: str = ""
    metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d: dict = {
            "from": self.from_agent,
            "to": self.to,
            "content": self.content,
            "timestamp": self.timestamp,
        }
        if self.signature:
            d["signature"] = self.signature
        if self.metadata:
            d["metadata"] = self.metadata
        return d


@dataclass
class MessageResponse:
    """Response from the oktsec proxy."""

    status: str
    message_id: str
    policy_decision: str
    rules_triggered: list[FindingSummary] = field(default_factory=list)
    verified_sender: bool = False
    quarantine_id: str = ""
    expires_at: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> MessageResponse:
        rules = [
            FindingSummary(
                rule_id=r.get("rule_id", ""),
                name=r.get("name", ""),
                severity=r.get("severity", ""),
                category=r.get("category", ""),
                match=r.get("match", ""),
            )
            for r in data.get("rules_triggered") or []
        ]
        return cls(
            status=data.get("status", ""),
            message_id=data.get("message_id", ""),
            policy_decision=data.get("policy_decision", ""),
            rules_triggered=rules,
            verified_sender=data.get("verified_sender", False),
            quarantine_id=data.get("quarantine_id", ""),
            expires_at=data.get("expires_at", ""),
        )


@dataclass
class HealthResponse:
    """Response from GET /health."""

    status: str
    version: str


class PolicyError(Exception):
    """Raised when the proxy rejects a message (4xx/5xx)."""

    def __init__(self, status_code: int, response: MessageResponse):
        self.status_code = status_code
        self.response = response
        super().__init__(
            f"oktsec: {response.status} (HTTP {status_code}, "
            f"decision={response.policy_decision}, id={response.message_id})"
        )
