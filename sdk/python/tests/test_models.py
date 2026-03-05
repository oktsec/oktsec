"""Tests for data models."""

from oktsec.models import FindingSummary, MessageResponse, PolicyError


def test_message_response_from_dict():
    data = {
        "status": "delivered",
        "message_id": "abc-123",
        "policy_decision": "allow",
        "rules_triggered": [
            {
                "rule_id": "IAP-001",
                "name": "Prompt Injection",
                "severity": "critical",
                "category": "injection",
                "match": "IGNORE ALL",
            }
        ],
        "verified_sender": True,
        "quarantine_id": "",
        "expires_at": "",
    }

    resp = MessageResponse.from_dict(data)

    assert resp.status == "delivered"
    assert resp.message_id == "abc-123"
    assert resp.policy_decision == "allow"
    assert resp.verified_sender is True
    assert len(resp.rules_triggered) == 1
    assert resp.rules_triggered[0].rule_id == "IAP-001"
    assert resp.rules_triggered[0].severity == "critical"


def test_message_response_from_dict_empty_rules():
    data = {
        "status": "blocked",
        "message_id": "xyz",
        "policy_decision": "acl_denied",
        "rules_triggered": None,
        "verified_sender": False,
    }

    resp = MessageResponse.from_dict(data)
    assert resp.rules_triggered == []
    assert resp.quarantine_id == ""


def test_message_response_from_dict_with_expires_at():
    data = {
        "status": "quarantined",
        "message_id": "q-1",
        "policy_decision": "content_quarantined",
        "expires_at": "2026-03-06T12:00:00Z",
    }

    resp = MessageResponse.from_dict(data)
    assert resp.expires_at == "2026-03-06T12:00:00Z"


def test_policy_error_message():
    resp = MessageResponse(
        status="blocked",
        message_id="err-1",
        policy_decision="content_blocked",
    )
    err = PolicyError(403, resp)

    assert "blocked" in str(err)
    assert "403" in str(err)
    assert "content_blocked" in str(err)
    assert err.status_code == 403
    assert err.response is resp


def test_finding_summary_defaults():
    f = FindingSummary(rule_id="R1", name="Test", severity="low")
    assert f.category == ""
    assert f.match == ""
