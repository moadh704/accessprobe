"""Tests for IDOR detection logic."""

from unittest.mock import MagicMock

from accessprobe.detector import IDORDetector
from accessprobe.models import FindingSeverity, Parameter, ParameterLocation


def mock_resp(code: int, body: str, headers: dict | None = None) -> MagicMock:
    r = MagicMock()
    r.status_code = code
    r.content = body.encode()
    r.text = body
    r.headers = headers or {}
    return r


def test_privilege_escalation_403_to_200() -> None:
    det = IDORDetector()
    a = det.analyze_responses(
        mock_resp(403, "Forbidden"),
        mock_resp(200, "Welcome admin dashboard profile settings"),
        "user",
        "admin",
    )
    assert a["is_vulnerable"] is True
    assert a["confidence"] >= 0.9
    assert a["severity"] == FindingSeverity.HIGH


def test_horizontal_idor_same_role_different_id() -> None:
    det = IDORDetector()
    body_a = '{"user_id":1,"name":"Alice","email":"a@x.com","profile":true}'
    body_b = '{"user_id":2,"name":"Bob","email":"b@x.com","profile":true}'
    a = det.analyze_responses(
        mock_resp(200, body_a),
        mock_resp(200, body_b),
        "user",
        "user",
        value_changed=True,
        same_role=True,
    )
    assert a["is_vulnerable"] is True
    assert a["confidence"] >= 0.75
    assert a["severity"] == FindingSeverity.HIGH


def test_same_value_both_200_is_lead_for_triage() -> None:
    """Cross-role same-ID success is a lead; ownership/privileged filters suppress FPs."""
    det = IDORDetector()
    body = '{"user_id":1,"name":"Alice","email":"a@x.com","profile":true}'
    a = det.analyze_responses(
        mock_resp(200, body),
        mock_resp(200, body),
        "user",
        "admin",
        value_changed=False,
        same_role=False,
    )
    assert a["is_vulnerable"] is True
    assert a["confidence"] >= 0.65


def test_none_response() -> None:
    det = IDORDetector()
    a = det.analyze_responses(None, mock_resp(200, "ok"), "a", "b")
    assert a["is_vulnerable"] is False


def test_create_finding() -> None:
    det = IDORDetector()
    analysis = det.analyze_responses(
        mock_resp(403, "no"),
        mock_resp(200, "yes admin dashboard"),
        "user",
        "admin",
    )
    p = Parameter(name="id", location=ParameterLocation.QUERY, value=1)
    finding = det.create_finding(p, analysis, "user", "admin")
    assert finding.is_vulnerable
    assert "admin" in finding.tested_roles
    assert finding.details.get("confidence", 0) > 0


def test_min_confidence_filter() -> None:
    det = IDORDetector(min_confidence=0.99)
    # Large length-diff only yields ~0.68 confidence → filtered out
    a = det.analyze_responses(
        mock_resp(200, "x" * 100),
        mock_resp(200, "Welcome admin " + ("y" * 2000)),
        "user",
        "admin",
        value_changed=True,
    )
    assert a["is_vulnerable"] is False
