"""Tests for ownership map and privileged-role false-positive suppression."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from accessprobe.cli import parse_own_ids
from accessprobe.detector import IDORDetector
from accessprobe.models import Finding, FindingSeverity, Parameter, ParameterLocation
from accessprobe.session import SessionManager
from accessprobe.tester import IDORTester
from accessprobe.models import UserSession


def mock_resp(code: int, body: str) -> MagicMock:
    r = MagicMock()
    r.status_code = code
    r.content = body.encode()
    r.text = body
    r.headers = {}
    return r


def test_parse_own_ids() -> None:
    assert parse_own_ids("alice=1;bob=2,20") == {
        "alice": ["1"],
        "bob": ["2", "20"],
    }
    assert parse_own_ids(None) == {}
    assert parse_own_ids("") == {}


def test_suppress_self_access() -> None:
    sm = SessionManager()
    sm.add_session(UserSession(name="bob", cookies={}))
    tester = IDORTester(sm, own_ids={"bob": {"2"}})
    param = Parameter(name="user_id", location=ParameterLocation.QUERY, value="2")
    finding = Finding(
        parameter=param,
        tested_roles=["alice", "bob"],
        is_vulnerable=True,
        severity=FindingSeverity.HIGH,
        evidence="would be FP",
        details={"confidence": 0.96},
    )
    out = tester._apply_context_filters(finding, test_role="bob", test_value="2")
    assert out.is_vulnerable is False
    assert out.details.get("suppressed") == "self_access"


def test_suppress_privileged_role() -> None:
    sm = SessionManager()
    tester = IDORTester(sm, privileged_roles={"admin"})
    param = Parameter(name="user_id", location=ParameterLocation.QUERY, value="1")
    finding = Finding(
        parameter=param,
        tested_roles=["alice", "admin"],
        is_vulnerable=True,
        severity=FindingSeverity.HIGH,
        evidence="admin can read",
        details={"confidence": 0.9},
    )
    out = tester._apply_context_filters(finding, test_role="admin", test_value="1")
    assert out.is_vulnerable is False
    assert out.details.get("suppressed") == "privileged_role"


def test_noise_candidates_filtered() -> None:
    sm = SessionManager()
    tester = IDORTester(sm)
    values = tester._generate_candidate_values(
        "1",
        '{"user_id":1,"private_notes":"x","email":"a@b.com","createdAt":"2026-08-05T14"}',
    )
    as_str = {str(v) for v in values}
    assert "private_notes" not in as_str
    assert "email" not in as_str
    assert "1" in as_str
    assert "2" in as_str  # +1 mutation


def test_keep_true_horizontal_idor() -> None:
    """Ownership must not suppress foreign object access."""
    sm = SessionManager()
    tester = IDORTester(sm, own_ids={"alice": {"1"}})
    param = Parameter(name="user_id", location=ParameterLocation.QUERY, value="2")
    finding = Finding(
        parameter=param,
        tested_roles=["alice", "alice"],
        is_vulnerable=True,
        severity=FindingSeverity.HIGH,
        evidence="Horizontal IDOR",
        details={"confidence": 1.0},
    )
    out = tester._apply_context_filters(finding, test_role="alice", test_value="2")
    assert out.is_vulnerable is True
