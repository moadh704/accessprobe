"""Tests for report generation."""

import json
from html import escape
from pathlib import Path

from accessprobe.models import (
    Finding,
    FindingSeverity,
    Parameter,
    ParameterLocation,
    TestResult,
)
from accessprobe.reporter import ReportGenerator


def test_json_and_html_reports(tmp_path: Path) -> None:
    p = Parameter(name="user_id", location=ParameterLocation.QUERY, value=42)
    finding = Finding(
        parameter=p,
        tested_roles=["user", "admin"],
        is_vulnerable=True,
        severity=FindingSeverity.HIGH,
        evidence="test evidence",
        similarity_score=0.95,
        original_response_code=200,
        modified_response_code=200,
        details={"confidence": 0.91, "same_role": False, "value_changed": True},
    )
    tr = TestResult(
        parameter=p,
        findings=[finding],
        success=True,
        tested_sessions=["user", "admin"],
    )
    rep = ReportGenerator([tr])
    data = rep.to_dict()
    assert data["total_tests"] == 1
    assert data["vulnerable_findings"] == 1
    assert data["findings"][0]["parameter"] == "user_id"
    assert data["findings"][0]["value_changed"] is True

    jp = tmp_path / "r.json"
    hp = tmp_path / "r.html"
    rep.save_json(jp)
    rep.save_html(hp)
    assert jp.exists()
    assert "AccessProbe" in hp.read_text()
    assert "test evidence" in hp.read_text()
    assert json.loads(jp.read_text())["vulnerable_findings"] == 1


def test_html_report_escapes_untrusted_values(tmp_path: Path) -> None:
    p = Parameter(
        name="id",
        location=ParameterLocation.QUERY,
        value="<script>alert(1)</script>",
    )
    finding = Finding(
        parameter=p,
        tested_roles=["user", "admin"],
        is_vulnerable=True,
        severity=FindingSeverity.HIGH,
        evidence="<img src=x onerror=alert(1)>",
        details={"confidence": 0.9},
    )
    html = ReportGenerator(
        [TestResult(parameter=p, findings=[finding], success=True)]
    ).generate_html()
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x onerror=alert(1)>" not in html
    assert escape("<script>alert(1)</script>") in html
    assert escape("<img src=x onerror=alert(1)>") in html
