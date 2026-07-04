"""Reporting module for generating JSON and HTML reports."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Template

from .models import TestResult, Finding


class ReportGenerator:
    """Generates reports from test results."""

    def __init__(self, results: list[TestResult]) -> None:
        self.results = results
        self.generated_at = datetime.now().isoformat()

    def to_dict(self) -> dict[str, Any]:
        """Convert results to a serializable dictionary."""
        findings_data = []
        for result in self.results:
            for finding in result.findings:
                findings_data.append(
                    {
                        "parameter": finding.parameter.name,
                        "location": finding.parameter.location.value,
                        "tested_value": str(finding.parameter.value),
                        "tested_roles": finding.tested_roles,
                        "is_vulnerable": finding.is_vulnerable,
                        "severity": finding.severity.value,
                        "evidence": finding.evidence,
                        "similarity_score": finding.similarity_score,
                        "original_status": finding.original_response_code,
                        "modified_status": finding.modified_response_code,
                    }
                )

        return {
            "generated_at": self.generated_at,
            "total_tests": len(self.results),
            "total_findings": len(findings_data),
            "vulnerable_findings": sum(1 for f in findings_data if f["is_vulnerable"]),
            "findings": findings_data,
        }

    def to_json(self, indent: int = 2) -> str:
        """Return JSON report as string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def save_json(self, filepath: str | Path) -> None:
        """Save JSON report to file."""
        Path(filepath).write_text(self.to_json())

    def generate_html(self) -> str:
        """Generate a simple but clean HTML report."""
        template_str = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>AccessProbe Report</title>
            <style>
                body { font-family: system-ui, sans-serif; margin: 40px; background: #f8f9fa; }
                h1 { color: #1e40af; }
                .summary { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                table { width: 100%; border-collapse: collapse; margin-top: 20px; background: white; }
                th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
                th { background: #1e40af; color: white; }
                .vulnerable { color: #dc2626; font-weight: bold; }
                .safe { color: #16a34a; }
            </style>
        </head>
        <body>
            <h1>AccessProbe Report</h1>
            <div class="summary">
                <p><strong>Generated:</strong> {{ generated_at }}</p>
                <p><strong>Total Tests:</strong> {{ total_tests }}</p>
                <p><strong>Vulnerable Findings:</strong> <span class="vulnerable">{{ vulnerable_findings }}</span></p>
            </div>

            <table>
                <tr>
                    <th>Parameter</th>
                    <th>Value</th>
                    <th>Roles Tested</th>
                    <th>Vulnerable</th>
                    <th>Severity</th>
                    <th>Evidence</th>
                </tr>
                {% for f in findings %}
                <tr>
                    <td>{{ f.parameter }}</td>
                    <td>{{ f.tested_value }}</td>
                    <td>{{ f.tested_roles | join(', ') }}</td>
                    <td class="{{ 'vulnerable' if f.is_vulnerable else 'safe' }}">
                        {{ 'Yes' if f.is_vulnerable else 'No' }}
                    </td>
                    <td>{{ f.severity | upper }}</td>
                    <td>{{ f.evidence or '-' }}</td>
                </tr>
                {% endfor %}
            </table>
        </body>
        </html>
        """

        template = Template(template_str)
        data = self.to_dict()
        return template.render(**data)

    def save_html(self, filepath: str | Path) -> None:
        """Save HTML report to file."""
        Path(filepath).write_text(self.generate_html())

    def print_summary(self) -> None:
        """Print a quick summary to console."""
        data = self.to_dict()
        print(f"AccessProbe Report - {data['generated_at']}")
        print(f"Total Tests: {data['total_tests']}")
        print(f"Vulnerable Findings: {data['vulnerable_findings']}")
