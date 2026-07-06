"""Reporting module with improved HTML output."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Template

from .models import TestResult, Finding


class ReportGenerator:
    """Generates professional JSON and HTML reports."""

    def __init__(self, results: list[TestResult]) -> None:
        self.results = results
        self.generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self) -> dict[str, Any]:
        findings_data = []
        for result in self.results:
            for finding in result.findings:
                conf = finding.details.get("confidence", 0.0) if finding.details else 0.0
                findings_data.append(
                    {
                        "parameter": finding.parameter.name,
                        "location": finding.parameter.location.value,
                        "tested_value": str(finding.parameter.value),
                        "tested_roles": finding.tested_roles,
                        "is_vulnerable": finding.is_vulnerable,
                        "severity": finding.severity.value,
                        "confidence": conf,
                        "evidence": finding.evidence,
                        "similarity_score": finding.similarity_score,
                        "original_status": finding.original_response_code,
                        "modified_status": finding.modified_response_code,
                    }
                )

        vulnerable_count = sum(1 for f in findings_data if f["is_vulnerable"])

        return {
            "generated_at": self.generated_at,
            "total_tests": len(self.results),
            "total_findings": len(findings_data),
            "vulnerable_findings": vulnerable_count,
            "findings": findings_data,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def save_json(self, filepath: str | Path) -> None:
        Path(filepath).write_text(self.to_json())

    def generate_html(self) -> str:
        template_str = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>AccessProbe Report</title>
            <style>
                @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&amp;family=Space+Grotesk:wght@500;600&amp;display=swap');
                
                :root {
                    --primary: #3b82f6;
                }
                
                body {
                    font-family: 'Inter', system_ui, sans-serif;
                    background: #0f172a;
                    color: #e2e8f0;
                    margin: 0;
                    padding: 40px 20px;
                    line-height: 1.6;
                }
                
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                }
                
                h1 {
                    font-family: 'Space Grotesk', sans-serif;
                    color: #fff;
                    font-size: 2.5rem;
                    margin-bottom: 8px;
                }
                
                .subtitle {
                    color: #64748b;
                    font-size: 1.1rem;
                    margin-bottom: 40px;
                }
                
                .summary {
                    background: #1e2937;
                    border-radius: 16px;
                    padding: 32px;
                    margin-bottom: 40px;
                    border: 1px solid #334155;
                }
                
                .summary-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 24px;
                }
                
                .stat {
                    text-align: center;
                }
                
                .stat-value {
                    font-size: 2.25rem;
                    font-weight: 700;
                    color: #3b82f6;
                }
                
                .stat-label {
                    color: #94a3b8;
                    font-size: 0.95rem;
                    margin-top: 4px;
                }
                
                table {
                    width: 100%;
                    border-collapse: collapse;
                    background: #1e2937;
                    border-radius: 12px;
                    overflow: hidden;
                    box-shadow: 0 10px 15px -3px rgb(0 0 0 / 0.1);
                }
                
                th {
                    background: #334155;
                    color: #e2e8f0;
                    padding: 16px 20px;
                    text-align: left;
                    font-weight: 600;
                    font-size: 0.9rem;
                }
                
                td {
                    padding: 16px 20px;
                    border-top: 1px solid #334155;
                }
                
                .vulnerable {
                    color: #ef4444;
                    font-weight: 600;
                }
                
                .safe {
                    color: #22c55e;
                    font-weight: 600;
                }
                
                .severity-high { color: #ef4444; font-weight: 600; }
                .severity-medium { color: #eab308; font-weight: 600; }
                .severity-low { color: #64748b; }
                
                .confidence {
                    font-family: monospace;
                    background: #334155;
                    padding: 2px 8px;
                    border-radius: 6px;
                    font-size: 0.85rem;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>AccessProbe</h1>
                <p class="subtitle">IDOR &amp; Broken Access Control Report • {{ generated_at }}</p>

                <div class="summary">
                    <div class="summary-grid">
                        <div class="stat">
                            <div class="stat-value">{{ total_tests }}</div>
                            <div class="stat-label">Tests Run</div>
                        </div>
                        <div class="stat">
                            <div class="stat-value">{{ total_findings }}</div>
                            <div class="stat-label">Total Findings</div>
                        </div>
                        <div class="stat">
                            <div class="stat-value" style="color: #ef4444;">{{ vulnerable_findings }}</div>
                            <div class="stat-label">Vulnerable</div>
                        </div>
                    </div>
                </div>

                <table>
                    <thead>
                        <tr>
                            <th>Parameter</th>
                            <th>Value Tested</th>
                            <th>Roles</th>
                            <th>Status</th>
                            <th>Vulnerable</th>
                            <th>Severity</th>
                            <th>Confidence</th>
                            <th>Evidence</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for f in findings %}
                        <tr>
                            <td><strong>{{ f.parameter }}</strong></td>
                            <td><code>{{ f.tested_value }}</code></td>
                            <td>{{ f.tested_roles | join(' → ') }}</td>
                            <td>{{ f.modified_status or '-' }}</td>
                            <td class="{{ 'vulnerable' if f.is_vulnerable else 'safe' }}">
                                {{ 'Yes' if f.is_vulnerable else 'No' }}
                            </td>
                            <td class="severity-{{ f.severity }}">{{ f.severity | upper }}</td>
                            <td><span class="confidence">{{ '%.2f'|format(f.confidence) }}</span></td>
                            <td>{{ f.evidence or '-' }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </body>
        </html>
        """

        template = Template(template_str)
        data = self.to_dict()
        return template.render(**data)

    def save_html(self, filepath: str | Path) -> None:
        Path(filepath).write_text(self.generate_html())

    def print_summary(self) -> None:
        data = self.to_dict()
        print(f"AccessProbe Report - {data['generated_at']}")
        print(f"Tests: {data['total_tests']} | Findings: {data['total_findings']} | Vulnerable: {data['vulnerable_findings']}")
