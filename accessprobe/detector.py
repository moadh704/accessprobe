"""Detection logic for identifying IDOR and Broken Access Control vulnerabilities."""

from __future__ import annotations

import difflib
from typing import Optional

import httpx

from .models import Finding, FindingSeverity


class IDORDetector:
    """Compares responses from different roles to detect potential IDORs."""

    def __init__(self, similarity_threshold: float = 0.85) -> None:
        self.similarity_threshold = similarity_threshold

    def analyze_responses(
        self,
        original_response: Optional[httpx.Response],
        modified_response: Optional[httpx.Response],
        original_role: str,
        test_role: str,
    ) -> dict:
        """Compare two responses and return analysis results."""
        if not original_response or not modified_response:
            return {
                "is_vulnerable": False,
                "reason": "One or both responses failed",
                "similarity": 0.0,
                "severity": FindingSeverity.LOW,
            }

        original_code = original_response.status_code
        modified_code = modified_response.status_code

        # Status code analysis
        status_diff = original_code != modified_code

        # Content similarity
        try:
            original_text = original_response.text[:2000]  # Limit for performance
            modified_text = modified_response.text[:2000]
            similarity = difflib.SequenceMatcher(None, original_text, modified_text).ratio()
        except Exception:
            similarity = 0.0

        # Length difference
        length_diff = abs(len(original_response.content) - len(modified_response.content))

        # Decision logic
        is_vulnerable = False
        reason = "No clear signs of IDOR"
        severity = FindingSeverity.LOW

        if status_diff:
            if modified_code in (200, 201, 202) and original_code in (401, 403, 404):
                is_vulnerable = True
                reason = f"Access granted to {test_role} when {original_role} was denied"
                severity = FindingSeverity.HIGH
            elif modified_code == 200 and original_code != 200:
                is_vulnerable = True
                reason = "Different success status codes between roles"
                severity = FindingSeverity.MEDIUM

        if similarity > self.similarity_threshold and not status_diff:
            # Very similar successful responses from different privilege levels
            if original_code == 200 and modified_code == 200:
                is_vulnerable = True
                reason = "Highly similar successful responses from different roles"
                severity = FindingSeverity.MEDIUM

        if length_diff > 500 and similarity < 0.6:
            # Significant content difference
            if original_code == 200 or modified_code == 200:
                is_vulnerable = True
                reason = "Significant content difference between roles"
                severity = FindingSeverity.MEDIUM

        return {
            "is_vulnerable": is_vulnerable,
            "reason": reason,
            "similarity": round(similarity, 3),
            "severity": severity,
            "status_diff": status_diff,
            "length_diff": length_diff,
        }

    def create_finding(
        self,
        parameter: any,
        analysis: dict,
        original_role: str,
        test_role: str,
    ) -> Finding:
        """Create a Finding object from analysis results."""
        return Finding(
            parameter=parameter,
            tested_roles=[original_role, test_role],
            is_vulnerable=analysis["is_vulnerable"],
            severity=analysis["severity"],
            evidence=analysis["reason"],
            similarity_score=analysis.get("similarity"),
        )
