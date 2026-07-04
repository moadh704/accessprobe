"""Improved detection logic for IDOR and Broken Access Control."""

from __future__ import annotations

import difflib
from typing import Optional

import httpx

from .models import Finding, FindingSeverity


class IDORDetector:
    """Advanced detector for authorization bypasses and IDOR vulnerabilities."""

    def __init__(self, similarity_threshold: float = 0.82) -> None:
        self.similarity_threshold = similarity_threshold

    def analyze_responses(
        self,
        original_response: Optional[httpx.Response],
        modified_response: Optional[httpx.Response],
        original_role: str,
        test_role: str,
    ) -> dict:
        """Analyze two responses and return detailed detection results."""
        if not original_response or not modified_response:
            return self._failed_analysis()

        orig_code = original_response.status_code
        mod_code = modified_response.status_code
        orig_len = len(original_response.content)
        mod_len = len(modified_response.content)

        # === Core Signals ===
        status_changed = orig_code != mod_code
        length_diff = abs(orig_len - mod_len)

        # Text similarity
        try:
            orig_text = original_response.text[:3000]
            mod_text = modified_response.text[:3000]
            similarity = difflib.SequenceMatcher(None, orig_text, mod_text).ratio()
        except Exception:
            similarity = 0.0

        # === Detection Rules ===
        is_vulnerable = False
        confidence = 0.0
        reasons = []
        severity = FindingSeverity.LOW

        # Rule 1: Status code improvement (very strong signal)
        if status_changed:
            if mod_code in (200, 201, 202) and orig_code in (401, 403, 404):
                is_vulnerable = True
                confidence = 0.92
                reasons.append(f"Access granted to {test_role} (status {mod_code}) while {original_role} got {orig_code}")
                severity = FindingSeverity.HIGH

            elif mod_code == 200 and orig_code != 200:
                is_vulnerable = True
                confidence = 0.75
                reasons.append("Successful response only from higher privilege role")
                severity = FindingSeverity.MEDIUM

        # Rule 2: High similarity + both successful (classic IDOR)
        if similarity >= self.similarity_threshold and orig_code == 200 and mod_code == 200:
            is_vulnerable = True
            confidence = max(confidence, 0.78)
            reasons.append("Highly similar successful responses from different privilege levels")
            if severity == FindingSeverity.LOW:
                severity = FindingSeverity.MEDIUM

        # Rule 3: Large content difference with success
        if length_diff > 800 and similarity < 0.55:
            if orig_code == 200 or mod_code == 200:
                is_vulnerable = True
                confidence = max(confidence, 0.65)
                reasons.append("Significant content difference between roles")
                if severity == FindingSeverity.LOW:
                    severity = FindingSeverity.MEDIUM

        # Rule 4: Keyword analysis (bonus confidence)
        keywords = ["admin", "success", "profile", "dashboard", "settings", "delete", "edit"]
        mod_lower = modified_response.text.lower()
        keyword_hits = sum(1 for kw in keywords if kw in mod_lower)

        if keyword_hits >= 2 and mod_code == 200:
            confidence = min(1.0, confidence + 0.08)
            reasons.append(f"Interesting keywords found in response ({keyword_hits} hits)")

        # Final confidence adjustment
        if is_vulnerable and confidence < 0.5:
            confidence = 0.55

        return {
            "is_vulnerable": is_vulnerable,
            "confidence": round(confidence, 2),
            "severity": severity,
            "reasons": reasons,
            "similarity": round(similarity, 3),
            "status_changed": status_changed,
            "length_diff": length_diff,
        }

    def create_finding(
        self,
        parameter: any,
        analysis: dict,
        original_role: str,
        test_role: str,
    ) -> Finding:
        """Create Finding from analysis."""
        evidence = "; ".join(analysis.get("reasons", [])) if analysis.get("reasons") else analysis.get("reason", "")

        return Finding(
            parameter=parameter,
            tested_roles=[original_role, test_role],
            is_vulnerable=analysis["is_vulnerable"],
            severity=analysis["severity"],
            evidence=evidence,
            similarity_score=analysis.get("similarity"),
            details={"confidence": analysis.get("confidence", 0.0)},
        )

    def _failed_analysis(self) -> dict:
        return {
            "is_vulnerable": False,
            "confidence": 0.0,
            "severity": FindingSeverity.LOW,
            "reasons": ["Response failed or missing"],
            "similarity": 0.0,
            "status_changed": False,
            "length_diff": 0,
        }
