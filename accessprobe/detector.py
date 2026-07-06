"""Advanced IDOR Detection Engine - Improved for higher accuracy."""

from __future__ import annotations

import difflib
import re
from typing import Optional

import httpx

from .models import Finding, FindingSeverity


class IDORDetector:
    """High-accuracy detector for IDOR and Broken Access Control vulnerabilities."""

    INTERESTING_KEYWORDS = [
        "admin", "dashboard", "profile", "settings", "account",
        "delete", "edit", "update", "success", "welcome",
        "user", "owner", "creator", "private", "sensitive"
    ]

    def __init__(self, similarity_threshold: float = 0.80) -> None:
        self.similarity_threshold = similarity_threshold

    def analyze_responses(
        self,
        original_response: Optional[httpx.Response],
        modified_response: Optional[httpx.Response],
        original_role: str,
        test_role: str,
    ) -> dict:
        if not original_response or not modified_response:
            return self._failed_analysis()

        orig_code = original_response.status_code
        mod_code = modified_response.status_code
        orig_len = len(original_response.content)
        mod_len = len(modified_response.content)
        orig_text = original_response.text[:4000].lower()
        mod_text = modified_response.text[:4000].lower()

        # === Signals ===
        status_changed = orig_code != mod_code
        length_diff = abs(orig_len - mod_len)

        try:
            similarity = difflib.SequenceMatcher(None, orig_text, mod_text).ratio()
        except Exception:
            similarity = 0.0

        # === Detection Logic ===
        is_vulnerable = False
        confidence = 0.0
        reasons = []
        severity = FindingSeverity.LOW

        # Rule 1: Strong status code signal (highest confidence)
        if status_changed:
            if mod_code in (200, 201, 202) and orig_code in (401, 403, 404):
                is_vulnerable = True
                confidence = 0.93
                reasons.append(f"Privilege escalation: {original_role} denied ({orig_code}) but {test_role} allowed ({mod_code})")
                severity = FindingSeverity.HIGH

            elif mod_code == 200 and orig_code not in (200, 201, 202):
                is_vulnerable = True
                confidence = 0.80
                reasons.append("Only higher-privilege role received successful response")
                severity = FindingSeverity.MEDIUM

        # Rule 2: High similarity on successful responses (classic IDOR)
        if similarity >= self.similarity_threshold and orig_code == 200 and mod_code == 200:
            is_vulnerable = True
            confidence = max(confidence, 0.82)
            reasons.append("High content similarity between different privilege levels")
            if severity == FindingSeverity.LOW:
                severity = FindingSeverity.MEDIUM

        # Rule 3: Large structural difference
        if length_diff > 1200 and similarity < 0.50:
            if orig_code == 200 or mod_code == 200:
                is_vulnerable = True
                confidence = max(confidence, 0.68)
                reasons.append("Significant content difference between roles")
                if severity == FindingSeverity.LOW:
                    severity = FindingSeverity.MEDIUM

        # Rule 4: Keyword analysis (boosts confidence)
        keyword_hits = sum(1 for kw in self.INTERESTING_KEYWORDS if kw in mod_text)
        if keyword_hits >= 2 and mod_code == 200:
            boost = min(0.12, keyword_hits * 0.04)
            confidence = min(1.0, confidence + boost)
            reasons.append(f"Interesting keywords found in response ({keyword_hits} hits)")

        # Rule 5: Header analysis (new)
        sensitive_headers = ['x-user-id', 'x-account-id', 'x-owner']
        for header in sensitive_headers:
            if header in modified_response.headers and header not in original_response.headers:
                confidence = min(1.0, confidence + 0.07)
                reasons.append(f"Sensitive header appeared: {header}")

        # Final adjustments
        if is_vulnerable and confidence < 0.55:
            confidence = 0.58

        if confidence > 0.90:
            severity = FindingSeverity.HIGH

        return {
            "is_vulnerable": is_vulnerable,
            "confidence": round(confidence, 2),
            "severity": severity,
            "reasons": reasons,
            "similarity": round(similarity, 3),
            "status_changed": status_changed,
            "length_diff": length_diff,
        }

    def create_finding(self, parameter: any, analysis: dict, original_role: str, test_role: str) -> Finding:
        evidence = "; ".join(analysis.get("reasons", [])) if analysis.get("reasons") else ""
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
            "reasons": ["One or both responses failed"],
            "similarity": 0.0,
            "status_changed": False,
            "length_diff": 0,
        }
