"""Advanced IDOR and Broken Access Control Detection Engine."""

from __future__ import annotations

import difflib
import re
from typing import Optional

import httpx

from .models import Finding, FindingSeverity


class IDORDetector:
    """High-accuracy detector for IDOR and authorization bypass vulnerabilities."""

    def __init__(self, similarity_threshold: float = 0.80) -> None:
        self.similarity_threshold = similarity_threshold

    def analyze_responses(
        self,
        original_response: Optional[httpx.Response],
        modified_response: Optional[httpx.Response],
        original_role: str,
        test_role: str,
    ) -> dict:
        """Analyze responses with advanced detection logic."""
        if not original_response or not modified_response:
            return self._create_analysis(False, 0.0, FindingSeverity.LOW, ["Response failed"])

        orig_code = original_response.status_code
        mod_code = modified_response.status_code
        orig_text = original_response.text[:4000]
        mod_text = modified_response.text[:4000]

        # === Signals ===
        status_changed = orig_code != mod_code
        length_diff = abs(len(original_response.content) - len(modified_response.content))

        similarity = self._calculate_similarity(orig_text, mod_text)

        # Header analysis
        header_signals = self._analyze_headers(original_response, modified_response)

        # Keyword & pattern analysis
        keyword_score, keyword_reasons = self._analyze_keywords(mod_text)

        # === Scoring System ===
        score = 0.0
        reasons = []

        # Strong signal: Status code improvement
        if status_changed:
            if mod_code in (200, 201, 202) and orig_code in (401, 403, 404):
                score += 0.45
                reasons.append(f"Privilege escalation: {original_role} denied ({orig_code}) → {test_role} allowed ({mod_code})")

            elif mod_code == 200 and orig_code != 200:
                score += 0.30
                reasons.append("Higher privilege role received successful response")

        # Similarity + success (classic IDOR pattern)
        if similarity >= self.similarity_threshold and mod_code == 200:
            score += 0.35
            reasons.append(f"High content similarity ({similarity:.2f}) with successful response")

        # Large content difference
        if length_diff > 600 and similarity < 0.6 and mod_code == 200:
            score += 0.25
            reasons.append("Significant content difference between roles")

        # Header signals
        score += header_signals["score"]
        reasons.extend(header_signals["reasons"])

        # Keyword signals
        score += keyword_score
        reasons.extend(keyword_reasons)

        # Normalize score
        final_score = min(1.0, score)
        is_vulnerable = final_score >= 0.55

        # Severity assignment
        if final_score >= 0.85:
            severity = FindingSeverity.CRITICAL
        elif final_score >= 0.70:
            severity = FindingSeverity.HIGH
        elif final_score >= 0.55:
            severity = FindingSeverity.MEDIUM
        else:
            severity = FindingSeverity.LOW

        return {
            "is_vulnerable": is_vulnerable,
            "confidence": round(final_score, 2),
            "severity": severity,
            "reasons": reasons,
            "similarity": round(similarity, 3),
            "status_changed": status_changed,
            "length_diff": length_diff,
        }

    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate text similarity using multiple methods."""
        if not text1 or not text2:
            return 0.0

        # Sequence matcher
        seq_sim = difflib.SequenceMatcher(None, text1, text2).ratio()

        # Simple token overlap
        tokens1 = set(text1.lower().split())
        tokens2 = set(text2.lower().split())
        if tokens1 and tokens2:
            overlap = len(tokens1 & tokens2) / len(tokens1 | tokens2)
        else:
            overlap = 0.0

        return max(seq_sim, overlap)

    def _analyze_headers(self, orig_resp: httpx.Response, mod_resp: httpx.Response) -> dict:
        """Analyze response headers for authorization signals."""
        score = 0.0
        reasons = []

        orig_headers = {k.lower(): v for k, v in orig_resp.headers.items()}
        mod_headers = {k.lower(): v for k, v in mod_resp.headers.items()}

        # Content-Type change
        if orig_headers.get("content-type") != mod_headers.get("content-type"):
            score += 0.08
            reasons.append("Content-Type changed between roles")

        # Server / technology headers
        interesting_headers = ["server", "x-powered-by", "x-frame-options"]
        for h in interesting_headers:
            if h in mod_headers and h not in orig_headers:
                score += 0.05

        return {"score": min(0.15, score), "reasons": reasons}

    def _analyze_keywords(self, text: str) -> tuple[float, list[str]]:
        """Detect interesting keywords and patterns."""
        score = 0.0
        reasons = []
        text_lower = text.lower()

        high_value = ["admin", "dashboard", "settings", "delete", "edit", "create", "sensitive"]
        medium_value = ["profile", "account", "user", "order", "item", "data"]

        high_hits = sum(1 for word in high_value if word in text_lower)
        medium_hits = sum(1 for word in medium_value if word in text_lower)

        if high_hits >= 2:
            score += 0.12
            reasons.append(f"High-value keywords detected ({high_hits})")
        elif high_hits == 1:
            score += 0.06

        if medium_hits >= 3:
            score += 0.08
            reasons.append(f"Multiple context keywords found ({medium_hits})")

        # Look for potential data leakage patterns
        if re.search(r'\b(email|password|token|api_key|secret)\b', text_lower):
            score += 0.10
            reasons.append("Potential sensitive data exposure")

        return min(0.20, score), reasons

    def create_finding(self, parameter: any, analysis: dict, original_role: str, test_role: str) -> Finding:
        """Create Finding object from analysis."""
        evidence = "; ".join(analysis.get("reasons", []))[:300] if analysis.get("reasons") else ""

        return Finding(
            parameter=parameter,
            tested_roles=[original_role, test_role],
            is_vulnerable=analysis["is_vulnerable"],
            severity=analysis["severity"],
            evidence=evidence,
            similarity_score=analysis.get("similarity"),
            details={"confidence": analysis.get("confidence", 0.0)},
        )

    def _create_analysis(self, is_vulnerable: bool, confidence: float, severity: FindingSeverity, reasons: list[str]) -> dict:
        return {
            "is_vulnerable": is_vulnerable,
            "confidence": confidence,
            "severity": severity,
            "reasons": reasons,
            "similarity": 0.0,
            "status_changed": False,
            "length_diff": 0,
        }
