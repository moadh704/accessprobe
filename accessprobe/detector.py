"""Advanced IDOR Detection Engine - Improved for higher accuracy."""

from __future__ import annotations

import difflib
from typing import Any

import httpx

from .models import Finding, FindingSeverity, Parameter


class IDORDetector:
    """High-accuracy detector for IDOR and Broken Access Control vulnerabilities."""

    INTERESTING_KEYWORDS = [
        "admin",
        "dashboard",
        "profile",
        "settings",
        "account",
        "delete",
        "edit",
        "update",
        "success",
        "welcome",
        "user",
        "owner",
        "creator",
        "private",
        "sensitive",
        "email",
        "phone",
        "ssn",
        "password",
        "token",
    ]

    ERROR_KEYWORDS = [
        "unauthorized",
        "forbidden",
        "access denied",
        "not allowed",
        "permission",
        "login required",
        "authentication",
    ]

    def __init__(
        self,
        similarity_threshold: float = 0.80,
        min_confidence: float = 0.55,
    ) -> None:
        self.similarity_threshold = similarity_threshold
        self.min_confidence = min_confidence

    def analyze_responses(
        self,
        original_response: httpx.Response | None,
        modified_response: httpx.Response | None,
        original_role: str,
        test_role: str,
        *,
        value_changed: bool = False,
        same_role: bool = False,
    ) -> dict[str, Any]:
        """Compare baseline vs modified response and score IDOR likelihood.

        Args:
            value_changed: True when the tested object ID differs from the original.
            same_role: True when both requests used the same session/role
                (horizontal IDOR test).
        """
        if not original_response or not modified_response:
            return self._failed_analysis()

        orig_code = original_response.status_code
        mod_code = modified_response.status_code
        orig_len = len(original_response.content)
        mod_len = len(modified_response.content)
        orig_text = original_response.text[:4000].lower()
        mod_text = modified_response.text[:4000].lower()

        status_changed = orig_code != mod_code
        length_diff = abs(orig_len - mod_len)

        try:
            similarity = difflib.SequenceMatcher(None, orig_text, mod_text).ratio()
        except Exception:
            similarity = 0.0

        is_vulnerable = False
        confidence = 0.0
        reasons: list[str] = []
        severity = FindingSeverity.LOW

        # Rule 1: Privilege escalation via status codes
        if status_changed:
            if mod_code in (200, 201, 202) and orig_code in (401, 403, 404):
                is_vulnerable = True
                confidence = 0.93
                reasons.append(
                    f"Privilege escalation: {original_role} denied ({orig_code}) "
                    f"but {test_role} allowed ({mod_code})"
                )
                severity = FindingSeverity.HIGH
            elif mod_code == 200 and orig_code not in (200, 201, 202):
                is_vulnerable = True
                confidence = 0.80
                reasons.append("Only higher-privilege role received successful response")
                severity = FindingSeverity.MEDIUM

        # Rule 2: Horizontal IDOR — same role accesses a different object ID
        if (
            same_role
            and value_changed
            and orig_code == 200
            and mod_code == 200
            and not self._looks_like_error(mod_text)
        ):
            # Similar structure on a different resource ID is a strong signal
            if similarity >= 0.55:
                is_vulnerable = True
                confidence = max(confidence, 0.88)
                reasons.append(
                    f"Horizontal IDOR: role '{original_role}' accessed a different "
                    "object ID with a successful, similar response"
                )
                severity = FindingSeverity.HIGH
            elif length_diff < 500:
                # Different content but still 200 on foreign ID
                is_vulnerable = True
                confidence = max(confidence, 0.75)
                reasons.append(
                    f"Horizontal IDOR: role '{original_role}' received 200 for a "
                    "different object ID"
                )
                if severity == FindingSeverity.LOW:
                    severity = FindingSeverity.HIGH

        # Rule 3: Cross-role high similarity on a *changed* object ID
        if (
            not same_role
            and value_changed
            and similarity >= self.similarity_threshold
            and orig_code == 200
            and mod_code == 200
            and not self._looks_like_error(mod_text)
        ):
            is_vulnerable = True
            confidence = max(confidence, 0.84)
            reasons.append(
                "Cross-role access to alternate object ID with highly similar content"
            )
            if severity == FindingSeverity.LOW:
                severity = FindingSeverity.MEDIUM

        # Rule 4: Cross-role access to the *same* object ID with success on both.
        # Often legitimate (shared resource or privileged role). Still surface as
        # a medium lead so ownership / privileged-role filters can suppress
        # intended cases while real horizontal/cross-user leaks stay visible.
        if (
            not same_role
            and not value_changed
            and orig_code == 200
            and mod_code == 200
            and not self._looks_like_error(mod_text)
        ):
            keyword_hits = sum(1 for kw in self.INTERESTING_KEYWORDS if kw in mod_text)
            if similarity >= self.similarity_threshold or keyword_hits >= 2:
                is_vulnerable = True
                confidence = max(confidence, 0.72 if keyword_hits >= 2 else 0.65)
                reasons.append(
                    f"Cross-role: '{test_role}' can access the same object ID as "
                    f"'{original_role}' with a successful response "
                    "(verify ownership; use --own-ids / --privileged-roles to suppress)"
                )
                if severity == FindingSeverity.LOW:
                    severity = FindingSeverity.MEDIUM

        # Rule 5: Large structural difference with success on BOTH sides.
        # A 200 vs 401/403/404 size gap is expected access control, not IDOR.
        success_codes = {200, 201, 202}
        if (
            length_diff > 1200
            and similarity < 0.50
            and orig_code in success_codes
            and mod_code in success_codes
        ):
            is_vulnerable = True
            confidence = max(confidence, 0.68)
            reasons.append("Significant content difference between successful responses")
            if severity == FindingSeverity.LOW:
                severity = FindingSeverity.MEDIUM

        # Rule 6: Keyword analysis (boosts existing confidence)
        keyword_hits = sum(1 for kw in self.INTERESTING_KEYWORDS if kw in mod_text)
        if keyword_hits >= 2 and mod_code == 200 and is_vulnerable:
            boost = min(0.12, keyword_hits * 0.04)
            confidence = min(1.0, confidence + boost)
            reasons.append(f"Interesting keywords found in response ({keyword_hits} hits)")

        # Rule 7: Sensitive headers only on modified response
        sensitive_headers = ["x-user-id", "x-account-id", "x-owner", "x-role"]
        for header in sensitive_headers:
            if (
                header in modified_response.headers
                and header not in original_response.headers
            ):
                if is_vulnerable:
                    confidence = min(1.0, confidence + 0.07)
                else:
                    is_vulnerable = True
                    confidence = max(confidence, 0.62)
                reasons.append(f"Sensitive header appeared: {header}")

        # Drop low-confidence noise
        if is_vulnerable and confidence < self.min_confidence:
            is_vulnerable = False
            reasons.append(
                f"Below min confidence threshold ({confidence:.2f} < {self.min_confidence})"
            )

        if is_vulnerable and confidence < 0.55:
            confidence = 0.55

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
            "value_changed": value_changed,
            "same_role": same_role,
        }

    def create_finding(
        self,
        parameter: Parameter,
        analysis: dict[str, Any],
        original_role: str,
        test_role: str,
    ) -> Finding:
        evidence = (
            "; ".join(analysis.get("reasons", [])) if analysis.get("reasons") else ""
        )
        return Finding(
            parameter=parameter,
            tested_roles=[original_role, test_role],
            is_vulnerable=bool(analysis["is_vulnerable"]),
            severity=analysis["severity"],
            evidence=evidence,
            similarity_score=analysis.get("similarity"),
            details={
                "confidence": analysis.get("confidence", 0.0),
                "value_changed": analysis.get("value_changed", False),
                "same_role": analysis.get("same_role", False),
            },
        )

    def _looks_like_error(self, text: str) -> bool:
        return any(kw in text for kw in self.ERROR_KEYWORDS)

    def _failed_analysis(self) -> dict[str, Any]:
        return {
            "is_vulnerable": False,
            "confidence": 0.0,
            "severity": FindingSeverity.LOW,
            "reasons": ["One or both responses failed"],
            "similarity": 0.0,
            "status_changed": False,
            "length_diff": 0,
            "value_changed": False,
            "same_role": False,
        }
