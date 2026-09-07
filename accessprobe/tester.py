"""IDOR Testing Engine with smart value extraction from responses."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from .detector import IDORDetector
from .models import Finding, FindingSeverity, Parameter, ParameterLocation, TestResult
from .session import SessionManager

# Field-name / noise tokens that look like IDs but rarely are object identifiers
_NOISE_CANDIDATES = {
    "user_id",
    "userid",
    "account_id",
    "order_id",
    "owner_user_id",
    "private_notes",
    "profile",
    "email",
    "phone",
    "password",
    "token",
    "success",
    "error",
    "message",
    "status",
    "createdat",
    "updatedat",
    "node_modules",
    "process_params",
}

_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


class IDORTester:
    """Advanced IDOR tester with response-based value extraction."""

    def __init__(
        self,
        session_manager: SessionManager,
        delay: float = 0.25,
        min_confidence: float = 0.55,
        own_ids: Mapping[str, set[str] | list[str]] | None = None,
        privileged_roles: set[str] | list[str] | None = None,
    ) -> None:
        self.session_manager = session_manager
        self.detector = IDORDetector(min_confidence=min_confidence)
        self.results: list[TestResult] = []
        self.delay = delay
        self.own_ids: dict[str, set[str]] = {
            role: {str(v) for v in values}
            for role, values in (own_ids or {}).items()
        }
        self.privileged_roles: set[str] = {str(r) for r in (privileged_roles or set())}

    def _extract_potential_ids(self, text: str) -> list[str]:
        """Extract potential IDs from response text (numbers, UUIDs, etc)."""
        ids: list[str] = []
        seen: set[str] = set()
        occupied: list[tuple[int, int]] = []

        def add(val: str, start: int, end: int) -> None:
            if val in seen:
                return
            seen.add(val)
            ids.append(val)
            occupied.append((start, end))

        def overlaps(start: int, end: int) -> bool:
            return any(start < b and end > a for a, b in occupied)

        for match in _UUID_RE.finditer(text):
            add(match.group(0), match.start(), match.end())

        # Skip phone-like +E.164 numbers and digits that sit inside a UUID
        for match in re.finditer(r"(?<![+\d])(\d{1,12})(?!\d)", text):
            if overlaps(match.start(), match.end()):
                continue
            add(match.group(1), match.start(), match.end())

        # Long opaque tokens only when they do not look like field names
        for match in re.finditer(r"\b([a-zA-Z0-9_-]{16,})\b", text):
            token = match.group(1)
            if overlaps(match.start(), match.end()):
                continue
            if token.lower() not in _NOISE_CANDIDATES and not re.search(
                r"(19|20)\d{2}-\d{2}", token
            ):
                add(token, match.start(), match.end())

        return ids[:10]

    def _is_plausible_candidate(self, value: Any, original_value: Any) -> bool:
        """Drop obvious noise (JSON keys, timestamps, field names)."""
        s = str(value).strip()
        if not s:
            return False
        if s.lower() in _NOISE_CANDIDATES:
            return False
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}.*", s):
            return False  # ISO-ish dates
        orig_numeric = str(original_value).isdigit()
        is_uuid = bool(_UUID_RE.fullmatch(s))
        return (not orig_numeric) or s.isdigit() or is_uuid

    def _generate_candidate_values(
        self, original_value: Any, response_text: str = ""
    ) -> list[Any]:
        candidates: list[Any] = [original_value]

        if isinstance(original_value, (int, str)) and str(original_value).isdigit():
            val = int(original_value)
            candidates.extend([val + 1, val - 1, val + 5, val + 10])

        if response_text:
            extracted = self._extract_potential_ids(response_text)
            candidates.extend(extracted)

        seen: set[str] = set()
        unique: list[Any] = []
        for v in candidates:
            key = str(v)
            if key in seen:
                continue
            if not self._is_plausible_candidate(v, original_value):
                continue
            seen.add(key)
            unique.append(v)
        return unique[:8]

    def _apply_context_filters(
        self,
        finding: Finding,
        *,
        test_role: str,
        test_value: Any,
    ) -> Finding:
        """Suppress known false positives using ownership and privilege context."""
        if not finding.is_vulnerable:
            return finding

        details = dict(finding.details or {})

        if test_role in self.privileged_roles:
            finding.is_vulnerable = False
            finding.severity = FindingSeverity.LOW
            details["suppressed"] = "privileged_role"
            details["confidence"] = 0.0
            note = (
                f"Suppressed: role '{test_role}' is privileged "
                "(intended broader access)"
            )
            finding.evidence = (
                f"{finding.evidence}; {note}" if finding.evidence else note
            )
            finding.details = details
            return finding

        owned = self.own_ids.get(test_role, set())
        if str(test_value) in owned:
            finding.is_vulnerable = False
            finding.severity = FindingSeverity.LOW
            details["suppressed"] = "self_access"
            details["confidence"] = 0.0
            note = (
                f"Suppressed: value '{test_value}' is owned by role '{test_role}' "
                "(self-access)"
            )
            finding.evidence = (
                f"{finding.evidence}; {note}" if finding.evidence else note
            )
            finding.details = details
            return finding

        return finding

    def _values_differ(self, a: Any, b: Any) -> bool:
        return str(a) != str(b)

    def _inject_query(self, url: str, parameter: Parameter) -> str:
        """Set the tested query param without dropping sibling keys.

        httpx ``params=`` replaces the entire query string, so ``?user_id=1&extra=keep``
        would otherwise become ``?user_id=2``.
        """
        parsed = urlparse(url)
        pairs = [
            (k, v)
            for k, v in parse_qsl(parsed.query, keep_blank_values=True)
            if k != parameter.name
        ]
        pairs.append((parameter.name, str(parameter.value)))
        return urlunparse(parsed._replace(query=urlencode(pairs)))

    def _inject_path(self, url: str, parameter: Parameter) -> str:
        """Put the test value into a path parameter.

        Prefers ``{name}`` placeholders. Otherwise replaces the last path segment
        that equals the original ID (``/users/8/profile`` or ``/rest/basket/8``)
        instead of appending.
        """
        name = parameter.name
        value = str(parameter.value)
        token = "{" + name + "}"
        if token in url:
            return url.replace(token, value)

        parsed = urlparse(url)
        segs = parsed.path.split("/")
        current = parameter.original_value
        current_id = str(current) if current is not None else None
        if current_id:
            for i in range(len(segs) - 1, -1, -1):
                if segs[i] == current_id:
                    segs[i] = value
                    return urlunparse(parsed._replace(path="/".join(segs)))
        if segs and segs[-1] == value:
            return url
        new_path = parsed.path.rstrip("/") + f"/{value}"
        return urlunparse(parsed._replace(path=new_path))

    def _attach_status_codes(
        self,
        finding: Finding,
        analysis: dict[str, Any],
        original_resp: httpx.Response | None,
        modified_resp: httpx.Response | None,
    ) -> None:
        orig = analysis.get("effective_original_status")
        if orig is None:
            orig = original_resp.status_code if original_resp else None
        mod = analysis.get("effective_modified_status")
        if mod is None:
            mod = modified_resp.status_code if modified_resp else None
        finding.original_response_code = int(orig) if orig is not None else None
        finding.modified_response_code = int(mod) if mod is not None else None

    async def test_parameter(
        self,
        parameter: Parameter,
        target_url: str,
        original_session: str,
        test_sessions: list[str],
        method: str = "GET",
        values_to_test: list[Any] | None = None,
        test_horizontal: bool = True,
    ) -> TestResult:
        """Test a parameter for IDOR / broken access control.

        Runs:
        1. Baseline request as original_session with the original value
        2. Horizontal tests: same role, alternate object IDs
        3. Cross-role tests: other sessions with original + alternate IDs
        """
        test_result = TestResult(parameter=parameter)
        test_result.tested_sessions = [original_session] + list(test_sessions)

        if not self.session_manager.get_session(original_session):
            test_result.error = f"Session '{original_session}' not found"
            return test_result

        original_auth = self.session_manager.get_auth_kwargs(original_session)
        original_value = parameter.value

        try:
            async with httpx.AsyncClient(
                **original_auth, follow_redirects=True, timeout=30.0
            ) as client:
                original_resp = await self._make_request(
                    client, method, target_url, parameter
                )
                await asyncio.sleep(self.delay)

                original_text = original_resp.text if original_resp else ""
                values = values_to_test or self._generate_candidate_values(
                    parameter.value, original_text
                )

                findings = []

                # --- Horizontal IDOR: same low-priv role, other object IDs ---
                if test_horizontal:
                    for test_value in values:
                        if not self._values_differ(original_value, test_value):
                            continue
                        modified_param = parameter.model_copy(
                            update={
                                "value": test_value,
                                "original_value": original_value,
                            }
                        )
                        modified_resp = await self._make_request(
                            client, method, target_url, modified_param
                        )
                        await asyncio.sleep(self.delay)

                        analysis = self.detector.analyze_responses(
                            original_resp,
                            modified_resp,
                            original_session,
                            original_session,
                            value_changed=True,
                            same_role=True,
                        )
                        finding = self.detector.create_finding(
                            modified_param, analysis, original_session, original_session
                        )
                        self._attach_status_codes(
                            finding, analysis, original_resp, modified_resp
                        )
                        finding.similarity_score = analysis.get("similarity")
                        finding = self._apply_context_filters(
                            finding,
                            test_role=original_session,
                            test_value=test_value,
                        )
                        findings.append(finding)

                # --- Cross-role tests ---
                for test_role in test_sessions:
                    if not self.session_manager.get_session(test_role):
                        continue

                    test_auth = self.session_manager.get_auth_kwargs(test_role)

                    async with httpx.AsyncClient(
                        **test_auth, follow_redirects=True, timeout=30.0
                    ) as test_client:
                        for test_value in values:
                            modified_param = parameter.model_copy(
                                update={
                                    "value": test_value,
                                    "original_value": original_value,
                                }
                            )
                            modified_resp = await self._make_request(
                                test_client, method, target_url, modified_param
                            )
                            await asyncio.sleep(self.delay)

                            analysis = self.detector.analyze_responses(
                                original_resp,
                                modified_resp,
                                original_session,
                                test_role,
                                value_changed=self._values_differ(
                                    original_value, test_value
                                ),
                                same_role=False,
                            )
                            finding = self.detector.create_finding(
                                modified_param, analysis, original_session, test_role
                            )
                            self._attach_status_codes(
                                finding, analysis, original_resp, modified_resp
                            )
                            finding.similarity_score = analysis.get("similarity")
                            finding = self._apply_context_filters(
                                finding,
                                test_role=test_role,
                                test_value=test_value,
                            )
                            findings.append(finding)

                test_result.findings = findings
                test_result.success = True

        except Exception as e:
            test_result.error = str(e)

        self.results.append(test_result)
        return test_result

    async def _make_request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        parameter: Parameter,
    ) -> httpx.Response | None:
        try:
            name = parameter.name
            value = parameter.value
            location = parameter.location

            if location == ParameterLocation.QUERY:
                return await client.request(method, self._inject_query(url, parameter))
            if location == ParameterLocation.PATH:
                new_url = self._inject_path(url, parameter)
                return await client.request(method, new_url)
            if location == ParameterLocation.BODY:
                return await client.request(
                    method, url, json={name: value}
                )
            if location == ParameterLocation.HEADER:
                return await client.request(
                    method, url, headers={name: str(value)}
                )
            if location == ParameterLocation.COOKIE:
                return await client.request(
                    method, url, cookies={name: str(value)}
                )
            return await client.request(method, url)
        except Exception:
            return None

    def get_results(self) -> list[TestResult]:
        return self.results
