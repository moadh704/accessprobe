"""IDOR Testing Engine with smart value extraction from responses."""

from __future__ import annotations

import asyncio
import re
from typing import Any

import httpx

from .detector import IDORDetector
from .models import Parameter, ParameterLocation, TestResult
from .session import SessionManager


class IDORTester:
    """Advanced IDOR tester with response-based value extraction."""

    def __init__(
        self,
        session_manager: SessionManager,
        delay: float = 0.25,
        min_confidence: float = 0.55,
    ) -> None:
        self.session_manager = session_manager
        self.detector = IDORDetector(min_confidence=min_confidence)
        self.results: list[TestResult] = []
        self.delay = delay

    def _extract_potential_ids(self, text: str) -> list[str]:
        """Extract potential IDs from response text (numbers, UUIDs, etc)."""
        ids: set[str] = set()

        for match in re.finditer(r"\b(\d{3,})\b", text):
            ids.add(match.group(1))

        for match in re.finditer(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            text,
        ):
            ids.add(match.group(0))

        for match in re.finditer(r"\b([a-zA-Z0-9_-]{12,})\b", text):
            ids.add(match.group(1))

        return list(ids)[:10]

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
            if key not in seen:
                seen.add(key)
                unique.append(v)
        return unique[:8]

    def _values_differ(self, a: Any, b: Any) -> bool:
        return str(a) != str(b)

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
                        finding.original_response_code = (
                            original_resp.status_code if original_resp else None
                        )
                        finding.modified_response_code = (
                            modified_resp.status_code if modified_resp else None
                        )
                        finding.similarity_score = analysis.get("similarity")
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
                            finding.original_response_code = (
                                original_resp.status_code if original_resp else None
                            )
                            finding.modified_response_code = (
                                modified_resp.status_code if modified_resp else None
                            )
                            finding.similarity_score = analysis.get("similarity")
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
                return await client.request(
                    method, url, params={name: value}
                )
            if location == ParameterLocation.PATH:
                token = "{" + name + "}"
                if token in url:
                    new_url = url.replace(token, str(value))
                else:
                    # Fallback: append /value if no placeholder
                    new_url = url.rstrip("/") + f"/{value}"
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
