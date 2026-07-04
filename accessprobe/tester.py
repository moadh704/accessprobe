"""Core IDOR Testing Engine with improved value handling."""

from __future__ import annotations

from typing import Any, Optional

import httpx

from .models import Parameter, TestResult, ParameterLocation
from .session import SessionManager
from .detector import IDORDetector


class IDORTester:
    """Main engine for testing parameters across different user roles."""

    def __init__(self, session_manager: SessionManager) -> None:
        self.session_manager = session_manager
        self.detector = IDORDetector()
        self.results: list[TestResult] = []

    def _generate_candidate_values(
        self, original_value: Any, count: int = 5
    ) -> list[Any]:
        """Generate candidate values to test (basic version)."""
        candidates = [original_value]

        # Add some common variations for numeric IDs
        if isinstance(original_value, (int, str)) and str(original_value).isdigit():
            val = int(original_value)
            candidates.extend([val + 1, val - 1, val + 10, val * 2])

        # Remove duplicates while preserving order
        seen = set()
        unique = []
        for v in candidates:
            if v not in seen:
                seen.add(v)
                unique.append(v)
        return unique[:count]

    async def test_parameter(
        self,
        parameter: Parameter,
        target_url: str,
        original_session: str,
        test_sessions: list[str],
        method: str = "GET",
        values_to_test: Optional[list[Any]] = None,
    ) -> TestResult:
        """Test a parameter across roles with smart value selection."""
        test_result = TestResult(parameter=parameter)
        test_result.tested_sessions = [original_session] + test_sessions

        if not self.session_manager.get_session(original_session):
            test_result.error = f"Session '{original_session}' not found"
            return test_result

        original_auth = self.session_manager.get_auth_kwargs(original_session)

        try:
            async with httpx.AsyncClient(**original_auth, follow_redirects=True, timeout=30.0) as client:
                original_resp = await self._make_request(client, method, target_url, parameter)

                # Determine values to test
                if values_to_test:
                    values = values_to_test
                else:
                    values = self._generate_candidate_values(parameter.value)

                findings = []

                for test_role in test_sessions:
                    test_auth = self.session_manager.get_auth_kwargs(test_role)
                    if not test_auth:
                        continue

                    for test_value in values:
                        modified_param = parameter.model_copy(update={"value": test_value})

                        async with httpx.AsyncClient(**test_auth, follow_redirects=True, timeout=30.0) as test_client:
                            modified_resp = await self._make_request(
                                test_client, method, target_url, modified_param
                            )

                            analysis = self.detector.analyze_responses(
                                original_resp, modified_resp, original_session, test_role
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
        self, client: httpx.AsyncClient, method: str, url: str, parameter: Parameter
    ) -> Optional[httpx.Response]:
        """Send HTTP request with parameter in correct location."""
        try:
            if parameter.location == ParameterLocation.QUERY:
                return await client.request(method, url, params={parameter.name: parameter.value})

            elif parameter.location == ParameterLocation.PATH:
                if "{" + parameter.name + "}" in url:
                    new_url = url.replace("{" + parameter.name + "}", str(parameter.value))
                    return await client.request(method, new_url)
                return await client.request(method, url)

            elif parameter.location in (ParameterLocation.BODY, "json"):
                return await client.request(method, url, json={parameter.name: parameter.value})

            else:
                return await client.request(method, url)

        except Exception:
            return None

    def get_results(self) -> list[TestResult]:
        return self.results
