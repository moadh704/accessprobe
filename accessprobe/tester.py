"""Core testing engine for IDOR and Broken Access Control vulnerabilities."""

from __future__ import annotations

from typing import Any, Optional

import httpx

from .models import Parameter, TestResult, FindingSeverity

from .session import SessionManager
from .detector import IDORDetector


class IDORTester:
    """Main engine responsible for testing parameters across different user roles for IDORs."""

    def __init__(self, session_manager: SessionManager) -> None:
        self.session_manager = session_manager
        self.detector = IDORDetector()
        self.results: list[TestResult] = []

    async def test_parameter(
        self,
        parameter: Parameter,
        target_url: str,
        original_session: str,
        test_sessions: list[str],
        method: str = "GET",
        values_to_test: Optional[list[Any]] = None,
    ) -> TestResult:
        """Test a parameter across roles, optionally with specific values to try.

        If values_to_test is provided, those values will be tested on the test_sessions.
        Otherwise falls back to basic behavior.
        """
        test_result = TestResult(parameter=parameter)
        test_result.tested_sessions = [original_session] + test_sessions

        if not self.session_manager.get_session(original_session):
            test_result.error = f"Original session '{original_session}' not found"
            return test_result

        original_auth = self.session_manager.get_auth_kwargs(original_session)

        try:
            async with httpx.AsyncClient(**original_auth, follow_redirects=True, timeout=30.0) as client:
                original_resp = await self._make_request(
                    client, method, target_url, parameter
                )

                findings = []

                # Determine which values to test on other roles
                values = values_to_test or [parameter.value]

                for test_role in test_sessions:
                    test_auth = self.session_manager.get_auth_kwargs(test_role)
                    if not test_auth:
                        continue

                    for test_value in values:
                        modified_param = parameter.model_copy(update={"value": test_value})

                        async with httpx.AsyncClient(
                            **test_auth, follow_redirects=True, timeout=30.0
                        ) as test_client:
                            modified_resp = await self._make_request(
                                test_client, method, target_url, modified_param
                            )

                            analysis = self.detector.analyze_responses(
                                original_resp,
                                modified_resp,
                                original_session,
                                test_role,
                            )

                            finding = self.detector.create_finding(
                                modified_param,
                                analysis,
                                original_session,
                                test_role,
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
    ) -> Optional[httpx.Response]:
        """Send request with parameter in the correct location."""
        try:
            if parameter.location.value == "query":
                params = {parameter.name: parameter.value}
                return await client.request(method, url, params=params)

            elif parameter.location.value == "path":
                # Basic path parameter replacement
                if "{" + parameter.name + "}" in url:
                    formatted_url = url.replace(
                        "{" + parameter.name + "}", str(parameter.value)
                    )
                    return await client.request(method, formatted_url)
                else:
                    # Fallback if no placeholder in URL
                    return await client.request(method, url)

            elif parameter.location.value in ("body", "json"):
                # Simple JSON body support
                return await client.request(
                    method, url, json={parameter.name: parameter.value}
                )

            else:
                # Header / Cookie - basic support
                return await client.request(method, url)

        except Exception:
            return None

    def get_results(self) -> list[TestResult]:
        return self.results
