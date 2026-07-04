"""Core testing engine for IDOR and Broken Access Control vulnerabilities."""

from __future__ import annotations

import asyncio
from typing import Optional

import httpx

from .models import Parameter, TestResult, Finding, FindingSeverity, UserSession

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
    ) -> TestResult:
        """Test a single parameter by swapping its value across different roles.

        Now uses IDORDetector for response analysis.
        """
        test_result = TestResult(parameter=parameter)
        test_result.tested_sessions = [original_session] + test_sessions

        original_session_obj = self.session_manager.get_session(original_session)
        if not original_session_obj:
            test_result.error = f"Original session '{original_session}' not found"
            return test_result

        original_auth = self.session_manager.get_auth_kwargs(original_session)

        try:
            async with httpx.AsyncClient(**original_auth, follow_redirects=True, timeout=30.0) as client:
                original_resp = await self._make_request(
                    client, method, target_url, parameter
                )

                findings = []

                for test_role in test_sessions:
                    test_auth = self.session_manager.get_auth_kwargs(test_role)
                    if not test_auth:
                        continue

                    async with httpx.AsyncClient(**test_auth, follow_redirects=True, timeout=30.0) as test_client:
                        # For now we test with the same value (future: smart value selection)
                        modified_param = parameter.model_copy()

                        modified_resp = await self._make_request(
                            test_client, method, target_url, modified_param
                        )

                        # === Use Detector ===
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

                        # Store extra info
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
        """Helper to send a request with the parameter in the correct location."""
        try:
            if parameter.location.value == "query":
                params = {parameter.name: parameter.value}
                resp = await client.request(method, url, params=params)
            else:
                # TODO: Improve path, body, header, cookie parameter handling
                resp = await client.request(method, url)

            return resp
        except Exception:
            return None

    def get_results(self) -> list[TestResult]:
        return self.results
