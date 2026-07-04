"""Core testing engine for IDOR and Broken Access Control vulnerabilities."""

from __future__ import annotations

import asyncio
from typing import Optional

import httpx

from .models import Parameter, TestResult, Finding, FindingSeverity, UserSession

from .session import SessionManager


class IDORTester:
    """Main engine responsible for testing parameters across different user roles for IDORs."""

    def __init__(self, session_manager: SessionManager) -> None:
        self.session_manager = session_manager
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

        This is the core IDOR testing logic.
        """
        test_result = TestResult(parameter=parameter)
        test_result.tested_sessions = [original_session] + test_sessions

        original_session_obj = self.session_manager.get_session(original_session)
        if not original_session_obj:
            test_result.error = f"Original session '{original_session}' not found"
            return test_result

        # Get auth for original session
        original_auth = self.session_manager.get_auth_kwargs(original_session)

        try:
            async with httpx.AsyncClient(**original_auth, follow_redirects=True, timeout=30.0) as client:
                # First, make request with original value
                original_resp = await self._make_request(
                    client, method, target_url, parameter
                )
                test_result.parameter.original_value = parameter.value

                findings = []

                # Now test with values from other roles
                for test_role in test_sessions:
                    test_auth = self.session_manager.get_auth_kwargs(test_role)
                    if not test_auth:
                        continue

                    async with httpx.AsyncClient(**test_auth, follow_redirects=True, timeout=30.0) as test_client:
                        # Modify the parameter value (basic version: use value from original for now)
                        # In later versions we will intelligently pick values from other sessions
                        modified_param = parameter.model_copy()
                        # TODO: Implement smart value selection from other sessions

                        modified_resp = await self._make_request(
                            test_client, method, target_url, modified_param
                        )

                        finding = Finding(
                            parameter=modified_param,
                            tested_roles=[original_session, test_role],
                            original_response_code=original_resp.status_code if original_resp else None,
                            modified_response_code=modified_resp.status_code if modified_resp else None,
                            is_vulnerable=False,  # Detection logic comes later
                            severity=FindingSeverity.MEDIUM,
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
    ) -> Optional[httpx.Response]:
        """Helper to send a request with the parameter in the correct location."""
        try:
            if parameter.location.value == "query":
                params = {parameter.name: parameter.value}
                resp = await client.request(method, url, params=params)
            elif parameter.location.value == "path":
                # For path parameters, we assume the URL already contains a placeholder
                # In real usage we would replace it properly
                resp = await client.request(method, url)
            else:
                # Body / Header / Cookie - basic implementation for now
                resp = await client.request(method, url)

            return resp
        except Exception:
            return None

    def get_results(self) -> list[TestResult]:
        return self.results
