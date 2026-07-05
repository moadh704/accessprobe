"""Core IDOR Testing Engine with advanced value selection."""

from __future__ import annotations

import re
from typing import Any, Optional

import httpx

from .models import Parameter, TestResult, ParameterLocation
from .session import SessionManager
from .detector import IDORDetector


class IDORTester:
    """Main engine for testing parameters across different user roles.

    Features improved value selection for better IDOR detection.
    """

    def __init__(self, session_manager: SessionManager) -> None:
        self.session_manager = session_manager
        self.detector = IDORDetector()
        self.results: list[TestResult] = []

    def _extract_potential_ids(self, text: str) -> list[str]:
        """Extract potential ID-like values from response text."""
        ids = set()

        # Numeric IDs
        numeric = re.findall(r'\b(\d{2,10})\b', text)
        ids.update(numeric)

        # UUIDs
        uuids = re.findall(
            r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b', text
        )
        ids.update(uuids)

        # Common ID patterns in JSON
        json_ids = re.findall(r'["\'](?:id|user_id|profile_id|item_id)["\']\s*:\s*["\']?([\w-]+)["\']?', text)
        ids.update(json_ids)

        return list(ids)

    def _generate_smart_candidates(
        self, original_value: Any, response_text: str = ""
    ) -> list[Any]:
        """Generate smart candidate values for testing."""
        candidates = [original_value]

        # Extract IDs from previous response if available
        if response_text:
            extracted = self._extract_potential_ids(response_text)
            candidates.extend(extracted)

        # Numeric ID variations
        if str(original_value).isdigit():
            val = int(original_value)
            for offset in [1, -1, 5, 10, 100]:
                candidates.append(str(val + offset))
            candidates.append(str(val * 2))

        # UUID variation (if original looks like UUID)
        if re.match(r'^[0-9a-fA-F-]{36}$', str(original_value)):
            # Keep original + try a few variations (in real tool we could generate fake ones)
            pass

        # Clean and deduplicate
        seen = set()
        unique = []
        for v in candidates:
            v_str = str(v)
            if v_str not in seen:
                seen.add(v_str)
                unique.append(v_str)

        return unique[:15]  # Limit to avoid too many requests

    async def test_parameter(
        self,
        parameter: Parameter,
        target_url: str,
        original_session: str,
        test_sessions: list[str],
        method: str = "GET",
        values_to_test: Optional[list[Any]] = None,
    ) -> TestResult:
        """Test a parameter across roles using smart value selection."""
        test_result = TestResult(parameter=parameter)
        test_result.tested_sessions = [original_session] + test_sessions

        if not self.session_manager.get_session(original_session):
            test_result.error = f"Session '{original_session}' not found"
            return test_result

        original_auth = self.session_manager.get_auth_kwargs(original_session)

        try:
            async with httpx.AsyncClient(**original_auth, follow_redirects=True, timeout=30.0) as client:
                original_resp = await self._make_request(client, method, target_url, parameter)
                original_text = original_resp.text if original_resp else ""

                # Generate smart candidates
                if values_to_test:
                    values = values_to_test
                else:
                    values = self._generate_smart_candidates(parameter.value, original_text)

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
        """Send request handling different parameter locations."""
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
