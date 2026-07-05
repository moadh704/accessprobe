"""Core IDOR Testing Engine with rate limiting and better robustness."""

from __future__ import annotations

import asyncio
import re
from typing import Any, Optional

import httpx

from .models import Parameter, TestResult, ParameterLocation
from .session import SessionManager
from .detector import IDORDetector


class IDORTester:
    """Main engine for IDOR testing with rate limiting support."""

    def __init__(self, session_manager: SessionManager, rate_limit: float = 0.5) -> None:
        """
        Args:
            session_manager: SessionManager instance
            rate_limit: Minimum delay between requests in seconds (default 0.5s)
        """
        self.session_manager = session_manager
        self.detector = IDORDetector()
        self.results: list[TestResult] = []
        self.rate_limit = rate_limit  # seconds between requests
        self._last_request_time = 0.0

    async def _apply_rate_limit(self):
        """Simple rate limiting between requests."""
        if self.rate_limit > 0:
            now = asyncio.get_event_loop().time()
            time_since_last = now - self._last_request_time
            if time_since_last < self.rate_limit:
                await asyncio.sleep(self.rate_limit - time_since_last)
            self._last_request_time = asyncio.get_event_loop().time()

    def _extract_potential_ids(self, text: str) -> list[str]:
        """Extract potential ID values from text."""
        ids = set()
        numeric = re.findall(r'\b(\d{2,10})\b', text)
        ids.update(numeric)

        uuids = re.findall(
            r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b', text
        )
        ids.update(uuids)

        json_ids = re.findall(r'["\'](?:id|user_id|profile_id|item_id)["\']\s*:\s*["\']?([\w-]+)["\']?', text)
        ids.update(json_ids)

        return list(ids)

    def _generate_smart_candidates(self, original_value: Any, response_text: str = "") -> list[Any]:
        """Generate candidate values for testing."""
        candidates = [original_value]

        if response_text:
            extracted = self._extract_potential_ids(response_text)
            candidates.extend(extracted)

        if str(original_value).isdigit():
            val = int(original_value)
            for offset in [1, -1, 5, 10, 100]:
                candidates.append(str(val + offset))

        seen = set()
        unique = []
        for v in candidates:
            v_str = str(v)
            if v_str not in seen:
                seen.add(v_str)
                unique.append(v_str)

        return unique[:12]

    async def test_parameter(
        self,
        parameter: Parameter,
        target_url: str,
        original_session: str,
        test_sessions: list[str],
        method: str = "GET",
        values_to_test: Optional[list[Any]] = None,
    ) -> TestResult:
        """Test parameter with rate limiting."""
        test_result = TestResult(parameter=parameter)
        test_result.tested_sessions = [original_session] + test_sessions

        if not self.session_manager.get_session(original_session):
            test_result.error = f"Session '{original_session}' not found"
            return test_result

        original_auth = self.session_manager.get_auth_kwargs(original_session)

        try:
            async with httpx.AsyncClient(**original_auth, follow_redirects=True, timeout=30.0) as client:
                await self._apply_rate_limit()
                original_resp = await self._make_request(client, method, target_url, parameter)
                original_text = original_resp.text if original_resp else ""

                values = values_to_test or self._generate_smart_candidates(parameter.value, original_text)

                findings = []

                for test_role in test_sessions:
                    test_auth = self.session_manager.get_auth_kwargs(test_role)
                    if not test_auth:
                        continue

                    for test_value in values:
                        modified_param = parameter.model_copy(update={"value": test_value})

                        async with httpx.AsyncClient(**test_auth, follow_redirects=True, timeout=30.0) as test_client:
                            await self._apply_rate_limit()
                            modified_resp = await self._make_request(test_client, method, target_url, modified_param)

                            analysis = self.detector.analyze_responses(
                                original_resp, modified_resp, original_session, test_role
                            )

                            finding = self.detector.create_finding(
                                modified_param, analysis, original_session, test_role
                            )
                            finding.original_response_code = original_resp.status_code if original_resp else None
                            finding.modified_response_code = modified_resp.status_code if modified_resp else None
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
        """Make request with basic error handling."""
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

        except httpx.RequestError as e:
            # Network / connection errors
            return None
        except Exception:
            return None

    def get_results(self) -> list[TestResult]:
        return self.results

    def set_rate_limit(self, delay: float):
        """Change rate limit between requests (in seconds)."""
        self.rate_limit = max(0.0, delay)
