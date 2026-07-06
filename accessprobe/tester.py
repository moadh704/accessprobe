"""Advanced IDOR Testing Engine with logging and robustness."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Optional

import httpx

from .models import Parameter, TestResult, ParameterLocation
from .session import SessionManager
from .detector import IDORDetector

from .utils import get_logger

logger = get_logger("accessprobe.tester")


class IDORTester:
    """Production-grade IDOR testing engine."""

    def __init__(self, session_manager: SessionManager, delay: float = 0.25) -> None:
        self.session_manager = session_manager
        self.detector = IDORDetector()
        self.results: list[TestResult] = []
        self.delay = delay

    def _extract_potential_ids(self, text: str) -> list[str]:
        ids = set()
        for match in re.finditer(r'["\']?(?:id|user_id|profile_id|account_id|item_id)["\']?\s*[:=]\s*["\']?(\d{1,10})["\']?', text, re.IGNORECASE):
            ids.add(match.group(1))
        for match in re.finditer(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', text):
            ids.add(match.group(0))
        return list(ids)[:8]

    def _generate_candidate_values(self, original_value: Any, response_text: str = "") -> list[Any]:
        candidates = [original_value]
        if response_text:
            candidates.extend(self._extract_potential_ids(response_text))
        if isinstance(original_value, (int, str)) and str(original_value).isdigit():
            val = int(original_value)
            candidates.extend([val + 1, val - 1, val + 5, val + 10])
        seen = set()
        unique = []
        for v in candidates:
            if str(v) not in seen:
                seen.add(str(v))
                unique.append(v)
        return unique[:10]

    async def test_parameter(
        self, parameter: Parameter, target_url: str, original_session: str, test_sessions: list[str], method: str = "GET", values_to_test: Optional[list[Any]] = None
    ) -> TestResult:
        logger.info(f"Testing parameter '{parameter.name}' on {target_url}")

        test_result = TestResult(parameter=parameter)
        test_result.tested_sessions = [original_session] + test_sessions

        if not self.session_manager.get_session(original_session):
            test_result.error = f"Session '{original_session}' not found"
            logger.error(test_result.error)
            return test_result

        original_auth = self.session_manager.get_auth_kwargs(original_session)

        try:
            async with httpx.AsyncClient(**original_auth, follow_redirects=True, timeout=30.0) as client:
                original_resp = await self._make_request(client, method, target_url, parameter)
                await asyncio.sleep(self.delay)

                response_text = original_resp.text if original_resp else ""
                values = values_to_test or self._generate_candidate_values(parameter.value, response_text)

                findings = []

                for test_role in test_sessions:
                    test_auth = self.session_manager.get_auth_kwargs(test_role)
                    if not test_auth:
                        logger.warning(f"No auth found for role '{test_role}'")
                        continue

                    for test_value in values:
                        modified_param = parameter.model_copy(update={"value": test_value})

                        async with httpx.AsyncClient(**test_auth, follow_redirects=True, timeout=30.0) as test_client:
                            modified_resp = await self._make_request(test_client, method, target_url, modified_param)
                            await asyncio.sleep(self.delay)

                            analysis = self.detector.analyze_responses(original_resp, modified_resp, original_session, test_role)

                            finding = self.detector.create_finding(modified_param, analysis, original_session, test_role)
                            finding.original_response_code = original_resp.status_code if original_resp else None
                            finding.modified_response_code = modified_resp.status_code if modified_resp else None
                            finding.similarity_score = analysis.get("similarity")

                            findings.append(finding)

                test_result.findings = findings
                test_result.success = True
                logger.info(f"Completed testing '{parameter.name}' — {len(findings)} findings")

        except Exception as e:
            test_result.error = str(e)
            logger.error(f"Error testing parameter: {e}")

        self.results.append(test_result)
        return test_result

    async def _make_request(self, client: httpx.AsyncClient, method: str, url: str, parameter: Parameter) -> Optional[httpx.Response]:
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
