"""Advanced Parameter Discovery for IDOR and Broken Access Control testing."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from bs4 import BeautifulSoup, Tag

from .models import Parameter, ParameterLocation


class ParameterDiscoverer:
    """Improved parameter discovery from multiple sources."""

    INTERESTING_NAMES = [
        "id", "user_id", "profile_id", "account_id", "item_id", "order_id",
        "post_id", "comment_id", "file_id", "doc_id", "resource_id", "uuid",
        "uid", "pid", "oid", "eid", "rid"
    ]

    def __init__(self) -> None:
        self.discovered: list[Parameter] = []

    def discover_from_url(self, url: str) -> list[Parameter]:
        """Extract parameters from URL query string."""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        params = []
        for name, values in query_params.items():
            if self._is_interesting_name(name):
                param = Parameter(
                    name=name,
                    location=ParameterLocation.QUERY,
                    value=values[0] if values else "",
                    description="Query parameter from URL",
                )
                params.append(param)

        self.discovered.extend(params)
        return params

    def discover_from_html(self, html: str) -> list[Parameter]:
        """Extract potential IDOR parameters from HTML content."""
        soup = BeautifulSoup(html, "html.parser")
        params: list[Parameter] = []

        # Forms (inputs, selects, textareas)
        for form in soup.find_all("form"):
            method = form.get("method", "get").lower()
            location = ParameterLocation.BODY if method == "post" else ParameterLocation.QUERY

            for tag in form.find_all(["input", "textarea", "select", "button"]):
                name = tag.get("name") or tag.get("id")
                if not name or not self._is_interesting_name(name):
                    continue

                value = tag.get("value", "")
                param = Parameter(
                    name=name,
                    location=location,
                    value=value,
                    description=f"Form field ({tag.name})",
                )
                params.append(param)

        # Data attributes (common in modern web apps)
        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if attr.startswith("data-") and any(x in attr.lower() for x in ["id", "user", "item", "order"]):
                    clean_name = attr.replace("data-", "")
                    if self._is_interesting_name(clean_name):
                        param = Parameter(
                            name=clean_name,
                            location=ParameterLocation.QUERY,
                            value=str(value),
                            description="Data attribute parameter",
                        )
                        params.append(param)

        # Links with query parameters
        for link in soup.find_all("a", href=True):
            href = link.get("href", "")
            if "?" in href:
                parsed = urlparse(href)
                for name, values in parse_qs(parsed.query).items():
                    if self._is_interesting_name(name):
                        param = Parameter(
                            name=name,
                            location=ParameterLocation.QUERY,
                            value=values[0] if values else "",
                            description="Parameter from link",
                        )
                        params.append(param)

        self.discovered.extend(params)
        return params

    def discover_from_javascript(self, js_code: str) -> list[Parameter]:
        """Extract potential parameters from JavaScript code."""
        params = []

        # JSON-like ID assignments
        patterns = [
            r'["\']?(user_id|profile_id|item_id|order_id|post_id|comment_id)["\']?\s*[:=]\s*["\']?([\w-]+)["\']?',
            r'["\']?id["\']?\s*[:=]\s*["\']?([\w-]{3,})["\']?',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, js_code, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    name = match[0] if len(match) > 1 else "id"
                    value = match[1] if len(match) > 1 else match[0]
                else:
                    name = "id"
                    value = match

                if self._is_interesting_name(name):
                    param = Parameter(
                        name=name,
                        location=ParameterLocation.BODY,
                        value=value,
                        description="JavaScript parameter",
                    )
                    params.append(param)

        self.discovered.extend(params)
        return params

    def discover_from_api_response(self, json_data: dict | list) -> list[Parameter]:
        """Extract potential ID parameters from API/JSON responses."""
        params = []

        def extract_from_dict(d: dict, prefix: str = ""):
            for key, value in d.items():
                if isinstance(value, (dict, list)):
                    extract_from_dict(value if isinstance(value, dict) else {}, f"{prefix}{key}.")
                elif isinstance(value, (str, int)) and self._is_interesting_name(key):
                    param = Parameter(
                        name=key,
                        location=ParameterLocation.BODY,
                        value=str(value),
                        description=f"API response field ({prefix}{key})",
                    )
                    params.append(param)

        if isinstance(json_data, dict):
            extract_from_dict(json_data)
        elif isinstance(json_data, list):
            for item in json_data:
                if isinstance(item, dict):
                    extract_from_dict(item)

        self.discovered.extend(params)
        return params

    def _is_interesting_name(self, name: str) -> bool:
        """Check if parameter name looks like it could be IDOR-related."""
        name_lower = name.lower()
        return any(x in name_lower for x in self.INTERESTING_NAMES)

    def get_all_discovered(self, unique: bool = True) -> list[Parameter]:
        """Return discovered parameters."""
        if not unique:
            return self.discovered

        seen = set()
        unique_params = []
        for p in self.discovered:
            if p.name not in seen:
                seen.add(p.name)
                unique_params.append(p)
        return unique_params
