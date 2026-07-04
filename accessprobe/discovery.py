"""Parameter discovery module for finding potential IDOR-prone parameters."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from bs4 import BeautifulSoup

from .models import Parameter, ParameterLocation


class ParameterDiscoverer:
    """Discovers potential parameters that may be vulnerable to IDOR."""

    def __init__(self) -> None:
        self.discovered: list[Parameter] = []

    def discover_from_url(self, url: str) -> list[Parameter]:
        """Extract parameters from URL query string."""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        params = []
        for name, values in query_params.items():
            param = Parameter(
                name=name,
                location=ParameterLocation.QUERY,
                value=values[0] if values else "",
                description=f"Query parameter from URL",
            )
            params.append(param)

        self.discovered.extend(params)
        return params

    def discover_from_html(self, html: str, base_url: str = "") -> list[Parameter]:
        """Extract potential parameters from HTML forms and links."""
        soup = BeautifulSoup(html, "html.parser")
        params: list[Parameter] = []

        # Forms
        for form in soup.find_all("form"):
            for input_tag in form.find_all(["input", "textarea", "select"]):
                name = input_tag.get("name")
                if not name:
                    continue

                value = input_tag.get("value", "")
                input_type = input_tag.get("type", "text").lower()

                # Focus on likely IDOR candidates
                if any(x in name.lower() for x in ["id", "user", "account", "profile", "item", "order"]):
                    location = ParameterLocation.BODY if form.get("method", "get").lower() == "post" else ParameterLocation.QUERY
                    param = Parameter(
                        name=name,
                        location=location,
                        value=value,
                        description=f"Form input ({input_type})",
                    )
                    params.append(param)

        # Simple link parsing for query parameters
        for link in soup.find_all("a", href=True):
            href = link["href"]
            if "?" in href:
                parsed = urlparse(href)
                query_params = parse_qs(parsed.query)
                for name, values in query_params.items():
                    if any(x in name.lower() for x in ["id", "user", "uid", "account"]):
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
        """Basic extraction of potential parameters from JavaScript (simple regex)."""
        params = []
        # Look for common patterns like userId, user_id, profileId, etc.
        pattern = r'["\']?(user_id|userId|profile_id|profileId|account_id|item_id|order_id)["\']?\s*[:=]\s*["\']?([\w-]+)["\']?'
        matches = re.findall(pattern, js_code, re.IGNORECASE)

        for name, value in matches:
            param = Parameter(
                name=name,
                location=ParameterLocation.BODY,  # Often in API calls
                value=value,
                description="Potential parameter from JavaScript",
            )
            params.append(param)

        self.discovered.extend(params)
        return params

    def get_all_discovered(self) -> list[Parameter]:
        """Return all discovered parameters (deduplicated by name)."""
        seen = set()
        unique = []
        for p in self.discovered:
            if p.name not in seen:
                seen.add(p.name)
                unique.append(p)
        return unique
