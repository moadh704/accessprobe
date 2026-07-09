"""Configuration loading with cookie_file support."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from pydantic import BaseModel, Field, ValidationError


def load_cookies_from_file(filepath: str | Path) -> dict[str, str]:
    """Load cookies from a file.

    Supports two formats:
    1. Netscape cookies.txt format (most common from browser export)
    2. Simple key=value format (one per line)
    """
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"Cookie file not found: {filepath}")

    cookies = {}

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Netscape format: domain	flag	path	secure	expiration	name	value
            if "\t" in line:
                parts = line.split("\t")
                if len(parts) >= 7:
                    name = parts[5]
                    value = parts[6]
                    cookies[name] = value
            else:
                # Simple key=value format
                if "=" in line:
                    key, value = line.split("=", 1)
                    cookies[key.strip()] = value.strip()

    return cookies


class SessionConfig(BaseModel):
    name: str
    cookies: dict[str, str] = Field(default_factory=dict)
    cookie_file: str | None = None          # New: path to cookie file
    headers: dict[str, str] = Field(default_factory=dict)
    description: str | None = None


class TargetConfig(BaseModel):
    url: str
    description: str | None = None


class ScanConfig(BaseModel):
    target: TargetConfig
    original_role: str
    test_roles: list[str]
    parameters: list[dict] = Field(default_factory=list)


class AccessProbeConfig(BaseModel):
    sessions: list[SessionConfig] = Field(default_factory=list)
    scan: ScanConfig | None = None


def load_config(path: str | Path) -> AccessProbeConfig:
    """Load and validate configuration. Automatically loads cookie_file if present."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    try:
        config = AccessProbeConfig(**data)

        # Load cookies from file if cookie_file is specified
        for session in config.sessions:
            if session.cookie_file:
                file_cookies = load_cookies_from_file(session.cookie_file)
                # Merge with any manually defined cookies
                session.cookies = {**file_cookies, **session.cookies}

        return config

    except ValidationError as e:
        raise ValueError(f"Invalid configuration: {e}") from e


def save_config(config: AccessProbeConfig, path: str | Path) -> None:
    path = Path(path)
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(config.model_dump(exclude_none=True), f, sort_keys=False, allow_unicode=True)


def create_example_config() -> AccessProbeConfig:
    return AccessProbeConfig(
        sessions=[
            SessionConfig(
                name="user",
                cookie_file="cookies/user.txt",
                description="Low privilege user",
            ),
            SessionConfig(
                name="admin",
                cookie_file="cookies/admin.txt",
                description="Administrator",
            ),
        ],
        scan=ScanConfig(
            target=TargetConfig(url="https://target.example.com/profile"),
            original_role="user",
            test_roles=["admin"],
            parameters=[
                {"name": "user_id", "location": "query", "value": "42"}
            ],
        ),
    )
