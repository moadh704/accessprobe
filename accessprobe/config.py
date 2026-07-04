"""Configuration loading for AccessProbe using YAML."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from pydantic import BaseModel, Field, ValidationError


class SessionConfig(BaseModel):
    name: str
    cookies: dict[str, str] = Field(default_factory=dict)
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
    """Load and validate AccessProbe configuration from YAML file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    try:
        return AccessProbeConfig(**data)
    except ValidationError as e:
        raise ValueError(f"Invalid configuration: {e}") from e


def save_config(config: AccessProbeConfig, path: str | Path) -> None:
    """Save configuration to YAML file."""
    path = Path(path)
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(config.model_dump(exclude_none=True), f, sort_keys=False, allow_unicode=True)


def create_example_config() -> AccessProbeConfig:
    """Create an example configuration."""
    return AccessProbeConfig(
        sessions=[
            SessionConfig(
                name="user",
                cookies={"session": "user_cookie_value"},
                description="Low privilege user",
            ),
            SessionConfig(
                name="admin",
                cookies={"session": "admin_cookie_value"},
                description="Administrator",
            ),
        ],
        scan=ScanConfig(
            target=TargetConfig(url="https://target.example.com/profile", description="User profile endpoint"),
            original_role="user",
            test_roles=["admin"],
            parameters=[
                {"name": "user_id", "location": "query", "value": "42"}
            ],
        ),
    )
