"""Configuration loading with cookie_file support."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator


def load_cookies_from_file(filepath: str | Path) -> dict[str, str]:
    """Load cookies from a file.

    Supports two formats:
    1. Netscape cookies.txt format (most common from browser export)
    2. Simple key=value format (one per line)
    """
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"Cookie file not found: {filepath}")

    cookies: dict[str, str] = {}

    with open(filepath, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Netscape format: domain  flag  path  secure  expiration  name  value
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


def _resolve_path(base_dir: Path, filepath: str) -> Path:
    """Resolve a path relative to base_dir when not absolute."""
    p = Path(filepath)
    if p.is_absolute():
        return p
    return (base_dir / p).resolve()


class SessionConfig(BaseModel):
    name: str
    cookies: dict[str, str] = Field(default_factory=dict)
    cookie_file: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    description: str | None = None


class TargetConfig(BaseModel):
    url: str
    description: str | None = None


class ScanConfig(BaseModel):
    target: TargetConfig
    original_role: str
    test_roles: list[str]
    parameters: list[dict[str, Any]] = Field(default_factory=list)
    method: str = "GET"
    # role → list of object IDs that role is allowed to access (self-owned)
    own_ids: dict[str, list[str]] = Field(default_factory=dict)
    # roles expected to have broad access (e.g. admin)
    privileged_roles: list[str] = Field(default_factory=list)

    @field_validator("own_ids", mode="before")
    @classmethod
    def _coerce_own_ids(cls, value: Any) -> Any:
        """YAML `alice: [1]` should work the same as `alice: ["1"]`."""
        if not isinstance(value, dict):
            return value
        coerced: dict[str, list[str]] = {}
        for role, ids in value.items():
            if ids is None:
                coerced[str(role)] = []
            elif isinstance(ids, list):
                coerced[str(role)] = [str(i) for i in ids]
            else:
                coerced[str(role)] = [str(ids)]
        return coerced

    @field_validator("privileged_roles", mode="before")
    @classmethod
    def _coerce_privileged_roles(cls, value: Any) -> Any:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(v) for v in value]
        return value


class AccessProbeConfig(BaseModel):
    sessions: list[SessionConfig] = Field(default_factory=list)
    scan: ScanConfig | None = None


def load_config(path: str | Path) -> AccessProbeConfig:
    """Load and validate configuration. Automatically loads cookie_file if present.

    Relative cookie_file paths are resolved relative to the config file directory.
    """
    path = Path(path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    config_dir = path.parent

    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    try:
        config = AccessProbeConfig(**data)

        for session in config.sessions:
            if session.cookie_file:
                cookie_path = _resolve_path(config_dir, session.cookie_file)
                file_cookies = load_cookies_from_file(cookie_path)
                # Merge: explicit cookies override file cookies
                session.cookies = {**file_cookies, **session.cookies}
                # Store resolved path for transparency
                session.cookie_file = str(cookie_path)

        return config

    except ValidationError as e:
        raise ValueError(f"Invalid configuration: {e}") from e


def save_config(config: AccessProbeConfig, path: str | Path) -> None:
    path = Path(path)
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(
            config.model_dump(exclude_none=True),
            f,
            sort_keys=False,
            allow_unicode=True,
        )


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
            parameters=[{"name": "user_id", "location": "query", "value": "42"}],
        ),
    )
