"""Core Pydantic models for AccessProbe."""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field, HttpUrl


class ParameterLocation(str, Enum):
    """Where the parameter is located in the request."""
    QUERY = "query"
    PATH = "path"
    BODY = "body"
    HEADER = "header"
    COOKIE = "cookie"


class IDType(str, Enum):
    """Common types of IDs that are often vulnerable to IDOR."""
    NUMERIC = "numeric"
    UUID = "uuid"
    BASE64 = "base64"
    HASHED = "hashed"
    CUSTOM = "custom"


class UserSession(BaseModel):
    """Represents a single user/role session for testing."""
    name: str = Field(..., description="Role name, e.g. 'user', 'admin', 'guest'")
    cookies: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    description: Optional[str] = Field(None, description="Optional description of this role")

    model_config = {"extra": "forbid"}


class Target(BaseModel):
    """Target web application configuration."""
    base_url: HttpUrl = Field(..., description="Base URL of the target application")
    name: Optional[str] = Field(None, description="Friendly name for the target")
    description: Optional[str] = Field(None)

    model_config = {"extra": "forbid"}


class Parameter(BaseModel):
    """A discovered parameter that may be vulnerable to IDOR."""
    name: str = Field(..., description="Parameter name")
    location: ParameterLocation = Field(..., description="Where the parameter appears")
    value: Any = Field(..., description="Current/original value")
    id_type: IDType = Field(default=IDType.CUSTOM)
    original_value: Optional[Any] = Field(None, description="Original value before modification")
    description: Optional[str] = Field(None)

    model_config = {"extra": "forbid"}


class FindingSeverity(str, Enum):
    """Severity levels for findings."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    """Represents a potential or confirmed IDOR / Broken Access Control finding."""
    parameter: Parameter
    tested_roles: list[str] = Field(default_factory=list)
    original_response_code: Optional[int] = None
    modified_response_code: Optional[int] = None
    similarity_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    is_vulnerable: bool = False
    severity: FindingSeverity = FindingSeverity.MEDIUM
    evidence: Optional[str] = Field(None, description="Short evidence or reason")
    details: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "forbid"}


class TestResult(BaseModel):
    """Result of testing one parameter across multiple roles."""
    parameter: Parameter
    findings: list[Finding] = Field(default_factory=list)
    tested_sessions: list[str] = Field(default_factory=list)
    success: bool = False
    error: Optional[str] = None

    model_config = {"extra": "forbid"}
