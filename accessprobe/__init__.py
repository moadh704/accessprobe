"""AccessProbe - Advanced IDOR & Broken Access Control Testing Tool."""

from __future__ import annotations

__version__ = "0.3.0"

from .detector import IDORDetector
from .discovery import ParameterDiscoverer
from .models import (
    Finding,
    FindingSeverity,
    Parameter,
    ParameterLocation,
    Target,
    TestResult,
    UserSession,
)
from .reporter import ReportGenerator
from .session import SessionManager
from .tester import IDORTester

__all__ = [
    "Finding",
    "FindingSeverity",
    "IDORDetector",
    "IDORTester",
    "Parameter",
    "ParameterDiscoverer",
    "ParameterLocation",
    "ReportGenerator",
    "SessionManager",
    "Target",
    "TestResult",
    "UserSession",
    "__version__",
]
