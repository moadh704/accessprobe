"""AccessProbe - Advanced IDOR & Broken Access Control Testing Tool."""

__version__ = "0.1.0"

# Core models
from .models import (
    Parameter,
    ParameterLocation,
    UserSession,
    Target,
    Finding,
    TestResult,
    FindingSeverity,
)

# Main components
from .session import SessionManager
from .tester import IDORTester
from .detector import IDORDetector
from .discovery import ParameterDiscoverer
from .reporter import ReportGenerator

__all__ = [
    "__version__",
    # Models
    "Parameter",
    "ParameterLocation",
    "UserSession",
    "Target",
    "Finding",
    "TestResult",
    "FindingSeverity",
    # Core classes
    "SessionManager",
    "IDORTester",
    "IDORDetector",
    "ParameterDiscoverer",
    "ReportGenerator",
]
