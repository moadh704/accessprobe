"""Session management for multi-role IDOR and access control testing."""

from __future__ import annotations

from typing import Optional

import httpx

from .models import UserSession


class SessionManager:
    """Manages multiple user sessions/roles for testing.

    Provides convenient methods for multi-role access control testing.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, UserSession] = {}

    def add_session(self, session: UserSession) -> None:
        """Add or update a session."""
        self._sessions[session.name] = session

    def add_sessions(self, sessions: list[UserSession]) -> None:
        """Add multiple sessions at once."""
        for session in sessions:
            self.add_session(session)

    def get_session(self, name: str) -> Optional[UserSession]:
        """Get a session by name."""
        return self._sessions.get(name)

    def list_sessions(self) -> list[str]:
        """Return list of session names."""
        return list(self._sessions.keys())

    def get_all_sessions(self) -> list[UserSession]:
        """Return all session objects."""
        return list(self._sessions.values())

    def remove_session(self, name: str) -> bool:
        """Remove a session. Returns True if removed."""
        if name in self._sessions:
            del self._sessions[name]
            return True
        return False

    def clear(self) -> None:
        """Remove all sessions."""
        self._sessions.clear()

    def get_client(self, session_name: str) -> Optional[httpx.AsyncClient]:
        """Return an async httpx client configured for the session."""
        session = self.get_session(session_name)
        if not session:
            return None

        return httpx.AsyncClient(
            cookies=session.cookies,
            headers=session.headers,
            follow_redirects=True,
            timeout=30.0,
        )

    def get_auth_kwargs(self, session_name: str) -> dict:
        """Return cookies and headers ready for httpx requests."""
        session = self.get_session(session_name)
        if not session:
            return {}

        return {
            "cookies": session.cookies.copy(),
            "headers": session.headers.copy(),
        }

    def __len__(self) -> int:
        return len(self._sessions)

    def __contains__(self, name: str) -> bool:
        return name in self._sessions

    def __repr__(self) -> str:
        return f"SessionManager(roles={self.list_sessions()})"
