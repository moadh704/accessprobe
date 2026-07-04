"""Session management for multi-role / multi-user testing."""

from __future__ import annotations

from typing import Optional

import httpx

from .models import UserSession


class SessionManager:
    """Manages multiple UserSession objects for IDOR testing across different roles."""

    def __init__(self) -> None:
        self._sessions: dict[str, UserSession] = {}

    def add_session(self, session: UserSession) -> None:
        """Add or update a user session."""
        self._sessions[session.name] = session

    def get_session(self, name: str) -> Optional[UserSession]:
        """Get a session by role name."""
        return self._sessions.get(name)

    def list_sessions(self) -> list[str]:
        """Return list of available session/role names."""
        return list(self._sessions.keys())

    def remove_session(self, name: str) -> bool:
        """Remove a session. Returns True if removed."""
        if name in self._sessions:
            del self._sessions[name]
            return True
        return False

    def get_client(self, session_name: str) -> Optional[httpx.AsyncClient]:
        """Create an async httpx client configured with the session's cookies and headers."""
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
        """Return cookies and headers dict ready to pass to httpx requests."""
        session = self.get_session(session_name)
        if not session:
            return {}

        return {
            "cookies": session.cookies,
            "headers": session.headers,
        }

    def __len__(self) -> int:
        return len(self._sessions)

    def __repr__(self) -> str:
        return f"SessionManager(sessions={list(self._sessions.keys())})"