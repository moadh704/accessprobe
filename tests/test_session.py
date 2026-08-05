"""Tests for SessionManager."""

import pytest

from accessprobe.models import UserSession
from accessprobe.session import SessionManager


@pytest.mark.asyncio
async def test_session_manager_basics() -> None:
    sm = SessionManager()
    sm.add_session(UserSession(name="user", cookies={"c": "1"}))
    sm.add_session(UserSession(name="admin", cookies={"c": "2"}, headers={"X": "y"}))

    assert sm.list_sessions() == ["user", "admin"]
    assert len(sm) == 2
    assert "user" in sm
    assert sm.get_session("user") is not None
    assert sm.get_session("user").cookies["c"] == "1"  # type: ignore[union-attr]

    auth = sm.get_auth_kwargs("admin")
    assert auth["cookies"]["c"] == "2"
    assert auth["headers"]["X"] == "y"
    assert sm.get_session("nope") is None
    assert sm.get_auth_kwargs("nope") == {}

    client = sm.get_client("user")
    assert client is not None
    await client.aclose()

    assert sm.remove_session("user") is True
    assert "user" not in sm
    sm.clear()
    assert len(sm) == 0
