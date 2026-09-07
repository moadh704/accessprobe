"""Integration tests for IDORTester against a local mock server."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from accessprobe.models import Parameter, ParameterLocation, UserSession
from accessprobe.session import SessionManager
from accessprobe.tester import IDORTester


class _IDORApp(BaseHTTPRequestHandler):
    """Mock: user may only view user_id=1; admin may view all."""

    def log_message(self, *args: object) -> None:
        return

    def do_GET(self) -> None:
        qs = parse_qs(urlparse(self.path).query)
        uid = (qs.get("user_id") or ["?"])[0]
        cookie = self.headers.get("Cookie", "")

        if "role=admin" in cookie:
            body = (
                f'{{"user_id":{uid},"name":"User{uid}",'
                f'"email":"u{uid}@ex.com","profile":true,"account":true}}'
            )
            self.send_response(200)
        elif "role=user" in cookie:
            if uid == "1":
                body = '{"user_id":1,"name":"Alice","email":"a@ex.com","profile":true}'
                self.send_response(200)
            else:
                body = '{"error":"forbidden","message":"access denied"}'
                self.send_response(403)
        else:
            body = "unauth"
            self.send_response(401)

        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true,"echo":' + raw + b"}")


@pytest.fixture(scope="module")
def mock_server() -> tuple[str, HTTPServer]:
    server = HTTPServer(("127.0.0.1", 0), _IDORApp)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}/profile", server
    server.shutdown()


@pytest.mark.asyncio
async def test_horizontal_idor_detected(mock_server: tuple[str, HTTPServer]) -> None:
    base, _ = mock_server
    sm = SessionManager()
    sm.add_session(UserSession(name="user", cookies={"role": "user"}))
    sm.add_session(UserSession(name="admin", cookies={"role": "admin"}))

    tester = IDORTester(sm, delay=0.01)
    param = Parameter(name="user_id", location=ParameterLocation.QUERY, value="1")
    result = await tester.test_parameter(
        parameter=param,
        target_url=base,
        original_session="user",
        test_sessions=["admin"],
        values_to_test=["1", "2"],
        test_horizontal=True,
    )

    assert result.success is True
    assert result.error is None
    assert len(result.findings) >= 1

    # Horizontal: user accessing id=2 should be 403 (not vulnerable access)
    # Admin accessing alternate IDs may flag cross-role
    # User id=1 baseline works; user id=2 gets 403 → not horizontal success
    horizontal = [
        f
        for f in result.findings
        if f.details.get("same_role") and str(f.parameter.value) == "2"
    ]
    assert horizontal, "expected horizontal finding for value 2"
    # 403 on foreign id is correct access control → not vulnerable
    assert horizontal[0].modified_response_code == 403
    assert horizontal[0].is_vulnerable is False


@pytest.mark.asyncio
async def test_broken_acl_when_user_can_read_others() -> None:
    """If low-priv can read foreign IDs, horizontal IDOR should fire."""

    class OpenApp(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            return

        def do_GET(self) -> None:
            qs = parse_qs(urlparse(self.path).query)
            uid = (qs.get("user_id") or ["?"])[0]
            body = (
                f'{{"user_id":{uid},"name":"User{uid}",'
                f'"email":"u{uid}@ex.com","profile":true,"secret":"x"}}'
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode())

    server = HTTPServer(("127.0.0.1", 0), OpenApp)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}/profile"

    sm = SessionManager()
    sm.add_session(UserSession(name="user", cookies={"s": "1"}))
    sm.add_session(UserSession(name="admin", cookies={"s": "2"}))
    tester = IDORTester(sm, delay=0.01)
    param = Parameter(name="user_id", location=ParameterLocation.QUERY, value="1")
    result = await tester.test_parameter(
        parameter=param,
        target_url=base,
        original_session="user",
        test_sessions=["admin"],
        values_to_test=["1", "2"],
        test_horizontal=True,
    )
    server.shutdown()

    assert result.success
    horizontal_vulns = [
        f
        for f in result.findings
        if f.is_vulnerable and f.details.get("same_role") and str(f.parameter.value) == "2"
    ]
    assert horizontal_vulns, "expected horizontal IDOR when user can read id=2"


@pytest.mark.asyncio
async def test_missing_session() -> None:
    sm = SessionManager()
    tester = IDORTester(sm, delay=0.01)
    param = Parameter(name="id", location=ParameterLocation.QUERY, value=1)
    result = await tester.test_parameter(
        param, "http://127.0.0.1:9/", "missing", ["admin"]
    )
    assert result.error is not None
    assert "not found" in result.error


@pytest.mark.asyncio
async def test_path_and_body_params(mock_server: tuple[str, HTTPServer]) -> None:
    base, _server = mock_server
    # Reuse same host for path/body via custom handlers is heavy; unit-test request builder
    sm = SessionManager()
    sm.add_session(UserSession(name="u", cookies={}))
    sm.add_session(UserSession(name="a", cookies={}))
    tester = IDORTester(sm, delay=0.01)

    # PATH without live assertion of body — just ensure no crash
    # Use the mock which ignores path shape but answers GET
    host = base.rsplit("/profile", 1)[0]
    param = Parameter(name="id", location=ParameterLocation.PATH, value="5")
    result = await tester.test_parameter(
        param,
        f"{host}/users/{{id}}",
        "u",
        ["a"],
        values_to_test=["5"],
        test_horizontal=False,
    )
    assert result.success is True

    pbody = Parameter(name="order_id", location=ParameterLocation.BODY, value="10")
    rbody = await tester.test_parameter(
        pbody,
        host + "/api",
        "u",
        ["a"],
        method="POST",
        values_to_test=["10"],
        test_horizontal=False,
    )
    assert rbody.success is True


def test_candidate_generation() -> None:
    sm = SessionManager()
    tester = IDORTester(sm)
    vals = tester._generate_candidate_values(42, "")
    assert 42 in vals
    assert 43 in vals
    assert 41 in vals

    text = "User 1001 and uuid a1b2c3d4-e5f6-7890-abcd-ef1234567890 found"
    vals2 = tester._generate_candidate_values(100, text)
    assert any(str(v) == "1001" for v in vals2)
    assert any("a1b2c3d4" in str(v) for v in vals2)
    assert len(vals2) <= 8


def test_inject_path_replaces_trailing_id() -> None:
    sm = SessionManager()
    tester = IDORTester(sm)
    baseline = Parameter(name="id", location=ParameterLocation.PATH, value="8")
    assert (
        tester._inject_path("http://127.0.0.1:3000/rest/basket/8", baseline)
        == "http://127.0.0.1:3000/rest/basket/8"
    )
    modified = Parameter(
        name="id",
        location=ParameterLocation.PATH,
        value="9",
        original_value="8",
    )
    assert (
        tester._inject_path("http://127.0.0.1:3000/rest/basket/8", modified)
        == "http://127.0.0.1:3000/rest/basket/9"
    )
    placeholder = Parameter(name="id", location=ParameterLocation.PATH, value="9")
    assert (
        tester._inject_path("http://127.0.0.1:3000/rest/basket/{id}", placeholder)
        == "http://127.0.0.1:3000/rest/basket/9"
    )
    nested = Parameter(
        name="id",
        location=ParameterLocation.PATH,
        value="9",
        original_value="8",
    )
    assert (
        tester._inject_path("http://127.0.0.1:3000/users/8/profile", nested)
        == "http://127.0.0.1:3000/users/9/profile"
    )


def test_inject_query_keeps_sibling_params() -> None:
    sm = SessionManager()
    tester = IDORTester(sm)
    param = Parameter(name="user_id", location=ParameterLocation.QUERY, value="2")
    out = tester._inject_query(
        "http://example.com/profile?user_id=1&extra=keep", param
    )
    assert "extra=keep" in out
    assert "user_id=2" in out
    assert "user_id=1" not in out
    no_qs = tester._inject_query("http://example.com/profile", param)
    assert no_qs.endswith("?user_id=2") or "?user_id=2" in no_qs


@pytest.mark.asyncio
async def test_login_redirect_not_reported_as_idor() -> None:
    class App(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            return

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            qs = parse_qs(urlparse(self.path).query)
            cookie = self.headers.get("Cookie", "")
            if path == "/login":
                body = b"<html>Please login</html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body)
                return
            uid = (qs.get("id") or ["1"])[0]
            if "role=alice" in cookie and uid != "1":
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
                return
            body = (
                f'{{"id":{uid},"name":"User{uid}",'
                f'"email":"u{uid}@ex.com","profile":true}}'
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), App)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}/profile"

    sm = SessionManager()
    sm.add_session(UserSession(name="alice", cookies={"role": "alice"}))
    sm.add_session(UserSession(name="bob", cookies={"role": "bob"}))
    tester = IDORTester(sm, delay=0.0)
    param = Parameter(name="id", location=ParameterLocation.QUERY, value="1")
    result = await tester.test_parameter(
        parameter=param,
        target_url=base,
        original_session="alice",
        test_sessions=["bob"],
        values_to_test=["1", "2"],
        test_horizontal=True,
    )
    server.shutdown()

    assert result.success
    horiz = [
        f
        for f in result.findings
        if f.details.get("same_role") and str(f.parameter.value) == "2"
    ]
    assert horiz
    assert horiz[0].is_vulnerable is False
    assert horiz[0].modified_response_code == 401
