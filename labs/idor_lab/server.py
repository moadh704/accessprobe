#!/usr/bin/env python3
"""Local multi-user IDOR lab for authorized AccessProbe testing.

Two ACL modes:
  /vuln/profile?user_id=N   — broken access control (any authed user can read any profile)
  /secure/profile?user_id=N — correct ACL (only own profile, or admin can read all)

Sessions (cookie ``session``):
  alice  → user_id 1
  bob    → user_id 2
  admin  → user_id 3 (admin role)

Also serves a small HTML page with discoverable parameters at /
and a JSON list at /api/users.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

USERS = {
    1: {
        "user_id": 1,
        "name": "Alice",
        "email": "alice@lab.local",
        "role": "user",
        "profile": True,
        "account": True,
        "private_notes": "Alice secret diary",
        "phone": "+10000000001",
    },
    2: {
        "user_id": 2,
        "name": "Bob",
        "email": "bob@lab.local",
        "role": "user",
        "profile": True,
        "account": True,
        "private_notes": "Bob salary info",
        "phone": "+10000000002",
    },
    3: {
        "user_id": 3,
        "name": "Admin",
        "email": "admin@lab.local",
        "role": "admin",
        "profile": True,
        "account": True,
        "private_notes": "Admin vault",
        "phone": "+10000000003",
        "dashboard": True,
    },
}

# session cookie value → owning user id + role
SESSIONS = {
    "alice": {"user_id": 1, "role": "user"},
    "bob": {"user_id": 2, "role": "user"},
    "admin": {"user_id": 3, "role": "admin"},
}


def parse_cookies(header: str) -> dict[str, str]:
    out: dict[str, str] = {}
    if not header:
        return out
    for part in header.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            out[k] = v
    return out


class LabHandler(BaseHTTPRequestHandler):
    server_version = "AccessProbeIDORLab/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, code: int, body: bytes, content_type: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, payload: object) -> None:
        self._send(code, json.dumps(payload).encode(), "application/json")

    def _auth(self) -> dict | None:
        cookies = parse_cookies(self.headers.get("Cookie", ""))
        session = cookies.get("session")
        if not session or session not in SESSIONS:
            return None
        return SESSIONS[session]

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qs = parse_qs(parsed.query)

        if path == "/":
            html = """<!DOCTYPE html>
<html><head><title>AccessProbe IDOR Lab</title></head>
<body>
  <h1>IDOR Lab</h1>
  <p>Authorized testing target for AccessProbe.</p>
  <form method="get" action="/vuln/profile">
    <input type="hidden" name="user_id" value="1" />
    <button>Open profile</button>
  </form>
  <a href="/vuln/profile?user_id=1">My profile</a>
  <a href="/orders?order_id=100">Order 100</a>
  <div data-user-id="1" data-account-id="1"></div>
  <script>
    const user_id = "1";
    const order_id = 100;
  </script>
</body></html>"""
            self._send(200, html.encode(), "text/html; charset=utf-8")
            return

        if path == "/api/users":
            auth = self._auth()
            if not auth:
                self._json(401, {"error": "login required"})
                return
            # intentionally leak list of ids for discovery/candidate generation
            self._json(
                200,
                {
                    "users": [
                        {"user_id": u["user_id"], "name": u["name"]} for u in USERS.values()
                    ]
                },
            )
            return

        if path == "/health":
            self._json(200, {"status": "ok", "lab": "idor"})
            return

        if path in ("/vuln/profile", "/secure/profile"):
            auth = self._auth()
            if not auth:
                self._json(401, {"error": "unauthorized", "message": "login required"})
                return

            raw_id = (qs.get("user_id") or [None])[0]
            if raw_id is None:
                self._json(400, {"error": "user_id required"})
                return
            try:
                target_id = int(raw_id)
            except ValueError:
                self._json(400, {"error": "invalid user_id"})
                return

            if target_id not in USERS:
                self._json(404, {"error": "not found"})
                return

            if path == "/secure/profile":
                # Correct ACL: own profile or admin
                if auth["role"] != "admin" and auth["user_id"] != target_id:
                    self._json(
                        403,
                        {
                            "error": "forbidden",
                            "message": "access denied",
                            "user_id": target_id,
                        },
                    )
                    return

            # /vuln/profile: any authenticated user can read any profile (IDOR)
            self._json(200, USERS[target_id])
            return

        if path == "/orders":
            auth = self._auth()
            if not auth:
                self._json(401, {"error": "login required"})
                return
            order_id = (qs.get("order_id") or ["0"])[0]
            # Always returns order if authed → broken object-level auth
            self._json(
                200,
                {
                    "order_id": order_id,
                    "owner_user_id": 1 if str(order_id) in ("100", "101") else 2,
                    "item": "Lab Widget",
                    "total": 42.0,
                    "private": True,
                    "account": True,
                },
            )
            return

        self._json(404, {"error": "unknown path", "path": path})


def main() -> None:
    host = "127.0.0.1"
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    server = ThreadingHTTPServer((host, port), LabHandler)
    print(f"IDOR lab listening on http://{host}:{port}", flush=True)
    print("Sessions: session=alice | session=bob | session=admin", flush=True)
    print("Vuln:   GET /vuln/profile?user_id=N", flush=True)
    print("Secure: GET /secure/profile?user_id=N", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down", flush=True)
        server.shutdown()


if __name__ == "__main__":
    main()
