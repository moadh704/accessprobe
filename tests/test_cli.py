"""CLI smoke tests."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "accessprobe.cli", *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_cli_version() -> None:
    r = subprocess.run(
        [sys.executable, "-m", "accessprobe.cli", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0
    assert "0.3.0" in r.stdout


def test_cli_help_no_command() -> None:
    r = _run()
    assert r.returncode == 0
    assert "AccessProbe" in r.stdout


def test_cli_scan_missing_args() -> None:
    r = _run("scan")
    assert r.returncode == 1
    assert "required" in (r.stdout + r.stderr).lower()
    # Must NOT raise asyncio TypeError / ValueError traceback for missing coro
    assert "a coroutine was expected" not in (r.stdout + r.stderr)


def test_cli_scan_e2e(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            return

        def do_GET(self) -> None:
            qs = parse_qs(urlparse(self.path).query)
            uid = (qs.get("user_id") or ["1"])[0]
            body = (
                f'{{"user_id":{uid},"name":"U{uid}",'
                f'"email":"u{uid}@x.com","profile":true,"account":true,"private":true}}'
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode())

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    cookies = tmp_path / "cookies"
    cookies.mkdir()
    (cookies / "user.txt").write_text("session=user1\n")
    (cookies / "admin.txt").write_text("session=admin1\n")
    cfg = tmp_path / "scan.yaml"
    cfg.write_text(
        f"""
sessions:
  - name: user
    cookie_file: cookies/user.txt
  - name: admin
    cookie_file: cookies/admin.txt
scan:
  target:
    url: "http://127.0.0.1:{port}/profile"
  original_role: user
  test_roles:
    - admin
  parameters:
    - name: user_id
      location: query
      value: "1"
"""
    )
    report = tmp_path / "out.json"
    html = tmp_path / "out.html"

    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "accessprobe.cli",
            "scan",
            "--config",
            str(cfg),
            "--report",
            str(report),
            "--html-report",
            str(html),
            "--delay",
            "0.01",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(tmp_path),
        check=False,
    )
    server.shutdown()

    assert "a coroutine was expected" not in (r.stdout + r.stderr)
    assert r.returncode == 0, r.stdout + r.stderr
    assert report.exists()
    assert html.exists()
    data = json.loads(report.read_text())
    assert data["total_tests"] >= 1
    assert "Scan finished" in r.stdout
