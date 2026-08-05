"""Tests for configuration and cookie loading."""

from pathlib import Path

import pytest

from accessprobe.config import (
    create_example_config,
    load_config,
    load_cookies_from_file,
)


def test_load_netscape_cookies(tmp_path: Path) -> None:
    f = tmp_path / "c.txt"
    f.write_text(
        "# Netscape HTTP Cookie File\n"
        ".example.com\tTRUE\t/\tFALSE\t0\tsession\tabc\n"
        ".example.com\tTRUE\t/\tFALSE\t0\tuid\t7\n"
    )
    cookies = load_cookies_from_file(f)
    assert cookies == {"session": "abc", "uid": "7"}


def test_load_kv_cookies(tmp_path: Path) -> None:
    f = tmp_path / "c.txt"
    f.write_text("session=xyz\n# comment\ntoken=tok\n")
    assert load_cookies_from_file(f) == {"session": "xyz", "token": "tok"}


def test_missing_cookie_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_cookies_from_file(tmp_path / "missing.txt")


def test_load_config_resolves_cookie_relative_to_config(tmp_path: Path) -> None:
    cookies_dir = tmp_path / "cookies"
    cookies_dir.mkdir()
    (cookies_dir / "user.txt").write_text("session=fromfile\n")

    cfg = tmp_path / "scan.yaml"
    cfg.write_text(
        """
sessions:
  - name: user
    cookie_file: cookies/user.txt
    cookies:
      extra: manual
scan:
  target:
    url: "https://app.example.com/profile"
  original_role: user
  test_roles:
    - admin
  parameters:
    - name: user_id
      location: query
      value: "42"
"""
    )
    # Load from another CWD to ensure relative resolution uses config dir
    loaded = load_config(cfg)
    assert loaded.sessions[0].cookies["session"] == "fromfile"
    assert loaded.sessions[0].cookies["extra"] == "manual"
    assert loaded.scan is not None
    assert loaded.scan.target.url == "https://app.example.com/profile"
    assert loaded.scan.parameters[0]["name"] == "user_id"


def test_missing_config(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "nope.yaml")


def test_create_example_config() -> None:
    ex = create_example_config()
    assert ex.scan is not None
    assert len(ex.sessions) == 2
