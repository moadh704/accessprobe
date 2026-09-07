"""Tests for parameter discovery."""

from accessprobe.discovery import ParameterDiscoverer


def test_discover_from_url() -> None:
    d = ParameterDiscoverer()
    params = d.discover_from_url(
        "https://app.com/profile?user_id=42&page=1&order_id=99"
    )
    names = {p.name for p in params}
    assert "user_id" in names
    assert "order_id" in names
    assert "page" not in names


def test_discover_from_html() -> None:
    d = ParameterDiscoverer()
    html = """
    <html><body>
    <form method="post">
      <input name="user_id" value="7"/>
      <input name="email" value="a@b.com"/>
    </form>
    <div data-user-id="55"></div>
    <a href="/item?item_id=123">link</a>
    </body></html>
    """
    params = d.discover_from_html(html)
    names = {p.name for p in params}
    assert "user_id" in names
    assert "item_id" in names
    assert "email" not in names


def test_discover_from_js() -> None:
    d = ParameterDiscoverer()
    params = d.discover_from_javascript(
        'const user_id = "abc-123"; var order_id = 999;'
    )
    assert len(params) >= 1


def test_discover_from_api() -> None:
    d = ParameterDiscoverer()
    params = d.discover_from_api_response(
        {"user_id": 1, "profile": {"account_id": 2}, "name": "x"}
    )
    names = {p.name for p in params}
    assert "user_id" in names
    assert "account_id" in names
    assert "name" not in names


def test_unique_discovered() -> None:
    d = ParameterDiscoverer()
    d.discover_from_url("https://x.com?user_id=1")
    d.discover_from_url("https://x.com?user_id=2")
    unique = d.get_all_discovered(unique=True)
    assert len([p for p in unique if p.name == "user_id"]) == 1


def test_noise_names_not_interesting() -> None:
    d = ParameterDiscoverer()
    for noise in ("hidden", "valid", "width", "invalid", "video", "grid"):
        assert d._is_interesting_name(noise) is False
    for good in ("id", "user_id", "userId", "account-id", "uid", "order_id"):
        assert d._is_interesting_name(good) is True
    html = '<form><input name="hidden" value="x"/><input name="user_id" value="1"/></form>'
    names = {p.name for p in ParameterDiscoverer().discover_from_html(html)}
    assert "hidden" not in names
    assert "user_id" in names


def test_js_does_not_extract_id_from_order_id() -> None:
    params = ParameterDiscoverer().discover_from_javascript(
        'const user_id = "1"; const order_id = 100;'
    )
    names = {p.name for p in params}
    assert "user_id" in names
    assert "order_id" in names
    assert "id" not in names
