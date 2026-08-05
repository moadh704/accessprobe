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
