"""Command Line Interface for AccessProbe."""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import Sequence
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from accessprobe import __version__

console = Console()


def print_banner() -> None:
    banner = Text()
    banner.append("AccessProbe", style="bold cyan")
    banner.append(f" v{__version__}", style="dim")
    banner.append(
        "\nAdvanced IDOR & Broken Access Control Tester", style="italic dim"
    )
    panel = Panel(banner, border_style="cyan", padding=(1, 2))
    console.print(panel)


def parse_cookie_string(cookie_str: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for pair in cookie_str.split(";"):
        if "=" in pair:
            k, v = pair.strip().split("=", 1)
            cookies[k] = v
    return cookies


def parse_own_ids(spec: str | None) -> dict[str, list[str]]:
    """Parse ``alice=1,10;bob=2`` into ``{alice: [1,10], bob: [2]}``."""
    if not spec:
        return {}
    result: dict[str, list[str]] = {}
    for chunk in spec.split(";"):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        role, ids_part = chunk.split("=", 1)
        role = role.strip()
        ids = [x.strip() for x in ids_part.split(",") if x.strip()]
        if role and ids:
            result[role] = ids
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="accessprobe",
        description="AccessProbe - Specialized IDOR and Broken Access Control Testing Tool",
        epilog="For authorized security testing and educational purposes only.",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"AccessProbe {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- scan ---
    scan_parser = subparsers.add_parser(
        "scan", help="Run IDOR / broken access control scan"
    )
    scan_parser.add_argument("--config", help="YAML config file")
    scan_parser.add_argument("--url", help="Target URL")
    scan_parser.add_argument("--param", help="Parameter name (single)")
    scan_parser.add_argument("--value", help="Parameter value (single)")
    scan_parser.add_argument(
        "--location",
        default="query",
        choices=["query", "path", "body", "header", "cookie"],
        help="Parameter location (default: query)",
    )
    scan_parser.add_argument(
        "--method", default=None, help="HTTP method (default: GET or config)"
    )
    scan_parser.add_argument("--original-role", help="Original / baseline role name")
    scan_parser.add_argument("--test-roles", nargs="+", help="Roles to test against")
    scan_parser.add_argument(
        "--cookie", help="Cookie string for original role (key=val; key2=val2)"
    )
    scan_parser.add_argument("--report", help="Save JSON report path")
    scan_parser.add_argument("--html-report", help="Save HTML report path")
    scan_parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.55,
        help="Minimum confidence to mark as vulnerable (default: 0.55)",
    )
    scan_parser.add_argument(
        "--delay",
        type=float,
        default=0.25,
        help="Delay between requests in seconds (default: 0.25)",
    )
    scan_parser.add_argument(
        "--no-horizontal",
        action="store_true",
        help="Skip same-role horizontal IDOR tests",
    )
    scan_parser.add_argument(
        "--discover",
        action="store_true",
        help="Auto-discover interesting parameters from the target URL/page",
    )
    scan_parser.add_argument(
        "--own-ids",
        default=None,
        metavar="role=id,id;role=id",
        help=(
            "Ownership map to suppress self-access FPs. "
            "Example: alice=1;bob=2,20;admin=3"
        ),
    )
    scan_parser.add_argument(
        "--privileged-roles",
        nargs="+",
        default=None,
        metavar="ROLE",
        help="Roles with intended broad access (suppress their access findings)",
    )

    # --- discover ---
    disc_parser = subparsers.add_parser(
        "discover", help="Discover potential IDOR parameters from a URL"
    )
    disc_parser.add_argument("--url", required=True, help="Target URL to analyze")
    disc_parser.add_argument(
        "--cookie", help="Optional cookie string for authenticated fetch"
    )
    disc_parser.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="Name:Value",
        help="Extra header (repeatable)",
    )

    return parser


async def run_scan(args: argparse.Namespace) -> int:
    """Execute a scan. Returns process exit code (0 = success)."""
    from accessprobe.config import load_config
    from accessprobe.models import Parameter, ParameterLocation, UserSession
    from accessprobe.reporter import ReportGenerator
    from accessprobe.session import SessionManager
    from accessprobe.tester import IDORTester

    session_manager = SessionManager()
    all_results = []
    target_url: str
    original_role: str
    test_roles: list[str]
    parameters_to_test: list[Parameter]
    method = "GET"
    own_ids: dict[str, list[str]] = {}
    privileged_roles: list[str] = []

    if args.config:
        try:
            config = load_config(args.config)
            for sess in config.sessions:
                session_manager.add_session(
                    UserSession(
                        name=sess.name,
                        cookies=sess.cookies,
                        headers=sess.headers,
                        description=sess.description,
                    )
                )

            if not config.scan:
                console.print("[red]No scan section found in config[/red]")
                return 1

            target_url = args.url or config.scan.target.url
            original_role = args.original_role or config.scan.original_role
            test_roles = args.test_roles or config.scan.test_roles
            method = (args.method or config.scan.method or "GET").upper()
            own_ids = dict(config.scan.own_ids or {})
            privileged_roles = list(config.scan.privileged_roles or [])

            parameters_to_test = []
            if args.param and args.value:
                parameters_to_test.append(
                    Parameter(
                        name=args.param,
                        location=ParameterLocation(args.location),
                        value=args.value,
                    )
                )
            else:
                for p in config.scan.parameters:
                    parameters_to_test.append(
                        Parameter(
                            name=str(p.get("name", "id")),
                            location=ParameterLocation(p.get("location", "query")),
                            value=p.get("value", ""),
                        )
                    )
        except Exception as e:
            console.print(f"[red]Config error:[/red] {e}")
            return 1
    else:
        if not args.url:
            console.print(
                "[red]Error: --url is required (or provide --config)[/red]"
            )
            return 1
        if not args.param and not args.discover:
            console.print(
                "[red]Error: --param/--value required, or use --discover / --config[/red]"
            )
            return 1

        original_cookies = parse_cookie_string(args.cookie) if args.cookie else {}
        original_role = args.original_role or "user"
        test_roles = args.test_roles or ["admin"]
        method = (args.method or "GET").upper()
        target_url = args.url

        session_manager.add_session(
            UserSession(name=original_role, cookies=original_cookies)
        )
        for role in test_roles:
            if role not in session_manager:
                session_manager.add_session(UserSession(name=role, cookies={}))

        parameters_to_test = []
        if args.param and args.value is not None:
            parameters_to_test.append(
                Parameter(
                    name=args.param,
                    location=ParameterLocation(args.location),
                    value=args.value,
                )
            )

    # Optional auto-discovery
    if args.discover:
        try:
            discovered = await _discover_parameters(
                target_url,
                session_manager.get_auth_kwargs(original_role),
            )
            # Avoid duplicates by name
            existing = {p.name for p in parameters_to_test}
            for p in discovered:
                if p.name not in existing:
                    parameters_to_test.append(p)
                    existing.add(p.name)
            console.print(
                f"[cyan]Discovered {len(discovered)} parameter(s) "
                f"({len(parameters_to_test)} total to test)[/cyan]"
            )
        except Exception as e:
            console.print(f"[yellow]Discovery warning:[/yellow] {e}")

    if not parameters_to_test:
        console.print("[red]No parameters to test[/red]")
        return 1

    if original_role not in session_manager:
        console.print(f"[red]Original role '{original_role}' not loaded[/red]")
        return 1

    missing = [r for r in test_roles if r not in session_manager]
    if missing:
        console.print(
            f"[yellow]Warning: test roles not found (skipped): {', '.join(missing)}[/yellow]"
        )

    # CLI overrides for accuracy context (merge over config)
    cli_own = parse_own_ids(getattr(args, "own_ids", None))
    if cli_own:
        for role, ids in cli_own.items():
            own_ids.setdefault(role, [])
            for i in ids:
                if i not in own_ids[role]:
                    own_ids[role].append(i)
    if getattr(args, "privileged_roles", None):
        for r in args.privileged_roles:
            if r not in privileged_roles:
                privileged_roles.append(r)

    tester = IDORTester(
        session_manager,
        delay=args.delay,
        min_confidence=args.min_confidence,
        own_ids=own_ids,
        privileged_roles=set(privileged_roles),
    )

    console.print(f"[bold cyan]AccessProbe Scan v{__version__}[/bold cyan]")
    console.print(f"Target: {target_url}")
    console.print(f"Method: {method}")
    console.print(
        f"Parameters: {len(parameters_to_test)} | "
        f"Roles: {original_role} → {', '.join(test_roles)}"
    )
    if own_ids:
        mapped = ", ".join(f"{r}=[{','.join(v)}]" for r, v in own_ids.items())
        console.print(f"Ownership map: {mapped}")
    if privileged_roles:
        console.print(f"Privileged roles: {', '.join(privileged_roles)}")
    console.print()

    for param in parameters_to_test:
        try:
            result = await tester.test_parameter(
                parameter=param,
                target_url=target_url,
                original_session=original_role,
                test_sessions=test_roles,
                method=method,
                test_horizontal=not args.no_horizontal,
            )
            all_results.append(result)

            if result.error:
                console.print(f"[red]Error on {param.name}:[/red] {result.error}")
                continue

            table = Table(title=f"{param.name} ({param.location.value})", show_lines=True)
            table.add_column("Tested As", style="cyan")
            table.add_column("Value", style="magenta")
            table.add_column("Status", justify="center")
            table.add_column("Vulnerable", justify="center")
            table.add_column("Conf.", justify="center")
            table.add_column("Severity")

            for finding in result.findings:
                conf = (
                    finding.details.get("confidence", 0) if finding.details else 0
                )
                table.add_row(
                    finding.tested_roles[-1] if finding.tested_roles else "-",
                    str(finding.parameter.value),
                    str(finding.modified_response_code or "-"),
                    "[red]Yes[/red]" if finding.is_vulnerable else "[green]No[/green]",
                    f"{conf:.2f}",
                    finding.severity.value.upper(),
                )
            console.print(table)

        except Exception as e:
            console.print(f"[red]Error on {param.name}:[/red] {e}")

    total_vuln = sum(
        1 for r in all_results for f in r.findings if f.is_vulnerable
    )
    console.print(
        f"\n[bold green]Scan finished[/bold green] — "
        f"{total_vuln} potential IDOR(s) found."
    )

    if all_results:
        reporter = ReportGenerator(all_results)
        if args.report:
            reporter.save_json(args.report)
            console.print(f"[green]✓ JSON report saved: {args.report}[/green]")
        if args.html_report:
            reporter.save_html(args.html_report)
            console.print(f"[green]✓ HTML report saved: {args.html_report}[/green]")

    return 2 if total_vuln else 0


async def _discover_parameters(
    url: str, auth: dict[str, Any]
) -> list[Any]:
    import httpx

    from accessprobe.discovery import ParameterDiscoverer
    from accessprobe.models import Parameter

    discoverer = ParameterDiscoverer()
    params: list[Parameter] = []
    params.extend(discoverer.discover_from_url(url))

    async with httpx.AsyncClient(
        **auth, follow_redirects=True, timeout=30.0
    ) as client:
        resp = await client.get(url)
        content_type = resp.headers.get("content-type", "")
        if "html" in content_type or resp.text.lstrip().startswith("<"):
            params.extend(discoverer.discover_from_html(resp.text))
            # Inline scripts
            for chunk in _extract_script_blocks(resp.text):
                params.extend(discoverer.discover_from_javascript(chunk))
        try:
            data = resp.json()
            params.extend(discoverer.discover_from_api_response(data))
        except Exception:
            pass

    return discoverer.get_all_discovered(unique=True)


def _extract_script_blocks(html: str) -> list[str]:
    import re

    return re.findall(
        r"<script[^>]*>(.*?)</script>", html, flags=re.IGNORECASE | re.DOTALL
    )


async def run_discover(args: argparse.Namespace) -> int:
    from accessprobe.models import UserSession
    from accessprobe.session import SessionManager

    sm = SessionManager()
    cookies = parse_cookie_string(args.cookie) if args.cookie else {}
    headers: dict[str, str] = {}
    for h in args.header or []:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    sm.add_session(UserSession(name="default", cookies=cookies, headers=headers))

    try:
        params = await _discover_parameters(args.url, sm.get_auth_kwargs("default"))
    except Exception as e:
        console.print(f"[red]Discovery failed:[/red] {e}")
        return 1

    if not params:
        console.print("[yellow]No interesting parameters found.[/yellow]")
        return 0

    table = Table(title="Discovered Parameters", show_lines=True)
    table.add_column("Name", style="cyan")
    table.add_column("Location")
    table.add_column("Value", style="magenta")
    table.add_column("Source")

    for p in params:
        table.add_row(
            p.name,
            p.location.value,
            str(p.value)[:60],
            p.description or "-",
        )
    console.print(table)
    console.print(f"\n[green]Found {len(params)} parameter(s)[/green]")
    return 0


def main(argv: Sequence[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command is None:
        print_banner()
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        code = asyncio.run(run_scan(args))
        sys.exit(code)
    elif args.command == "discover":
        code = asyncio.run(run_discover(args))
        sys.exit(code)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
