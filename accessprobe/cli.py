"""Command Line Interface for AccessProbe."""

from __future__ import annotations

import argparse
import asyncio
import sys

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()


def print_banner() -> None:
    banner = Text()
    banner.append("AccessProbe", style="bold cyan")
    banner.append(" v0.1.0", style="dim")
    banner.append("\nAdvanced IDOR & Broken Access Control Tester", style="italic dim")

    panel = Panel(banner, border_style="cyan", padding=(1, 2))
    console.print(panel)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="accessprobe",
        description="AccessProbe - Specialized IDOR and Broken Access Control Testing Tool",
        epilog="For authorized security testing and educational purposes only.",
    )

    parser.add_argument("-v", "--version", action="version", version="AccessProbe 0.1.0")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ==================== SCAN COMMAND ====================
    scan_parser = subparsers.add_parser("scan", help="Run IDOR test on a target")
    scan_parser.add_argument("--url", required=True, help="Target base URL")
    scan_parser.add_argument("--param", required=True, help="Parameter name to test")
    scan_parser.add_argument("--value", required=True, help="Original parameter value")
    scan_parser.add_argument(
        "--location", default="query", choices=["query", "path", "body"],
        help="Parameter location"
    )
    scan_parser.add_argument("--original-role", default="user", help="Name of the low-privilege role")
    scan_parser.add_argument(
        "--test-roles", nargs="+", default=["admin"], help="Roles to test against"
    )
    scan_parser.add_argument("--method", default="GET", help="HTTP method")
    scan_parser.add_argument(
        "--cookie", help="Cookie string for original role (format: name=value; name2=value2)"
    )
    scan_parser.add_argument("--report", help="Path to save JSON report")

    args = parser.parse_args()

    if args.command is None:
        print_banner()
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        asyncio.run(run_scan(args))


def parse_cookie_string(cookie_str: str) -> dict:
    """Parse simple cookie string into dict."""
    cookies = {}
    if not cookie_str:
        return cookies
    for pair in cookie_str.split(";"):
        if "=" in pair:
            k, v = pair.strip().split("=", 1)
            cookies[k] = v
    return cookies


def run_scan(args: argparse.Namespace) -> None:
    """Run an IDOR scan from CLI."""
    from accessprobe.models import Parameter, ParameterLocation, UserSession
    from accessprobe.session import SessionManager
    from accessprobe.tester import IDORTester
    from accessprobe.reporter import ReportGenerator

    console.print("[bold cyan]AccessProbe Scan Started[/bold cyan]\n")

    # Create session for original role
    original_cookies = parse_cookie_string(args.cookie) if args.cookie else {}
    original_session = UserSession(
        name=args.original_role,
        cookies=original_cookies,
        description="Original / low-privilege role"
    )

    session_manager = SessionManager()
    session_manager.add_session(original_session)

    # Create placeholder sessions for test roles (user will need to provide cookies in real use)
    for role in args.test_roles:
        # In real usage, we would load proper cookies for each role
        session_manager.add_session(UserSession(name=role, cookies={})) 

    # Create parameter
    location = ParameterLocation(args.location)
    param = Parameter(
        name=args.param,
        location=location,
        value=args.value,
    )

    # Run test
    tester = IDORTester(session_manager)

    try:
        result = asyncio.run(
            tester.test_parameter(
                parameter=param,
                target_url=args.url,
                original_session=args.original_role,
                test_sessions=args.test_roles,
                method=args.method,
            )
        )

        # Generate report
        reporter = ReportGenerator([result])
        reporter.print_summary()

        if args.report:
            reporter.save_json(args.report)
            console.print(f"[green]Report saved to {args.report}[/green]")

        # Show vulnerable findings
        vulnerable = [f for f in result.findings if f.is_vulnerable]
        if vulnerable:
            console.print(f"\n[bold red]Potential IDORs found: {len(vulnerable)}[/bold red]")
        else:
            console.print("\n[green]No obvious IDORs detected in this run.[/green]")

    except Exception as e:
        console.print(f"[red]Error during scan:[/red] {e}")


if __name__ == "__main__":
    main()