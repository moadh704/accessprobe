"""Command Line Interface for AccessProbe with polished output."""

from __future__ import annotations

import argparse
import asyncio
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
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

    scan_parser = subparsers.add_parser("scan", help="Run IDOR/access control tests")
    scan_parser.add_argument("--config", help="Path to YAML config file")
    scan_parser.add_argument("--url", help="Target URL")
    scan_parser.add_argument("--param", help="Parameter name")
    scan_parser.add_argument("--value", help="Original value")
    scan_parser.add_argument("--original-role", help="Original role name")
    scan_parser.add_argument("--test-roles", nargs="+", help="Roles to test against")
    scan_parser.add_argument("--cookie", help="Cookie string for original role")
    scan_parser.add_argument("--report", help="Save JSON report path")

    args = parser.parse_args()

    if args.command is None:
        print_banner()
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        asyncio.run(run_scan(args))


def run_scan(args: argparse.Namespace) -> None:
    """Execute scan with nice output."""
    from accessprobe.config import load_config
    from accessprobe.models import Parameter, ParameterLocation, UserSession
    from accessprobe.session import SessionManager
    from accessprobe.tester import IDORTester
    from accessprobe.reporter import ReportGenerator

    console.rule("[bold cyan]AccessProbe Scan[/bold cyan]")

    session_manager = SessionManager()

    # Config mode
    if args.config:
        try:
            config = load_config(args.config)
            for sess in config.sessions:
                session_manager.add_session(UserSession(
                    name=sess.name, cookies=sess.cookies, headers=sess.headers, description=sess.description
                ))

            if config.scan:
                target_url = args.url or config.scan.target.url
                original_role = args.original_role or config.scan.original_role
                test_roles = args.test_roles or config.scan.test_roles

                if not args.param and config.scan.parameters:
                    p = config.scan.parameters[0]
                    param = Parameter(name=p["name"], location=ParameterLocation(p.get("location", "query")), value=p["value"])
                else:
                    param = Parameter(name=args.param or "id", location=ParameterLocation.QUERY, value=args.value or "")

        except Exception as e:
            console.print(f"[red]Config error:[/red] {e}")
            return
    else:
        if not all([args.url, args.param, args.value]):
            console.print("[red]Error:[/red] --url, --param and --value required when not using --config")
            return

        cookies = parse_cookie_string(args.cookie) if args.cookie else {}
        session_manager.add_session(UserSession(name=args.original_role or "user", cookies=cookies))
        for role in (args.test_roles or ["admin"]):
            session_manager.add_session(UserSession(name=role, cookies={}))

        param = Parameter(name=args.param, location=ParameterLocation.QUERY, value=args.value)
        target_url = args.url
        original_role = args.original_role or "user"
        test_roles = args.test_roles or ["admin"]

    # Run test
    tester = IDORTester(session_manager, rate_limit=0.6)

    try:
        result = asyncio.run(tester.test_parameter(
            parameter=param,
            target_url=target_url,
            original_session=original_role,
            test_sessions=test_roles,
        ))

        # Report
        reporter = ReportGenerator([result])
        reporter.print_summary()

        # Show findings table
        if result.findings:
            table = Table(title="Findings")
            table.add_column("Role", style="cyan")
            table.add_column("Value", style="magenta")
            table.add_column("Vulnerable", justify="center")
            table.add_column("Severity", style="yellow")
            table.add_column("Confidence")

            for f in result.findings:
                vulnerable = "[red]Yes[/red]" if f.is_vulnerable else "[green]No[/green]"
                conf = f.details.get("confidence", 0.0) if hasattr(f, 'details') else 0.0
                table.add_row(
                    f.tested_roles[-1] if f.tested_roles else "-",
                    str(f.parameter.value),
                    vulnerable,
                    f.severity.value.upper(),
                    str(conf)
                )
            console.print(table)

        if args.report:
            reporter.save_json(args.report)
            console.print(f"[green]Report saved to {args.report}[/green]")

    except Exception as e:
        console.print(f"[red]Scan failed:[/red] {e}")


def parse_cookie_string(cookie_str: str) -> dict:
    cookies = {}
    for pair in cookie_str.split(";"):
        if "=" in pair:
            k, v = pair.strip().split("=", 1)
            cookies[k] = v
    return cookies


if __name__ == "__main__":
    main()