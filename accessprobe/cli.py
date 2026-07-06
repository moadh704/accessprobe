"""Command Line Interface for AccessProbe with multi-parameter support."""

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

    scan_parser = subparsers.add_parser("scan", help="Run IDOR tests (supports multiple parameters via config)")
    scan_parser.add_argument("--config", help="YAML config file (recommended for multiple parameters)")
    scan_parser.add_argument("--url", help="Target URL")
    scan_parser.add_argument("--param", help="Single parameter name")
    scan_parser.add_argument("--value", help="Single parameter value")
    scan_parser.add_argument("--original-role", help="Original role")
    scan_parser.add_argument("--test-roles", nargs="+", help="Roles to test against")
    scan_parser.add_argument("--cookie", help="Cookie string")
    scan_parser.add_argument("--report", help="Save JSON report")

    args = parser.parse_args()

    if args.command is None:
        print_banner()
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        asyncio.run(run_scan(args))


def run_scan(args):
    from accessprobe.config import load_config
    from accessprobe.models import Parameter, ParameterLocation, UserSession
    from accessprobe.session import SessionManager
    from accessprobe.tester import IDORTester
    from accessprobe.reporter import ReportGenerator

    session_manager = SessionManager()
    all_results = []

    if args.config:
        try:
            config = load_config(args.config)
            for sess in config.sessions:
                session_manager.add_session(UserSession(
                    name=sess.name, cookies=sess.cookies, headers=sess.headers, description=sess.description
                ))

            if not config.scan:
                console.print("[red]No scan section in config[/red]")
                return

            target_url = args.url or config.scan.target.url
            original_role = args.original_role or config.scan.original_role
            test_roles = args.test_roles or config.scan.test_roles

            # Support multiple parameters from config
            parameters_to_test = []
            if args.param and args.value:
                parameters_to_test.append(Parameter(name=args.param, location=ParameterLocation.QUERY, value=args.value))
            else:
                for p in config.scan.parameters:
                    parameters_to_test.append(Parameter(
                        name=p.get("name", "id"),
                        location=ParameterLocation(p.get("location", "query")),
                        value=p.get("value", ""),
                    ))

        except Exception as e:
            console.print(f"[red]Config error:[/red] {e}")
            return
    else:
        if not all([args.url, args.param, args.value]):
            console.print("[red]Error: --url, --param, --value required without --config[/red]")
            return
        # single parameter manual mode
        original_cookies = parse_cookie_string(args.cookie) if args.cookie else {}
        session_manager.add_session(UserSession(name=args.original_role or "user", cookies=original_cookies))
        for role in (args.test_roles or ["admin"]):
            session_manager.add_session(UserSession(name=role, cookies={}))
        parameters_to_test = [Parameter(name=args.param, location=ParameterLocation.QUERY, value=args.value)]
        target_url = args.url
        original_role = args.original_role or "user"
        test_roles = args.test_roles or ["admin"]

    tester = IDORTester(session_manager)

    console.print(f"[bold cyan]Starting AccessProbe Scan[/bold cyan]")
    console.print(f"Target: {target_url}")
    console.print(f"Testing {len(parameters_to_test)} parameter(s) across roles: {original_role} → {', '.join(test_roles)}\n")

    for param in parameters_to_test:
        try:
            result = asyncio.run(tester.test_parameter(
                parameter=param,
                target_url=target_url,
                original_session=original_role,
                test_sessions=test_roles
            ))
            all_results.append(result)

            # Show table for this parameter
            table = Table(title=f"Parameter: {param.name}", show_lines=True)
            table.add_column("Role", style="cyan")
            table.add_column("Value", style="magenta")
            table.add_column("Vulnerable", justify="center")
            table.add_column("Confidence", justify="center")
            table.add_column("Severity")

            for finding in result.findings:
                conf = finding.details.get("confidence", 0) if finding.details else 0
                table.add_row(
                    finding.tested_roles[-1],
                    str(finding.parameter.value),
                    "[red]Yes[/red]" if finding.is_vulnerable else "[green]No[/green]",
                    f"{conf:.2f}",
                    finding.severity.value.upper()
                )
            console.print(table)

        except Exception as e:
            console.print(f"[red]Error testing {param.name}:[/red] {e}")

    # Final summary
    total_vulnerable = sum(1 for r in all_results for f in r.findings if f.is_vulnerable)
    console.print(f"\n[bold]Scan Complete[/bold] — {total_vulnerable} potential IDOR(s) found across {len(parameters_to_test)} parameters.")

    if args.report and all_results:
        reporter = ReportGenerator(all_results)
        reporter.save_json(args.report)
        console.print(f"[green]Report saved to {args.report}[/green]")


def parse_cookie_string(cookie_str: str) -> dict:
    cookies = {}
    for pair in cookie_str.split(";"):
        if "=" in pair:
            k, v = pair.strip().split("=", 1)
            cookies[k] = v
    return cookies


if __name__ == "__main__":
    main()