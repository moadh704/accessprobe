"""Command Line Interface for AccessProbe (v0.3 - 9/10 level)."""

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
    banner.append(" v0.3", style="dim")
    banner.append("\nAdvanced IDOR & Broken Access Control Tester", style="italic dim")

    panel = Panel(banner, border_style="cyan", padding=(1, 2))
    console.print(panel)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="accessprobe",
        description="AccessProbe - Specialized IDOR and Broken Access Control Testing Tool",
        epilog="For authorized security testing and educational purposes only.",
    )

    parser.add_argument("-v", "--version", action="version", version="AccessProbe 0.3")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    scan_parser = subparsers.add_parser("scan", help="Run IDOR scan (multi-parameter supported)")
    scan_parser.add_argument("--config", help="YAML config file")
    scan_parser.add_argument("--url", help="Target URL")
    scan_parser.add_argument("--param", help="Parameter name (single)")
    scan_parser.add_argument("--value", help="Parameter value (single)")
    scan_parser.add_argument("--original-role", help="Original role name")
    scan_parser.add_argument("--test-roles", nargs="+", help="Roles to test")
    scan_parser.add_argument("--cookie", help="Cookie string for original role")
    scan_parser.add_argument("--report", help="Save JSON report")
    scan_parser.add_argument("--html-report", help="Save HTML report")

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
                    name=sess.name, cookies=sess.cookies,
                    headers=sess.headers, description=sess.description
                ))

            if not config.scan:
                console.print("[red]No scan section found in config[/red]")
                return

            target_url = args.url or config.scan.target.url
            original_role = args.original_role or config.scan.original_role
            test_roles = args.test_roles or config.scan.test_roles

            parameters_to_test = []
            if args.param and args.value:
                parameters_to_test.append(Parameter(
                    name=args.param, location=ParameterLocation.QUERY, value=args.value
                ))
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
            console.print("[red]Error: --url, --param and --value required without config[/red]")
            return

        original_cookies = parse_cookie_string(args.cookie) if args.cookie else {}
        session_manager.add_session(UserSession(name=args.original_role or "user", cookies=original_cookies))
        for role in (args.test_roles or ["admin"]):
            session_manager.add_session(UserSession(name=role, cookies={}))

        parameters_to_test = [Parameter(name=args.param, location=ParameterLocation.QUERY, value=args.value)]
        target_url = args.url
        original_role = args.original_role or "user"
        test_roles = args.test_roles or ["admin"]

    tester = IDORTester(session_manager)

    console.print(f"[bold cyan]AccessProbe Scan v0.3[/bold cyan]")
    console.print(f"Target: {target_url}")
    console.print(f"Parameters: {len(parameters_to_test)} | Roles: {original_role} → {', '.join(test_roles)}\n")

    for param in parameters_to_test:
        try:
            result = asyncio.run(tester.test_parameter(
                parameter=param, target_url=target_url,
                original_session=original_role, test_sessions=test_roles
            ))
            all_results.append(result)

            table = Table(title=f"{param.name}", show_lines=True)
            table.add_column("Tested As", style="cyan")
            table.add_column("Value", style="magenta")
            table.add_column("Vulnerable", justify="center")
            table.add_column("Conf.", justify="center")
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
            console.print(f"[red]Error on {param.name}:[/red] {e}")

    total_vuln = sum(1 for r in all_results for f in r.findings if f.is_vulnerable)
    console.print(f"\n[bold green]Scan finished[/bold green] — {total_vuln} potential IDOR(s) found.")

    if all_results:
        reporter = ReportGenerator(all_results)
        if args.report:
            reporter.save_json(args.report)
            console.print(f"[green]✓ JSON report saved: {args.report}[/green]")
        if args.html_report:
            reporter.save_html(args.html_report)
            console.print(f"[green]✓ HTML report saved: {args.html_report}[/green]")


def parse_cookie_string(cookie_str: str) -> dict:
    cookies = {}
    for pair in cookie_str.split(";"):
        if "=" in pair:
            k, v = pair.strip().split("=", 1)
            cookies[k] = v
    return cookies


if __name__ == "__main__":
    main()