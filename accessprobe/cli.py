"""Command Line Interface for AccessProbe."""

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

    # ==================== SCAN COMMAND ====================
    scan_parser = subparsers.add_parser("scan", help="Run IDOR tests")
    scan_parser.add_argument("--config", help="Path to YAML configuration file")
    scan_parser.add_argument("--url", help="Target URL (overrides config)")
    scan_parser.add_argument("--param", help="Parameter name")
    scan_parser.add_argument("--value", help="Original parameter value")
    scan_parser.add_argument("--original-role", help="Original role name")
    scan_parser.add_argument("--test-roles", nargs="+", help="Roles to test against")
    scan_parser.add_argument("--cookie", help="Cookie string for original role")
    scan_parser.add_argument("--report", help="Save JSON report to this path")

    args = parser.parse_args()

    if args.command is None:
        print_banner()
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        asyncio.run(run_scan(args))


def run_scan(args: argparse.Namespace) -> None:
    """Main scan execution logic with rich output."""
    from accessprobe.config import load_config
    from accessprobe.models import Parameter, ParameterLocation, UserSession
    from accessprobe.session import SessionManager
    from accessprobe.tester import IDORTester
    from accessprobe.reporter import ReportGenerator

    session_manager = SessionManager()
    target_url = ""
    original_role = "user"
    test_roles = ["admin"]
    param = None

    # === Load from config if provided ===
    if args.config:
        try:
            config = load_config(args.config)
            console.print(f"[green]✓ Loaded config from {args.config}[/green]")

            for sess in config.sessions:
                session_manager.add_session(
                    UserSession(
                        name=sess.name,
                        cookies=sess.cookies,
                        headers=sess.headers,
                        description=sess.description,
                    )
                )

            if config.scan:
                target_url = args.url or config.scan.target.url
                original_role = args.original_role or config.scan.original_role
                test_roles = args.test_roles or config.scan.test_roles

                if not args.param and config.scan.parameters:
                    p = config.scan.parameters[0]
                    param = Parameter(
                        name=p.get("name", "id"),
                        location=ParameterLocation(p.get("location", "query")),
                        value=p.get("value", ""),
                    )
                else:
                    param = Parameter(
                        name=args.param or "id",
                        location=ParameterLocation.QUERY,
                        value=args.value or "",
                    )

        except Exception as e:
            console.print(f"[red]✗ Failed to load config:[/red] {e}")
            return
    else:
        if not all([args.url, args.param, args.value]):
            console.print("[red]✗ Error:[/red] --url, --param and --value are required when not using --config")
            return

        original_cookies = parse_cookie_string(args.cookie) if args.cookie else {}
        session_manager.add_session(UserSession(name=args.original_role or "user", cookies=original_cookies))

        for role in (args.test_roles or ["admin"]):
            session_manager.add_session(UserSession(name=role, cookies={}))

        param = Parameter(
            name=args.param,
            location=ParameterLocation(args.location if hasattr(args, "location") else "query"),
            value=args.value,
        )
        target_url = args.url
        original_role = args.original_role or "user"
        test_roles = args.test_roles or ["admin"]

    if not param:
        console.print("[red]✗ No parameter to test.[/red]")
        return

    console.print(f"\n[bold]Target:[/bold] {target_url}")
    console.print(f"[bold]Parameter:[/bold] {param.name} ({param.location.value}) = {param.value}")
    console.print(f"[bold]Testing roles:[/bold] {original_role} → {', '.join(test_roles)}\n")

    tester = IDORTester(session_manager)

    try:
        result = asyncio.run(
            tester.test_parameter(
                parameter=param,
                target_url=target_url,
                original_session=original_role,
                test_sessions=test_roles,
            )
        )

        # Show detailed findings table
        table = Table(title="Findings", show_lines=True)
        table.add_column("Test Role", style="cyan")
        table.add_column("Value", style="magenta")
        table.add_column("Status", justify="center")
        table.add_column("Vulnerable", justify="center")
        table.add_column("Severity", style="yellow")
        table.add_column("Confidence", justify="center")
        table.add_column("Evidence")

        for finding in result.findings:
            vulnerable_style = "[bold red]Yes[/bold red]" if finding.is_vulnerable else "[green]No[/green]"
            conf = finding.details.get("confidence", 0.0) if finding.details else 0.0

            table.add_row(
                finding.tested_roles[-1] if finding.tested_roles else "-",
                str(finding.parameter.value),
                str(finding.modified_response_code or "-"),
                vulnerable_style,
                finding.severity.value.upper(),
                f"{conf:.2f}",
                finding.evidence or "-",
            )

        console.print(table)

        # Summary
        vulnerable_count = sum(1 for f in result.findings if f.is_vulnerable)
        console.print(f"\n[bold]Summary:[/bold] {vulnerable_count} potential IDOR(s) found out of {len(result.findings)} tests.")

        reporter = ReportGenerator([result])

        if args.report:
            reporter.save_json(args.report)
            console.print(f"[green]✓ Report saved to {args.report}[/green]")

    except Exception as e:
        console.print(f"[red]✗ Error during scan:[/red] {e}")


def parse_cookie_string(cookie_str: str) -> dict:
    cookies = {}
    for pair in cookie_str.split(";"):
        if "=" in pair:
            k, v = pair.strip().split("=", 1)
            cookies[k] = v
    return cookies


if __name__ == "__main__":
    main()