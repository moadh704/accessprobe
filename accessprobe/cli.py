"""AccessProbe - Professional Command Line Interface"""

from __future__ import annotations

import argparse
import asyncio
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from rich import box

console = Console()


def print_banner() -> None:
    title = Text()
    title.append("ACCESS PROBE", style="bold cyan")
    title.append("  v0.2", style="dim")

    subtitle = Text("Advanced IDOR & Broken Access Control Testing", style="italic dim")

    content = Text.assemble(title, "\n", subtitle)

    panel = Panel(
        content,
        border_style="cyan",
        padding=(1, 2),
        box=box.ROUNDED,
    )
    console.print(panel)
    console.print()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="accessprobe",
        description="AccessProbe - Specialized IDOR and Broken Access Control Testing Tool",
        epilog="For authorized security testing and educational purposes only.",
    )

    parser.add_argument("-v", "--version", action="version", version="AccessProbe 0.2")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    scan_parser = subparsers.add_parser("scan", help="Run IDOR tests")
    scan_parser.add_argument("--config", help="YAML configuration file")
    scan_parser.add_argument("--url", help="Target URL")
    scan_parser.add_argument("--param", help="Parameter name (single mode)")
    scan_parser.add_argument("--value", help="Parameter value (single mode)")
    scan_parser.add_argument("--original-role", help="Original/low-privilege role")
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


def run_scan(args):
    from accessprobe.config import load_config
    from accessprobe.models import Parameter, ParameterLocation, UserSession
    from accessprobe.session import SessionManager
    from accessprobe.tester import IDORTester
    from accessprobe.reporter import ReportGenerator

    session_manager = SessionManager()
    all_results = []

    # === Configuration Loading ===
    if args.config:
        try:
            config = load_config(args.config)
            console.print("[cyan]▶[/cyan] Loaded configuration file")

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

                parameters_to_test = []
                if args.param and args.value:
                    parameters_to_test.append(
                        Parameter(name=args.param, location=ParameterLocation.QUERY, value=args.value)
                    )
                else:
                    for p in config.scan.parameters:
                        parameters_to_test.append(
                            Parameter(
                                name=p.get("name", "id"),
                                location=ParameterLocation(p.get("location", "query")),
                                value=p.get("value", ""),
                            )
                        )

        except Exception as e:
            console.print(f"[red]✗[/red] Failed to load config: {e}")
            return
    else:
        if not all([args.url, args.param, args.value]):
            console.print("[red]✗[/red] Error: --url, --param and --value are required in manual mode")
            return

        original_cookies = parse_cookie_string(args.cookie) if args.cookie else {}
        session_manager.add_session(UserSession(name=args.original_role or "user", cookies=original_cookies))

        for role in (args.test_roles or ["admin"]):
            session_manager.add_session(UserSession(name=role, cookies={}))

        parameters_to_test = [
            Parameter(name=args.param, location=ParameterLocation.QUERY, value=args.value)
        ]
        target_url = args.url
        original_role = args.original_role or "user"
        test_roles = args.test_roles or ["admin"]

    tester = IDORTester(session_manager)

    # === Beautiful Header ===
    console.rule("[bold cyan]Scan Started[/bold cyan]", style="cyan")
    console.print(f"[bold]Target:[/bold]     {target_url}")
    console.print(f"[bold]Parameters:[/bold]  {len(parameters_to_test)}")
    console.print(f"[bold]Roles:[/bold]      {original_role}  →  {', '.join(test_roles)}")
    console.print()

    # === Run Tests ===
    for param in parameters_to_test:
        try:
            result = asyncio.run(
                tester.test_parameter(
                    parameter=param,
                    target_url=target_url,
                    original_session=original_role,
                    test_sessions=test_roles,
                )
            )
            all_results.append(result)

            # === Beautiful Findings Table ===
            table = Table(
                title=f"[bold]{param.name}[/bold]  •  {param.location.value}",
                show_lines=True,
                box=box.ROUNDED,
            )
            table.add_column("Test Role", style="cyan")
            table.add_column("Value", style="magenta")
            table.add_column("Status", justify="center")
            table.add_column("Vulnerable", justify="center")
            table.add_column("Confidence", justify="center")
            table.add_column("Severity", style="yellow")

            for finding in result.findings:
                conf = finding.details.get("confidence", 0.0) if finding.details else 0.0
                vulnerable = "[bold red]✗ Vulnerable[/bold red]" if finding.is_vulnerable else "[green]✓ Safe[/green]"

                table.add_row(
                    finding.tested_roles[-1] if finding.tested_roles else "-",
                    str(finding.parameter.value),
                    str(finding.modified_response_code or "-"),
                    vulnerable,
                    f"{conf:.2f}",
                    finding.severity.value.upper(),
                )

            console.print(table)
            console.print()

        except Exception as e:
            console.print(f"[red]✗ Error testing {param.name}:[/red] {e}")

    # === Final Summary ===
    total_vulnerable = sum(1 for r in all_results for f in r.findings if f.is_vulnerable)
    total_tests = sum(len(r.findings) for r in all_results)

    summary_text = Text()
    summary_text.append("Scan Complete  •  ", style="bold")
    summary_text.append(f"{total_vulnerable} vulnerable", style="bold red" if total_vulnerable > 0 else "bold green")
    summary_text.append(f" out of {total_tests} tests", style="dim")

    console.rule(summary_text, style="cyan")

    if args.report and all_results:
        reporter = ReportGenerator(all_results)
        reporter.save_json(args.report)
        console.print(f"[green]✓[/green] Report saved to {args.report}")


def parse_cookie_string(cookie_str: str) -> dict:
    cookies = {}
    for pair in cookie_str.split(";"):
        if "=" in pair:
            k, v = pair.strip().split("=", 1)
            cookies[k] = v
    return cookies


if __name__ == "__main__":
    main()