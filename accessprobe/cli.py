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
    scan_parser = subparsers.add_parser("scan", help="Run IDOR tests against a target")
    scan_parser.add_argument("--url", required=True, help="Target URL to test")
    scan_parser.add_argument("--param", required=True, help="Parameter name to test (e.g. user_id, id)")
    scan_parser.add_argument(
        "--location",
        default="query",
        choices=["query", "path", "body"],
        help="Parameter location (default: query)",
    )
    scan_parser.add_argument(
        "--value", required=True, type=str, help="Original value of the parameter"
    )
    scan_parser.add_argument(
        "--original-role",
        default="user",
        help="Name of the original/low-privilege role",
    )
    scan_parser.add_argument(
        "--test-roles",
        nargs="+",
        default=["admin"],
        help="Roles to test the parameter against (space separated)",
    )
    scan_parser.add_argument(
        "--method", default="GET", help="HTTP method to use"
    )

    args = parser.parse_args()

    if args.command is None:
        print_banner()
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        asyncio.run(run_scan(args))


def run_scan(args: argparse.Namespace) -> None:
    """Execute the scan command."""
    from accessprobe.models import Parameter, ParameterLocation, UserSession
    from accessprobe.session import SessionManager
    from accessprobe.tester import IDORTester

    console.print(f"[bold cyan]Starting AccessProbe Scan[/bold cyan]")
    console.print(f"URL: {args.url}")
    console.print(f"Parameter: {args.param} ({args.location})")
    console.print(f"Original value: {args.value}")
    console.print(f"Testing roles: {args.test_roles} against '{args.original_role}'\n")

    # Note: For full functionality, sessions should be loaded from config or interactively.
    # This is a simplified version for demonstration.
    console.print(
        "[yellow]Note:[/yellow] Full session/cookie support will be added in a future update."
    )
    console.print("For now, use the Python API (see examples/basic_idor_test.py).\n")

    # Placeholder for future full implementation
    console.print("[green]Scan command structure is ready.[/green] This will become fully functional soon.")


if __name__ == "__main__":
    main()