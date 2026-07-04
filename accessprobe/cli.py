"""Command Line Interface for AccessProbe using rich for beautiful output."""

from __future__ import annotations

import argparse
import sys

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()


def print_banner() -> None:
    """Print a nice banner for the tool."""
    banner = Text()
    banner.append("AccessProbe", style="bold cyan")
    banner.append(" v0.1.0", style="dim")
    banner.append("\n", style="default")
    banner.append("Advanced IDOR & Broken Access Control Tester", style="italic dim")

    panel = Panel(
        banner,
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(panel)


def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="accessprobe",
        description="AccessProbe - Advanced IDOR and Broken Access Control Testing Tool",
        epilog="For authorized security testing only.",
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version="AccessProbe 0.1.0",
        help="Show version and exit",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Future commands will be added here
    # Example: scan, sessions, etc.

    args = parser.parse_args()

    if args.command is None:
        print_banner()
        parser.print_help()
        sys.exit(0)

    # Placeholder for future command handling
    if args.command == "version":
        console.print("AccessProbe v0.1.0", style="bold green")


if __name__ == "__main__":
    main()