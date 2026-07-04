"""Basic usage example for AccessProbe.

This script shows how to use the core components:
- UserSession + SessionManager
- Parameter
- IDORTester + IDORDetector

Run this after: pip install -e .

WARNING: Only use on systems you are authorized to test.
"""

import asyncio

from rich.console import Console
from rich.table import Table

try:
    from accessprobe.models import Parameter, ParameterLocation, UserSession
    from accessprobe.session import SessionManager
    from accessprobe.tester import IDORTester
except ImportError:
    print("Please run: pip install -e .")
    exit(1)

console = Console()


async def main():
    console.rule("[bold cyan]AccessProbe - Basic IDOR Testing Example[/bold cyan]")

    # ============================================
    # 1. Define multiple roles/sessions
    # ============================================
    sessions = [
        UserSession(
            name="low_priv",
            cookies={"session": "low_priv_session_value"},
            description="Regular user account",
        ),
        UserSession(
            name="high_priv",
            cookies={"session": "high_priv_session_value"},
            description="Administrator account",
        ),
    ]

    session_manager = SessionManager()
    for s in sessions:
        session_manager.add_session(s)

    console.print(f"[green]✓[/green] Loaded sessions: {session_manager.list_sessions()}")

    # ============================================
    # 2. Define the parameter we want to test
    # ============================================
    param = Parameter(
        name="user_id",
        location=ParameterLocation.QUERY,
        value=42,  # Value observed while logged in as low_priv
        description="ID of the user profile being viewed",
    )

    # ============================================
    # 3. Create tester and run test
    # ============================================
    tester = IDORTester(session_manager)

    target_url = "https://target.example.com/profile"  # <-- Change this

    console.print(f"\n[bold]Target URL:[/bold] {target_url}")
    console.print(f"[bold]Parameter:[/bold] {param.name} (location={param.location.value})")
    console.print(f"[bold]Original value (low_priv):[/bold] {param.value}\n")

    # Test the value seen as low_priv against the high_priv role
    # We can also pass additional values to test
    result = await tester.test_parameter(
        parameter=param,
        target_url=target_url,
        original_session="low_priv",
        test_sessions=["high_priv"],
        method="GET",
        values_to_test=[42, 100, 999],  # Try these values as high_priv
    )

    # ============================================
    # 4. Display results nicely
    # ============================================
    console.rule("[bold]Test Results[/bold]")

    if result.error:
        console.print(f"[red]Error during test:[/red] {result.error}")
        return

    table = Table(title="IDOR Test Findings")
    table.add_column("Tested As", style="cyan")
    table.add_column("Value Tested", style="magenta")
    table.add_column("Status", justify="center")
    table.add_column("Vulnerable", justify="center")
    table.add_column("Severity", style="yellow")
    table.add_column("Evidence / Reason")

    for finding in result.findings:
        vulnerable = "[bold red]Yes[/bold red]" if finding.is_vulnerable else "[green]No[/green]"
        table.add_row(
            finding.tested_roles[-1] if finding.tested_roles else "-",
            str(finding.parameter.value),
            str(finding.modified_response_code or "-"),
            vulnerable,
            finding.severity.value.upper(),
            finding.evidence or "-",
        )

    console.print(table)

    # Summary
    vulnerable_count = sum(1 for f in result.findings if f.is_vulnerable)
    console.print(f"\n[bold]Summary:[/bold] {vulnerable_count} potential IDOR(s) detected out of {len(result.findings)} tests.")

    console.print("\n[italic dim]Tip: Replace cookies and target URL with real data from an authorized engagement.[/italic dim]")


if __name__ == "__main__":
    asyncio.run(main())
