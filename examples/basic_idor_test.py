"""Basic usage example for AccessProbe.

This script demonstrates how to use SessionManager + IDORTester together.

Note: Use this only on applications you are authorized to test.
"""

import asyncio

from rich.console import Console
from rich.table import Table

# Import from the package (after `pip install -e .`)
try:
    from accessprobe.models import Parameter, ParameterLocation, UserSession
    from accessprobe.session import SessionManager
    from accessprobe.tester import IDORTester
except ImportError:
    print("Please install the package first: pip install -e .")
    exit(1)

console = Console()


async def main():
    console.print("[bold cyan]AccessProbe - Basic IDOR Testing Example[/bold cyan]\n")

    # 1. Create sessions for different roles
    user_session = UserSession(
        name="user",
        cookies={"session": "user_session_cookie_here"},
        headers={"User-Agent": "AccessProbe/0.1"},
        description="Low privilege user",
    )

    admin_session = UserSession(
        name="admin",
        cookies={"session": "admin_session_cookie_here"},
        headers={"User-Agent": "AccessProbe/0.1"},
        description="High privilege admin",
    )

    # 2. Add sessions to the manager
    session_manager = SessionManager()
    session_manager.add_session(user_session)
    session_manager.add_session(admin_session)

    console.print(f"[green]✓[/green] Loaded {len(session_manager)} sessions: {session_manager.list_sessions()}")

    # 3. Define a parameter to test (example: numeric ID in query string)
    param = Parameter(
        name="id",
        location=ParameterLocation.QUERY,
        value=123,  # Original value seen as 'user'
        description="User profile ID parameter",
    )

    # 4. Create the tester
    tester = IDORTester(session_manager)

    # Example target URL (replace with a real authorized target)
    target_url = "https://vulnerable-app.example.com/profile"

    console.print(f"\n[bold]Testing parameter:[/bold] {param.name} (location: {param.location.value})")
    console.print(f"[bold]Target:[/bold] {target_url}\n")

    # 5. Run the test
    # We test the 'user' value against the 'admin' role
    result = await tester.test_parameter(
        parameter=param,
        target_url=target_url,
        original_session="user",
        test_sessions=["admin"],
        method="GET",
    )

    # 6. Display results
    console.print("[bold underline]Results:[/bold underline]\n")

    table = Table(title="Findings")
    table.add_column("Test Role", style="cyan")
    table.add_column("Test Value", style="magenta")
    table.add_column("Vulnerable?", style="green")
    table.add_column("Severity", style="yellow")
    table.add_column("Evidence", style="white")

    for finding in result.findings:
        table.add_row(
            finding.tested_roles[-1] if finding.tested_roles else "-",
            str(finding.parameter.value),
            "[red]Yes[/red]" if finding.is_vulnerable else "[green]No[/green]",
            finding.severity.value,
            finding.evidence or "-",
        )

    console.print(table)

    if result.error:
        console.print(f"[red]Error:[/red] {result.error}")

    console.print("\n[italic dim]Note: Replace cookies and target URL with real authorized test data.[/italic dim]")


if __name__ == "__main__":
    asyncio.run(main())
