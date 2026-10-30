"""Terminal output."""

from collections import Counter

from rich.console import Console
from rich.table import Table

from vulnsift.trivy import Finding

STYLES = {"P1": "bold white on red", "P2": "bold red", "P3": "yellow", "P4": "dim"}


def show(findings: list[Finding], name: str, top: int) -> None:
    """Print a summary line and a table of the most urgent findings."""
    console = Console()
    counts = Counter(f.priority for f in findings)
    console.print(f"\n[bold]{name}[/bold]: {len(findings)} unique CVEs")
    console.print("  ".join(f"[{STYLES[p]}]{p}: {counts[p]}[/]" for p in STYLES))

    table = Table(header_style="bold")
    table.add_column("Prio", no_wrap=True)
    table.add_column("CVE", no_wrap=True)
    table.add_column("Packages")
    table.add_column("Fix")
    table.add_column("EPSS", justify="right", no_wrap=True)
    table.add_column("Why")

    for f in findings[:top]:
        table.add_row(
            f"[{STYLES[f.priority]}]{f.priority}[/]",
            f.cve,
            ", ".join(f.packages),
            f.fixed or "[dim]none[/dim]",
            f"{f.epss:.1%}" if f.epss is not None else "-",
            f.reason,
        )
    console.print(table)