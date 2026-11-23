"""Shared table and JSON report renderers."""

from __future__ import annotations

import sys

from rich.console import Console
from rich.table import Table

from infra_tools.core.models import ORDERED_SEVERITIES, OutputFormat, Severity, ToolReport

_SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def render_report(
    report: ToolReport,
    fmt: OutputFormat,
    *,
    console: Console | None = None,
) -> None:
    """Render a ``ToolReport`` as either deterministic JSON or a Rich terminal table."""
    if fmt is OutputFormat.JSON:
        sys.stdout.write(report.model_dump_json(indent=2) + "\n")
        return

    out = console or Console()
    status_label = "[bold green]PASS[/bold green]" if report.passed else "[bold red]FAIL[/bold red]"
    out.print(
        f"[bold]{report.tool}[/bold] target={report.target} "
        f"documents={report.summary.documents_scanned} "
        f"findings={report.summary.total_findings} status={status_label}"
    )

    if not report.findings:
        out.print("[green]No policy violations found.[/green]")
        return

    table = Table(show_header=True, header_style="bold", expand=False)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Resource")
    table.add_column("Location")
    table.add_column("Message")
    table.add_column("Remediation")

    for finding in report.findings:
        style = _SEVERITY_STYLES[finding.severity]
        table.add_row(
            f"[{style}]{finding.severity.value}[/{style}]",
            finding.rule_id,
            finding.resource,
            finding.location,
            finding.message,
            finding.remediation,
        )

    out.print(table)

    breakdown = "  ".join(
        f"{sev.value}={report.summary.by_severity.get(sev.value, 0)}"
        for sev in ORDERED_SEVERITIES
        if report.summary.by_severity.get(sev.value, 0) > 0
    )
    if breakdown:
        out.print(f"[dim]Summary: {breakdown}[/dim]")


def render_error(message: str, *, console: Console | None = None) -> None:
    """Render a clean, non-traceback error message to stderr."""
    err_console = console or Console(stderr=True)
    err_console.print(f"[bold red]Error:[/bold red] {message}", soft_wrap=True)
