"""Shared human-readable text and deterministic JSON report renderers."""

from __future__ import annotations

import sys

from rich.console import Console
from rich.text import Text

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
    """Render a ``ToolReport`` as deterministic JSON or non-truncating text blocks."""
    if fmt is OutputFormat.JSON:
        sys.stdout.write(report.model_dump_json(indent=2) + "\n")
        return

    out = console or Console()
    header = Text()
    header.append(report.tool, style="bold")
    header.append(
        f" target={report.target} scanned={report.summary.documents_scanned} "
        f"findings={report.summary.total_findings} status="
    )
    if report.passed:
        header.append("PASS", style="bold green")
    else:
        header.append("FAIL", style="bold red")
    out.print(header, overflow="fold", crop=False)

    if not report.findings:
        out.print(Text("No findings.", style="green"), overflow="fold", crop=False)
        return

    sorted_findings = sorted(
        report.findings,
        key=lambda f: (-f.severity.rank, f.rule_id, f.resource, f.location, f.message),
    )

    for finding in sorted_findings:
        out.print()
        title = Text()
        title.append(f"{finding.severity.value:<8}", style=_SEVERITY_STYLES[finding.severity])
        title.append("  ")
        title.append(finding.rule_id, style="bold")
        title.append("  ")
        title.append(finding.resource)
        out.print(title, overflow="fold", crop=False)

        for label, value in (
            ("location:", finding.location),
            ("message: ", finding.message),
            ("fix:     ", finding.remediation),
        ):
            line = Text()
            line.append(f"  {label} ", style="dim")
            line.append(value)
            out.print(line, overflow="fold", crop=False)

    breakdown = "  ".join(
        f"{sev.value}={report.summary.by_severity.get(sev.value, 0)}"
        for sev in ORDERED_SEVERITIES
        if report.summary.by_severity.get(sev.value, 0) > 0
    )
    if breakdown:
        out.print()
        out.print(Text(f"Summary: {breakdown}", style="dim"), overflow="fold", crop=False)


def render_error(message: str, *, console: Console | None = None) -> None:
    """Render a clean, non-traceback error message to stderr."""
    err_console = console or Console(stderr=True)
    err = Text()
    err.append("Error: ", style="bold red")
    err.append(message)
    err_console.print(err, soft_wrap=True)
