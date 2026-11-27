"""Typer CLI entrypoint for k8s-guard."""

from __future__ import annotations

import json
import sys
from enum import StrEnum
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from infra_tools.core.models import ExitCode, OutputFormat, ReportFormat, Severity
from infra_tools.core.output import render_error, render_report
from infra_tools.core.sarif import build_sarif
from infra_tools.k8s_guard.loader import ManifestLoadError
from infra_tools.k8s_guard.rules import RULE_CATALOG, VALID_RULE_IDS
from infra_tools.k8s_guard.scanner import scan_target

app = typer.Typer(
    name="k8s-guard",
    help="Static reliability, security, and GPU-hygiene linter for Kubernetes manifests.",
    no_args_is_help=True,
)


class FailOnLevel(StrEnum):
    """Allowed --fail-on severity thresholds."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    def to_severity(self) -> Severity:
        return Severity(self.value.upper())


def _parse_ignore_rules(raw_ignore: list[str] | None) -> set[str]:
    if not raw_ignore:
        return set()
    parsed: set[str] = set()
    for item in raw_ignore:
        for token in item.split(","):
            cleaned = token.strip().upper()
            if cleaned:
                parsed.add(cleaned)
    return parsed


@app.callback()
def main() -> None:
    """Static Kubernetes manifest reliability, security, and GPU-hygiene linter."""


@app.command("scan")
def scan(
    target: Annotated[
        str,
        typer.Argument(help="Path to a YAML file, directory of manifests, or '-' for stdin."),
    ],
    fmt: Annotated[
        ReportFormat,
        typer.Option(
            "--format", "-f", case_sensitive=False, help="Output format: table, json, or sarif."
        ),
    ] = ReportFormat.TABLE,
    fail_on: Annotated[
        FailOnLevel,
        typer.Option(
            "--fail-on",
            case_sensitive=False,
            help="Minimum severity that causes a non-zero exit code (1).",
        ),
    ] = FailOnLevel.LOW,
    ignore: Annotated[
        list[str] | None,
        typer.Option(
            "--ignore",
            help="Rule ID to suppress (repeatable or comma-separated, e.g. --ignore KG008).",
        ),
    ] = None,
) -> None:
    """Scan Kubernetes YAML manifests for reliability, security, and GPU-hygiene issues."""
    ignore_set = _parse_ignore_rules(ignore)
    unknown_rules = sorted(ignore_set - VALID_RULE_IDS)
    if unknown_rules:
        render_error(
            f"Unknown rule ID(s) in --ignore: {', '.join(unknown_rules)}. "
            f"Valid rules: {', '.join(sorted(VALID_RULE_IDS))}."
        )
        raise typer.Exit(code=int(ExitCode.ERROR))

    try:
        report = scan_target(
            target,
            fail_on=fail_on.to_severity(),
            ignore_rules=ignore_set,
        )
    except ManifestLoadError as exc:
        render_error(str(exc))
        raise typer.Exit(code=int(ExitCode.ERROR)) from None

    if fmt is ReportFormat.SARIF:
        sarif = build_sarif(report, RULE_CATALOG)
        sys.stdout.write(sarif.to_json())
        if sarif.unlocated:
            render_error(
                f"{sarif.unlocated} SARIF result(s) have no file location (stdin input); "
                "GitHub code scanning will not display them. Scan files instead of '-'."
            )
    else:
        render_report(report, fmt.as_output_format())
    exit_code = ExitCode.OK if report.passed else ExitCode.FINDINGS
    raise typer.Exit(code=int(exit_code))


@app.command("rules")
def list_rules(
    fmt: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", case_sensitive=False, help="Output format: table or json."),
    ] = OutputFormat.TABLE,
) -> None:
    """List all built-in k8s-guard policy rules."""
    if fmt is OutputFormat.JSON:
        payload = [
            {
                "rule_id": spec.rule_id,
                "severity": spec.severity.value,
                "title": spec.title,
                "description": spec.description,
            }
            for spec in RULE_CATALOG
        ]
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return

    console = Console()
    table = Table(show_header=True, header_style="bold")
    table.add_column("Rule", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Title")
    table.add_column("Description")
    for spec in RULE_CATALOG:
        table.add_row(spec.rule_id, spec.severity.value, spec.title, spec.description)
    console.print(table)


if __name__ == "__main__":
    app()
