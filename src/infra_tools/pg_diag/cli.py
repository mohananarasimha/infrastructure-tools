"""Typer CLI entrypoint for pg-diag."""

from __future__ import annotations

import json
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from infra_tools.core.models import ExitCode, OutputFormat, ReportFormat, Severity
from infra_tools.core.output import render_error, render_report
from infra_tools.core.sarif import build_sarif
from infra_tools.pg_diag.analyzer import RULE_CATALOG, Thresholds, diagnose
from infra_tools.pg_diag.collector import (
    PgCollectionError,
    collect_live_snapshot,
    load_snapshot_from_fixture,
)

app = typer.Typer(
    name="pg-diag",
    help="Read-only PostgreSQL diagnosis: lock chains, connection saturation, idle transactions.",
    no_args_is_help=True,
)

DsnOption = Annotated[
    str,
    typer.Option(
        "--dsn",
        envvar="PG_DIAG_DSN",
        show_default=False,
        help=(
            "libpq connection string or URI (env: PG_DIAG_DSN). Empty uses PGHOST/PGUSER/... "
            "Keep passwords in PGPASSWORD or ~/.pgpass, not on the command line."
        ),
    ),
]
NoQueryOption = Annotated[
    bool,
    typer.Option("--no-query-text", help="Do not collect or print SQL text."),
]


class FailOnLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    def to_severity(self) -> Severity:
        return Severity(self.value.upper())


@app.callback()
def main() -> None:
    """PostgreSQL lock-chain, connection-saturation, and idle-in-transaction analyzer."""


@app.command("inspect")
def inspect(
    dsn: DsnOption = "",
    fixture: Annotated[
        Path | None,
        typer.Option("--fixture", help="Analyze a saved snapshot JSON instead of a live server."),
    ] = None,
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
            help="Minimum severity that causes exit code 1.",
        ),
    ] = FailOnLevel.LOW,
    sarif_artifact: Annotated[
        str | None,
        typer.Option(
            "--sarif-artifact",
            help=(
                "Repository-relative file that SARIF results are attached to (line 1). "
                "Defaults to the --fixture path; live results need it to show in GitHub."
            ),
        ),
    ] = None,
    idle_in_txn_seconds: Annotated[
        float,
        typer.Option("--idle-in-txn-seconds", min=0, help="PG002 threshold."),
    ] = Thresholds.idle_in_txn_s,
    lock_wait_critical_seconds: Annotated[
        float,
        typer.Option("--lock-wait-critical-seconds", min=0, help="PG001 CRITICAL threshold."),
    ] = Thresholds.lock_wait_critical_s,
    no_query_text: NoQueryOption = False,
) -> None:
    """Diagnose a live server (read-only) or a saved snapshot."""
    try:
        if fixture is not None:
            snapshot = load_snapshot_from_fixture(fixture)
            if no_query_text:
                snapshot = snapshot.model_copy(
                    update={
                        "sessions": [
                            s.model_copy(update={"query": None}) for s in snapshot.sessions
                        ]
                    }
                )
            target = str(fixture)
        else:
            snapshot = collect_live_snapshot(dsn, include_query_text=not no_query_text)
            target = snapshot.source
    except PgCollectionError as exc:
        render_error(str(exc))
        raise typer.Exit(code=int(ExitCode.ERROR)) from None

    thresholds = Thresholds(
        idle_in_txn_s=idle_in_txn_seconds,
        lock_wait_critical_s=lock_wait_critical_seconds,
    )
    report = diagnose(
        snapshot, target=target, thresholds=thresholds, fail_on=fail_on.to_severity()
    )
    if fmt is ReportFormat.SARIF:
        anchor = sarif_artifact if sarif_artifact is not None else fixture
        sarif = build_sarif(
            report,
            RULE_CATALOG,
            artifact_uri=None if anchor is None else Path(anchor).as_posix(),
            file_locations=False,
        )
        sys.stdout.write(sarif.to_json())
        if sarif.unlocated:
            render_error(
                f"{sarif.unlocated} SARIF result(s) have no file location; GitHub code scanning "
                "will not display them. Pass --sarif-artifact <repo file>."
            )
    else:
        render_report(report, fmt.as_output_format())
    raise typer.Exit(code=int(ExitCode.OK if report.passed else ExitCode.FINDINGS))


@app.command("snapshot")
def snapshot_cmd(dsn: DsnOption = "", no_query_text: NoQueryOption = False) -> None:
    """Write a snapshot as JSON to stdout, for later `inspect --fixture`."""
    try:
        snap = collect_live_snapshot(dsn, include_query_text=not no_query_text)
    except PgCollectionError as exc:
        render_error(str(exc))
        raise typer.Exit(code=int(ExitCode.ERROR)) from None
    sys.stdout.write(snap.model_dump_json(indent=2) + "\n")


@app.command("rules")
def list_rules(
    fmt: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", case_sensitive=False, help="Output format: table or json."),
    ] = OutputFormat.TABLE,
) -> None:
    """List built-in pg-diag rules."""
    if fmt is OutputFormat.JSON:
        payload = [
            {
                "rule_id": r.rule_id,
                "severity": r.severity.value,
                "title": r.title,
                "description": r.description,
            }
            for r in RULE_CATALOG
        ]
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return
    table = Table(show_header=True, header_style="bold")
    for col in ("Rule", "Severity", "Title", "Description"):
        table.add_column(col, no_wrap=col in ("Rule", "Severity"))
    for r in RULE_CATALOG:
        table.add_row(r.rule_id, r.severity.value, r.title, r.description)
    Console().print(table)


if __name__ == "__main__":
    app()
