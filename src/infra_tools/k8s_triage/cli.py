"""Typer CLI entrypoint for k8s-triage."""

from __future__ import annotations

import json
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from infra_tools.core.models import ExitCode, OutputFormat, Severity
from infra_tools.core.output import render_error, render_report
from infra_tools.k8s_triage.analyzer import RULE_CATALOG, triage_snapshot
from infra_tools.k8s_triage.collector import (
    TriageCollectionError,
    collect_live_snapshot,
    load_snapshot_from_fixture,
)
from infra_tools.k8s_triage.models import ClusterSnapshot

app = typer.Typer(
    name="k8s-triage",
    help="Correlate unhealthy Kubernetes pods, events, probes, and node conditions.",
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


@app.callback()
def main() -> None:
    """Kubernetes pod, event, probe, and node-condition failure correlator."""


def _filter_snapshot_namespace(snapshot: ClusterSnapshot, namespace: str) -> ClusterSnapshot:
    return ClusterSnapshot(
        source=snapshot.source,
        namespace=namespace,
        pods=[p for p in snapshot.pods if p.namespace == namespace],
        events=[e for e in snapshot.events if e.namespace == namespace],
        nodes=snapshot.nodes,
    )


@app.command("inspect")
def inspect(
    namespace: Annotated[
        str | None,
        typer.Option(
            "--namespace", "-n", help="Kubernetes namespace to inspect (default: default)."
        ),
    ] = None,
    all_namespaces: Annotated[
        bool,
        typer.Option("--all-namespaces", "-A", help="Inspect resources across all namespaces."),
    ] = False,
    context: Annotated[
        str | None,
        typer.Option("--context", help="Kubeconfig context name for live inspection."),
    ] = None,
    kubeconfig: Annotated[
        Path | None,
        typer.Option("--kubeconfig", help="Path to kubeconfig file for live inspection."),
    ] = None,
    fixture: Annotated[
        Path | None,
        typer.Option("--fixture", help="Offline ClusterSnapshot JSON file to inspect."),
    ] = None,
    fmt: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", case_sensitive=False, help="Output format: table or json."),
    ] = OutputFormat.TABLE,
    fail_on: Annotated[
        FailOnLevel,
        typer.Option(
            "--fail-on",
            case_sensitive=False,
            help="Minimum severity that causes a non-zero exit code (1).",
        ),
    ] = FailOnLevel.LOW,
) -> None:
    """Inspect a live Kubernetes cluster or offline snapshot fixture for failures."""
    if namespace is not None and all_namespaces:
        render_error("Cannot specify both --namespace and --all-namespaces.")
        raise typer.Exit(code=int(ExitCode.ERROR))

    try:
        if fixture is not None:
            snapshot = load_snapshot_from_fixture(fixture)
            if namespace is not None:
                snapshot = _filter_snapshot_namespace(snapshot, namespace)
            target_label = str(fixture)
        else:
            snapshot = collect_live_snapshot(
                namespace=namespace,
                all_namespaces=all_namespaces,
                context=context,
                kubeconfig=kubeconfig,
            )
            ns_label = "all-namespaces" if all_namespaces else (namespace or "default")
            target_label = f"{snapshot.source}/{ns_label}"
    except TriageCollectionError as exc:
        render_error(str(exc))
        raise typer.Exit(code=int(ExitCode.ERROR)) from None

    report = triage_snapshot(snapshot, target=target_label, fail_on=fail_on.to_severity())
    render_report(report, fmt)
    exit_code = ExitCode.OK if report.passed else ExitCode.FINDINGS
    raise typer.Exit(code=int(exit_code))


@app.command("rules")
def list_rules(
    fmt: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", case_sensitive=False, help="Output format: table or json."),
    ] = OutputFormat.TABLE,
) -> None:
    """List all built-in k8s-triage diagnostic rules."""
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
