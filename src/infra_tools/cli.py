"""Unified dispatcher CLI for infrastructure-tools."""

from __future__ import annotations

import typer

from infra_tools import __version__
from infra_tools.infer_bench.cli import app as infer_bench_app
from infra_tools.k8s_guard.cli import app as k8s_guard_app
from infra_tools.k8s_triage.cli import app as k8s_triage_app
from infra_tools.pg_diag.cli import app as pg_diag_app

app = typer.Typer(
    name="infra-tools",
    help="CLI utilities for Kubernetes reliability, data infrastructure, and AI inference checks.",
    no_args_is_help=True,
)
app.add_typer(k8s_guard_app, name="k8s-guard")
app.add_typer(k8s_triage_app, name="k8s-triage")
app.add_typer(infer_bench_app, name="infer-bench")
app.add_typer(pg_diag_app, name="pg-diag")


@app.command()
def version() -> None:
    """Print the installed package version."""
    typer.echo(f"infrastructure-tools {__version__}")


if __name__ == "__main__":
    app()
