"""Unified dispatcher CLI for infrastructure-tools."""

from __future__ import annotations

import typer

from infra_tools import __version__
from infra_tools.k8s_guard.cli import app as k8s_guard_app

app = typer.Typer(
    name="infra-tools",
    help="CLI utilities for Kubernetes reliability, data infrastructure, and AI inference checks.",
    no_args_is_help=True,
)
app.add_typer(k8s_guard_app, name="k8s-guard")


@app.command()
def version() -> None:
    """Print the installed package version."""
    typer.echo(f"infrastructure-tools {__version__}")


if __name__ == "__main__":
    app()
