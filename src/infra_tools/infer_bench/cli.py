"""Typer CLI entrypoint for infer-bench."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys
from enum import StrEnum
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from infra_tools.core.models import ExitCode, OutputFormat, Severity
from infra_tools.core.output import render_error, render_report
from infra_tools.infer_bench.client import BenchConfigError, run_benchmark
from infra_tools.infer_bench.mock_server import MockInferenceServer, MockServerConfig
from infra_tools.infer_bench.models import (
    BenchmarkStats,
    BenchReport,
    LatencyPercentiles,
    SloConfig,
)
from infra_tools.infer_bench.slo import RULE_CATALOG, evaluate_slos

app = typer.Typer(
    name="infer-bench",
    help="Async streaming latency, throughput, and SLO analyzer for OpenAI/vLLM endpoints.",
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


def _fmt_pct(pct: LatencyPercentiles) -> str:
    if pct.count == 0:
        return "n/a (0 samples)"
    return (
        f"p50={pct.p50_ms:.2f}ms  p95={pct.p95_ms:.2f}ms  "
        f"p99={pct.p99_ms:.2f}ms  max={pct.max_ms:.2f}ms"
    )


def render_metrics_block(stats: BenchmarkStats, *, console: Console | None = None) -> None:
    """Render non-truncating benchmark summary metrics for human terminal reading."""
    out = console or Console()
    lines = [
        f"mode={stats.mode.value}  model={stats.model}  duration={stats.duration_s:.3f}s",
        (
            f"requests={stats.total_requests}  succeeded={stats.succeeded}  "
            f"failed={stats.failed}  error_rate={stats.error_rate * 100:.2f}%"
        ),
        f"ttft:       {_fmt_pct(stats.ttft)}",
        f"itl:        {_fmt_pct(stats.itl)}",
        (
            f"max_stall:  {stats.max_stall_ms:.2f}ms"
            if stats.max_stall_ms is not None
            else "max_stall:  n/a"
        ),
        f"e2e:        {_fmt_pct(stats.e2e)}",
        (
            f"throughput: {stats.aggregate_tokens_per_sec:.2f} tok/s "
            f"(total={stats.total_output_tokens}, source={stats.token_count_label})"
        ),
    ]
    if stats.per_request_tps_p50 is not None:
        lines.append(
            f"req_tps:    p50={stats.per_request_tps_p50:.2f} tok/s  "
            f"p95={stats.per_request_tps_p95:.2f} tok/s"
        )
    if stats.errors_by_class:
        err_str = ", ".join(f"{k}={v}" for k, v in stats.errors_by_class.items())
        lines.append(f"errors:     {err_str}")
    if stats.schedule.delayed_sends > 0:
        lines.append(
            f"schedule:   delayed_sends={stats.schedule.delayed_sends}/{stats.total_requests}  "
            f"p95_delay={stats.schedule.p95_send_delay_ms:.2f}ms  "
            f"max_delay={stats.schedule.max_send_delay_ms:.2f}ms"
        )

    for line in lines:
        out.print(Text(f"  {line}"), overflow="fold", crop=False)
    out.print()


@app.callback()
def main() -> None:
    """Async OpenAI-compatible / vLLM streaming latency and SLO benchmark tool."""


@app.command("run")
def run_cmd(
    url: Annotated[
        str,
        typer.Option(
            "--url",
            help="Base URL (e.g. http://127.0.0.1:8081) or full /v1/chat/completions URL.",
        ),
    ],
    model: Annotated[str, typer.Option("--model", help="Model name in request payload.")] = (
        "mock-model"
    ),
    prompt: Annotated[
        str,
        typer.Option("--prompt", help="User prompt sent to /v1/chat/completions."),
    ] = "Explain Kubernetes readiness probes in two sentences.",
    max_tokens: Annotated[
        int, typer.Option("--max-tokens", help="Maximum output tokens requested.")
    ] = 64,
    requests: Annotated[
        int, typer.Option("--requests", "-n", help="Total number of requests to send.")
    ] = 10,
    rate: Annotated[
        float | None,
        typer.Option(
            "--rate",
            help="Open-loop arrival rate in requests/second (default: 5.0 unless --concurrency).",
        ),
    ] = None,
    poisson: Annotated[
        bool,
        typer.Option(
            "--poisson/--fixed-rate",
            help="Use Poisson inter-arrival times in open-loop mode.",
        ),
    ] = False,
    max_concurrency: Annotated[
        int,
        typer.Option("--max-concurrency", help="In-flight concurrency cap for open-loop mode."),
    ] = 16,
    concurrency: Annotated[
        int | None,
        typer.Option(
            "--concurrency",
            "-c",
            help="Run closed-loop fixed worker pool (mutually exclusive with --rate/--poisson).",
        ),
    ] = None,
    timeout: Annotated[
        float, typer.Option("--timeout", help="Stream read timeout per chunk in seconds.")
    ] = 10.0,
    connect_timeout: Annotated[
        float, typer.Option("--connect-timeout", help="TCP/TLS connect timeout in seconds.")
    ] = 5.0,
    api_key_env: Annotated[
        str | None,
        typer.Option(
            "--api-key-env",
            help="Environment variable name containing Bearer API key (never logged).",
        ),
    ] = None,
    include_usage: Annotated[
        bool,
        typer.Option(
            "--include-usage/--no-include-usage",
            help="Request stream_options.include_usage from server.",
        ),
    ] = True,
    seed: Annotated[
        int | None, typer.Option("--seed", help="Optional RNG seed for Poisson arrival schedule.")
    ] = None,
    slo_ttft_p95_ms: Annotated[
        float | None, typer.Option("--slo-ttft-p95-ms", help="Fail if TTFT p95 exceeds ms.")
    ] = None,
    slo_itl_p99_ms: Annotated[
        float | None, typer.Option("--slo-itl-p99-ms", help="Fail if ITL p99 exceeds ms.")
    ] = None,
    slo_max_stall_ms: Annotated[
        float | None, typer.Option("--slo-max-stall-ms", help="Fail if max stall exceeds ms.")
    ] = None,
    slo_e2e_p95_ms: Annotated[
        float | None, typer.Option("--slo-e2e-p95-ms", help="Fail if E2E p95 exceeds ms.")
    ] = None,
    min_tps: Annotated[
        float | None, typer.Option("--min-tps", help="Fail if aggregate throughput < tok/s.")
    ] = None,
    max_error_rate: Annotated[
        float | None,
        typer.Option("--max-error-rate", help="Fail if error rate (0.0-1.0) exceeds threshold."),
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
            help="Minimum finding severity that triggers exit code 1.",
        ),
    ] = FailOnLevel.LOW,
) -> None:
    """Benchmark an OpenAI-compatible streaming endpoint and evaluate SLOs."""
    if concurrency is not None and (rate is not None or poisson):
        render_error("Cannot combine closed-loop --concurrency with open-loop --rate/--poisson.")
        raise typer.Exit(code=int(ExitCode.ERROR))

    if max_error_rate is not None and not (0.0 <= max_error_rate <= 1.0):
        render_error("--max-error-rate must be between 0.0 and 1.0.")
        raise typer.Exit(code=int(ExitCode.ERROR))

    for flag_name, val in (
        ("--slo-ttft-p95-ms", slo_ttft_p95_ms),
        ("--slo-itl-p99-ms", slo_itl_p99_ms),
        ("--slo-max-stall-ms", slo_max_stall_ms),
        ("--slo-e2e-p95-ms", slo_e2e_p95_ms),
        ("--min-tps", min_tps),
    ):
        if val is not None and val <= 0:
            render_error(f"{flag_name} must be > 0.")
            raise typer.Exit(code=int(ExitCode.ERROR))

    api_key: str | None = None
    if api_key_env is not None:
        api_key = os.environ.get(api_key_env)
        if not api_key:
            render_error(f"Environment variable '{api_key_env}' is unset or empty.")
            raise typer.Exit(code=int(ExitCode.ERROR))

    effective_rate = rate if rate is not None else 5.0
    slo = SloConfig(
        ttft_p95_ms=slo_ttft_p95_ms,
        itl_p99_ms=slo_itl_p99_ms,
        max_stall_ms=slo_max_stall_ms,
        e2e_p95_ms=slo_e2e_p95_ms,
        min_aggregate_tps=min_tps,
        max_error_rate=max_error_rate,
    )

    try:
        stats = asyncio.run(
            run_benchmark(
                url=url,
                model=model,
                prompt=prompt,
                max_tokens=max_tokens,
                num_requests=requests,
                rate_rps=None if concurrency is not None else effective_rate,
                poisson=poisson,
                max_concurrency=max_concurrency,
                concurrency=concurrency,
                timeout_s=timeout,
                connect_timeout_s=connect_timeout,
                include_usage=include_usage,
                api_key=api_key,
                seed=seed,
            )
        )
    except BenchConfigError as exc:
        render_error(str(exc))
        raise typer.Exit(code=int(ExitCode.ERROR)) from None

    findings = evaluate_slos(stats, slo)
    report = BenchReport.build(
        target=stats.target_url,
        stats=stats,
        findings=findings,
        fail_on=fail_on.to_severity(),
    )

    if fmt is OutputFormat.JSON:
        render_report(report, fmt)
    else:
        render_report(report, fmt)
        Console().print()
        render_metrics_block(stats)

    exit_code = ExitCode.OK if report.passed else ExitCode.FINDINGS
    raise typer.Exit(code=int(exit_code))


@app.command("mock")
def mock_cmd(
    port: Annotated[int, typer.Option("--port", help="Loopback TCP port (127.0.0.1 only).")] = 8081,
    ttft_ms: Annotated[float, typer.Option("--ttft-ms", help="Simulated TTFT in ms.")] = 25.0,
    itl_ms: Annotated[
        float, typer.Option("--itl-ms", help="Simulated inter-token latency in ms.")
    ] = 10.0,
    tokens: Annotated[
        int, typer.Option("--tokens", help="Tokens emitted per healthy response.")
    ] = 12,
    stall_ms: Annotated[
        float, typer.Option("--stall-ms", help="Extra mid-stream stall delay in ms.")
    ] = 0.0,
    stall_at: Annotated[
        int, typer.Option("--stall-at", help="Token index where mid-stream stall occurs.")
    ] = 4,
    error_429_rate: Annotated[
        float, typer.Option("--error-429-rate", help="Probability (0-1) of HTTP 429.")
    ] = 0.0,
    error_503_rate: Annotated[
        float, typer.Option("--error-503-rate", help="Probability (0-1) of HTTP 503.")
    ] = 0.0,
    truncate_rate: Annotated[
        float, typer.Option("--truncate-rate", help="Probability (0-1) of stream truncation.")
    ] = 0.0,
    malformed_rate: Annotated[
        float, typer.Option("--malformed-rate", help="Probability (0-1) of malformed SSE chunk.")
    ] = 0.0,
    emit_usage: Annotated[
        bool,
        typer.Option("--emit-usage/--no-usage", help="Include final usage chunk when requested."),
    ] = True,
    seed: Annotated[int, typer.Option("--seed", help="RNG seed for failure injection.")] = 42,
) -> None:
    """Start the local 127.0.0.1 OpenAI-compatible SSE mock server for demos."""
    try:
        cfg = MockServerConfig(
            host="127.0.0.1",
            port=port,
            ttft_ms=ttft_ms,
            itl_ms=itl_ms,
            tokens_per_response=tokens,
            stall_ms=stall_ms,
            stall_at_token=stall_at,
            error_429_rate=error_429_rate,
            error_503_rate=error_503_rate,
            truncate_rate=truncate_rate,
            malformed_rate=malformed_rate,
            emit_usage=emit_usage,
            seed=seed,
        )
    except ValueError as exc:
        render_error(str(exc))
        raise typer.Exit(code=int(ExitCode.ERROR)) from None

    async def _serve() -> None:
        async with MockInferenceServer(cfg) as server:
            typer.echo(f"infer-bench mock listening on {server.base_url} (Ctrl+C to stop)")
            await asyncio.Event().wait()

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(_serve())


@app.command("rules")
def list_rules(
    fmt: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", case_sensitive=False, help="Output format: table or json."),
    ] = OutputFormat.TABLE,
) -> None:
    """List all built-in infer-bench SLO and reliability rules."""
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
