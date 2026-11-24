"""Unit tests for infer-bench SSE parsing, stats aggregation, SLO rules, and CLI validation."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError
from rich.console import Console
from typer.testing import CliRunner

from infra_tools.cli import app as root_app
from infra_tools.core.models import ExitCode, Severity
from infra_tools.infer_bench.cli import app as bench_app
from infra_tools.infer_bench.cli import render_metrics_block
from infra_tools.infer_bench.client import BenchConfigError, normalize_completions_url
from infra_tools.infer_bench.mock_server import MockServerConfig
from infra_tools.infer_bench.models import (
    BenchReport,
    ErrorClass,
    LoadMode,
    RequestResult,
    SloConfig,
    TokenCountSource,
)
from infra_tools.infer_bench.slo import RULE_CATALOG, evaluate_slos
from infra_tools.infer_bench.sse import SseParseError, parse_sse_line
from infra_tools.infer_bench.stats import percentile, summarize_results

runner = CliRunner()


def test_parse_sse_line_handles_content_role_usage_done_and_errors() -> None:
    assert parse_sse_line("") is None
    assert parse_sse_line(": keep-alive comment") is None
    assert parse_sse_line("event: message") is None

    done = parse_sse_line("data: [DONE]\n")
    assert done is not None and done.is_done is True

    # Role-only framing chunk has no content delta.
    role_chunk = json.dumps({"choices": [{"delta": {"role": "assistant"}}]})
    parsed_role = parse_sse_line(f"data: {role_chunk}")
    assert parsed_role is not None
    assert parsed_role.has_content is False
    assert parsed_role.completion_tokens is None

    # Content delta without space after data: prefix.
    delta_chunk = json.dumps({"choices": [{"delta": {"content": "hello"}}]})
    parsed_delta = parse_sse_line(f"data:{delta_chunk}")
    assert parsed_delta is not None
    assert parsed_delta.has_content is True
    assert parsed_delta.content == "hello"

    # Final usage chunk.
    usage_chunk = json.dumps({"choices": [], "usage": {"completion_tokens": 42}})
    parsed_usage = parse_sse_line(f"data: {usage_chunk}")
    assert parsed_usage is not None
    assert parsed_usage.has_content is False
    assert parsed_usage.completion_tokens == 42

    with pytest.raises(SseParseError, match="Malformed JSON"):
        parse_sse_line("data: {broken-json")

    with pytest.raises(SseParseError, match="Expected JSON object"):
        parse_sse_line("data: [1, 2, 3]")


def test_percentile_interpolation_and_edge_cases() -> None:
    assert percentile([], 50.0) is None
    assert percentile([12.5], 99.0) == 12.5
    assert percentile([10.0, 20.0, 30.0, 40.0], 50.0) == 25.0
    assert percentile([10.0, 20.0, 30.0, 40.0], 95.0) == pytest.approx(38.5)
    with pytest.raises(ValueError, match="between 0 and 100"):
        percentile([1.0], 101.0)


def test_summarize_results_and_slo_evaluation_all_rules() -> None:
    results = [
        RequestResult(
            request_id=0,
            scheduled_offset_ms=0.0,
            actual_send_offset_ms=0.5,
            send_delay_ms=0.5,
            http_status=200,
            ok=True,
            ttft_ms=120.0,
            e2e_ms=420.0,
            itl_ms=[10.0, 85.0, 12.0],
            max_stall_ms=85.0,
            output_tokens=4,
            token_source=TokenCountSource.CHUNKS_APPROXIMATE,
            tokens_per_sec=9.52,
        ),
        RequestResult(
            request_id=1,
            scheduled_offset_ms=50.0,
            actual_send_offset_ms=75.0,
            send_delay_ms=25.0,
            cap_wait_ms=24.0,
            http_status=429,
            ok=False,
            error_class=ErrorClass.HTTP_429,
            error_detail="HTTP 429: rate limit exceeded",
            e2e_ms=5.0,
        ),
    ]

    stats = summarize_results(
        results,
        mode=LoadMode.OPEN_LOOP_FIXED,
        target_url="http://127.0.0.1:8081/v1/chat/completions",
        model="test-llm",
        duration_s=1.0,
    )
    assert stats.total_requests == 2
    assert stats.succeeded == 1
    assert stats.failed == 1
    assert stats.error_rate == 0.5
    assert stats.errors_by_class == {"http_429": 1}
    assert stats.token_count_label == TokenCountSource.CHUNKS_APPROXIMATE.value
    assert stats.schedule.cap_saturated is True
    assert stats.schedule.delayed_sends == 1

    slo = SloConfig(
        ttft_p95_ms=50.0,
        itl_p99_ms=40.0,
        max_stall_ms=50.0,
        e2e_p95_ms=200.0,
        min_aggregate_tps=20.0,
        max_error_rate=0.05,
    )
    findings = evaluate_slos(stats, slo)
    rule_ids = {f.rule_id for f in findings}
    assert rule_ids == {"IB001", "IB002", "IB003", "IB004", "IB005", "IB006", "IB007"}

    # IB007 alone (INFO) must not fail default --fail-on low.
    info_only = evaluate_slos(stats, SloConfig())
    assert [f.rule_id for f in info_only] == ["IB007"]
    assert info_only[0].severity == Severity.INFO
    report = BenchReport.build(
        target=stats.target_url, stats=stats, findings=info_only, fail_on=Severity.LOW
    )
    assert report.passed is True

    # Metrics block renders cleanly at 80 columns with no ellipsis truncation.
    console = Console(width=80, record=True, force_terminal=False)
    render_metrics_block(stats, console=console)
    rendered = console.export_text()
    assert "…" not in rendered
    assert "chunks, approximate" in rendered
    assert "http_429=1" in rendered


def test_url_normalization_and_loopback_enforcement() -> None:
    assert (
        normalize_completions_url("http://127.0.0.1:8081")
        == "http://127.0.0.1:8081/v1/chat/completions"
    )
    assert (
        normalize_completions_url("http://127.0.0.1:8081/v1/")
        == "http://127.0.0.1:8081/v1/chat/completions"
    )
    assert (
        normalize_completions_url("https://api.example.com/v1/chat/completions")
        == "https://api.example.com/v1/chat/completions"
    )
    with pytest.raises(BenchConfigError, match="Invalid target URL"):
        normalize_completions_url("ftp://example.com")

    with pytest.raises(ValidationError, match="loopback"):
        MockServerConfig(host="0.0.0.0")  # noqa: S104


def test_cli_validation_errors_and_rules_subcommand() -> None:
    # Conflicting --rate and --concurrency -> exit 2
    res_conflict = runner.invoke(
        bench_app,
        ["run", "--url", "http://127.0.0.1:8081", "--rate", "5", "--concurrency", "2"],
    )
    assert res_conflict.exit_code == ExitCode.ERROR
    assert "Cannot combine" in res_conflict.output

    # Invalid --max-error-rate -> exit 2
    res_err_rate = runner.invoke(
        bench_app,
        ["run", "--url", "http://127.0.0.1:8081", "--max-error-rate", "1.5"],
    )
    assert res_err_rate.exit_code == ExitCode.ERROR
    assert "--max-error-rate" in res_err_rate.output

    # Unset --api-key-env -> exit 2
    res_key = runner.invoke(
        bench_app,
        ["run", "--url", "http://127.0.0.1:8081", "--api-key-env", "NONEXISTENT_KEY_VAR_XYZ"],
    )
    assert res_key.exit_code == ExitCode.ERROR
    assert "unset or empty" in res_key.output

    # Invalid URL -> exit 2
    res_url = runner.invoke(bench_app, ["run", "--url", "not-a-url"])
    assert res_url.exit_code == ExitCode.ERROR
    assert "Invalid target URL" in res_url.output

    # Rules catalog matches JSON and root dispatcher.
    res_rules = runner.invoke(bench_app, ["rules", "--format", "json"])
    assert res_rules.exit_code == ExitCode.OK
    payload = json.loads(res_rules.stdout)
    assert [r["rule_id"] for r in payload] == [r.rule_id for r in RULE_CATALOG]

    res_root = runner.invoke(root_app, ["infer-bench", "rules"])
    assert res_root.exit_code == ExitCode.OK
    assert "IB001" in res_root.stdout
