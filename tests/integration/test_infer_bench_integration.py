"""In-process integration tests for infer-bench against MockInferenceServer."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from typer.testing import CliRunner

from infra_tools.core.models import ExitCode, Severity, ToolReport
from infra_tools.infer_bench.cli import app as bench_app
from infra_tools.infer_bench.client import run_benchmark
from infra_tools.infer_bench.mock_server import MockInferenceServer, MockServerConfig
from infra_tools.infer_bench.models import BenchReport, LoadMode, SloConfig, TokenCountSource
from infra_tools.infer_bench.slo import evaluate_slos

runner = CliRunner()


@contextmanager
def _running_mock_in_thread(config: MockServerConfig) -> Iterator[str]:
    """Run ``MockInferenceServer`` on a background thread for synchronous CLI tests."""
    ready_url: list[str] = []
    ready_event = threading.Event()
    stop_event = threading.Event()

    async def _serve() -> None:
        async with MockInferenceServer(config) as server:
            ready_url.append(server.base_url)
            ready_event.set()
            while not stop_event.is_set():
                await asyncio.sleep(0.01)

    thread = threading.Thread(target=lambda: asyncio.run(_serve()), daemon=True)
    thread.start()
    assert ready_event.wait(timeout=3.0), "Mock server failed to start"
    try:
        yield ready_url[0]
    finally:
        stop_event.set()
        thread.join(timeout=3.0)


@pytest.mark.asyncio
async def test_healthy_open_loop_and_usage_vs_approx_chunks() -> None:
    cfg = MockServerConfig(ttft_ms=5.0, itl_ms=2.0, tokens_per_response=6, emit_usage=True)
    async with MockInferenceServer(cfg) as server:
        stats = await run_benchmark(
            url=server.base_url,
            model="vllm-test",
            num_requests=6,
            rate_rps=100.0,
            max_concurrency=6,
        )
    assert stats.mode is LoadMode.OPEN_LOOP_FIXED
    assert stats.succeeded == 6
    assert stats.failed == 0
    assert stats.total_output_tokens == 36
    assert stats.token_count_label == TokenCountSource.USAGE.value
    assert stats.ttft.p95_ms is not None and stats.ttft.p95_ms >= 4.0
    assert stats.itl.p99_ms is not None
    assert stats.aggregate_tokens_per_sec > 0

    # When server omits usage, token_count_label must clearly mark "chunks, approximate".
    cfg_no_usage = MockServerConfig(
        ttft_ms=3.0, itl_ms=2.0, tokens_per_response=5, emit_usage=False
    )
    async with MockInferenceServer(cfg_no_usage) as server:
        stats_approx = await run_benchmark(
            url=server.base_url,
            model="vllm-no-usage",
            num_requests=4,
            rate_rps=None,
            concurrency=2,
        )
    assert stats_approx.mode is LoadMode.CLOSED_LOOP
    assert stats_approx.succeeded == 4
    assert stats_approx.total_output_tokens == 20
    assert stats_approx.token_count_label == TokenCountSource.CHUNKS_APPROXIMATE.value


@pytest.mark.asyncio
async def test_slow_ttft_and_mid_stream_stall_trigger_ib001_ib002_ib003() -> None:
    cfg = MockServerConfig(
        ttft_ms=60.0,
        itl_ms=2.0,
        tokens_per_response=6,
        stall_ms=70.0,
        stall_at_token=3,
    )
    async with MockInferenceServer(cfg) as server:
        stats = await run_benchmark(
            url=server.base_url,
            model="stalling-llm",
            num_requests=4,
            rate_rps=80.0,
            poisson=True,
            seed=7,
            max_concurrency=4,
        )
    assert stats.mode is LoadMode.OPEN_LOOP_POISSON
    assert stats.succeeded == 4
    assert stats.ttft.p95_ms is not None and stats.ttft.p95_ms >= 50.0
    assert stats.max_stall_ms is not None and stats.max_stall_ms >= 60.0

    findings = evaluate_slos(
        stats,
        SloConfig(ttft_p95_ms=25.0, itl_p99_ms=30.0, max_stall_ms=40.0),
    )
    assert {f.rule_id for f in findings} >= {"IB001", "IB002", "IB003"}


@pytest.mark.asyncio
async def test_http_429_503_truncation_malformed_and_read_timeout() -> None:
    # 1. HTTP 429 rate limiting
    async with MockInferenceServer(MockServerConfig(error_429_rate=1.0)) as srv_429:
        st_429 = await run_benchmark(url=srv_429.base_url, num_requests=3, rate_rps=100.0)
    assert st_429.errors_by_class == {"http_429": 3}
    assert st_429.error_rate == 1.0

    # 2. HTTP 503 overload
    async with MockInferenceServer(MockServerConfig(error_503_rate=1.0)) as srv_503:
        st_503 = await run_benchmark(url=srv_503.base_url, num_requests=2, rate_rps=100.0)
    assert st_503.errors_by_class == {"http_5xx": 2}

    # 3. Stream truncation without [DONE]
    cfg_trunc = MockServerConfig(ttft_ms=2.0, itl_ms=1.0, tokens_per_response=6, truncate_rate=1.0)
    async with MockInferenceServer(cfg_trunc) as srv_trunc:
        st_trunc = await run_benchmark(url=srv_trunc.base_url, num_requests=3, rate_rps=100.0)
    assert st_trunc.errors_by_class == {"stream_truncated": 3}

    # 4. Malformed SSE payload
    cfg_bad = MockServerConfig(ttft_ms=2.0, malformed_rate=1.0)
    async with MockInferenceServer(cfg_bad) as srv_bad:
        st_bad = await run_benchmark(url=srv_bad.base_url, num_requests=2, rate_rps=100.0)
    assert st_bad.errors_by_class == {"malformed_sse": 2}

    # 5. Read timeout (server TTFT slower than client read timeout)
    cfg_timeout = MockServerConfig(ttft_ms=200.0, itl_ms=5.0, tokens_per_response=4)
    async with MockInferenceServer(cfg_timeout) as srv_to:
        st_to = await run_benchmark(
            url=srv_to.base_url,
            num_requests=2,
            rate_rps=100.0,
            timeout_s=0.05,
        )
    assert st_to.errors_by_class == {"read_timeout": 2}


@pytest.mark.asyncio
async def test_open_loop_concurrency_cap_reports_delayed_sends() -> None:
    # 4 requests scheduled at 200 RPS (5ms apart) with max_concurrency=1 and 30ms service time
    # must visibly queue behind the cap and emit IB007 (INFO).
    cfg = MockServerConfig(ttft_ms=25.0, itl_ms=2.0, tokens_per_response=4)
    async with MockInferenceServer(cfg) as server:
        stats = await run_benchmark(
            url=server.base_url,
            num_requests=4,
            rate_rps=200.0,
            max_concurrency=1,
        )
    assert stats.succeeded == 4
    assert stats.schedule.cap_saturated is True
    assert stats.schedule.delayed_sends >= 2
    assert stats.schedule.max_send_delay_ms >= 20.0

    findings = evaluate_slos(stats, SloConfig())
    assert [f.rule_id for f in findings] == ["IB007"]
    assert findings[0].severity == Severity.INFO


def test_cli_end_to_end_slo_pass_fail_json_and_80_col_text() -> None:
    cfg_ok = MockServerConfig(ttft_ms=5.0, itl_ms=2.0, tokens_per_response=6, emit_usage=True)
    with _running_mock_in_thread(cfg_ok) as url:
        res_pass = runner.invoke(
            bench_app,
            [
                "run",
                "--url",
                url,
                "--requests",
                "4",
                "--rate",
                "100",
                "--slo-ttft-p95-ms",
                "500",
                "--max-error-rate",
                "0.0",
                "--format",
                "json",
            ],
        )
        assert res_pass.exit_code == ExitCode.OK
        # Valid against both BenchReport and base ToolReport schemas.
        report = BenchReport.model_validate_json(res_pass.stdout)
        ToolReport.model_validate_json(res_pass.stdout)
        assert report.passed is True
        assert report.metrics.succeeded == 4
        assert report.metrics.token_count_label == TokenCountSource.USAGE.value

        # Now enforce impossible TTFT SLO -> exit 1 with IB001.
        res_fail = runner.invoke(
            bench_app,
            [
                "run",
                "--url",
                url,
                "--requests",
                "3",
                "--rate",
                "100",
                "--slo-ttft-p95-ms",
                "0.1",
                "--format",
                "table",
            ],
            env={"COLUMNS": "80"},
        )
        assert res_fail.exit_code == ExitCode.FINDINGS
        assert "IB001" in res_fail.stdout
        assert "…" not in res_fail.stdout
        assert "FAIL" in res_fail.stdout
