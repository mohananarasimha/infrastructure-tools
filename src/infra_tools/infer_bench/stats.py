"""Percentile calculation and aggregate benchmark statistics."""

from __future__ import annotations

from collections import Counter

from infra_tools.infer_bench.models import (
    BenchmarkStats,
    LatencyPercentiles,
    LoadMode,
    RequestResult,
    ScheduleStats,
    TokenCountSource,
)

SEND_DELAY_WARN_MS = 5.0


def percentile(values: list[float], p: float) -> float | None:
    """Compute linear-interpolated percentile ``p`` in [0, 100], or ``None`` if empty."""
    if not values:
        return None
    if not 0.0 <= p <= 100.0:
        raise ValueError(f"Percentile must be between 0 and 100, got {p}")

    ordered = sorted(values)
    n = len(ordered)
    if n == 1:
        return ordered[0]

    rank = (p / 100.0) * (n - 1)
    lower = int(rank)
    upper = min(lower + 1, n - 1)
    weight = rank - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * weight


def _round_opt(val: float | None) -> float | None:
    return round(val, 2) if val is not None else None


def _build_percentiles(values: list[float]) -> LatencyPercentiles:
    if not values:
        return LatencyPercentiles(count=0)
    return LatencyPercentiles(
        count=len(values),
        p50_ms=_round_opt(percentile(values, 50.0)),
        p95_ms=_round_opt(percentile(values, 95.0)),
        p99_ms=_round_opt(percentile(values, 99.0)),
        max_ms=round(max(values), 2),
    )


def summarize_results(
    results: list[RequestResult],
    *,
    mode: LoadMode,
    target_url: str,
    model: str,
    duration_s: float,
) -> BenchmarkStats:
    """Aggregate per-request measurements into ``BenchmarkStats``."""
    total = len(results)
    succeeded_reqs = [r for r in results if r.ok]
    failed_reqs = [r for r in results if not r.ok]

    error_counts: Counter[str] = Counter()
    for req in failed_reqs:
        key = req.error_class.value if req.error_class is not None else "request_error"
        error_counts[key] += 1

    ttft_values = [r.ttft_ms for r in succeeded_reqs if r.ttft_ms is not None]
    e2e_values = [r.e2e_ms for r in succeeded_reqs if r.e2e_ms is not None]
    itl_values = [gap for r in succeeded_reqs for gap in r.itl_ms]
    all_stalls = [r.max_stall_ms for r in results if r.max_stall_ms is not None]
    tps_values = [r.tokens_per_sec for r in succeeded_reqs if r.tokens_per_sec is not None]

    total_output_tokens = sum(r.output_tokens for r in succeeded_reqs)
    sources = {r.token_source for r in succeeded_reqs if r.output_tokens > 0}
    if not sources:
        token_label = TokenCountSource.CHUNKS_APPROXIMATE.value
    elif sources == {TokenCountSource.USAGE}:
        token_label = TokenCountSource.USAGE.value
    elif sources == {TokenCountSource.CHUNKS_APPROXIMATE}:
        token_label = TokenCountSource.CHUNKS_APPROXIMATE.value
    else:
        token_label = TokenCountSource.MIXED.value

    safe_duration = max(duration_s, 1e-6)
    aggregate_tps = (
        round(total_output_tokens / safe_duration, 2) if total_output_tokens > 0 else 0.0
    )
    error_rate = round(len(failed_reqs) / total, 4) if total > 0 else 0.0

    # Open-loop arrival schedule adherence (detects concurrency-cap queuing).
    if mode is LoadMode.CLOSED_LOOP:
        schedule = ScheduleStats()
    else:
        delays = [r.send_delay_ms for r in results]
        cap_delayed = sum(1 for r in results if r.cap_wait_ms >= SEND_DELAY_WARN_MS)
        max_delay = round(max(delays), 2) if delays else 0.0
        p95_delay = round(percentile(delays, 95.0) or 0.0, 2) if delays else 0.0
        schedule = ScheduleStats(
            delayed_sends=cap_delayed,
            max_send_delay_ms=max_delay,
            p95_send_delay_ms=p95_delay,
            cap_saturated=cap_delayed > 0,
        )

    return BenchmarkStats(
        mode=mode,
        target_url=target_url,
        model=model,
        duration_s=round(duration_s, 3),
        total_requests=total,
        succeeded=len(succeeded_reqs),
        failed=len(failed_reqs),
        error_rate=error_rate,
        errors_by_class=dict(sorted(error_counts.items())),
        total_output_tokens=total_output_tokens,
        token_count_label=token_label,
        aggregate_tokens_per_sec=aggregate_tps,
        per_request_tps_p50=_round_opt(percentile(tps_values, 50.0)),
        per_request_tps_p95=_round_opt(percentile(tps_values, 95.0)),
        ttft=_build_percentiles(ttft_values),
        itl=_build_percentiles(itl_values),
        max_stall_ms=round(max(all_stalls), 2) if all_stalls else None,
        e2e=_build_percentiles(e2e_values),
        schedule=schedule,
    )
