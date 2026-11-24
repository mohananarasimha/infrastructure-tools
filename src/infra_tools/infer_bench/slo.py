"""SLO evaluation rules (IB001-IB007) for infer-bench."""

from __future__ import annotations

from dataclasses import dataclass

from infra_tools.core.models import Finding, Severity
from infra_tools.infer_bench.models import BenchmarkStats, SloConfig


@dataclass(frozen=True)
class RuleSpec:
    """Metadata describing a built-in infer-bench SLO/reliability rule."""

    rule_id: str
    severity: Severity
    title: str
    description: str


RULE_CATALOG: tuple[RuleSpec, ...] = (
    RuleSpec(
        rule_id="IB001",
        severity=Severity.HIGH,
        title="TTFT p95 SLO violation",
        description=(
            "Flags when time-to-first-token p95 exceeds --slo-ttft-p95-ms "
            "(or no TTFT samples succeeded)."
        ),
    ),
    RuleSpec(
        rule_id="IB002",
        severity=Severity.HIGH,
        title="Inter-token latency p99 SLO violation",
        description=(
            "Flags when inter-token latency (ITL) p99 exceeds --slo-itl-p99-ms "
            "(or no ITL samples succeeded)."
        ),
    ),
    RuleSpec(
        rule_id="IB003",
        severity=Severity.MEDIUM,
        title="Mid-stream stall threshold exceeded",
        description="Flags when worst inter-token gap exceeds --slo-max-stall-ms.",
    ),
    RuleSpec(
        rule_id="IB004",
        severity=Severity.HIGH,
        title="End-to-end p95 latency SLO violation",
        description="Flags when end-to-end request p95 exceeds --slo-e2e-p95-ms.",
    ),
    RuleSpec(
        rule_id="IB005",
        severity=Severity.CRITICAL,
        title="Error rate SLO violation",
        description=(
            "Flags when request error rate exceeds --max-error-rate, summarizing "
            "failures by error class (HTTP 429/5xx, timeout, truncation, malformed SSE)."
        ),
    ),
    RuleSpec(
        rule_id="IB006",
        severity=Severity.MEDIUM,
        title="Aggregate throughput below floor",
        description="Flags when aggregate output tokens/s falls below --min-tps.",
    ),
    RuleSpec(
        rule_id="IB007",
        severity=Severity.INFO,
        title="Open-loop arrival schedule delayed by concurrency cap",
        description=(
            "Informational warning when open-loop requests queued behind --max-concurrency, "
            "indicating potential client-side saturation."
        ),
    ),
)


def evaluate_slos(stats: BenchmarkStats, slo: SloConfig) -> list[Finding]:
    """Evaluate configured SLO thresholds and scheduling health into ``Finding`` objects."""
    findings: list[Finding] = []
    resource = f"Endpoint/{stats.model}"

    # IB001: TTFT p95
    if slo.ttft_p95_ms is not None:
        if stats.ttft.p95_ms is None:
            findings.append(
                Finding(
                    rule_id="IB001",
                    severity=Severity.HIGH,
                    resource=resource,
                    location=stats.target_url,
                    message=(
                        f"TTFT p95 unavailable (0 successful streaming responses) against "
                        f"SLO <= {slo.ttft_p95_ms:.2f}ms."
                    ),
                    remediation=(
                        "Inspect request error breakdown and server logs to restore successful "
                        "streaming completions."
                    ),
                )
            )
        elif stats.ttft.p95_ms > slo.ttft_p95_ms:
            findings.append(
                Finding(
                    rule_id="IB001",
                    severity=Severity.HIGH,
                    resource=resource,
                    location=stats.target_url,
                    message=(
                        f"TTFT p95={stats.ttft.p95_ms:.2f}ms exceeded SLO <= "
                        f"{slo.ttft_p95_ms:.2f}ms (p50={stats.ttft.p50_ms}ms, "
                        f"p99={stats.ttft.p99_ms}ms)."
                    ),
                    remediation=(
                        "Reduce prefill queue depth, tune max_num_batched_tokens / prefix caching, "
                        "or scale inference replicas."
                    ),
                )
            )

    # IB002: ITL p99
    if slo.itl_p99_ms is not None:
        if stats.itl.p99_ms is None:
            findings.append(
                Finding(
                    rule_id="IB002",
                    severity=Severity.HIGH,
                    resource=resource,
                    location=stats.target_url,
                    message=(
                        f"ITL p99 unavailable (fewer than 2 content deltas per response) against "
                        f"SLO <= {slo.itl_p99_ms:.2f}ms."
                    ),
                    remediation=(
                        "Verify the endpoint streams multiple content deltas and check error rates."
                    ),
                )
            )
        elif stats.itl.p99_ms > slo.itl_p99_ms:
            findings.append(
                Finding(
                    rule_id="IB002",
                    severity=Severity.HIGH,
                    resource=resource,
                    location=stats.target_url,
                    message=(
                        f"ITL p99={stats.itl.p99_ms:.2f}ms exceeded SLO <= "
                        f"{slo.itl_p99_ms:.2f}ms (p50={stats.itl.p50_ms}ms, "
                        f"max_stall={stats.max_stall_ms}ms)."
                    ),
                    remediation=(
                        "Inspect KV-cache preemption, chunked prefill interference, or GPU memory "
                        "bandwidth saturation during decode."
                    ),
                )
            )

    # IB003: Max mid-stream stall
    if (
        slo.max_stall_ms is not None
        and stats.max_stall_ms is not None
        and stats.max_stall_ms > slo.max_stall_ms
    ):
        findings.append(
            Finding(
                rule_id="IB003",
                severity=Severity.MEDIUM,
                resource=resource,
                location=stats.target_url,
                message=(
                    f"Max stream stall={stats.max_stall_ms:.2f}ms exceeded threshold <= "
                    f"{slo.max_stall_ms:.2f}ms."
                ),
                remediation=(
                    "Check for KV-cache swapping/recomputation pauses, GC pauses, or upstream "
                    "proxy buffering."
                ),
            )
        )

    # IB004: End-to-end p95
    if slo.e2e_p95_ms is not None:
        if stats.e2e.p95_ms is None:
            findings.append(
                Finding(
                    rule_id="IB004",
                    severity=Severity.HIGH,
                    resource=resource,
                    location=stats.target_url,
                    message=(
                        f"End-to-end p95 unavailable (0 completed requests) against "
                        f"SLO <= {slo.e2e_p95_ms:.2f}ms."
                    ),
                    remediation="Investigate failed requests before evaluating latency SLOs.",
                )
            )
        elif stats.e2e.p95_ms > slo.e2e_p95_ms:
            findings.append(
                Finding(
                    rule_id="IB004",
                    severity=Severity.HIGH,
                    resource=resource,
                    location=stats.target_url,
                    message=(
                        f"End-to-end p95={stats.e2e.p95_ms:.2f}ms exceeded SLO <= "
                        f"{slo.e2e_p95_ms:.2f}ms (p50={stats.e2e.p50_ms}ms)."
                    ),
                    remediation=(
                        "Reduce max_tokens, lower decode concurrency, or add GPU serving capacity."
                    ),
                )
            )

    # IB005: Error rate
    if slo.max_error_rate is not None and stats.error_rate > slo.max_error_rate:
        breakdown = ", ".join(f"{k}={v}" for k, v in stats.errors_by_class.items()) or "none"
        findings.append(
            Finding(
                rule_id="IB005",
                severity=Severity.CRITICAL,
                resource=resource,
                location=stats.target_url,
                message=(
                    f"Error rate={stats.error_rate * 100:.2f}% ({stats.failed}/"
                    f"{stats.total_requests}) exceeded SLO <= {slo.max_error_rate * 100:.2f}%. "
                    f"Errors: {breakdown}."
                ),
                remediation=(
                    "Inspect rate limits (HTTP 429), backend saturation (HTTP 5xx/timeouts), "
                    "and streaming proxy timeouts (truncated/malformed SSE)."
                ),
            )
        )

    # IB006: Minimum aggregate throughput
    if (
        slo.min_aggregate_tps is not None
        and stats.aggregate_tokens_per_sec < slo.min_aggregate_tps
    ):
        findings.append(
            Finding(
                rule_id="IB006",
                severity=Severity.MEDIUM,
                resource=resource,
                location=stats.target_url,
                message=(
                    f"Aggregate throughput={stats.aggregate_tokens_per_sec:.2f} tok/s "
                    f"({stats.token_count_label}) fell below SLO >= "
                    f"{slo.min_aggregate_tps:.2f} tok/s."
                ),
                remediation=(
                    "Check GPU utilization, tensor-parallel/batch settings, and client arrival "
                    "rate."
                ),
            )
        )

    # IB007: Open-loop concurrency cap delayed sends (INFO so it informs without false SLO fail)
    if stats.schedule.cap_saturated:
        findings.append(
            Finding(
                rule_id="IB007",
                severity=Severity.INFO,
                resource=resource,
                location=stats.target_url,
                message=(
                    f"Open-loop arrival schedule delayed {stats.schedule.delayed_sends}/"
                    f"{stats.total_requests} sends behind --max-concurrency "
                    f"(p95_delay={stats.schedule.p95_send_delay_ms:.2f}ms, "
                    f"max_delay={stats.schedule.max_send_delay_ms:.2f}ms)."
                ),
                remediation=(
                    "Raise --max-concurrency or reduce --rate so open-loop arrivals are not "
                    "throttled by the client."
                ),
            )
        )

    return findings
