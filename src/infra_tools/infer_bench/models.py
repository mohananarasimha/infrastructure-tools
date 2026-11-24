"""Typed Pydantic models for infer-bench requests, stats, SLOs, and reports."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from infra_tools.core.models import Finding, Severity, ToolReport


class ErrorClass(StrEnum):
    """Normalized failure categories for streaming inference requests."""

    HTTP_429 = "http_429"
    HTTP_5XX = "http_5xx"
    HTTP_4XX = "http_4xx"
    CONNECT_ERROR = "connect_error"
    READ_TIMEOUT = "read_timeout"
    STREAM_TRUNCATED = "stream_truncated"
    MALFORMED_SSE = "malformed_sse"
    REQUEST_ERROR = "request_error"


class TokenCountSource(StrEnum):
    """Indicates whether output token counts came from server usage or chunk counting."""

    USAGE = "usage"
    CHUNKS_APPROXIMATE = "chunks, approximate"
    MIXED = "mixed (usage + chunks, approximate)"


class LoadMode(StrEnum):
    """Supported arrival/concurrency load generation modes."""

    OPEN_LOOP_FIXED = "open-loop-fixed"
    OPEN_LOOP_POISSON = "open-loop-poisson"
    CLOSED_LOOP = "closed-loop"


class RequestResult(BaseModel):
    """Per-request timing, token accounting, and error outcome."""

    model_config = ConfigDict(frozen=True)

    request_id: int = Field(..., ge=0)
    scheduled_offset_ms: float = Field(default=0.0, ge=0.0)
    actual_send_offset_ms: float = Field(default=0.0, ge=0.0)
    send_delay_ms: float = Field(default=0.0, ge=0.0)
    cap_wait_ms: float = Field(default=0.0, ge=0.0)
    http_status: int | None = None
    ok: bool
    error_class: ErrorClass | None = None
    error_detail: str | None = None
    ttft_ms: float | None = None
    e2e_ms: float | None = None
    itl_ms: list[float] = Field(default_factory=list)
    max_stall_ms: float | None = None
    output_tokens: int = Field(default=0, ge=0)
    token_source: TokenCountSource = TokenCountSource.CHUNKS_APPROXIMATE
    tokens_per_sec: float | None = None


class LatencyPercentiles(BaseModel):
    """Summary percentiles in milliseconds."""

    model_config = ConfigDict(frozen=True)

    count: int = Field(default=0, ge=0)
    p50_ms: float | None = None
    p95_ms: float | None = None
    p99_ms: float | None = None
    max_ms: float | None = None


class ScheduleStats(BaseModel):
    """Open-loop arrival scheduling adherence (detects concurrency-cap queuing)."""

    model_config = ConfigDict(frozen=True)

    delayed_sends: int = Field(default=0, ge=0)
    max_send_delay_ms: float = Field(default=0.0, ge=0.0)
    p95_send_delay_ms: float = Field(default=0.0, ge=0.0)
    cap_saturated: bool = False


class BenchmarkStats(BaseModel):
    """Aggregate benchmark statistics embedded in JSON reports and rendered in text."""

    model_config = ConfigDict(frozen=True)

    mode: LoadMode
    target_url: str
    model: str
    duration_s: float = Field(..., ge=0.0)
    total_requests: int = Field(..., ge=0)
    succeeded: int = Field(..., ge=0)
    failed: int = Field(..., ge=0)
    error_rate: float = Field(..., ge=0.0, le=1.0)
    errors_by_class: dict[str, int] = Field(default_factory=dict)
    total_output_tokens: int = Field(default=0, ge=0)
    token_count_label: str = TokenCountSource.CHUNKS_APPROXIMATE.value
    aggregate_tokens_per_sec: float = Field(default=0.0, ge=0.0)
    per_request_tps_p50: float | None = None
    per_request_tps_p95: float | None = None
    ttft: LatencyPercentiles
    itl: LatencyPercentiles
    max_stall_ms: float | None = None
    e2e: LatencyPercentiles
    schedule: ScheduleStats


class SloConfig(BaseModel):
    """Optional SLO thresholds evaluated into structured Findings."""

    model_config = ConfigDict(frozen=True)

    ttft_p95_ms: float | None = None
    itl_p99_ms: float | None = None
    max_stall_ms: float | None = None
    e2e_p95_ms: float | None = None
    min_aggregate_tps: float | None = None
    max_error_rate: float | None = None


class BenchReport(ToolReport):
    """ToolReport subclass embedding typed raw benchmark metrics for JSON consumers."""

    metrics: BenchmarkStats

    @classmethod
    def build(
        cls,
        *,
        target: str,
        stats: BenchmarkStats,
        findings: list[Finding],
        fail_on: Severity = Severity.LOW,
    ) -> BenchReport:
        """Build a sorted ``BenchReport`` consistent with the shared ``ToolReport`` contract."""
        base = ToolReport.from_findings(
            tool="infer-bench",
            target=target,
            documents_scanned=stats.total_requests,
            findings=findings,
            fail_on=fail_on,
        )
        return cls(
            tool=base.tool,
            target=base.target,
            summary=base.summary,
            findings=base.findings,
            passed=base.passed,
            metrics=stats,
        )
