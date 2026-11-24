"""Async httpx OpenAI-compatible streaming client with open-loop and closed-loop drivers."""

from __future__ import annotations

import asyncio
import random
import time
from urllib.parse import urlparse

import httpx

from infra_tools.infer_bench.models import (
    BenchmarkStats,
    ErrorClass,
    LoadMode,
    RequestResult,
    TokenCountSource,
)
from infra_tools.infer_bench.sse import SseParseError, parse_sse_line
from infra_tools.infer_bench.stats import summarize_results


class BenchConfigError(Exception):
    """Raised when benchmark configuration or URL parameters are invalid."""


def normalize_completions_url(raw_url: str) -> str:
    """Validate an http(s) URL and normalize to a ``/v1/chat/completions`` endpoint."""
    cleaned = raw_url.strip()
    parsed = urlparse(cleaned)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise BenchConfigError(
            f"Invalid target URL '{raw_url}': expected http:// or https:// URL with host."
        )

    path = parsed.path.rstrip("/")
    if not path:
        return f"{cleaned.rstrip('/')}/v1/chat/completions"
    if path.endswith("/v1"):
        return f"{cleaned.rstrip('/')}/chat/completions"
    return cleaned


def _classify_http_status(status_code: int) -> ErrorClass:
    if status_code == 429:
        return ErrorClass.HTTP_429
    if 500 <= status_code < 600:
        return ErrorClass.HTTP_5XX
    return ErrorClass.HTTP_4XX


async def send_streaming_request(
    client: httpx.AsyncClient,
    *,
    request_id: int,
    url: str,
    model: str,
    prompt: str,
    max_tokens: int,
    include_usage: bool,
    api_key: str | None,
    scheduled_offset_ms: float,
    run_start: float,
    cap_wait_ms: float = 0.0,
) -> RequestResult:
    """Send one streaming ``/v1/chat/completions`` request and measure TTFT/ITL/E2E."""
    send_start = time.perf_counter()
    actual_send_offset_ms = max(0.0, (send_start - run_start) * 1000.0)
    send_delay_ms = max(0.0, actual_send_offset_ms - scheduled_offset_ms)

    headers: dict[str, str] = {"Accept": "text/event-stream"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    payload: dict[str, object] = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": True,
        "max_tokens": max_tokens,
    }
    if include_usage:
        payload["stream_options"] = {"include_usage": True}

    first_token_at: float | None = None
    last_token_at: float | None = None
    ttft_ms: float | None = None
    itl_ms: list[float] = []
    chunk_count = 0
    usage_tokens: int | None = None
    saw_done = False
    http_status: int | None = None

    try:
        async with client.stream("POST", url, json=payload, headers=headers) as response:
            http_status = response.status_code
            if http_status != 200:
                body_bytes = await response.aread()
                snippet = body_bytes.decode("utf-8", errors="replace").strip()[:160]
                return RequestResult(
                    request_id=request_id,
                    scheduled_offset_ms=scheduled_offset_ms,
                    actual_send_offset_ms=actual_send_offset_ms,
                    send_delay_ms=send_delay_ms,
                    cap_wait_ms=cap_wait_ms,
                    http_status=http_status,
                    ok=False,
                    error_class=_classify_http_status(http_status),
                    error_detail=f"HTTP {http_status}" + (f": {snippet}" if snippet else ""),
                    e2e_ms=(time.perf_counter() - send_start) * 1000.0,
                )

            async for raw_line in response.aiter_lines():
                try:
                    parsed = parse_sse_line(raw_line)
                except SseParseError as exc:
                    return RequestResult(
                        request_id=request_id,
                        scheduled_offset_ms=scheduled_offset_ms,
                        actual_send_offset_ms=actual_send_offset_ms,
                        send_delay_ms=send_delay_ms,
                        http_status=http_status,
                        ok=False,
                        error_class=ErrorClass.MALFORMED_SSE,
                        error_detail=str(exc),
                        ttft_ms=ttft_ms,
                        e2e_ms=(time.perf_counter() - send_start) * 1000.0,
                        itl_ms=itl_ms,
                        max_stall_ms=max(itl_ms) if itl_ms else None,
                    )

                if parsed is None:
                    continue

                if parsed.is_done:
                    saw_done = True
                    break

                if parsed.completion_tokens is not None:
                    usage_tokens = parsed.completion_tokens

                if parsed.has_content:
                    now = time.perf_counter()
                    if first_token_at is None:
                        first_token_at = now
                        ttft_ms = (now - send_start) * 1000.0
                    elif last_token_at is not None:
                        itl_ms.append((now - last_token_at) * 1000.0)
                    last_token_at = now
                    chunk_count += 1

    except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
        return RequestResult(
            request_id=request_id,
            scheduled_offset_ms=scheduled_offset_ms,
            actual_send_offset_ms=actual_send_offset_ms,
            send_delay_ms=send_delay_ms,
            cap_wait_ms=cap_wait_ms,
            http_status=http_status,
            ok=False,
            error_class=ErrorClass.CONNECT_ERROR,
            error_detail=f"{type(exc).__name__}: {exc}",
            e2e_ms=(time.perf_counter() - send_start) * 1000.0,
        )
    except (httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout) as exc:
        return RequestResult(
            request_id=request_id,
            scheduled_offset_ms=scheduled_offset_ms,
            actual_send_offset_ms=actual_send_offset_ms,
            send_delay_ms=send_delay_ms,
            cap_wait_ms=cap_wait_ms,
            http_status=http_status,
            ok=False,
            error_class=ErrorClass.READ_TIMEOUT,
            error_detail=f"{type(exc).__name__}: {exc}",
            ttft_ms=ttft_ms,
            e2e_ms=(time.perf_counter() - send_start) * 1000.0,
            itl_ms=itl_ms,
            max_stall_ms=max(itl_ms) if itl_ms else None,
        )
    except (httpx.RemoteProtocolError, httpx.ReadError) as exc:
        err_cls = ErrorClass.STREAM_TRUNCATED if http_status == 200 else ErrorClass.REQUEST_ERROR
        return RequestResult(
            request_id=request_id,
            scheduled_offset_ms=scheduled_offset_ms,
            actual_send_offset_ms=actual_send_offset_ms,
            send_delay_ms=send_delay_ms,
            cap_wait_ms=cap_wait_ms,
            http_status=http_status,
            ok=False,
            error_class=err_cls,
            error_detail=f"{type(exc).__name__}: {exc}",
            ttft_ms=ttft_ms,
            e2e_ms=(time.perf_counter() - send_start) * 1000.0,
            itl_ms=itl_ms,
            max_stall_ms=max(itl_ms) if itl_ms else None,
        )
    except httpx.HTTPError as exc:
        return RequestResult(
            request_id=request_id,
            scheduled_offset_ms=scheduled_offset_ms,
            actual_send_offset_ms=actual_send_offset_ms,
            send_delay_ms=send_delay_ms,
            cap_wait_ms=cap_wait_ms,
            http_status=http_status,
            ok=False,
            error_class=ErrorClass.REQUEST_ERROR,
            error_detail=f"{type(exc).__name__}: {exc}",
            e2e_ms=(time.perf_counter() - send_start) * 1000.0,
        )

    e2e_ms = (time.perf_counter() - send_start) * 1000.0
    max_stall = max(itl_ms) if itl_ms else None

    if not saw_done:
        return RequestResult(
            request_id=request_id,
            scheduled_offset_ms=scheduled_offset_ms,
            actual_send_offset_ms=actual_send_offset_ms,
            send_delay_ms=send_delay_ms,
            cap_wait_ms=cap_wait_ms,
            http_status=http_status,
            ok=False,
            error_class=ErrorClass.STREAM_TRUNCATED,
            error_detail="SSE stream ended without [DONE] sentinel.",
            ttft_ms=ttft_ms,
            e2e_ms=e2e_ms,
            itl_ms=itl_ms,
            max_stall_ms=max_stall,
        )

    if usage_tokens is not None:
        output_tokens = usage_tokens
        token_source = TokenCountSource.USAGE
    else:
        output_tokens = chunk_count
        token_source = TokenCountSource.CHUNKS_APPROXIMATE

    tps = (output_tokens / (e2e_ms / 1000.0)) if (output_tokens > 0 and e2e_ms > 0) else None
    return RequestResult(
        request_id=request_id,
        scheduled_offset_ms=scheduled_offset_ms,
        actual_send_offset_ms=actual_send_offset_ms,
        send_delay_ms=send_delay_ms,
        cap_wait_ms=cap_wait_ms,
        http_status=http_status,
        ok=True,
        ttft_ms=ttft_ms,
        e2e_ms=e2e_ms,
        itl_ms=itl_ms,
        max_stall_ms=max_stall,
        output_tokens=output_tokens,
        token_source=token_source,
        tokens_per_sec=tps,
    )


def _generate_open_loop_offsets(
    num_requests: int,
    *,
    rate_rps: float,
    poisson: bool,
    seed: int | None,
) -> list[float]:
    if not poisson:
        return [idx / rate_rps for idx in range(num_requests)]

    rng = random.Random(seed)  # noqa: S311
    offsets = [0.0]
    elapsed = 0.0
    for _ in range(1, num_requests):
        elapsed += rng.expovariate(rate_rps)
        offsets.append(elapsed)
    return offsets


async def run_benchmark(
    *,
    url: str,
    model: str = "mock-model",
    prompt: str = "Explain Kubernetes readiness probes in two sentences.",
    max_tokens: int = 64,
    num_requests: int = 10,
    rate_rps: float | None = 5.0,
    poisson: bool = False,
    max_concurrency: int = 16,
    concurrency: int | None = None,
    timeout_s: float = 10.0,
    connect_timeout_s: float = 5.0,
    include_usage: bool = True,
    api_key: str | None = None,
    seed: int | None = None,
) -> BenchmarkStats:
    """Execute an open-loop or closed-loop async streaming benchmark."""
    endpoint_url = normalize_completions_url(url)

    if num_requests < 1:
        raise BenchConfigError("--requests must be >= 1.")
    if max_tokens < 1:
        raise BenchConfigError("--max-tokens must be >= 1.")
    if timeout_s <= 0 or connect_timeout_s <= 0:
        raise BenchConfigError("Timeouts must be > 0.")

    if concurrency is not None:
        if concurrency < 1:
            raise BenchConfigError("--concurrency must be >= 1.")
        mode = LoadMode.CLOSED_LOOP
        pool_cap = concurrency
    else:
        if rate_rps is None or rate_rps <= 0:
            raise BenchConfigError("--rate must be > 0 in open-loop mode.")
        if max_concurrency < 1:
            raise BenchConfigError("--max-concurrency must be >= 1.")
        mode = LoadMode.OPEN_LOOP_POISSON if poisson else LoadMode.OPEN_LOOP_FIXED
        pool_cap = max_concurrency

    timeout = httpx.Timeout(
        connect=connect_timeout_s,
        read=timeout_s,
        write=timeout_s,
        pool=timeout_s,
    )
    limits = httpx.Limits(max_connections=pool_cap, max_keepalive_connections=pool_cap)

    run_start = time.perf_counter()
    results: list[RequestResult] = []

    async with httpx.AsyncClient(timeout=timeout, limits=limits) as client:
        if mode is LoadMode.CLOSED_LOOP:
            next_id = 0
            lock = asyncio.Lock()

            async def worker() -> None:
                nonlocal next_id
                while True:
                    async with lock:
                        if next_id >= num_requests:
                            return
                        req_id = next_id
                        next_id += 1
                    res = await send_streaming_request(
                        client,
                        request_id=req_id,
                        url=endpoint_url,
                        model=model,
                        prompt=prompt,
                        max_tokens=max_tokens,
                        include_usage=include_usage,
                        api_key=api_key,
                        scheduled_offset_ms=0.0,
                        run_start=run_start,
                    )
                    results.append(res)

            worker_count = min(pool_cap, num_requests)
            await asyncio.gather(*(worker() for _ in range(worker_count)))
        else:
            assert rate_rps is not None  # noqa: S101
            offsets_s = _generate_open_loop_offsets(
                num_requests, rate_rps=rate_rps, poisson=poisson, seed=seed
            )
            semaphore = asyncio.Semaphore(pool_cap)

            async def scheduled_sender(req_id: int, offset_s: float) -> RequestResult:
                sleep_for = (run_start + offset_s) - time.perf_counter()
                if sleep_for > 0:
                    await asyncio.sleep(sleep_for)
                before_sem = time.perf_counter()
                async with semaphore:
                    cap_wait_ms = max(0.0, (time.perf_counter() - before_sem) * 1000.0)
                    return await send_streaming_request(
                        client,
                        request_id=req_id,
                        url=endpoint_url,
                        model=model,
                        prompt=prompt,
                        max_tokens=max_tokens,
                        include_usage=include_usage,
                        api_key=api_key,
                        scheduled_offset_ms=offset_s * 1000.0,
                        run_start=run_start,
                        cap_wait_ms=cap_wait_ms,
                    )

            tasks = [
                asyncio.create_task(scheduled_sender(req_id, offset_s))
                for req_id, offset_s in enumerate(offsets_s)
            ]
            results = list(await asyncio.gather(*tasks))

    duration_s = time.perf_counter() - run_start
    results.sort(key=lambda r: r.request_id)
    return summarize_results(
        results,
        mode=mode,
        target_url=endpoint_url,
        model=model,
        duration_s=duration_s,
    )
