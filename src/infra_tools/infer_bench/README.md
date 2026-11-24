# `infer-bench`

Async streaming latency, throughput, and SLO benchmark tool for OpenAI-compatible and vLLM `/v1/chat/completions` endpoints (`stream: true`).

## Problem

Evaluating LLM inference reliability with simple curl scripts or closed-loop HTTP tools hides the failure modes that break streaming UX in production:

- High time-to-first-token (TTFT) under prefill queueing.
- Mid-stream decode stalls (high p99 inter-token latency or worst-case gaps).
- Silent SSE failures: HTTP 429 rate limits, HTTP 5xx overloads, read timeouts, streams truncated before `[DONE]`, or malformed SSE JSON chunks.
- **Coordinated omission** in closed-loop benchmarks: when a fixed worker pool waits for slow responses before sending the next request, arrival rate drops whenever the server slows down, masking tail latency under real user arrival rates.

## Load Models & Coordinated Omission

`infer-bench` defaults to **open-loop arrival scheduling**:

- **Open-loop fixed rate (`--rate RPS`, default)** or **Poisson arrivals (`--rate RPS --poisson`)**: requests are scheduled at independent arrival timestamps regardless of how long prior requests take.
- **`--max-concurrency N`**: protects the client from unbounded socket growth. `infer-bench` measures both `scheduled_offset` vs `actual_send_offset` and explicit semaphore wait time (`cap_wait_ms`). If arrivals queue behind `--max-concurrency`, `schedule.cap_saturated=true` is recorded in JSON and an informational `IB007` finding reports how many sends were delayed so client-side throttling is never silently mistaken for clean open-loop load.
- **Closed-loop (`--concurrency C`)**: optional fixed-worker mode, explicitly labeled `mode=closed-loop` in both text and JSON output.

## Metric Definitions

| Metric | Definition |
| --- | --- |
| **TTFT** (`ttft`) | Monotonic time from actual HTTP request send to receipt of the first non-empty `choices[0].delta.content` SSE chunk (role-only framing chunks are ignored). Reported as p50/p95/p99/max over completed streams. |
| **ITL** (`itl`) | Inter-token latency: monotonic gaps between consecutive non-empty content delta chunks within a stream. Reported as p50/p95/p99/max across all completed-stream gaps. |
| **Max Stall** (`max_stall_ms`) | Worst single inter-token gap observed across any stream (including streams that later failed or timed out after receiving >= 2 deltas). |
| **End-to-End** (`e2e`) | Monotonic time from actual HTTP request send to receipt of the `data: [DONE]` sentinel. |
| **Output Tokens & Throughput** | Prefers exact server `usage.completion_tokens` when `stream_options.include_usage` is honored (`source=usage`). When absent, counts non-empty content delta chunks and explicitly labels throughput as `source=chunks, approximate`. Reports both aggregate `total_output_tokens / duration_s` and per-request p50/p95 `tokens/s`. |
| **Errors by Class** | Categorizes failures into `http_429`, `http_5xx`, `http_4xx`, `connect_error`, `read_timeout`, `stream_truncated` (EOF before `[DONE]`), `malformed_sse`, and `request_error`. |

## SLO Rules

| Rule ID | Severity | Condition |
| --- | --- | --- |
| `IB001` | `HIGH` | TTFT p95 exceeds `--slo-ttft-p95-ms` (or 0 successful streaming samples) |
| `IB002` | `HIGH` | ITL p99 exceeds `--slo-itl-p99-ms` (or < 2 content deltas per response) |
| `IB003` | `MEDIUM` | Worst inter-token stall exceeds `--slo-max-stall-ms` |
| `IB004` | `HIGH` | End-to-end p95 latency exceeds `--slo-e2e-p95-ms` |
| `IB005` | `CRITICAL` | Request error rate exceeds `--max-error-rate` |
| `IB006` | `MEDIUM` | Aggregate output throughput falls below `--min-tps` |
| `IB007` | `INFO` | Open-loop sends queued behind `--max-concurrency` (does not fail default `--fail-on low`) |

## Usage

```bash
# Terminal 1: start the local 127.0.0.1 OpenAI SSE mock server with failure injection
uv run infer-bench mock --port 18081 --ttft-ms 45 --itl-ms 8 --tokens 8 \
  --stall-ms 85 --stall-at 4 --error-429-rate 0.25 --seed 7

# Terminal 2: run an open-loop benchmark with SLO gates (text output)
uv run infer-bench run --url http://127.0.0.1:18081 --model llama-3.1-8b \
  --requests 8 --rate 20 --slo-ttft-p95-ms 40 --slo-itl-p99-ms 50 --max-error-rate 0.05

# Same run with JSON output for CI pipelines
uv run infer-bench run --url http://127.0.0.1:18081 --model llama-3.1-8b \
  --requests 8 --rate 20 --slo-ttft-p95-ms 40 --slo-itl-p99-ms 50 \
  --max-error-rate 0.05 --format json

# Against a live vLLM or OpenAI-compatible server using an API key from env (never logged)
export OPENAI_API_KEY="sk-..."
uv run infer-bench run --url http://127.0.0.1:8000 --model meta-llama/Llama-3.1-8B-Instruct \
  --api-key-env OPENAI_API_KEY --requests 20 --rate 5 --poisson --slo-ttft-p95-ms 500

# Closed-loop fixed-concurrency run (explicitly labeled closed-loop)
uv run infer-bench run --url http://127.0.0.1:18081 --requests 10 --concurrency 4

# List SLO rules
uv run infer-bench rules
```

## Real Example Output (`--format table`, `COLUMNS=80`)

Captured from running `infer-bench run` against `infer-bench mock` (`--ttft-ms 45 --itl-ms 8 --tokens 8 --stall-ms 85 --stall-at 4 --error-429-rate 0.25 --seed 7`, exit code `1`):

```text
infer-bench target=http://127.0.0.1:18081/v1/chat/completions scanned=8 
findings=3 status=FAIL

CRITICAL  IB005  Endpoint/llama-3.1-8b
  location: http://127.0.0.1:18081/v1/chat/completions
  message:  Error rate=37.50% (3/8) exceeded SLO <= 5.00%. Errors: http_429=3.
  fix:      Inspect rate limits (HTTP 429), backend saturation (HTTP 
5xx/timeouts), and streaming proxy timeouts (truncated/malformed SSE).

HIGH      IB001  Endpoint/llama-3.1-8b
  location: http://127.0.0.1:18081/v1/chat/completions
  message:  TTFT p95=53.68ms exceeded SLO <= 40.00ms (p50=47.2ms, p99=54.89ms).
  fix:      Reduce prefill queue depth, tune max_num_batched_tokens / prefix 
caching, or scale inference replicas.

HIGH      IB002  Endpoint/llama-3.1-8b
  location: http://127.0.0.1:18081/v1/chat/completions
  message:  ITL p99=93.99ms exceeded SLO <= 50.00ms (p50=8.69ms, 
max_stall=94.14ms).
  fix:      Inspect KV-cache preemption, chunked prefill interference, or GPU 
memory bandwidth saturation during decode.

Summary: CRITICAL=1  HIGH=2

  mode=open-loop-fixed  model=llama-3.1-8b  duration=0.545s
  requests=8  succeeded=5  failed=3  error_rate=37.50%
  ttft:       p50=47.20ms  p95=53.68ms  p99=54.89ms  max=55.20ms
  itl:        p50=8.69ms  p95=93.37ms  p99=93.99ms  max=94.14ms
  max_stall:  94.14ms
  e2e:        p50=193.29ms  p95=198.75ms  p99=199.73ms  max=199.97ms
  throughput: 73.41 tok/s (total=40, source=usage)
  req_tps:    p50=41.39 tok/s  p95=41.73 tok/s
  errors:     http_429=3
```

## Real Example Output (`--format json`, excerpt)

```json
{
  "tool": "infer-bench",
  "target": "http://127.0.0.1:18081/v1/chat/completions",
  "summary": {
    "documents_scanned": 8,
    "total_findings": 3,
    "by_severity": {
      "CRITICAL": 1,
      "HIGH": 2,
      "MEDIUM": 0,
      "LOW": 0,
      "INFO": 0
    }
  },
  "passed": false,
  "metrics": {
    "mode": "open-loop-fixed",
    "model": "llama-3.1-8b",
    "duration_s": 0.547,
    "total_requests": 8,
    "succeeded": 5,
    "failed": 3,
    "error_rate": 0.375,
    "errors_by_class": { "http_429": 3 },
    "total_output_tokens": 40,
    "token_count_label": "usage",
    "aggregate_tokens_per_sec": 73.08,
    "per_request_tps_p50": 41.24,
    "per_request_tps_p95": 41.44,
    "ttft": { "count": 5, "p50_ms": 47.5, "p95_ms": 51.06, "p99_ms": 51.46, "max_ms": 51.56 },
    "itl": { "count": 35, "p50_ms": 8.72, "p95_ms": 93.7, "p99_ms": 94.12, "max_ms": 94.13 },
    "max_stall_ms": 94.13,
    "e2e": { "count": 5, "p50_ms": 194.0, "p95_ms": 196.43, "p99_ms": 196.43, "max_ms": 196.43 },
    "schedule": { "delayed_sends": 0, "max_send_delay_ms": 10.52, "p95_send_delay_ms": 7.21, "cap_saturated": false }
  }
}
```

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Benchmark completed and no findings met or exceeded `--fail-on` |
| `1` | One or more SLO findings met or exceeded `--fail-on` |
| `2` | Invalid CLI flags, URL, missing `--api-key-env` variable, or non-loopback mock bind attempt |

## Limitations

- **Chunk count != token count**: When a server does not honor `stream_options.include_usage`, `infer-bench` counts non-empty SSE content deltas and labels throughput as `chunks, approximate`. Providers and proxies may batch multiple tokens into a single SSE chunk or emit multi-chunk UTF-8 fragments.
- **Client-side timing includes network and proxy overhead**: TTFT, ITL, and E2E are measured at the client socket (`time.perf_counter()`), so DNS, TLS handshake, load-balancer buffering, and client event-loop scheduling are included alongside model prefill/decode latency.
- **Mock server is not a real model**: `infer-bench mock` (bound strictly to `127.0.0.1`) replays synthetic sleeps and deterministic fault injection to verify client accounting, SSE error handling, and SLO gates — it does not simulate KV-cache memory pressure, continuous batching, or prompt-length scaling.
- **Fixed prompt**: Sends one configured prompt per run rather than sampling a variable-length prompt distribution (realistic prefill/decode mixes require pairing with a corpus harness).
