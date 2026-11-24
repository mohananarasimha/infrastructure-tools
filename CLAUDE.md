# CLAUDE.md

## Repository Charter

`infrastructure-tools` is a single Python package providing four focused, locally testable CLI utilities for Kubernetes/SRE, data-infrastructure, and AI-inference reliability workflows.

### Four-Tool Roadmap

1. **`k8s-guard`** *(Complete)* — Static Kubernetes manifest reliability, security, and GPU-hygiene linter with file/line diagnostics and stdin (`helm template`) support.
2. **`k8s-triage`** *(Complete)* — Kubernetes pod/event/probe/node-pressure failure correlator with offline `--fixture` replay and `kind` integration testing.
3. **`infer-bench`** *(Planned)* — Async SSE streaming latency (TTFT, ITL), throughput, and timeout/error-rate analyzer for OpenAI-compatible/vLLM inference endpoints with SLO gates.
4. **`pg-diag`** *(Planned)* — Read-only PostgreSQL blocking lock-tree, connection-pool saturation, and `idle in transaction` diagnostic tool.

## Shared CLI, Output, and Exit-Code Contract

All utilities under `src/infra_tools/` share primitives from `src/infra_tools/core/`:

- **Output formats**: `--format table|json`
  - `table`: Rich formatted terminal table for human operators.
  - `json`: Deterministic `ToolReport.model_dump_json(indent=2)` written directly to stdout without ANSI codes or line wrapping.
- **Exit codes** (`ExitCode`):
  - `0` (`OK`): Passed / no findings at or above the configured failure threshold.
  - `1` (`FINDINGS`): Findings or SLO violations met/exceeded the failure threshold.
  - `2` (`ERROR`): Invalid arguments, missing files, parse failures, or runtime/connectivity errors (never raw Python tracebacks).

## Verification Gates

Run all three gates before considering any change complete:

```bash
uv run ruff check .
uv run mypy src
uv run pytest -v
```

## Clean-Room & Security Boundaries

- Clean-room personal code only. Zero employer, client, or internal system references.
- Never commit secrets, `.env*`, `*.pem`, `*.key`, or `kubeconfig*`.
- Never use unsafe YAML loading (`yaml.load`) or unvalidated shell execution.
- Never log or serialize secret values, API keys, or database passwords in reports or error messages.
