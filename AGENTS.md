# AGENTS.md

Instructions for coding agents working in `infrastructure-tools`.

## Project Scope

This repository implements four standalone Python CLI utilities inside one `uv`-managed package (`src/infra_tools/`):

- `k8s-guard` (Complete): Static K8s manifest reliability, security, and GPU-hygiene linter.
- `k8s-triage` (Planned): K8s pod, event, probe, and node-condition root-cause correlator.
- `infer-bench` (Planned): Async streaming TTFT/ITL/throughput and reliability analyzer for OpenAI-compatible/vLLM endpoints.
- `pg-diag` (Planned): Read-only PostgreSQL lock-tree, pool-saturation, and idle-in-transaction diagnostics.

## Architecture & Conventions

- **Package manager**: `uv` with `hatchling` build backend (`pyproject.toml`, Python 3.11+).
- **Shared core** (`src/infra_tools/core/`):
  - `models.py`: `Severity`, `ExitCode`, `OutputFormat`, `Finding`, `ReportSummary`, `ToolReport`.
  - `output.py`: Deterministic JSON serialization and Rich table formatting.
- **Exit-code contract**:
  - `0`: Healthy / checks passed.
  - `1`: Policy findings or SLO threshold breaches.
  - `2`: Input, parse, or connectivity/runtime error (formatted error on stderr, no raw traceback).
- **Entrypoints**: Individual tool scripts (e.g., `k8s-guard`) plus unified `infra-tools` dispatcher (`src/infra_tools/cli.py`).

## Mandatory Checks

Every change must pass:

1. `uv run ruff check .` (includes security rules `S`)
2. `uv run mypy src` (strict mode)
3. `uv run pytest -v`

## Security & Clean-Room Rules

- Clean-room personal implementation only; no company or employer references.
- Use `yaml.SafeLoader` exclusively; never call `yaml.load` or execute untrusted input.
- Never log or output secrets, tokens, kubeconfig credentials, or DSN passwords.
- Never commit `.env*`, `*.pem`, `*.key`, or `kubeconfig*`.
