# Security Policy

## Scope and Operational Guarantees

Utilities in `infrastructure-tools` follow strict read-only and static-analysis defaults:

- **`k8s-guard`**: Pure static analysis of local YAML files or stdin. Makes zero network calls and parses YAML exclusively with `yaml.SafeLoader` (never `yaml.load` or unsafe constructors).
- **Planned live-inspection tools (`k8s-triage`, `pg-diag`, `infer-bench`)**: Read-only cluster/database queries and explicit operator-targeted HTTP requests only; never mutate Kubernetes resources, database state, or cluster configuration.

## Credential and Secret Handling Rules

- Never commit `.env` files, kubeconfigs, TLS private keys (`*.pem`, `*.key`), API keys, or database credentials.
- Never log, echo, or embed secrets, bearer tokens, kubeconfig credentials, or PostgreSQL DSN passwords in terminal output, JSON reports, or error messages.
- Sensitive values must be supplied via environment variables or standard client credential stores at runtime and redacted before any diagnostic output is emitted.

## Supported Versions

Only the latest commit on `main` is actively maintained.

## Reporting a Vulnerability

If you discover a security vulnerability in this repository:

1. Do **not** open a public GitHub issue with exploit details.
2. Use GitHub Private Vulnerability Reporting on `mohananarasimha/infrastructure-tools` (Security -> Advisories -> Report a vulnerability) or contact the repository maintainer directly.
3. Include a minimal reproduction, affected tool/version, and expected vs. actual behavior.

You can expect an initial acknowledgment within 72 hours and a coordinated fix timeline based on severity.
