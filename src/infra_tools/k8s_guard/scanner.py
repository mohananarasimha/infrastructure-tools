"""High-level scanner orchestration for k8s-guard."""

from __future__ import annotations

from infra_tools.core.models import Severity, ToolReport
from infra_tools.k8s_guard.loader import load_manifests
from infra_tools.k8s_guard.rules import evaluate_documents


def scan_target(
    target: str,
    *,
    fail_on: Severity = Severity.LOW,
    ignore_rules: set[str] | None = None,
    stdin_text: str | None = None,
) -> ToolReport:
    """Load manifests from ``target``, evaluate guardrails, and return a ``ToolReport``."""
    documents = load_manifests(target, stdin_text=stdin_text)
    findings = evaluate_documents(documents, ignore_rules=ignore_rules)
    return ToolReport.from_findings(
        tool="k8s-guard",
        target="<stdin>" if target == "-" else target,
        documents_scanned=len(documents),
        findings=findings,
        fail_on=fail_on,
    )
