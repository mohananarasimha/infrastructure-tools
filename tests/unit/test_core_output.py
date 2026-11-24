"""Unit tests for shared core models and non-truncating report output."""

from __future__ import annotations

from rich.console import Console

from infra_tools.core.models import Finding, OutputFormat, Severity, ToolReport
from infra_tools.core.output import render_report


def test_empty_report_uses_generic_scanned_and_no_findings_wording() -> None:
    report = ToolReport.from_findings(
        tool="k8s-triage",
        target="live/default",
        documents_scanned=4,
        findings=[],
    )
    console = Console(width=80, record=True, force_terminal=False)
    render_report(report, OutputFormat.TABLE, console=console)
    rendered = console.export_text()

    assert "scanned=4" in rendered
    assert "documents=" not in rendered
    assert "No findings." in rendered
    assert "No policy violations found." not in rendered
    assert "PASS" in rendered


def test_block_output_does_not_truncate_at_80_columns_and_sorts_deterministically() -> None:
    long_resource = "Deployment/production-payments-us-east-1/payments-settlement-processor-api"
    long_location = "manifests/services/payments/overlays/production/deployment-settlement.yaml:142"
    long_message = (
        "container 'payments-api' is missing securityContext hardening: "
        "runAsNonRoot: true, allowPrivilegeEscalation: false, capabilities.drop: [ALL]."
    )
    findings = [
        Finding(
            rule_id="KG008",
            severity=Severity.LOW,
            resource="Deployment/prod/z-service",
            location="b.yaml:10",
            message="container 'app' is missing readOnlyRootFilesystem: true.",
            remediation="Set securityContext.readOnlyRootFilesystem: true.",
        ),
        Finding(
            rule_id="KG002",
            severity=Severity.HIGH,
            resource="Deployment/prod/b-service",
            location="a.yaml:5",
            message="missing cpu/memory limits",
            remediation="Add requests and limits.",
        ),
        Finding(
            rule_id="KG002",
            severity=Severity.HIGH,
            resource="Deployment/prod/a-service",
            location="z.yaml:99",
            message="missing cpu/memory limits",
            remediation="Add requests and limits.",
        ),
        Finding(
            rule_id="KG001",
            severity=Severity.HIGH,
            resource=long_resource,
            location=long_location,
            message=long_message,
            remediation="Pin image tag and drop [ALL] capabilities.",
        ),
    ]

    report = ToolReport.from_findings(
        tool="k8s-guard",
        target="manifests/",
        documents_scanned=3,
        findings=findings,
    )

    # Verify sort order: severity desc, then rule_id asc, then resource asc.
    assert [(f.severity, f.rule_id, f.resource) for f in report.findings] == [
        (Severity.HIGH, "KG001", long_resource),
        (Severity.HIGH, "KG002", "Deployment/prod/a-service"),
        (Severity.HIGH, "KG002", "Deployment/prod/b-service"),
        (Severity.LOW, "KG008", "Deployment/prod/z-service"),
    ]

    console = Console(width=80, record=True, force_terminal=False)
    render_report(report, OutputFormat.TABLE, console=console)
    rendered = console.export_text()

    assert "…" not in rendered
    # Join wrapped lines without newlines for checking unbroken long tokens.
    collapsed = rendered.replace("\n", "")
    assert long_resource in collapsed
    assert long_location in collapsed
    assert "[ALL]" in rendered
    assert "location:" in rendered
    assert "message:" in rendered
    assert "fix:" in rendered
    assert "Summary: HIGH=3  LOW=1" in rendered
