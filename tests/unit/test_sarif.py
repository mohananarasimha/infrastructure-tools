"""Unit tests for SARIF 2.1.0 output from k8s-guard and pg-diag."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from infra_tools.core.models import ExitCode, Finding, Severity, ToolReport
from infra_tools.core.sarif import build_sarif
from infra_tools.k8s_guard.cli import app as guard_app
from infra_tools.k8s_guard.rules import RULE_CATALOG as GUARD_RULES
from infra_tools.pg_diag.analyzer import RULE_CATALOG as PG_RULES
from infra_tools.pg_diag.cli import app as pg_app
from infra_tools.pg_diag.models import LockWait, PgSnapshot, ServerSettings, SessionSnapshot

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "k8s_guard"
runner = CliRunner()


def _run(doc: dict[str, Any]) -> dict[str, Any]:
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    assert len(doc["runs"]) == 1
    run: dict[str, Any] = doc["runs"][0]
    return run


def test_k8s_guard_sarif_maps_findings_to_file_lines_and_rule_indexes() -> None:
    target = FIXTURES / "broken_workload.yaml"
    json_out = runner.invoke(guard_app, ["scan", str(target), "--format", "json"])
    report = ToolReport.model_validate_json(json_out.stdout)

    result = runner.invoke(guard_app, ["scan", str(target), "--format", "sarif"])
    assert result.exit_code == ExitCode.FINDINGS
    assert result.stderr == ""
    run = _run(json.loads(result.stdout))

    rules = run["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == [r.rule_id for r in GUARD_RULES]
    assert run["tool"]["driver"]["name"] == "k8s-guard"
    assert run["automationDetails"]["id"] == "k8s-guard/"

    results = run["results"]
    assert len(results) == report.summary.total_findings > 0
    for finding, res in zip(report.findings, results, strict=True):
        assert res["ruleId"] == finding.rule_id
        assert rules[res["ruleIndex"]]["id"] == finding.rule_id
        physical = res["locations"][0]["physicalLocation"]
        path, line = finding.location.rsplit(":", 1)
        assert physical["artifactLocation"]["uri"] == path
        assert physical["region"]["startLine"] == int(line)
        assert finding.remediation in res["message"]["text"]
        assert "partialFingerprints" not in res


def test_severity_to_level_mapping() -> None:
    findings = [
        Finding(
            rule_id=rule_id,
            severity=sev,
            resource=f"Deployment/default/{sev.value.lower()}",
            location="deploy.yaml:3",
            message="m.",
            remediation="r.",
        )
        for rule_id, sev in (
            ("KG005", Severity.CRITICAL),
            ("KG001", Severity.HIGH),
            ("KG003", Severity.MEDIUM),
            ("KG008", Severity.LOW),
        )
    ]
    report = ToolReport.from_findings(
        tool="k8s-guard", target="deploy.yaml", documents_scanned=1, findings=findings
    )
    levels = {
        r["properties"]["severity"]: r["level"]
        for r in build_sarif(report, GUARD_RULES).document["runs"][0]["results"]
    }
    assert levels == {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}


def test_clean_scan_emits_empty_results_and_exit_0() -> None:
    result = runner.invoke(
        guard_app, ["scan", str(FIXTURES / "hardened_deployment.yaml"), "--format", "sarif"]
    )
    assert result.exit_code == ExitCode.OK
    assert _run(json.loads(result.stdout))["results"] == []


def test_stdin_scan_has_no_file_location_and_warns() -> None:
    manifest = (FIXTURES / "broken_workload.yaml").read_text(encoding="utf-8")
    result = runner.invoke(guard_app, ["scan", "-", "--format", "sarif"], input=manifest)
    assert result.exit_code == ExitCode.FINDINGS
    results = _run(json.loads(result.stdout))["results"]
    assert results
    assert all("physicalLocation" not in r["locations"][0] for r in results)
    assert f"{len(results)} SARIF result(s) have no file location" in result.stderr


def test_unknown_rule_id_is_rejected() -> None:
    report = ToolReport.from_findings(
        tool="k8s-guard",
        target="x",
        documents_scanned=1,
        findings=[
            Finding(
                rule_id="KG999",
                severity=Severity.LOW,
                resource="r",
                location="x.yaml:1",
                message="m.",
                remediation="r.",
            )
        ],
    )
    with pytest.raises(ValueError, match="KG999"):
        build_sarif(report, GUARD_RULES)


def _lock_chain_snapshot() -> PgSnapshot:
    def session(pid: int, **kw: Any) -> SessionSnapshot:
        base: dict[str, Any] = {"pid": pid, "usename": "app", "datname": "shop", "state": "active"}
        base.update(kw)
        return SessionSnapshot(**base)

    return PgSnapshot(
        source="db.internal:5432",
        collected_at="2026-01-01 00:00:00+00",
        settings=ServerSettings(
            server_version="18.1", max_connections=100, superuser_reserved_connections=3
        ),
        sessions=[
            session(10, state="idle in transaction", state_age_s=120.0, xact_age_s=125.0),
            session(11, query_age_s=4.0, blocked_by=[10], wait_event_type="Lock"),
            session(20, state="idle in transaction", state_age_s=90.0, xact_age_s=95.0),
        ],
        lock_waits=[
            LockWait(pid=11, locktype="transactionid", mode="ShareLock", transactionid="777")
        ],
    )


def test_pg_diag_fixture_results_anchor_to_fixture_with_distinct_fingerprints(
    tmp_path: Path,
) -> None:
    path = tmp_path / "incident.json"
    path.write_text(_lock_chain_snapshot().model_dump_json(), encoding="utf-8")

    result = runner.invoke(pg_app, ["inspect", "--fixture", str(path), "--format", "sarif"])
    assert result.exit_code == ExitCode.FINDINGS
    assert result.stderr == ""
    run = _run(json.loads(result.stdout))
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == [r.rule_id for r in PG_RULES]

    results = run["results"]
    assert {r["ruleId"] for r in results} >= {"PG001", "PG002"}
    for res in results:
        physical = res["locations"][0]["physicalLocation"]
        assert physical["artifactLocation"]["uri"] == path.as_posix()
        assert physical["region"]["startLine"] == 1
    hashes = [r["partialFingerprints"]["primaryLocationLineHash"] for r in results]
    assert len(set(hashes)) == len(hashes)


def test_pg_diag_sarif_artifact_overrides_fixture(tmp_path: Path) -> None:
    path = tmp_path / "incident.json"
    path.write_text(_lock_chain_snapshot().model_dump_json(), encoding="utf-8")
    result = runner.invoke(
        pg_app,
        [
            "inspect",
            "--fixture",
            str(path),
            "--format",
            "sarif",
            "--sarif-artifact",
            "db/README.md",
        ],
    )
    uris = {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in _run(json.loads(result.stdout))["results"]
    }
    assert uris == {"db/README.md"}


def test_pg_diag_host_port_location_is_not_read_as_file_line() -> None:
    finding = Finding(
        rule_id="PG003",
        severity=Severity.HIGH,
        resource="max_connections",
        location="db.internal:5432",
        message="m.",
        remediation="r.",
    )
    report = ToolReport.from_findings(
        tool="pg-diag", target="db.internal:5432", documents_scanned=1, findings=[finding]
    )
    sarif = build_sarif(report, PG_RULES, file_locations=False)
    location = sarif.document["runs"][0]["results"][0]["locations"][0]
    assert "physicalLocation" not in location
    assert location["logicalLocations"][0]["fullyQualifiedName"] == "max_connections"
    assert sarif.unlocated == 1
