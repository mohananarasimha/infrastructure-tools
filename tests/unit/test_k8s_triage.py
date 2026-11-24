"""Unit tests for k8s-triage models, collector, analyzer, and CLI."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

from kubernetes.client.exceptions import ApiException
from kubernetes.config.config_exception import ConfigException
from typer.testing import CliRunner

from infra_tools.cli import app as root_app
from infra_tools.core.models import ExitCode, Severity, ToolReport
from infra_tools.k8s_triage.analyzer import RULE_CATALOG, analyze_snapshot
from infra_tools.k8s_triage.cli import app as triage_app
from infra_tools.k8s_triage.collector import collect_live_snapshot
from infra_tools.k8s_triage.models import (
    ClusterSnapshot,
    ContainerStateSnapshot,
    EventSnapshot,
    PodConditionSnapshot,
    PodSnapshot,
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "k8s_triage"
runner = CliRunner()


def test_healthy_cluster_fixture_passes() -> None:
    fixture = FIXTURES_DIR / "healthy_cluster.json"
    result = runner.invoke(triage_app, ["inspect", "--fixture", str(fixture), "--format", "json"])
    assert result.exit_code == ExitCode.OK

    report = ToolReport.model_validate_json(result.stdout)
    assert report.tool == "k8s-triage"
    assert report.passed is True
    assert report.summary.documents_scanned == 4  # 2 pods + 2 nodes
    assert report.summary.total_findings == 0
    assert report.findings == []


def test_oom_and_crashloop_fixture_triggers_kt001_kt002_kt008() -> None:
    fixture = FIXTURES_DIR / "oom_and_crashloop.json"
    result = runner.invoke(triage_app, ["inspect", "--fixture", str(fixture), "--format", "json"])
    assert result.exit_code == ExitCode.FINDINGS

    report = ToolReport.model_validate_json(result.stdout)
    assert report.passed is False
    found_ids = {f.rule_id for f in report.findings}
    assert found_ids == {"KT001", "KT002", "KT008"}

    kt001 = next(f for f in report.findings if f.rule_id == "KT001")
    assert kt001.severity == Severity.CRITICAL
    assert "512Mi" in kt001.message
    assert "Back-off" in kt001.message

    kt002 = next(f for f in report.findings if f.rule_id == "KT002")
    assert kt002.severity == Severity.HIGH
    assert "last_reason=OOMKilled" in kt002.message
    assert "last_exit_code=137" in kt002.message

    # KT008 fires for both CrashLoopBackOff container (6 restarts) and Running proxy (4 restarts).
    kt008_list = [f for f in report.findings if f.rule_id == "KT008"]
    assert len(kt008_list) == 2
    assert any("cache-proxy" in f.resource and "state=running" in f.message for f in kt008_list)


def test_unschedulable_gpu_imagepull_and_probe_fixture() -> None:
    fixture = FIXTURES_DIR / "unschedulable_gpu_and_probe.json"
    result = runner.invoke(triage_app, ["inspect", "--fixture", str(fixture), "--format", "json"])
    assert result.exit_code == ExitCode.FINDINGS

    report = ToolReport.model_validate_json(result.stdout)
    found_ids = {f.rule_id for f in report.findings}
    assert found_ids == {"KT003", "KT005", "KT006"}

    kt005 = next(f for f in report.findings if f.rule_id == "KT005")
    assert kt005.severity == Severity.HIGH
    assert "insufficient GPU capacity" in kt005.message
    assert "node taint/toleration mismatch" in kt005.message

    kt003 = next(f for f in report.findings if f.rule_id == "KT003")
    assert kt003.severity == Severity.HIGH
    assert "ghcr.io/example-org/model-loader:9.9.9" in kt003.message
    assert "manifest unknown" in kt003.message

    kt006 = next(f for f in report.findings if f.rule_id == "KT006")
    assert kt006.severity == Severity.MEDIUM
    assert "readiness" in kt006.message
    assert "5 Unhealthy" in kt006.message
    assert "503" in kt006.message


def test_node_pressure_fixture_correlates_affected_pods() -> None:
    fixture = FIXTURES_DIR / "node_pressure.json"
    result = runner.invoke(triage_app, ["inspect", "--fixture", str(fixture), "--format", "json"])
    assert result.exit_code == ExitCode.FINDINGS

    report = ToolReport.model_validate_json(result.stdout)
    assert all(f.rule_id == "KT007" for f in report.findings)
    assert len(report.findings) == 3

    ready_finding = next(f for f in report.findings if f.location == "node/Ready")
    assert ready_finding.severity == Severity.CRITICAL
    assert "ml-serving/vllm-0" in ready_finding.message
    assert "production/batch-worker-1" in ready_finding.message

    mem_finding = next(f for f in report.findings if f.location == "node/MemoryPressure")
    assert mem_finding.severity == Severity.HIGH
    assert "ml-serving/vllm-0" in mem_finding.message

    disk_finding = next(f for f in report.findings if f.location == "node/DiskPressure")
    assert disk_finding.severity == Severity.HIGH
    assert "observability/log-shipper-0" in disk_finding.message


def test_kt004_create_container_config_error_and_kt005_cpu_affinity() -> None:
    snapshot = ClusterSnapshot(
        source="unit-test",
        pods=[
            PodSnapshot(
                name="payments-0",
                namespace="core",
                phase="Pending",
                containers=[
                    ContainerStateSnapshot(
                        name="app",
                        image="ghcr.io/example-org/payments:1.0.0",
                        state="waiting",
                        state_reason="CreateContainerConfigError",
                        state_message='secret "payments-db-creds" not found',
                    )
                ],
            ),
            PodSnapshot(
                name="analytics-worker-0",
                namespace="data",
                phase="Pending",
                conditions=[
                    PodConditionSnapshot(
                        type="PodScheduled",
                        status="False",
                        reason="Unschedulable",
                        message=(
                            "0/4 nodes are available: 2 Insufficient cpu, "
                            "2 node(s) didn't match Pod's node affinity/selector."
                        ),
                    )
                ],
            ),
        ],
        events=[
            EventSnapshot(
                namespace="core",
                involved_kind="Pod",
                involved_name="payments-0",
                event_type="Warning",
                reason="Failed",
                message='Error: secret "payments-db-creds" not found',
                count=2,
            )
        ],
    )

    findings = analyze_snapshot(snapshot)
    by_rule = {f.rule_id: f for f in findings}
    assert set(by_rule) == {"KT004", "KT005"}
    assert by_rule["KT004"].severity == Severity.HIGH
    assert "payments-db-creds" in by_rule["KT004"].message
    assert "insufficient CPU/memory capacity" in by_rule["KT005"].message
    assert "nodeSelector/affinity mismatch" in by_rule["KT005"].message


def test_malformed_missing_and_invalid_schema_fixtures_exit_2(tmp_path: Path) -> None:
    malformed = FIXTURES_DIR / "malformed.json"
    res_malformed = runner.invoke(triage_app, ["inspect", "--fixture", str(malformed)])
    assert res_malformed.exit_code == ExitCode.ERROR
    assert "Traceback" not in res_malformed.output
    assert "Invalid JSON" in res_malformed.output

    missing = tmp_path / "missing.json"
    res_missing = runner.invoke(triage_app, ["inspect", "--fixture", str(missing)])
    assert res_missing.exit_code == ExitCode.ERROR
    assert "does not exist" in res_missing.output

    bad_schema = tmp_path / "bad_schema.json"
    bad_schema.write_text(json.dumps({"pods": "not-a-list"}), encoding="utf-8")
    res_schema = runner.invoke(triage_app, ["inspect", "--fixture", str(bad_schema)])
    assert res_schema.exit_code == ExitCode.ERROR
    assert "Invalid ClusterSnapshot schema" in res_schema.output


def test_fail_on_threshold_and_namespace_flag_validation() -> None:
    fixture = FIXTURES_DIR / "unschedulable_gpu_and_probe.json"
    # Contains HIGH and MEDIUM findings, zero CRITICAL.
    res_crit = runner.invoke(
        triage_app,
        ["inspect", "--fixture", str(fixture), "--fail-on", "critical", "--format", "json"],
    )
    assert res_crit.exit_code == ExitCode.OK
    report = ToolReport.model_validate_json(res_crit.stdout)
    assert report.passed is True
    assert report.summary.total_findings == 3

    res_high = runner.invoke(
        triage_app,
        ["inspect", "--fixture", str(fixture), "--fail-on", "high", "--format", "json"],
    )
    assert res_high.exit_code == ExitCode.FINDINGS

    # Mutually exclusive flags exit 2.
    res_conflict = runner.invoke(
        triage_app, ["inspect", "--namespace", "prod", "--all-namespaces"]
    )
    assert res_conflict.exit_code == ExitCode.ERROR
    assert "Cannot specify both" in res_conflict.output


def test_live_collector_error_handling_and_translation() -> None:
    # 1. ApiException during pod listing -> exit 2 without traceback or secret leakage.
    mock_api = MagicMock()
    mock_api.list_namespaced_pod.side_effect = ApiException(status=401, reason="Unauthorized")
    with (
        patch("infra_tools.k8s_triage.collector.config.load_kube_config"),
        patch("infra_tools.k8s_triage.collector.client.CoreV1Api", return_value=mock_api),
    ):
        res_api_err = runner.invoke(triage_app, ["inspect", "--namespace", "default"])
    assert res_api_err.exit_code == ExitCode.ERROR
    assert "Traceback" not in res_api_err.output
    assert "HTTP 401" in res_api_err.output

    # 2. Missing kubeconfig / unreachable config -> exit 2 cleanly.
    with (
        patch(
            "infra_tools.k8s_triage.collector.config.load_kube_config",
            side_effect=ConfigException("no kubeconfig"),
        ),
        patch(
            "infra_tools.k8s_triage.collector.config.load_incluster_config",
            side_effect=ConfigException("not in cluster"),
        ),
    ):
        res_cfg = runner.invoke(triage_app, ["inspect"])
    assert res_cfg.exit_code == ExitCode.ERROR
    assert "Unable to load Kubernetes configuration" in res_cfg.output

    # 3. Successful live collection + RBAC 403 graceful degradation on list_node.
    mock_pod: Any = SimpleNamespace(
        metadata=SimpleNamespace(name="oom-pod", namespace="default"),
        spec=SimpleNamespace(
            node_name="node-1",
            containers=[
                SimpleNamespace(
                    name="app",
                    resources=SimpleNamespace(limits={"memory": "256Mi", "cpu": "500m"}),
                )
            ],
            init_containers=[],
        ),
        status=SimpleNamespace(
            phase="Running",
            conditions=[
                SimpleNamespace(
                    type="Ready", status="False", reason="ContainersNotReady", message=None
                )
            ],
            init_container_statuses=[],
            container_statuses=[
                SimpleNamespace(
                    name="app",
                    image="ghcr.io/example/app:1.0.0",
                    ready=False,
                    restart_count=2,
                    state=SimpleNamespace(
                        running=None,
                        waiting=SimpleNamespace(reason="CrashLoopBackOff", message="backing off"),
                        terminated=None,
                    ),
                    last_state=SimpleNamespace(
                        terminated=SimpleNamespace(reason="OOMKilled", message=None, exit_code=137)
                    ),
                )
            ],
        ),
    )
    mock_v1 = MagicMock()
    mock_v1.list_namespaced_pod.return_value = SimpleNamespace(items=[mock_pod])
    mock_v1.list_namespaced_event.return_value = SimpleNamespace(items=[])
    mock_v1.list_node.side_effect = ApiException(status=403, reason="Forbidden")

    with (
        patch("infra_tools.k8s_triage.collector.config.load_kube_config"),
        patch("infra_tools.k8s_triage.collector.client.CoreV1Api", return_value=mock_v1),
    ):
        snapshot = collect_live_snapshot(namespace="default", context="kind-dev")

    assert snapshot.source == "live:kind-dev"
    assert snapshot.nodes == []
    findings = analyze_snapshot(snapshot)
    assert {f.rule_id for f in findings} == {"KT001", "KT002"}


def test_rules_subcommand_table_output_and_root_dispatcher() -> None:
    fixture = FIXTURES_DIR / "oom_and_crashloop.json"
    res_table = runner.invoke(
        triage_app, ["inspect", "--fixture", str(fixture), "--format", "table"]
    )
    assert res_table.exit_code == ExitCode.FINDINGS
    assert "KT001" in res_table.stdout
    assert "FAIL" in res_table.stdout

    res_rules_table = runner.invoke(triage_app, ["rules"])
    assert res_rules_table.exit_code == ExitCode.OK
    assert "KT001" in res_rules_table.stdout
    assert "KT008" in res_rules_table.stdout

    res_rules_json = runner.invoke(triage_app, ["rules", "--format", "json"])
    assert res_rules_json.exit_code == ExitCode.OK
    payload = json.loads(res_rules_json.stdout)
    assert [r["rule_id"] for r in payload] == [r.rule_id for r in RULE_CATALOG]

    res_root = runner.invoke(
        root_app,
        [
            "k8s-triage",
            "inspect",
            "--fixture",
            str(FIXTURES_DIR / "healthy_cluster.json"),
            "--format",
            "json",
        ],
    )
    assert res_root.exit_code == ExitCode.OK
    assert ToolReport.model_validate_json(res_root.stdout).passed is True
