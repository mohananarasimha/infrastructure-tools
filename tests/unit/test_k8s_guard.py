"""Unit tests for k8s-guard loader, rules, scanner, and CLI."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from infra_tools.cli import app as root_app
from infra_tools.core.models import ExitCode, Severity, ToolReport
from infra_tools.k8s_guard.cli import app as guard_app
from infra_tools.k8s_guard.loader import parse_yaml_stream
from infra_tools.k8s_guard.rules import RULE_CATALOG, evaluate_documents
from infra_tools.k8s_guard.scanner import scan_target

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "k8s_guard"
runner = CliRunner()


def test_hardened_deployment_passes() -> None:
    fixture = FIXTURES_DIR / "hardened_deployment.yaml"
    result = runner.invoke(guard_app, ["scan", str(fixture), "--format", "json"])
    assert result.exit_code == ExitCode.OK

    report = ToolReport.model_validate_json(result.stdout)
    assert report.tool == "k8s-guard"
    assert report.passed is True
    assert report.summary.documents_scanned == 2
    assert report.summary.total_findings == 0
    assert report.findings == []


def test_broken_workload_triggers_expected_rules_and_line_numbers() -> None:
    fixture = FIXTURES_DIR / "broken_workload.yaml"
    result = runner.invoke(guard_app, ["scan", str(fixture), "--format", "json"])
    assert result.exit_code == ExitCode.FINDINGS

    report = ToolReport.model_validate_json(result.stdout)
    assert report.passed is False
    found_ids = {f.rule_id for f in report.findings}
    assert found_ids == {"KG001", "KG002", "KG003", "KG004", "KG005", "KG006", "KG008"}

    # KG005 should report both CRITICAL (privileged: true) and HIGH (missing hardening).
    kg005_severities = {f.severity for f in report.findings if f.rule_id == "KG005"}
    assert kg005_severities == {Severity.CRITICAL, Severity.HIGH}

    # Verify accurate 1-indexed line tracking on image and privileged fields.
    kg001 = next(f for f in report.findings if f.rule_id == "KG001")
    assert kg001.location.endswith(":18")
    kg005_crit = next(
        f for f in report.findings if f.rule_id == "KG005" and f.severity == Severity.CRITICAL
    )
    assert kg005_crit.location.endswith(":20")


def test_gpu_workload_broken_triggers_kg007_high_and_medium() -> None:
    fixture = FIXTURES_DIR / "gpu_workload_broken.yaml"
    result = runner.invoke(guard_app, ["scan", str(fixture), "--format", "json"])
    assert result.exit_code == ExitCode.FINDINGS

    report = ToolReport.model_validate_json(result.stdout)
    assert report.passed is False
    kg007_findings = [f for f in report.findings if f.rule_id == "KG007"]
    assert {f.severity for f in kg007_findings} == {Severity.HIGH, Severity.MEDIUM}
    assert any("!=" in f.message for f in kg007_findings)
    assert any("tolerations" in f.message for f in kg007_findings)


def test_gpu_workload_hardened_passes() -> None:
    manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vllm-ready
  namespace: ml
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vllm-ready
  template:
    metadata:
      labels:
        app: vllm-ready
    spec:
      securityContext:
        runAsNonRoot: true
      tolerations:
        - key: nvidia.com/gpu
          operator: Exists
          effect: NoSchedule
      nodeSelector:
        accelerator: nvidia-l4
      containers:
        - name: vllm
          image: vllm/vllm-openai:v0.6.4
          resources:
            requests:
              cpu: "4"
              memory: "16Gi"
              nvidia.com/gpu: "1"
            limits:
              cpu: "8"
              memory: "32Gi"
              nvidia.com/gpu: "1"
          readinessProbe:
            httpGet:
              path: /health
              port: 8000
          livenessProbe:
            httpGet:
              path: /health
              port: 8000
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
"""
    docs = parse_yaml_stream(manifest, source="gpu-ok.yaml")
    findings = evaluate_documents(docs)
    assert findings == []


def test_malformed_yaml_exits_2_without_traceback() -> None:
    fixture = FIXTURES_DIR / "malformed.yaml"
    result = runner.invoke(guard_app, ["scan", str(fixture)])
    assert result.exit_code == ExitCode.ERROR
    assert "Traceback" not in result.output
    assert "invalid YAML" in result.output


def test_missing_path_and_non_mapping_document_exit_2(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.yaml"
    res_missing = runner.invoke(guard_app, ["scan", str(missing)])
    assert res_missing.exit_code == ExitCode.ERROR
    assert "does not exist" in res_missing.output

    non_mapping = tmp_path / "list.yaml"
    non_mapping.write_text("- item-a\n- item-b\n", encoding="utf-8")
    res_non_map = runner.invoke(guard_app, ["scan", str(non_mapping)])
    assert res_non_map.exit_code == ExitCode.ERROR
    assert "mapping document" in res_non_map.output


def test_stdin_piping_reports_stdin_locations() -> None:
    raw = (FIXTURES_DIR / "broken_workload.yaml").read_text(encoding="utf-8")
    result = runner.invoke(guard_app, ["scan", "-", "--format", "json"], input=raw)
    assert result.exit_code == ExitCode.FINDINGS

    report = ToolReport.model_validate_json(result.stdout)
    assert report.target == "<stdin>"
    assert all(f.location.startswith("<stdin>:") for f in report.findings)


def test_fail_on_severity_threshold() -> None:
    fixture = FIXTURES_DIR / "gpu_workload_broken.yaml"
    # gpu_workload_broken has HIGH and MEDIUM findings, no CRITICAL.
    res_crit = runner.invoke(
        guard_app, ["scan", str(fixture), "--fail-on", "critical", "--format", "json"]
    )
    assert res_crit.exit_code == ExitCode.OK
    report_crit = ToolReport.model_validate_json(res_crit.stdout)
    assert report_crit.passed is True
    assert report_crit.summary.total_findings == 2

    res_high = runner.invoke(
        guard_app, ["scan", str(fixture), "--fail-on", "high", "--format", "json"]
    )
    assert res_high.exit_code == ExitCode.FINDINGS
    report_high = ToolReport.model_validate_json(res_high.stdout)
    assert report_high.passed is False


def test_ignore_flag_suppresses_rules_and_rejects_unknown_rule() -> None:
    fixture = FIXTURES_DIR / "gpu_workload_broken.yaml"
    res = runner.invoke(
        guard_app,
        ["scan", str(fixture), "--ignore", "KG007", "--format", "json"],
    )
    assert res.exit_code == ExitCode.OK
    report = ToolReport.model_validate_json(res.stdout)
    assert report.findings == []

    # Multiple/comma-separated ignore
    broken = FIXTURES_DIR / "broken_workload.yaml"
    res_multi = runner.invoke(
        guard_app,
        [
            "scan",
            str(broken),
            "--ignore",
            "KG001,KG002",
            "--ignore",
            "KG008",
            "--format",
            "json",
        ],
    )
    assert res_multi.exit_code == ExitCode.FINDINGS
    ids = {f.rule_id for f in ToolReport.model_validate_json(res_multi.stdout).findings}
    assert ids.isdisjoint({"KG001", "KG002", "KG008"})

    # Unknown rule ID fails with exit 2
    res_unknown = runner.invoke(guard_app, ["scan", str(fixture), "--ignore", "KG999"])
    assert res_unknown.exit_code == ExitCode.ERROR
    assert "KG999" in res_unknown.output


def test_pdb_selector_matching_across_directory_and_namespace_isolation(tmp_path: Path) -> None:
    deployment_yaml = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payments
  namespace: core
spec:
  replicas: 2
  selector:
    matchLabels:
      app: payments
  template:
    metadata:
      labels:
        app: payments
        tier: backend
    spec:
      securityContext:
        runAsNonRoot: true
      containers:
        - name: app
          image: ghcr.io/example/payments:2.1.0
          resources:
            requests: { cpu: "100m", memory: "128Mi" }
            limits: { cpu: "200m", memory: "256Mi" }
          readinessProbe:
            tcpSocket: { port: 8080 }
          livenessProbe:
            tcpSocket: { port: 8080 }
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: { drop: ["ALL"] }
"""
    pdb_wrong_ns = """
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: payments-pdb
  namespace: other
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: payments
"""
    pdb_match_expr = """
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: payments-pdb
  namespace: core
spec:
  minAvailable: 1
  selector:
    matchExpressions:
      - key: app
        operator: In
        values: ["payments"]
      - key: tier
        operator: Exists
"""
    (tmp_path / "deploy.yaml").write_text(deployment_yaml, encoding="utf-8")
    (tmp_path / "pdb.yaml").write_text(pdb_wrong_ns, encoding="utf-8")

    # Wrong namespace should still trigger KG006.
    report_wrong = scan_target(str(tmp_path))
    assert [f.rule_id for f in report_wrong.findings] == ["KG006"]

    # Matching namespace + matchExpressions resolves KG006.
    (tmp_path / "pdb.yaml").write_text(pdb_match_expr, encoding="utf-8")
    report_ok = scan_target(str(tmp_path))
    assert report_ok.passed is True
    assert report_ok.findings == []


def test_kg001_registry_port_without_tag_and_init_container() -> None:
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: registry-check
spec:
  securityContext:
    runAsNonRoot: true
  initContainers:
    - name: init-unpinned
      image: localhost:5000/internal/setup
      resources:
        requests: { cpu: "50m", memory: "64Mi" }
        limits: { cpu: "100m", memory: "128Mi" }
      securityContext:
        allowPrivilegeEscalation: false
        capabilities: { drop: ["ALL"] }
  containers:
    - name: main
      image: localhost:5000/internal/app:1.2.3
      resources:
        requests: { cpu: "100m", memory: "128Mi" }
        limits: { cpu: "200m", memory: "256Mi" }
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: { drop: ["ALL"] }
"""
    docs = parse_yaml_stream(manifest, source="pod.yaml")
    findings = evaluate_documents(docs)
    assert len(findings) == 1
    assert findings[0].rule_id == "KG001"
    assert "init-unpinned" in findings[0].message


def test_kg008_applies_to_all_non_init_workloads_regardless_of_replicas() -> None:
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: standalone-pod
spec:
  securityContext:
    runAsNonRoot: true
  initContainers:
    - name: bootstrap
      image: ghcr.io/example/init:1.0.0
      resources:
        requests: { cpu: "50m", memory: "64Mi" }
        limits: { cpu: "100m", memory: "128Mi" }
      securityContext:
        allowPrivilegeEscalation: false
        capabilities: { drop: ["ALL"] }
  containers:
    - name: worker
      image: ghcr.io/example/worker:1.0.0
      resources:
        requests: { cpu: "100m", memory: "128Mi" }
        limits: { cpu: "200m", memory: "256Mi" }
      securityContext:
        allowPrivilegeEscalation: false
        capabilities: { drop: ["ALL"] }
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: single-replica-api
spec:
  replicas: 1
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      securityContext:
        runAsNonRoot: true
      containers:
        - name: api
          image: ghcr.io/example/api:1.0.0
          resources:
            requests: { cpu: "100m", memory: "128Mi" }
            limits: { cpu: "200m", memory: "256Mi" }
          readinessProbe: { tcpSocket: { port: 8080 } }
          livenessProbe: { tcpSocket: { port: 8080 } }
          securityContext:
            allowPrivilegeEscalation: false
            capabilities: { drop: ["ALL"] }
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: cache
spec:
  replicas: 1
  serviceName: cache
  selector:
    matchLabels:
      app: cache
  template:
    metadata:
      labels:
        app: cache
    spec:
      securityContext:
        runAsNonRoot: true
      containers:
        - name: cache
          image: ghcr.io/example/cache:1.0.0
          resources:
            requests: { cpu: "100m", memory: "128Mi" }
            limits: { cpu: "200m", memory: "256Mi" }
          readinessProbe: { tcpSocket: { port: 6379 } }
          livenessProbe: { tcpSocket: { port: 6379 } }
          securityContext:
            allowPrivilegeEscalation: false
            capabilities: { drop: ["ALL"] }
"""
    docs = parse_yaml_stream(manifest, source="workloads.yaml")
    findings = evaluate_documents(docs)
    assert len(findings) == 3
    assert all(f.rule_id == "KG008" and f.severity == Severity.LOW for f in findings)
    assert {f.resource for f in findings} == {
        "Pod/standalone-pod",
        "Deployment/single-replica-api",
        "StatefulSet/cache",
    }
    # initContainer 'bootstrap' must NOT trigger KG008.
    assert all("bootstrap" not in f.message for f in findings)


def test_kg006_hpa_min_replicas_triggers_and_resolves_with_pdb() -> None:
    deployment_without_replicas = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: inference-gateway
  namespace: serving
spec:
  selector:
    matchLabels:
      app: inference-gateway
  template:
    metadata:
      labels:
        app: inference-gateway
    spec:
      securityContext:
        runAsNonRoot: true
      containers:
        - name: gateway
          image: ghcr.io/example/gateway:1.2.0
          resources:
            requests: { cpu: "200m", memory: "256Mi" }
            limits: { cpu: "500m", memory: "512Mi" }
          readinessProbe: { httpGet: { path: /readyz, port: 8080 } }
          livenessProbe: { httpGet: { path: /healthz, port: 8080 } }
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: { drop: ["ALL"] }
"""
    hpa_v2 = """
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: inference-gateway-hpa
  namespace: serving
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: inference-gateway
  minReplicas: 2
  maxReplicas: 10
"""
    matching_pdb = """
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: inference-gateway-pdb
  namespace: serving
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: inference-gateway
"""
    hpa_wrong_ns = hpa_v2.replace("namespace: serving", "namespace: other")

    # HPA minReplicas=2 with omitted spec.replicas and no PDB -> KG006 fires.
    docs_no_pdb = parse_yaml_stream(deployment_without_replicas + hpa_v2, source="hpa.yaml")
    findings_no_pdb = evaluate_documents(docs_no_pdb)
    assert len(findings_no_pdb) == 1
    assert findings_no_pdb[0].rule_id == "KG006"
    assert "HPA minReplicas=2" in findings_no_pdb[0].message

    # Same Deployment + HPA + matching PDB -> passes cleanly.
    docs_with_pdb = parse_yaml_stream(
        deployment_without_replicas + hpa_v2 + matching_pdb, source="hpa-pdb.yaml"
    )
    assert evaluate_documents(docs_with_pdb) == []

    # HPA in another namespace does not affect Deployment in 'serving'.
    docs_wrong_ns = parse_yaml_stream(
        deployment_without_replicas + hpa_wrong_ns, source="hpa-wrong-ns.yaml"
    )
    assert evaluate_documents(docs_wrong_ns) == []


def test_table_output_rules_subcommand_and_root_dispatcher() -> None:
    fixture = FIXTURES_DIR / "broken_workload.yaml"
    res_table = runner.invoke(guard_app, ["scan", str(fixture), "--format", "table"])
    assert res_table.exit_code == ExitCode.FINDINGS
    assert "KG001" in res_table.stdout
    assert "FAIL" in res_table.stdout

    res_rules = runner.invoke(guard_app, ["rules", "--format", "json"])
    assert res_rules.exit_code == ExitCode.OK
    rules_payload = json.loads(res_rules.stdout)
    assert len(rules_payload) == len(RULE_CATALOG)
    assert [r["rule_id"] for r in rules_payload] == [r.rule_id for r in RULE_CATALOG]

    res_root = runner.invoke(
        root_app,
        ["k8s-guard", "scan", str(FIXTURES_DIR / "hardened_deployment.yaml"), "--format", "json"],
    )
    assert res_root.exit_code == ExitCode.OK
    assert ToolReport.model_validate_json(res_root.stdout).passed is True
