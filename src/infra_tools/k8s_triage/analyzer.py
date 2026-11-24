"""Pure, deterministic failure correlator for Kubernetes cluster snapshots."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from infra_tools.core.models import Finding, Severity, ToolReport
from infra_tools.k8s_triage.models import (
    ClusterSnapshot,
    ContainerStateSnapshot,
    EventSnapshot,
    NodeSnapshot,
    PodSnapshot,
)

HIGH_RESTART_THRESHOLD = 3
IMAGE_PULL_REASONS: frozenset[str] = frozenset(
    {"ImagePullBackOff", "ErrImagePull", "InvalidImageName", "RegistryUnavailable"}
)
CONFIG_ERROR_REASONS: frozenset[str] = frozenset(
    {"CreateContainerConfigError", "CreateContainerError"}
)
NODE_PRESSURE_CONDITIONS: frozenset[str] = frozenset(
    {"MemoryPressure", "DiskPressure", "PIDPressure", "NetworkUnavailable"}
)


@dataclass(frozen=True)
class RuleSpec:
    """Metadata describing a built-in k8s-triage diagnostic rule."""

    rule_id: str
    severity: Severity
    title: str
    description: str


RULE_CATALOG: tuple[RuleSpec, ...] = (
    RuleSpec(
        rule_id="KT001",
        severity=Severity.CRITICAL,
        title="Container OOMKilled",
        description=(
            "Flags containers terminated with OOMKilled or exit code 137, correlated with "
            "pod events and declared memory limits."
        ),
    ),
    RuleSpec(
        rule_id="KT002",
        severity=Severity.HIGH,
        title="Container CrashLoopBackOff",
        description=(
            "Flags containers in CrashLoopBackOff with restart count, last termination "
            "reason/exit code, and correlated warning events."
        ),
    ),
    RuleSpec(
        rule_id="KT003",
        severity=Severity.HIGH,
        title="Image pull failure",
        description=(
            "Flags ImagePullBackOff/ErrImagePull states with the failing image reference "
            "and correlated registry error event."
        ),
    ),
    RuleSpec(
        rule_id="KT004",
        severity=Severity.HIGH,
        title="Container configuration or creation error",
        description=(
            "Flags CreateContainerConfigError/CreateContainerError states caused by missing "
            "ConfigMaps, Secrets, or runtime constraints."
        ),
    ),
    RuleSpec(
        rule_id="KT005",
        severity=Severity.HIGH,
        title="Unschedulable Pending pod",
        description=(
            "Flags Pending pods with PodScheduled=False or FailedScheduling events, "
            "classifying GPU/CPU/memory insufficiency vs taint/affinity mismatches."
        ),
    ),
    RuleSpec(
        rule_id="KT006",
        severity=Severity.MEDIUM,
        title="Failing container probe",
        description=(
            "Flags pods emitting Unhealthy warning events from failing readiness, liveness, "
            "or startup probes with event counts and failure messages."
        ),
    ),
    RuleSpec(
        rule_id="KT007",
        severity=Severity.CRITICAL,
        title="Unhealthy node condition",
        description=(
            "Flags nodes with Ready!=True (CRITICAL) or Memory/Disk/PID pressure (HIGH), "
            "listing pods scheduled on the affected node."
        ),
    ),
    RuleSpec(
        rule_id="KT008",
        severity=Severity.MEDIUM,
        title="High container restart count",
        description=(
            "Flags containers with restartCount >= 3 (including currently Running containers) "
            "to surface silent crash instability."
        ),
    ),
)

VALID_RULE_IDS: frozenset[str] = frozenset(spec.rule_id for spec in RULE_CATALOG)


def _index_pod_events(events: list[EventSnapshot]) -> dict[tuple[str, str], list[EventSnapshot]]:
    index: dict[tuple[str, str], list[EventSnapshot]] = defaultdict(list)
    for event in events:
        if event.involved_kind in ("", "Pod"):
            index[(event.namespace, event.involved_name)].append(event)
    return index


def _latest_matching_event(
    events: list[EventSnapshot],
    *,
    reasons: set[str] | None = None,
    keywords: tuple[str, ...] = (),
    warnings_only: bool = True,
) -> EventSnapshot | None:
    candidates: list[EventSnapshot] = []
    for ev in events:
        if warnings_only and ev.event_type.lower() != "warning":
            continue
        reason_ok = reasons is None or ev.reason in reasons
        msg_lower = ev.message.lower()
        kw_ok = not keywords or any(kw in msg_lower for kw in keywords)
        if reason_ok and kw_ok:
            candidates.append(ev)

    if not candidates:
        return None
    # Prefer the event with the latest timestamp (or highest count as deterministic tie-breaker).
    return max(candidates, key=lambda e: (e.last_timestamp or "", e.count, e.message))


def _classify_scheduling_failure(text: str) -> list[str]:
    lower = text.lower()
    causes: list[str] = []
    if "nvidia.com/gpu" in lower or "amd.com/gpu" in lower or "insufficient gpu" in lower:
        causes.append("insufficient GPU capacity")
    if (
        "insufficient cpu" in lower
        or "insufficient memory" in lower
        or "insufficient ephemeral" in lower
    ):
        causes.append("insufficient CPU/memory capacity")
    if "untolerated taint" in lower or "had taint" in lower or "taint" in lower:
        causes.append("node taint/toleration mismatch")
    if (
        "didn't match pod's node affinity" in lower
        or "node affinity" in lower
        or "node selector" in lower
        or "nodeselector" in lower
        or "topology spread" in lower
    ):
        causes.append("nodeSelector/affinity mismatch")
    if not causes:
        causes.append("scheduling constraint or cluster capacity shortage")
    return causes


def _container_location(container: ContainerStateSnapshot) -> str:
    prefix = "initContainer" if container.is_init else "container"
    return f"{prefix}/{container.name}"


def _analyze_pod(
    pod: PodSnapshot,
    pod_events: list[EventSnapshot],
) -> list[Finding]:
    findings: list[Finding] = []
    resource = f"Pod/{pod.namespace}/{pod.name}"

    for container in pod.containers:
        loc = _container_location(container)

        # KT001: Container OOMKilled
        is_oom = (
            container.state_reason == "OOMKilled"
            or container.last_state_reason == "OOMKilled"
            or container.exit_code == 137
            or container.last_exit_code == 137
        )
        if is_oom:
            mem_info = (
                f"memory limit={container.memory_limit}"
                if container.memory_limit
                else "memory limit unset"
            )
            ev = _latest_matching_event(
                pod_events,
                keywords=("oom", "killed", "memory", "back-off"),
                warnings_only=False,
            )
            ev_note = f" Event: {ev.reason} - {ev.message}" if ev and ev.message else ""
            findings.append(
                Finding(
                    rule_id="KT001",
                    severity=Severity.CRITICAL,
                    resource=resource,
                    location=loc,
                    message=(
                        f"Container '{container.name}' was OOMKilled "
                        f"(restarts={container.restart_count}, {mem_info}).{ev_note}"
                    ),
                    remediation=(
                        "Profile container memory usage for leaks, raise resources.limits.memory, "
                        "and align runtime heap/KV-cache ceilings with the cgroup limit."
                    ),
                )
            )

        # KT002: CrashLoopBackOff
        if container.state_reason == "CrashLoopBackOff":
            last_detail_parts: list[str] = []
            if container.last_state_reason:
                last_detail_parts.append(f"last_reason={container.last_state_reason}")
            if container.last_exit_code is not None:
                last_detail_parts.append(f"last_exit_code={container.last_exit_code}")
            last_detail = f", {', '.join(last_detail_parts)}" if last_detail_parts else ""
            ev = _latest_matching_event(pod_events, reasons={"BackOff", "Failed", "Killing"})
            ev_note = f" Event: {ev.message}" if ev and ev.message else ""
            findings.append(
                Finding(
                    rule_id="KT002",
                    severity=Severity.HIGH,
                    resource=resource,
                    location=loc,
                    message=(
                        f"Container '{container.name}' is in CrashLoopBackOff "
                        f"(restarts={container.restart_count}{last_detail}).{ev_note}"
                    ),
                    remediation=(
                        "Inspect previous logs (`kubectl logs <pod> -c <container> --previous`) "
                        "to resolve the recurring startup or runtime crash."
                    ),
                )
            )

        # KT003: ImagePullBackOff / ErrImagePull
        if container.state_reason in IMAGE_PULL_REASONS:
            ev = _latest_matching_event(
                pod_events,
                reasons={"Failed", "ErrImagePull", "ImagePullBackOff"},
                keywords=("pull", "image", "manifest", "unauthorized", "not found"),
            )
            detail = ev.message if ev and ev.message else (container.state_message or "")
            detail_note = f" Detail: {detail}" if detail else ""
            findings.append(
                Finding(
                    rule_id="KT003",
                    severity=Severity.HIGH,
                    resource=resource,
                    location=loc,
                    message=(
                        f"Container '{container.name}' failed to pull image "
                        f"'{container.image or '<unknown>'}' "
                        f"({container.state_reason}).{detail_note}"
                    ),
                    remediation=(
                        "Verify image name and tag exist in the registry, confirm imagePullSecrets "
                        "credentials, and check cluster egress to the registry."
                    ),
                )
            )

        # KT004: CreateContainerConfigError / CreateContainerError
        if container.state_reason in CONFIG_ERROR_REASONS:
            ev = _latest_matching_event(
                pod_events,
                reasons={"Failed", "CreateContainerConfigError", "CreateContainerError"},
            )
            detail = container.state_message or (ev.message if ev else "")
            detail_note = f" Detail: {detail}" if detail else ""
            findings.append(
                Finding(
                    rule_id="KT004",
                    severity=Severity.HIGH,
                    resource=resource,
                    location=loc,
                    message=(
                        f"Container '{container.name}' failed container creation "
                        f"({container.state_reason}).{detail_note}"
                    ),
                    remediation=(
                        "Verify referenced ConfigMaps, Secrets, ServiceAccounts, and "
                        "securityContext/runtime constraints in the target namespace."
                    ),
                )
            )

        # KT008: High restart count (>= 3)
        if container.restart_count >= HIGH_RESTART_THRESHOLD:
            state_desc = (
                f"{container.state} ({container.state_reason})"
                if container.state_reason
                else container.state
            )
            last_note = (
                f", last_reason={container.last_state_reason}"
                if container.last_state_reason
                else ""
            )
            findings.append(
                Finding(
                    rule_id="KT008",
                    severity=Severity.MEDIUM,
                    resource=resource,
                    location=loc,
                    message=(
                        f"Container '{container.name}' has {container.restart_count} restarts "
                        f"(current state={state_desc}{last_note})."
                    ),
                    remediation=(
                        "Investigate recurring container restarts even if currently Running to "
                        "eliminate silent crash loops or liveness-probe flaps."
                    ),
                )
            )

    # KT005: Unschedulable Pending pod
    sched_cond = next(
        (c for c in pod.conditions if c.type == "PodScheduled" and c.status == "False"),
        None,
    )
    sched_event = _latest_matching_event(pod_events, reasons={"FailedScheduling"})
    if pod.phase == "Pending" and (sched_cond is not None or sched_event is not None):
        evidence_parts: list[str] = []
        for candidate in (
            sched_cond.message if sched_cond and sched_cond.message else "",
            sched_event.message if sched_event and sched_event.message else "",
        ):
            cleaned = candidate.strip()
            if cleaned and cleaned not in evidence_parts:
                evidence_parts.append(cleaned)
        raw_msg = " ".join(evidence_parts)
        causes = _classify_scheduling_failure(raw_msg)
        fallback_reason = sched_cond.reason if sched_cond and sched_cond.reason else "Unschedulable"
        evidence = raw_msg or fallback_reason
        findings.append(
            Finding(
                rule_id="KT005",
                severity=Severity.HIGH,
                resource=resource,
                location="pod/scheduling",
                message=(
                    f"Pod is Pending/Unschedulable ({'; '.join(causes)}). Evidence: {evidence}"
                ),
                remediation=(
                    "Align resource requests (CPU/memory/GPU), nodeSelector/affinity, and "
                    "tolerations with available cluster nodes or scale the matching node pool."
                ),
            )
        )

    # KT006: Failing readiness/liveness/startup probes
    probe_events = [
        ev
        for ev in pod_events
        if ev.event_type.lower() == "warning"
        and (
            ev.reason == "Unhealthy"
            or "probe failed" in ev.message.lower()
            or "readiness probe" in ev.message.lower()
            or "liveness probe" in ev.message.lower()
            or "startup probe" in ev.message.lower()
        )
    ]
    if probe_events:
        total_count = sum(ev.count for ev in probe_events)
        latest_probe = max(probe_events, key=lambda e: (e.last_timestamp or "", e.count, e.message))
        probe_kinds = sorted(
            {
                kind
                for kind in ("readiness", "liveness", "startup")
                if any(kind in ev.message.lower() for ev in probe_events)
            }
        )
        kind_label = "/".join(probe_kinds) if probe_kinds else "health"
        findings.append(
            Finding(
                rule_id="KT006",
                severity=Severity.MEDIUM,
                resource=resource,
                location="pod/probes",
                message=(
                    f"Pod has failing {kind_label} probe ({total_count} Unhealthy event(s)). "
                    f"Latest: {latest_probe.message}"
                ),
                remediation=(
                    "Verify probe path/port, increase initialDelaySeconds/timeoutSeconds if "
                    "startup is slow, and inspect application logs for health-check errors."
                ),
            )
        )

    return findings


def _analyze_node(
    node: NodeSnapshot,
    pods_on_node: list[PodSnapshot],
) -> list[Finding]:
    findings: list[Finding] = []
    resource = f"Node/{node.name}"
    affected = sorted(f"{p.namespace}/{p.name}" for p in pods_on_node)
    affected_note = (
        f" Affected pods ({len(affected)}): {', '.join(affected)}."
        if affected
        else " No scheduled pods in snapshot."
    )

    for cond in node.conditions:
        if cond.type == "Ready" and cond.status != "True":
            detail = cond.message or cond.reason or f"Ready={cond.status}"
            findings.append(
                Finding(
                    rule_id="KT007",
                    severity=Severity.CRITICAL,
                    resource=resource,
                    location="node/Ready",
                    message=(
                        f"Node '{node.name}' is not Ready (status={cond.status}: {detail})."
                        f"{affected_note}"
                    ),
                    remediation=(
                        "Inspect kubelet/node health, cordon and drain if degraded, and verify "
                        "affected workloads reschedule cleanly."
                    ),
                )
            )
        elif cond.type in NODE_PRESSURE_CONDITIONS and cond.status == "True":
            detail = cond.message or cond.reason or f"{cond.type}=True"
            findings.append(
                Finding(
                    rule_id="KT007",
                    severity=Severity.HIGH,
                    resource=resource,
                    location=f"node/{cond.type}",
                    message=(
                        f"Node '{node.name}' reports {cond.type}=True ({detail})."
                        f"{affected_note}"
                    ),
                    remediation=(
                        f"Relieve {cond.type} on node '{node.name}' by reclaiming resources, "
                        "evicting noisy workloads, or scaling cluster capacity."
                    ),
                )
            )

    return findings


def analyze_snapshot(snapshot: ClusterSnapshot) -> list[Finding]:
    """Run all pure k8s-triage correlation rules over a ``ClusterSnapshot``."""
    pod_events = _index_pod_events(snapshot.events)
    pods_by_node: dict[str, list[PodSnapshot]] = defaultdict(list)
    for pod in snapshot.pods:
        if pod.node_name:
            pods_by_node[pod.node_name].append(pod)

    findings: list[Finding] = []
    for pod in snapshot.pods:
        findings.extend(_analyze_pod(pod, pod_events.get((pod.namespace, pod.name), [])))

    for node in snapshot.nodes:
        findings.extend(_analyze_node(node, pods_by_node.get(node.name, [])))

    return findings


def triage_snapshot(
    snapshot: ClusterSnapshot,
    *,
    target: str,
    fail_on: Severity = Severity.LOW,
) -> ToolReport:
    """Analyze a ``ClusterSnapshot`` and return a sorted ``ToolReport``."""
    findings = analyze_snapshot(snapshot)
    return ToolReport.from_findings(
        tool="k8s-triage",
        target=target,
        documents_scanned=len(snapshot.pods) + len(snapshot.nodes),
        findings=findings,
        fail_on=fail_on,
    )
