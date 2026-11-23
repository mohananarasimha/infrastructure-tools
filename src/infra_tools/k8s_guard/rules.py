"""Reliability, security, and GPU-hygiene lint rules for Kubernetes manifests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from infra_tools.core.models import Finding, Severity
from infra_tools.k8s_guard.loader import ParsedDocument, PathKey

GPU_RESOURCE_KEY = "nvidia.com/gpu"
PROBE_REQUIRED_KINDS: frozenset[str] = frozenset({"Deployment", "StatefulSet"})
PDB_REQUIRED_KINDS: frozenset[str] = frozenset({"Deployment", "StatefulSet"})
POD_TEMPLATE_KINDS: frozenset[str] = frozenset(
    {
        "Deployment",
        "StatefulSet",
        "DaemonSet",
        "ReplicaSet",
        "ReplicationController",
        "Job",
    }
)


@dataclass(frozen=True)
class RuleSpec:
    """Metadata describing a built-in k8s-guard lint rule."""

    rule_id: str
    severity: Severity
    title: str
    description: str


RULE_CATALOG: tuple[RuleSpec, ...] = (
    RuleSpec(
        rule_id="KG001",
        severity=Severity.HIGH,
        title="Unpinned container image tag",
        description="Flags containers using ':latest' or omitting an explicit tag/digest.",
    ),
    RuleSpec(
        rule_id="KG002",
        severity=Severity.HIGH,
        title="Missing CPU/memory requests or limits",
        description="Requires explicit cpu and memory requests and limits on containers.",
    ),
    RuleSpec(
        rule_id="KG003",
        severity=Severity.MEDIUM,
        title="Missing readinessProbe",
        description="Requires readinessProbe on Deployment and StatefulSet containers.",
    ),
    RuleSpec(
        rule_id="KG004",
        severity=Severity.MEDIUM,
        title="Missing livenessProbe",
        description="Requires livenessProbe on Deployment and StatefulSet containers.",
    ),
    RuleSpec(
        rule_id="KG005",
        severity=Severity.HIGH,
        title="Container securityContext hardening",
        description=(
            "Flags privileged containers (CRITICAL) and missing runAsNonRoot, "
            "allowPrivilegeEscalation: false, or capabilities.drop: [ALL] (HIGH)."
        ),
    ),
    RuleSpec(
        rule_id="KG006",
        severity=Severity.MEDIUM,
        title="Missing PodDisruptionBudget for multi-replica workload",
        description=(
            "Requires a matching PodDisruptionBudget (same namespace and label selector) "
            "for Deployment/StatefulSet with replicas > 1."
        ),
    ),
    RuleSpec(
        rule_id="KG007",
        severity=Severity.HIGH,
        title="GPU workload hygiene",
        description=(
            "Verifies nvidia.com/gpu requests == limits (> 0) (HIGH) and warns if GPU pods "
            "lack explicit tolerations or nodeSelector/nodeAffinity (MEDIUM)."
        ),
    ),
    RuleSpec(
        rule_id="KG008",
        severity=Severity.LOW,
        title="Writable root filesystem on replicated Deployment",
        description="Flags Deployment (replicas > 1) containers without readOnlyRootFilesystem.",
    ),
)

VALID_RULE_IDS: frozenset[str] = frozenset(spec.rule_id for spec in RULE_CATALOG)


@dataclass(frozen=True)
class _PodTarget:
    doc: ParsedDocument
    kind: str
    namespace: str
    resource_id: str
    replicas: int
    pod_labels: dict[str, str]
    pod_spec: dict[str, Any]
    pod_spec_path: PathKey


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _extract_resource_id(data: dict[str, Any]) -> tuple[str, str]:
    kind = str(data.get("kind") or "Unknown")
    metadata = _as_dict(data.get("metadata"))
    name = str(metadata.get("name") or "<unnamed>")
    raw_ns = metadata.get("namespace")
    namespace = str(raw_ns) if raw_ns else "default"
    resource_id = f"{kind}/{raw_ns}/{name}" if raw_ns else f"{kind}/{name}"
    return namespace, resource_id


def _extract_replicas(spec: dict[str, Any]) -> int:
    raw = spec.get("replicas")
    if isinstance(raw, int) and not isinstance(raw, bool):
        return raw
    return 1


def _extract_labels(metadata: dict[str, Any]) -> dict[str, str]:
    raw_labels = _as_dict(metadata.get("labels"))
    return {str(k): str(v) for k, v in raw_labels.items()}


def _extract_pod_target(doc: ParsedDocument) -> _PodTarget | None:
    kind = str(doc.data.get("kind") or "")
    namespace, resource_id = _extract_resource_id(doc.data)
    spec = _as_dict(doc.data.get("spec"))

    if kind == "Pod":
        metadata = _as_dict(doc.data.get("metadata"))
        return _PodTarget(
            doc=doc,
            kind=kind,
            namespace=namespace,
            resource_id=resource_id,
            replicas=1,
            pod_labels=_extract_labels(metadata),
            pod_spec=spec,
            pod_spec_path=("spec",),
        )

    if kind in POD_TEMPLATE_KINDS:
        template = _as_dict(spec.get("template"))
        pod_spec = _as_dict(template.get("spec"))
        pod_meta = _as_dict(template.get("metadata"))
        return _PodTarget(
            doc=doc,
            kind=kind,
            namespace=namespace,
            resource_id=resource_id,
            replicas=_extract_replicas(spec),
            pod_labels=_extract_labels(pod_meta),
            pod_spec=pod_spec,
            pod_spec_path=("spec", "template", "spec"),
        )

    if kind == "CronJob":
        job_template = _as_dict(spec.get("jobTemplate"))
        job_spec = _as_dict(job_template.get("spec"))
        template = _as_dict(job_spec.get("template"))
        pod_spec = _as_dict(template.get("spec"))
        pod_meta = _as_dict(template.get("metadata"))
        return _PodTarget(
            doc=doc,
            kind=kind,
            namespace=namespace,
            resource_id=resource_id,
            replicas=1,
            pod_labels=_extract_labels(pod_meta),
            pod_spec=pod_spec,
            pod_spec_path=("spec", "jobTemplate", "spec", "template", "spec"),
        )

    return None


def _is_image_pinned(image: str) -> bool:
    """Return True if an image reference has an immutable digest or non-latest tag."""
    cleaned = image.strip()
    if not cleaned:
        return False

    if "@" in cleaned:
        _, digest = cleaned.split("@", 1)
        return bool(digest.strip())

    # Inspect only the final path segment so registry ports (host:5000/app) are not treated as tags.
    last_segment = cleaned.rsplit("/", 1)[-1]
    if ":" not in last_segment:
        return False

    _, tag = last_segment.rsplit(":", 1)
    return bool(tag) and tag.lower() != "latest"


def _parse_gpu_quantity(raw: Any) -> float | None:
    """Parse an ``nvidia.com/gpu`` quantity into a float, or None if missing/invalid."""
    if raw is None or isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        return float(raw)
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return None
        try:
            return float(stripped)
        except ValueError:
            return None
    return None


def _selector_matches_labels(selector: Any, labels: dict[str, str]) -> bool:
    """Evaluate a Kubernetes LabelSelector (matchLabels + matchExpressions) against pod labels."""
    if not isinstance(selector, dict):
        return False

    match_labels = selector.get("matchLabels")
    if match_labels is not None:
        if not isinstance(match_labels, dict):
            return False
        for key, value in match_labels.items():
            if labels.get(str(key)) != str(value):
                return False

    match_expressions = selector.get("matchExpressions")
    if match_expressions is not None:
        if not isinstance(match_expressions, list):
            return False
        for expr in match_expressions:
            if not isinstance(expr, dict):
                return False
            key = str(expr.get("key") or "")
            operator = str(expr.get("operator") or "")
            values = [str(v) for v in _as_list(expr.get("values"))]

            if operator == "In":
                if key not in labels or labels[key] not in values:
                    return False
            elif operator == "NotIn":
                if key in labels and labels[key] in values:
                    return False
            elif operator == "Exists":
                if key not in labels:
                    return False
            elif operator == "DoesNotExist":
                if key in labels:
                    return False
            else:
                return False

    return True


def _collect_pdbs(documents: list[ParsedDocument]) -> list[tuple[str, Any]]:
    """Collect ``(namespace, spec.selector)`` for all PodDisruptionBudget manifests."""
    pdbs: list[tuple[str, Any]] = []
    for doc in documents:
        if doc.data.get("kind") != "PodDisruptionBudget":
            continue
        namespace, _ = _extract_resource_id(doc.data)
        spec = _as_dict(doc.data.get("spec"))
        if "selector" in spec:
            pdbs.append((namespace, spec["selector"]))
    return pdbs


def _check_container_rules(
    target: _PodTarget,
    container: dict[str, Any],
    container_path: PathKey,
    *,
    is_init: bool,
) -> tuple[list[Finding], bool]:
    """Run container-level rules (KG001-KG005, KG007 GPU math, KG008) on one container."""
    findings: list[Finding] = []
    cname = str(container.get("name") or "<unnamed>")
    container_label = f"initContainer '{cname}'" if is_init else f"container '{cname}'"
    doc = target.doc

    # KG001: Unpinned image tag
    image = container.get("image")
    if isinstance(image, str) and not _is_image_pinned(image):
        findings.append(
            Finding(
                rule_id="KG001",
                severity=Severity.HIGH,
                resource=target.resource_id,
                location=doc.location_for((*container_path, "image")),
                message=f"{container_label} uses unpinned image '{image}'.",
                remediation="Pin image to an immutable version tag or '@sha256:...' digest.",
            )
        )

    # KG002: Missing CPU/memory requests or limits
    resources = _as_dict(container.get("resources"))
    requests = _as_dict(resources.get("requests"))
    limits = _as_dict(resources.get("limits"))
    missing_resources: list[str] = []
    for section_name, section in (("requests", requests), ("limits", limits)):
        for res_key in ("cpu", "memory"):
            val = section.get(res_key)
            if val is None or (isinstance(val, str) and not val.strip()):
                missing_resources.append(f"{section_name}.{res_key}")

    if missing_resources:
        findings.append(
            Finding(
                rule_id="KG002",
                severity=Severity.HIGH,
                resource=target.resource_id,
                location=doc.location_for((*container_path, "resources")),
                message=(
                    f"{container_label} is missing resource constraints: "
                    f"{', '.join(missing_resources)}."
                ),
                remediation=(
                    "Set explicit cpu and memory values under resources.requests and "
                    "resources.limits."
                ),
            )
        )

    # KG003 & KG004: Readiness and liveness probes on Deployment/StatefulSet regular containers
    if not is_init and target.kind in PROBE_REQUIRED_KINDS:
        if not _as_dict(container.get("readinessProbe")):
            findings.append(
                Finding(
                    rule_id="KG003",
                    severity=Severity.MEDIUM,
                    resource=target.resource_id,
                    location=doc.location_for(container_path),
                    message=f"{container_label} is missing a readinessProbe.",
                    remediation=(
                        "Configure a readinessProbe so traffic is only routed to ready pods."
                    ),
                )
            )
        if not _as_dict(container.get("livenessProbe")):
            findings.append(
                Finding(
                    rule_id="KG004",
                    severity=Severity.MEDIUM,
                    resource=target.resource_id,
                    location=doc.location_for(container_path),
                    message=f"{container_label} is missing a livenessProbe.",
                    remediation="Configure a livenessProbe so deadlocked containers are restarted.",
                )
            )

    # KG005: securityContext hardening
    pod_sc = _as_dict(target.pod_spec.get("securityContext"))
    container_sc = _as_dict(container.get("securityContext"))

    if container_sc.get("privileged") is True:
        findings.append(
            Finding(
                rule_id="KG005",
                severity=Severity.CRITICAL,
                resource=target.resource_id,
                location=doc.location_for((*container_path, "securityContext", "privileged")),
                message=f"{container_label} runs with securityContext.privileged=true.",
                remediation="Remove privileged: true and grant only minimal required capabilities.",
            )
        )

    missing_sc: list[str] = []
    container_non_root = container_sc.get("runAsNonRoot")
    effective_non_root = (
        container_non_root if isinstance(container_non_root, bool) else pod_sc.get("runAsNonRoot")
    )
    if effective_non_root is not True:
        missing_sc.append("runAsNonRoot: true")

    if container_sc.get("allowPrivilegeEscalation") is not False:
        missing_sc.append("allowPrivilegeEscalation: false")

    capabilities = _as_dict(container_sc.get("capabilities"))
    dropped_caps = {str(cap).upper() for cap in _as_list(capabilities.get("drop"))}
    if "ALL" not in dropped_caps:
        missing_sc.append("capabilities.drop: [ALL]")

    if missing_sc:
        findings.append(
            Finding(
                rule_id="KG005",
                severity=Severity.HIGH,
                resource=target.resource_id,
                location=doc.location_for((*container_path, "securityContext")),
                message=(
                    f"{container_label} is missing securityContext hardening: "
                    f"{', '.join(missing_sc)}."
                ),
                remediation=(
                    "Set runAsNonRoot: true, allowPrivilegeEscalation: false, and "
                    "capabilities.drop: [ALL]."
                ),
            )
        )

    # KG007 (container level): GPU request/limit parity and non-zero quantity
    has_gpu = GPU_RESOURCE_KEY in requests or GPU_RESOURCE_KEY in limits
    if has_gpu:
        req_gpu = _parse_gpu_quantity(requests.get(GPU_RESOURCE_KEY))
        lim_gpu = _parse_gpu_quantity(limits.get(GPU_RESOURCE_KEY))
        gpu_issues: list[str] = []
        if req_gpu is None or req_gpu <= 0:
            gpu_issues.append("requests['nvidia.com/gpu'] must be > 0")
        if lim_gpu is None or lim_gpu <= 0:
            gpu_issues.append("limits['nvidia.com/gpu'] must be > 0")
        if req_gpu is not None and lim_gpu is not None and req_gpu > 0 and req_gpu != lim_gpu:
            req_raw = requests.get(GPU_RESOURCE_KEY)
            lim_raw = limits.get(GPU_RESOURCE_KEY)
            gpu_issues.append(f"requests ({req_raw}) != limits ({lim_raw})")

        if gpu_issues:
            findings.append(
                Finding(
                    rule_id="KG007",
                    severity=Severity.HIGH,
                    resource=target.resource_id,
                    location=doc.location_for((*container_path, "resources")),
                    message=(
                        f"{container_label} has invalid GPU allocation: "
                        f"{'; '.join(gpu_issues)}."
                    ),
                    remediation=(
                        "Set equal, positive integer values for both "
                        "resources.requests['nvidia.com/gpu'] and "
                        "resources.limits['nvidia.com/gpu']."
                    ),
                )
            )

    # KG008: readOnlyRootFilesystem on Deployment with replicas > 1
    if (
        not is_init
        and target.kind == "Deployment"
        and target.replicas > 1
        and container_sc.get("readOnlyRootFilesystem") is not True
    ):
        findings.append(
            Finding(
                rule_id="KG008",
                severity=Severity.LOW,
                resource=target.resource_id,
                location=doc.location_for((*container_path, "securityContext")),
                message=(
                    f"{container_label} on replicated Deployment (replicas={target.replicas}) "
                    "is missing readOnlyRootFilesystem: true."
                ),
                remediation=(
                    "Set securityContext.readOnlyRootFilesystem: true and mount emptyDir volumes "
                    "for writable scratch paths."
                ),
            )
        )

    return findings, has_gpu


def _check_gpu_scheduling(target: _PodTarget) -> list[Finding]:
    """KG007 (pod level): warn if GPU pod lacks tolerations or node placement constraints."""
    pod_spec = target.pod_spec
    has_tolerations = len(_as_list(pod_spec.get("tolerations"))) > 0
    node_selector = _as_dict(pod_spec.get("nodeSelector"))
    affinity = _as_dict(pod_spec.get("affinity"))
    node_affinity = _as_dict(affinity.get("nodeAffinity"))
    has_node_placement = bool(node_selector) or bool(node_affinity)

    missing_scheduling: list[str] = []
    if not has_tolerations:
        missing_scheduling.append("tolerations")
    if not has_node_placement:
        missing_scheduling.append("nodeSelector or affinity.nodeAffinity")

    if not missing_scheduling:
        return []

    return [
        Finding(
            rule_id="KG007",
            severity=Severity.MEDIUM,
            resource=target.resource_id,
            location=target.doc.location_for(target.pod_spec_path),
            message=(
                f"GPU workload lacks explicit GPU scheduling constraints: "
                f"missing {', '.join(missing_scheduling)}."
            ),
            remediation=(
                "Add GPU node tolerations (e.g., nvidia.com/gpu:NoSchedule) and a "
                "nodeSelector or affinity.nodeAffinity targeting GPU nodes."
            ),
        )
    ]


def evaluate_documents(
    documents: list[ParsedDocument],
    *,
    ignore_rules: set[str] | None = None,
) -> list[Finding]:
    """Evaluate all k8s-guard rules across a set of parsed Kubernetes documents."""
    ignored = {rule.upper() for rule in (ignore_rules or set())}
    pdbs = _collect_pdbs(documents)
    findings: list[Finding] = []

    for doc in documents:
        target = _extract_pod_target(doc)
        if target is None:
            continue

        uses_gpu = False
        for field_name, is_init in (("containers", False), ("initContainers", True)):
            containers = _as_list(target.pod_spec.get(field_name))
            for idx, raw_container in enumerate(containers):
                if not isinstance(raw_container, dict):
                    continue
                container_path: PathKey = (*target.pod_spec_path, field_name, idx)
                c_findings, c_has_gpu = _check_container_rules(
                    target,
                    raw_container,
                    container_path,
                    is_init=is_init,
                )
                findings.extend(c_findings)
                uses_gpu = uses_gpu or c_has_gpu

        if uses_gpu:
            findings.extend(_check_gpu_scheduling(target))

        # KG006: PodDisruptionBudget coverage for multi-replica Deployment/StatefulSet
        if target.kind in PDB_REQUIRED_KINDS and target.replicas > 1:
            has_matching_pdb = any(
                pdb_ns == target.namespace and _selector_matches_labels(selector, target.pod_labels)
                for pdb_ns, selector in pdbs
            )
            if not has_matching_pdb:
                findings.append(
                    Finding(
                        rule_id="KG006",
                        severity=Severity.MEDIUM,
                        resource=target.resource_id,
                        location=doc.location_for(("spec", "replicas")),
                        message=(
                            f"{target.kind} with replicas={target.replicas} has no matching "
                            "PodDisruptionBudget in scanned manifests."
                        ),
                        remediation=(
                            "Define a PodDisruptionBudget in the same namespace with a selector "
                            "matching the workload pod template labels."
                        ),
                    )
                )

    if ignored:
        findings = [f for f in findings if f.rule_id.upper() not in ignored]

    return findings
