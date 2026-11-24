"""Read-only Kubernetes API collector and offline JSON fixture loader."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from kubernetes import client, config
from kubernetes.client.exceptions import ApiException
from kubernetes.config.config_exception import ConfigException
from pydantic import ValidationError

from infra_tools.k8s_triage.models import (
    ClusterSnapshot,
    ContainerStateSnapshot,
    EventSnapshot,
    NodeConditionSnapshot,
    NodeSnapshot,
    PodConditionSnapshot,
    PodSnapshot,
)

DEFAULT_REQUEST_TIMEOUT = 10


class TriageCollectionError(Exception):
    """Raised when a snapshot fixture or live cluster cannot be collected."""


def load_snapshot_from_fixture(path: Path) -> ClusterSnapshot:
    """Load and validate an offline ``ClusterSnapshot`` JSON fixture."""
    if not path.exists():
        raise TriageCollectionError(f"Fixture file does not exist: {path}")
    if not path.is_file():
        raise TriageCollectionError(f"Fixture path is not a file: {path}")

    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TriageCollectionError(f"Unable to read fixture '{path}': {exc}") from exc

    try:
        raw_data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise TriageCollectionError(f"Invalid JSON in fixture '{path}': {exc}") from exc

    if not isinstance(raw_data, dict):
        raise TriageCollectionError(
            f"Fixture '{path}' must contain a JSON object matching ClusterSnapshot."
        )

    try:
        snapshot = ClusterSnapshot.model_validate(raw_data)
    except ValidationError as exc:
        errors = exc.errors()
        if errors:
            first_err = errors[0]
            loc = ".".join(str(part) for part in first_err["loc"])
            msg = first_err["msg"]
            detail = f"{loc}: {msg}" if loc else msg
        else:
            detail = "schema validation failed"
        raise TriageCollectionError(
            f"Invalid ClusterSnapshot schema in '{path}': {detail}"
        ) from exc

    return snapshot


def _extract_container_limits(pod: Any) -> dict[str, dict[str, str | None]]:
    """Map container name to memory/cpu/gpu limits declared in the pod spec."""
    limits_by_name: dict[str, dict[str, str | None]] = {}
    spec = getattr(pod, "spec", None)
    if spec is None:
        return limits_by_name

    for attr in ("containers", "init_containers"):
        for container in getattr(spec, attr, None) or []:
            resources = getattr(container, "resources", None)
            limits = getattr(resources, "limits", None) or {}
            limits_by_name[str(container.name)] = {
                "memory": str(limits["memory"]) if "memory" in limits else None,
                "cpu": str(limits["cpu"]) if "cpu" in limits else None,
                "gpu": str(limits["nvidia.com/gpu"]) if "nvidia.com/gpu" in limits else None,
            }
    return limits_by_name


def _container_state_from_k8s(
    status: Any,
    *,
    is_init: bool,
    limits_by_name: dict[str, dict[str, str | None]],
) -> ContainerStateSnapshot:
    """Convert a Kubernetes ``V1ContainerStatus`` into ``ContainerStateSnapshot``."""
    name = str(getattr(status, "name", "") or "<unnamed>")
    state_obj = getattr(status, "state", None)
    last_obj = getattr(status, "last_state", None)

    state_name = "unknown"
    state_reason: str | None = None
    state_message: str | None = None
    exit_code: int | None = None

    if state_obj is not None:
        if getattr(state_obj, "running", None) is not None:
            state_name = "running"
        elif getattr(state_obj, "waiting", None) is not None:
            state_name = "waiting"
            state_reason = getattr(state_obj.waiting, "reason", None)
            state_message = getattr(state_obj.waiting, "message", None)
        elif getattr(state_obj, "terminated", None) is not None:
            state_name = "terminated"
            state_reason = getattr(state_obj.terminated, "reason", None)
            state_message = getattr(state_obj.terminated, "message", None)
            exit_code = getattr(state_obj.terminated, "exit_code", None)

    last_reason: str | None = None
    last_message: str | None = None
    last_exit_code: int | None = None
    if last_obj is not None and getattr(last_obj, "terminated", None) is not None:
        last_reason = getattr(last_obj.terminated, "reason", None)
        last_message = getattr(last_obj.terminated, "message", None)
        last_exit_code = getattr(last_obj.terminated, "exit_code", None)

    limits = limits_by_name.get(name, {})
    return ContainerStateSnapshot(
        name=name,
        image=str(getattr(status, "image", "") or ""),
        ready=bool(getattr(status, "ready", False)),
        restart_count=int(getattr(status, "restart_count", 0) or 0),
        is_init=is_init,
        state=state_name,
        state_reason=state_reason,
        state_message=state_message,
        exit_code=exit_code,
        last_state_reason=last_reason,
        last_state_message=last_message,
        last_exit_code=last_exit_code,
        memory_limit=limits.get("memory"),
        cpu_limit=limits.get("cpu"),
        gpu_limit=limits.get("gpu"),
    )


def _pod_from_k8s(pod: Any) -> PodSnapshot:
    """Convert a Kubernetes ``V1Pod`` into ``PodSnapshot``."""
    meta = getattr(pod, "metadata", None)
    spec = getattr(pod, "spec", None)
    status = getattr(pod, "status", None)

    limits_by_name = _extract_container_limits(pod)
    containers: list[ContainerStateSnapshot] = []
    for c_status in getattr(status, "init_container_statuses", None) or []:
        containers.append(
            _container_state_from_k8s(c_status, is_init=True, limits_by_name=limits_by_name)
        )
    for c_status in getattr(status, "container_statuses", None) or []:
        containers.append(
            _container_state_from_k8s(c_status, is_init=False, limits_by_name=limits_by_name)
        )

    conditions = [
        PodConditionSnapshot(
            type=str(cond.type),
            status=str(cond.status),
            reason=getattr(cond, "reason", None),
            message=getattr(cond, "message", None),
        )
        for cond in (getattr(status, "conditions", None) or [])
    ]

    return PodSnapshot(
        name=str(getattr(meta, "name", "") or "<unnamed>"),
        namespace=str(getattr(meta, "namespace", None) or "default"),
        phase=str(getattr(status, "phase", None) or "Unknown"),
        node_name=getattr(spec, "node_name", None),
        conditions=conditions,
        containers=containers,
    )


def _event_from_k8s(event: Any) -> EventSnapshot:
    """Convert a Kubernetes ``CoreV1Event`` into ``EventSnapshot``."""
    meta = getattr(event, "metadata", None)
    involved = getattr(event, "involved_object", None)
    raw_ts = getattr(event, "last_timestamp", None) or getattr(event, "event_time", None)
    if raw_ts is not None and hasattr(raw_ts, "isoformat"):
        ts_str: str | None = str(raw_ts.isoformat())
    else:
        ts_str = str(raw_ts) if raw_ts else None
    raw_count = getattr(event, "count", None)
    count = int(raw_count) if isinstance(raw_count, int) and raw_count >= 1 else 1

    return EventSnapshot(
        namespace=str(getattr(meta, "namespace", None) or "default"),
        involved_kind=str(getattr(involved, "kind", "") or ""),
        involved_name=str(getattr(involved, "name", "") or ""),
        event_type=str(getattr(event, "type", None) or "Normal"),
        reason=str(getattr(event, "reason", "") or ""),
        message=str(getattr(event, "message", "") or ""),
        count=count,
        last_timestamp=ts_str,
    )


def _node_from_k8s(node: Any) -> NodeSnapshot:
    """Convert a Kubernetes ``V1Node`` into ``NodeSnapshot``."""
    meta = getattr(node, "metadata", None)
    spec = getattr(node, "spec", None)
    status = getattr(node, "status", None)

    conditions = [
        NodeConditionSnapshot(
            type=str(cond.type),
            status=str(cond.status),
            reason=getattr(cond, "reason", None),
            message=getattr(cond, "message", None),
        )
        for cond in (getattr(status, "conditions", None) or [])
    ]

    return NodeSnapshot(
        name=str(getattr(meta, "name", "") or "<unnamed>"),
        unschedulable=bool(getattr(spec, "unschedulable", False)),
        conditions=conditions,
    )


def _format_api_error(operation: str, exc: Exception) -> str:
    """Build a sanitized error message without leaking tokens or raw headers."""
    if isinstance(exc, ApiException):
        status = getattr(exc, "status", "unknown")
        reason = getattr(exc, "reason", "API request failed")
        return f"Kubernetes API error during {operation}: HTTP {status} ({reason})."
    return f"Unable to reach Kubernetes cluster during {operation}: {type(exc).__name__}: {exc}"


def _load_kube_configuration(context: str | None, kubeconfig: Path | None) -> None:
    """Load kubeconfig or in-cluster configuration without logging credentials."""
    kube_cfg: Any = config
    if kubeconfig is not None:
        if not kubeconfig.exists():
            raise TriageCollectionError(f"Kubeconfig file does not exist: {kubeconfig}")
        try:
            kube_cfg.load_kube_config(config_file=str(kubeconfig), context=context)
        except ConfigException as exc:
            raise TriageCollectionError(f"Failed to load kubeconfig '{kubeconfig}': {exc}") from exc
        return

    try:
        kube_cfg.load_kube_config(context=context)
    except ConfigException as kube_exc:
        if context is not None:
            raise TriageCollectionError(
                f"Failed to load kubeconfig context '{context}': {kube_exc}"
            ) from kube_exc
        try:
            kube_cfg.load_incluster_config()
        except ConfigException:
            raise TriageCollectionError(
                f"Unable to load Kubernetes configuration (kubeconfig or in-cluster): {kube_exc}"
            ) from kube_exc


def collect_live_snapshot(
    *,
    namespace: str | None = None,
    all_namespaces: bool = False,
    context: str | None = None,
    kubeconfig: Path | None = None,
    timeout_seconds: int = DEFAULT_REQUEST_TIMEOUT,
) -> ClusterSnapshot:
    """Collect a read-only ``ClusterSnapshot`` from a live Kubernetes cluster."""
    _load_kube_configuration(context=context, kubeconfig=kubeconfig)
    v1 = client.CoreV1Api()

    target_ns = None if all_namespaces else (namespace or "default")
    source_label = f"live:{context}" if context else "live"

    try:
        if all_namespaces:
            pod_list = v1.list_pod_for_all_namespaces(_request_timeout=timeout_seconds)
            event_list = v1.list_event_for_all_namespaces(_request_timeout=timeout_seconds)
        else:
            assert target_ns is not None  # noqa: S101
            pod_list = v1.list_namespaced_pod(
                namespace=target_ns, _request_timeout=timeout_seconds
            )
            event_list = v1.list_namespaced_event(
                namespace=target_ns, _request_timeout=timeout_seconds
            )
    except Exception as exc:
        raise TriageCollectionError(_format_api_error("pod/event collection", exc)) from exc

    nodes: list[NodeSnapshot] = []
    try:
        node_list = v1.list_node(_request_timeout=timeout_seconds)
        nodes = [_node_from_k8s(n) for n in (getattr(node_list, "items", None) or [])]
    except ApiException as exc:
        if getattr(exc, "status", None) != 403:
            raise TriageCollectionError(_format_api_error("node collection", exc)) from exc
    except Exception as exc:
        raise TriageCollectionError(_format_api_error("node collection", exc)) from exc

    pods = [_pod_from_k8s(p) for p in (getattr(pod_list, "items", None) or [])]
    events = [_event_from_k8s(e) for e in (getattr(event_list, "items", None) or [])]

    return ClusterSnapshot(
        source=source_label,
        namespace=target_ns,
        pods=pods,
        events=events,
        nodes=nodes,
    )
