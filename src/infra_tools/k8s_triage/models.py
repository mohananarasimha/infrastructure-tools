"""Typed Pydantic snapshot schema shared by live collection and offline fixture replay."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ContainerStateSnapshot(BaseModel):
    """Normalized state and limits for a single container or initContainer."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., min_length=1)
    image: str = ""
    ready: bool = False
    restart_count: int = Field(default=0, ge=0)
    is_init: bool = False
    state: str = "unknown"
    state_reason: str | None = None
    state_message: str | None = None
    exit_code: int | None = None
    last_state_reason: str | None = None
    last_state_message: str | None = None
    last_exit_code: int | None = None
    memory_limit: str | None = None
    cpu_limit: str | None = None
    gpu_limit: str | None = None


class PodConditionSnapshot(BaseModel):
    """Normalized Kubernetes pod condition."""

    model_config = ConfigDict(frozen=True)

    type: str = Field(..., min_length=1)
    status: str = Field(..., min_length=1)
    reason: str | None = None
    message: str | None = None


class PodSnapshot(BaseModel):
    """Normalized Kubernetes pod status and container state snapshot."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., min_length=1)
    namespace: str = "default"
    phase: str = "Unknown"
    node_name: str | None = None
    conditions: list[PodConditionSnapshot] = Field(default_factory=list)
    containers: list[ContainerStateSnapshot] = Field(default_factory=list)


class EventSnapshot(BaseModel):
    """Normalized Kubernetes event tied to an involved resource."""

    model_config = ConfigDict(frozen=True)

    namespace: str = "default"
    involved_kind: str = ""
    involved_name: str = ""
    event_type: str = "Normal"
    reason: str = ""
    message: str = ""
    count: int = Field(default=1, ge=1)
    last_timestamp: str | None = None


class NodeConditionSnapshot(BaseModel):
    """Normalized Kubernetes node condition."""

    model_config = ConfigDict(frozen=True)

    type: str = Field(..., min_length=1)
    status: str = Field(..., min_length=1)
    reason: str | None = None
    message: str | None = None


class NodeSnapshot(BaseModel):
    """Normalized Kubernetes node health snapshot."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., min_length=1)
    unschedulable: bool = False
    conditions: list[NodeConditionSnapshot] = Field(default_factory=list)


class ClusterSnapshot(BaseModel):
    """Complete read-only snapshot fed into the pure k8s-triage analyzer."""

    model_config = ConfigDict(frozen=True)

    source: str = "live"
    namespace: str | None = None
    pods: list[PodSnapshot] = Field(default_factory=list)
    events: list[EventSnapshot] = Field(default_factory=list)
    nodes: list[NodeSnapshot] = Field(default_factory=list)
