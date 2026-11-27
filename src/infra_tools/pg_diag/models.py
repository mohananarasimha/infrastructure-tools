"""Point-in-time PostgreSQL activity snapshot models (live collector and offline fixtures)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ServerSettings(BaseModel):
    """Connection-limit and timeout settings that bound the diagnosis."""

    model_config = ConfigDict(frozen=True)

    server_version: str
    max_connections: int = Field(..., ge=1)
    superuser_reserved_connections: int = Field(default=0, ge=0)
    reserved_connections: int = Field(default=0, ge=0)
    idle_in_transaction_session_timeout: str = "0"
    lock_timeout: str = "0"

    @property
    def available_connections(self) -> int:
        """Slots usable by ordinary (non-reserved) roles."""
        return max(
            1,
            self.max_connections - self.superuser_reserved_connections - self.reserved_connections,
        )


class SessionSnapshot(BaseModel):
    """One row of ``pg_stat_activity`` with ages precomputed in seconds."""

    model_config = ConfigDict(frozen=True)

    pid: int
    backend_type: str = "client backend"
    usename: str | None = None
    datname: str | None = None
    application_name: str = ""
    client_addr: str | None = None
    state: str | None = None
    wait_event_type: str | None = None
    wait_event: str | None = None
    xact_age_s: float | None = None
    query_age_s: float | None = None
    state_age_s: float | None = None
    query: str | None = None
    blocked_by: list[int] = Field(default_factory=list)

    @property
    def is_client(self) -> bool:
        return self.backend_type == "client backend"

    @property
    def label(self) -> str:
        app = self.application_name or "-"
        return f"pid {self.pid} ({self.usename or '?'}@{self.datname or '?'}, app={app})"


class LockWait(BaseModel):
    """An ungranted ``pg_locks`` entry: what a waiting session is queued on."""

    model_config = ConfigDict(frozen=True)

    pid: int
    locktype: str
    mode: str
    relation: str | None = None
    transactionid: str | None = None

    @property
    def target(self) -> str:
        if self.relation:
            return f"{self.locktype} {self.relation}"
        if self.transactionid:
            return f"{self.locktype} {self.transactionid}"
        return self.locktype


class PgSnapshot(BaseModel):
    """Everything ``pg-diag`` analyzes, collected in a single read-only transaction."""

    model_config = ConfigDict(frozen=True)

    source: str
    collected_at: str
    settings: ServerSettings
    sessions: list[SessionSnapshot] = Field(default_factory=list)
    lock_waits: list[LockWait] = Field(default_factory=list)
