"""Read-only PostgreSQL collector and offline JSON fixture loader."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import psycopg
from pydantic import ValidationError

from infra_tools.pg_diag.models import LockWait, PgSnapshot, ServerSettings, SessionSnapshot

CONNECT_TIMEOUT_S = 5
STATEMENT_TIMEOUT_MS = 5000
QUERY_TEXT_CHARS = 200

_SETTINGS_SQL = """
SELECT current_setting('server_version'),
       current_setting('max_connections')::int,
       current_setting('superuser_reserved_connections')::int,
       COALESCE(NULLIF(current_setting('reserved_connections', true), ''), '0')::int,
       current_setting('idle_in_transaction_session_timeout'),
       current_setting('lock_timeout'),
       now()::text
"""

_SESSIONS_SQL = """
SELECT a.pid,
       a.backend_type,
       a.usename::text,
       a.datname::text,
       COALESCE(a.application_name, ''),
       host(a.client_addr),
       a.state,
       a.wait_event_type,
       a.wait_event,
       EXTRACT(EPOCH FROM (now() - a.xact_start))::float8,
       EXTRACT(EPOCH FROM (now() - a.query_start))::float8,
       EXTRACT(EPOCH FROM (now() - a.state_change))::float8,
       left(a.query, %(chars)s),
       pg_blocking_pids(a.pid)
FROM pg_stat_activity AS a
WHERE a.pid <> pg_backend_pid()
ORDER BY a.pid
"""

_LOCK_WAITS_SQL = """
SELECT l.pid,
       l.locktype,
       l.mode,
       CASE WHEN l.relation IS NOT NULL THEN l.relation::regclass::text END,
       l.transactionid::text
FROM pg_locks AS l
WHERE NOT l.granted
ORDER BY l.pid
"""


class PgCollectionError(Exception):
    """Raised when a snapshot cannot be collected or loaded."""


def load_snapshot_from_fixture(path: Path) -> PgSnapshot:
    """Load and validate an offline ``PgSnapshot`` JSON file."""
    if not path.is_file():
        raise PgCollectionError(f"Fixture file does not exist or is not a file: {path}")
    try:
        raw: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PgCollectionError(f"Cannot read fixture {path}: {exc}") from None
    try:
        return PgSnapshot.model_validate(raw)
    except ValidationError as exc:
        raise PgCollectionError(f"Fixture {path} is not a valid pg-diag snapshot: {exc}") from None


def collect_live_snapshot(dsn: str, *, include_query_text: bool = True) -> PgSnapshot:
    """Collect a snapshot over one read-only connection.

    ``dsn`` may be empty, in which case libpq environment variables (PGHOST, PGUSER,
    ...) apply. Only catalog/statistics views are read; nothing is written.
    """
    try:
        conn = psycopg.connect(
            dsn,
            connect_timeout=CONNECT_TIMEOUT_S,
            application_name="pg-diag",
            options=f"-c statement_timeout={STATEMENT_TIMEOUT_MS}",
        )
    except psycopg.Error as exc:
        raise PgCollectionError(f"Cannot connect to PostgreSQL: {_first_line(exc)}") from None

    try:
        conn.read_only = True
        info = conn.info
        source = f"postgresql://{info.host}:{info.port}/{info.dbname}"
        with conn.transaction(), conn.cursor() as cur:
            cur.execute(_SETTINGS_SQL)
            row = cur.fetchone()
            if row is None:
                raise PgCollectionError("Server returned no settings row")
            settings = ServerSettings(
                server_version=row[0],
                max_connections=row[1],
                superuser_reserved_connections=row[2],
                reserved_connections=row[3],
                idle_in_transaction_session_timeout=row[4],
                lock_timeout=row[5],
            )
            collected_at = row[6]

            cur.execute(_SESSIONS_SQL, {"chars": QUERY_TEXT_CHARS})
            sessions = [
                SessionSnapshot(
                    pid=r[0],
                    backend_type=r[1] or "",
                    usename=r[2],
                    datname=r[3],
                    application_name=r[4],
                    client_addr=r[5],
                    state=r[6],
                    wait_event_type=r[7],
                    wait_event=r[8],
                    xact_age_s=r[9],
                    query_age_s=r[10],
                    state_age_s=r[11],
                    query=r[12] if include_query_text else None,
                    blocked_by=list(r[13] or []),
                )
                for r in cur.fetchall()
            ]

            cur.execute(_LOCK_WAITS_SQL)
            lock_waits = [
                LockWait(pid=r[0], locktype=r[1], mode=r[2], relation=r[3], transactionid=r[4])
                for r in cur.fetchall()
            ]
    except psycopg.Error as exc:
        raise PgCollectionError(f"Snapshot query failed: {_first_line(exc)}") from None
    finally:
        conn.close()

    return PgSnapshot(
        source=source,
        collected_at=collected_at,
        settings=settings,
        sessions=sessions,
        lock_waits=lock_waits,
    )


def _first_line(exc: Exception) -> str:
    text = str(exc).strip()
    return text.splitlines()[0] if text else type(exc).__name__
