"""pg-diag against a real PostgreSQL with deliberately induced problems.

Requires PG_DIAG_TEST_DSN (a superuser DSN on a disposable server), e.g.:

    docker run -d --rm --name pgdiag-it -p 127.0.0.1:55432:5432 \
      -e POSTGRES_PASSWORD=pgdiag-test postgres:18
    export PG_DIAG_TEST_DSN=postgresql://postgres:pgdiag-test@127.0.0.1:55432/postgres
"""

from __future__ import annotations

import math
import os
import threading
import time
from collections.abc import Iterator

import psycopg
import pytest
from typer.testing import CliRunner

from infra_tools.core.models import ExitCode, Severity, ToolReport
from infra_tools.pg_diag.analyzer import Thresholds, analyze_snapshot
from infra_tools.pg_diag.cli import app as pg_app
from infra_tools.pg_diag.collector import collect_live_snapshot

pytestmark = pytest.mark.integration

DSN = os.environ.get("PG_DIAG_TEST_DSN", "")


@pytest.fixture
def dsn() -> Iterator[str]:
    if not DSN:
        pytest.skip("PG_DIAG_TEST_DSN not set")
    with psycopg.connect(DSN, autocommit=True) as admin:
        admin.execute("DROP TABLE IF EXISTS pg_diag_it_accounts")
        admin.execute("CREATE TABLE pg_diag_it_accounts (id int PRIMARY KEY, balance int NOT NULL)")
        admin.execute("INSERT INTO pg_diag_it_accounts VALUES (1, 100)")
    yield DSN
    with psycopg.connect(DSN, autocommit=True) as admin:
        admin.execute("DROP TABLE IF EXISTS pg_diag_it_accounts")


def _wait_for_lock_waiters(dsn: str, expected: int, timeout_s: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_s
    with psycopg.connect(dsn, autocommit=True) as probe:
        while time.monotonic() < deadline:
            row = probe.execute(
                "SELECT count(*) FROM pg_stat_activity "
                "WHERE wait_event_type = 'Lock' AND application_name LIKE 'it-waiter-%'"
            ).fetchone()
            if row and row[0] >= expected:
                return
            time.sleep(0.1)
    raise AssertionError(f"expected {expected} lock waiters within {timeout_s}s")


def test_blocking_chain_and_idle_in_transaction(dsn: str) -> None:
    holder = psycopg.connect(dsn, application_name="it-holder")
    holder.execute("UPDATE pg_diag_it_accounts SET balance = balance - 10 WHERE id = 1")
    holder_pid = holder.info.backend_pid

    errors: list[BaseException] = []

    def waiter(name: str) -> None:
        try:
            with psycopg.connect(dsn, autocommit=True, application_name=name) as conn:
                conn.execute("SET lock_timeout = '30s'")
                conn.execute("UPDATE pg_diag_it_accounts SET balance = balance + 1 WHERE id = 1")
        except BaseException as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=waiter, args=(f"it-waiter-{i}",), daemon=True) for i in (1, 2)
    ]
    try:
        for t in threads:
            t.start()
            time.sleep(0.2)
        _wait_for_lock_waiters(dsn, expected=2)
        time.sleep(1.2)

        snap = collect_live_snapshot(dsn)
        findings = analyze_snapshot(snap, Thresholds(idle_in_txn_s=1.0))

        pg001 = [f for f in findings if f.rule_id == "PG001"]
        assert len(pg001) == 1, findings
        assert pg001[0].resource.startswith(f"pid {holder_pid} ")
        assert "2 session(s) waiting" in pg001[0].message
        assert "state=idle in transaction" in pg001[0].message
        assert pg001[0].severity is Severity.HIGH

        pg002 = [f for f in findings if f.rule_id == "PG002"]
        assert len(pg002) == 1
        assert pg002[0].severity is Severity.HIGH
        assert "UPDATE pg_diag_it_accounts" in pg002[0].message
    finally:
        holder.rollback()
        holder.close()
        for t in threads:
            t.join(timeout=10)

    assert errors == []
    after = analyze_snapshot(collect_live_snapshot(dsn), Thresholds(idle_in_txn_s=1.0))
    assert [f for f in after if f.rule_id in ("PG001", "PG002")] == []


def test_connection_saturation_from_idle_pool(dsn: str) -> None:
    baseline = collect_live_snapshot(dsn)
    available = baseline.settings.available_connections
    in_use = sum(1 for s in baseline.sessions if s.is_client) + 1  # + the collector itself
    to_open = math.ceil(0.85 * available) - in_use
    if to_open <= 0 or to_open > 300:
        pytest.skip(f"cannot reach 85% of {available} slots safely from {in_use} in use")

    pool = [psycopg.connect(dsn, application_name="it-leaky-pool") for _ in range(to_open)]
    try:
        findings = analyze_snapshot(collect_live_snapshot(dsn))
        pg003 = [f for f in findings if f.rule_id == "PG003"]
        assert len(pg003) == 1, findings
        assert pg003[0].severity is Severity.HIGH
        assert f"it-leaky-pool/postgres={to_open}" in pg003[0].message
        assert [f.rule_id for f in findings if f.rule_id == "PG004"] == ["PG004"]
    finally:
        for conn in pool:
            conn.close()


def test_cli_live_healthy_and_no_password_in_output(dsn: str) -> None:
    result = runner.invoke(pg_app, ["inspect", "--dsn", dsn, "--format", "json"])
    assert result.exit_code == ExitCode.OK, result.stdout
    report = ToolReport.model_validate_json(result.stdout)
    assert report.target.startswith("postgresql://")
    if "@" in dsn:
        secret = dsn.split("://", 1)[-1].split("@", 1)[0]
        assert secret not in result.stdout


runner = CliRunner()
