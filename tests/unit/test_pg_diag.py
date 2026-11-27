"""Unit tests for pg-diag analyzer and CLI using synthetic snapshots."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from infra_tools.cli import app as root_app
from infra_tools.core.models import ExitCode, Severity, ToolReport
from infra_tools.pg_diag.analyzer import RULE_CATALOG, Thresholds, analyze_snapshot
from infra_tools.pg_diag.cli import app as pg_app
from infra_tools.pg_diag.models import LockWait, PgSnapshot, ServerSettings, SessionSnapshot

runner = CliRunner()


def _session(pid: int, **kw: Any) -> SessionSnapshot:
    base: dict[str, Any] = {
        "pid": pid,
        "usename": "app",
        "datname": "shop",
        "application_name": "orders-api",
        "state": "idle",
        "state_age_s": 1.0,
    }
    base.update(kw)
    return SessionSnapshot(**base)


def _snapshot(
    sessions: list[SessionSnapshot],
    lock_waits: list[LockWait] | None = None,
    **settings: Any,
) -> PgSnapshot:
    cfg: dict[str, Any] = {
        "server_version": "18.1",
        "max_connections": 100,
        "superuser_reserved_connections": 3,
    }
    cfg.update(settings)
    return PgSnapshot(
        source="postgresql://db:5432/shop",
        collected_at="2026-01-01 00:00:00+00",
        settings=ServerSettings(**cfg),
        sessions=sessions,
        lock_waits=lock_waits or [],
    )


def _chain(waiter_age_s: float = 5.0) -> PgSnapshot:
    root = _session(
        10,
        state="idle in transaction",
        state_age_s=120.0,
        xact_age_s=125.0,
        query="UPDATE accounts SET balance = balance - 10 WHERE id = 1",
    )
    direct = _session(
        11, state="active", query_age_s=4.0, blocked_by=[10], wait_event_type="Lock"
    )
    transitive = _session(
        12,
        state="active",
        query_age_s=waiter_age_s,
        blocked_by=[10, 11],
        wait_event_type="Lock",
    )
    waits = [LockWait(pid=11, locktype="transactionid", mode="ShareLock", transactionid="777")]
    return _snapshot([root, direct, transitive], waits)


def _by_rule(findings: list[Any], rule: str) -> list[Any]:
    return [f for f in findings if f.rule_id == rule]


def test_healthy_snapshot_has_no_findings() -> None:
    snap = _snapshot([_session(1), _session(2, state="active", query_age_s=0.1)])
    assert analyze_snapshot(snap) == []


def test_chain_reports_one_root_with_transitive_waiters() -> None:
    findings = analyze_snapshot(_chain())
    pg001 = _by_rule(findings, "PG001")
    assert len(pg001) == 1
    f = pg001[0]
    assert f.severity is Severity.HIGH
    assert f.resource.startswith("pid 10 ")
    assert "2 session(s) waiting" in f.message
    assert "ShareLock on transactionid 777" in f.message
    assert "pg_cancel_backend(10)" in f.remediation


def test_chain_is_critical_when_a_waiter_exceeds_threshold() -> None:
    f = _by_rule(analyze_snapshot(_chain(waiter_age_s=90.0)), "PG001")[0]
    assert f.severity is Severity.CRITICAL
    assert "Longest wait 90s" in f.message


def test_prepared_transaction_root() -> None:
    snap = _snapshot([_session(5, state="active", query_age_s=3.0, blocked_by=[0])])
    f = _by_rule(analyze_snapshot(snap), "PG001")[0]
    assert f.resource == "prepared transaction"
    assert "pg_prepared_xacts" in f.remediation


def test_idle_in_txn_blocking_is_high_and_non_blocking_is_medium() -> None:
    snap = _chain()
    lone = _session(20, state="idle in transaction (aborted)", state_age_s=300.0)
    snap = snap.model_copy(update={"sessions": [*snap.sessions, lone]})
    pg002 = {f.resource.split()[1]: f for f in _by_rule(analyze_snapshot(snap), "PG002")}
    assert pg002["10"].severity is Severity.HIGH
    assert "blocking other sessions" in pg002["10"].message
    assert pg002["20"].severity is Severity.MEDIUM
    assert "is disabled (0)" in pg002["20"].remediation


def test_idle_in_txn_below_threshold_is_ignored() -> None:
    snap = _snapshot([_session(1, state="idle in transaction", state_age_s=30.0)])
    assert analyze_snapshot(snap) == []
    assert _by_rule(
        analyze_snapshot(snap, Thresholds(idle_in_txn_s=10.0)), "PG002"
    ), "threshold should be configurable"


def test_saturation_boundaries_and_non_client_backends() -> None:
    def clients(n: int) -> list[SessionSnapshot]:
        return [_session(i, state="active", query_age_s=0.1) for i in range(1, n + 1)]

    workers = [
        _session(900, backend_type="autovacuum launcher", state=None),
        _session(901, backend_type="checkpointer", state=None),
    ]
    # 97 usable slots (100 - 3 superuser reserved).
    assert _by_rule(analyze_snapshot(_snapshot(clients(77) + workers)), "PG003") == []
    high = _by_rule(analyze_snapshot(_snapshot(clients(78) + workers)), "PG003")[0]
    assert high.severity is Severity.HIGH
    assert "78/97" in high.message
    crit = _by_rule(analyze_snapshot(_snapshot(clients(93))), "PG003")[0]
    assert crit.severity is Severity.CRITICAL


def test_reserved_connections_reduce_usable_slots() -> None:
    sessions = [_session(i, state="active") for i in range(1, 81)]
    snap = _snapshot(sessions, reserved_connections=7)
    f = _by_rule(analyze_snapshot(snap), "PG003")[0]
    assert "80/90" in f.message
    assert "10 reserved" in f.message


def test_idle_share_only_reported_with_saturation() -> None:
    idle_heavy = [_session(i) for i in range(1, 61)] + [
        _session(i, state="active") for i in range(61, 81)
    ]
    findings = analyze_snapshot(_snapshot(idle_heavy))
    assert _by_rule(findings, "PG004")[0].message.startswith("60/80 client connections (75%)")
    assert "orders-api/app=80" in _by_rule(findings, "PG003")[0].message

    few_idle = [_session(i) for i in range(1, 11)]
    assert analyze_snapshot(_snapshot(few_idle)) == []


def _write(tmp_path: Path, snap: PgSnapshot) -> Path:
    path = tmp_path / "snap.json"
    path.write_text(snap.model_dump_json(), encoding="utf-8")
    return path


def test_cli_fixture_exit_codes_and_fail_on(tmp_path: Path) -> None:
    path = _write(tmp_path, _chain())
    result = runner.invoke(pg_app, ["inspect", "--fixture", str(path), "--format", "json"])
    assert result.exit_code == ExitCode.FINDINGS
    report = ToolReport.model_validate_json(result.stdout)
    assert report.tool == "pg-diag"
    assert report.summary.documents_scanned == 3
    assert {f.rule_id for f in report.findings} == {"PG001", "PG002"}

    result = runner.invoke(pg_app, ["inspect", "--fixture", str(path), "--fail-on", "critical"])
    assert result.exit_code == ExitCode.OK

    healthy = _write(tmp_path, _snapshot([_session(1)]))
    assert runner.invoke(pg_app, ["inspect", "--fixture", str(healthy)]).exit_code == ExitCode.OK


def test_cli_no_query_text_strips_sql(tmp_path: Path) -> None:
    path = _write(tmp_path, _chain())
    result = runner.invoke(
        pg_app, ["inspect", "--fixture", str(path), "--format", "json", "--no-query-text"]
    )
    assert "UPDATE accounts" not in result.stdout


def test_cli_invalid_fixture_and_unreachable_server_exit_2(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"source": "x"}), encoding="utf-8")
    result = runner.invoke(pg_app, ["inspect", "--fixture", str(bad)])
    assert result.exit_code == ExitCode.ERROR
    assert "not a valid pg-diag snapshot" in result.stderr

    result = runner.invoke(
        pg_app, ["inspect", "--dsn", "host=127.0.0.1 port=1 dbname=x user=x connect_timeout=2"]
    )
    assert result.exit_code == ExitCode.ERROR
    assert "Cannot connect to PostgreSQL" in result.stderr
    assert "Traceback" not in result.stderr


def test_rules_catalog_and_root_dispatch() -> None:
    result = runner.invoke(pg_app, ["rules", "--format", "json"])
    assert result.exit_code == 0
    assert [r["rule_id"] for r in json.loads(result.stdout)] == [r.rule_id for r in RULE_CATALOG]
    assert runner.invoke(root_app, ["pg-diag", "rules"]).exit_code == 0
