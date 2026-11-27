"""Pure, deterministic analysis of a PostgreSQL activity snapshot."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from infra_tools.core.models import Finding, Severity, ToolReport
from infra_tools.pg_diag.models import PgSnapshot, SessionSnapshot

IDLE_IN_TXN_STATES: frozenset[str] = frozenset(
    {"idle in transaction", "idle in transaction (aborted)"}
)
PREPARED_XACT_PID = 0


@dataclass(frozen=True)
class Thresholds:
    """Tunable limits; defaults are documented in the README."""

    idle_in_txn_s: float = 60.0
    lock_wait_critical_s: float = 60.0
    conn_high: float = 0.80
    conn_critical: float = 0.95
    idle_share: float = 0.50


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    severity: Severity
    title: str
    description: str


RULE_CATALOG: tuple[RuleSpec, ...] = (
    RuleSpec(
        "PG001",
        Severity.HIGH,
        "Blocking lock chain",
        "One finding per root blocker (a session that blocks others and is not itself "
        "blocked), with the number of sessions waiting behind it directly or transitively. "
        "CRITICAL when any waiter has waited at least lock_wait_critical_s.",
    ),
    RuleSpec(
        "PG002",
        Severity.MEDIUM,
        "Idle in transaction",
        "Session idle inside an open transaction for at least idle_in_txn_s. Its locks and "
        "snapshot are held until it commits or rolls back. HIGH when it is also blocking "
        "other sessions.",
    ),
    RuleSpec(
        "PG003",
        Severity.HIGH,
        "Connection saturation",
        "Client backends at or above conn_high of the slots available to ordinary roles "
        "(max_connections minus superuser_reserved_connections and reserved_connections). "
        "CRITICAL at conn_critical.",
    ),
    RuleSpec(
        "PG004",
        Severity.MEDIUM,
        "Idle connections hold most slots",
        "Reported alongside PG003 when at least idle_share of client backends are idle: "
        "the limit is being consumed by pooled or leaked connections, not by work.",
    ),
)


def _fmt_s(seconds: float | None) -> str:
    return "?" if seconds is None else f"{seconds:.0f}s"


def _short_query(session: SessionSnapshot, limit: int = 80) -> str:
    if not session.query:
        return ""
    text = " ".join(session.query.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _blocking_findings(
    snapshot: PgSnapshot, by_pid: dict[int, SessionSnapshot], th: Thresholds
) -> tuple[list[Finding], set[int]]:
    waiters_of: dict[int, set[int]] = defaultdict(set)
    for s in snapshot.sessions:
        for blocker in s.blocked_by:
            waiters_of[blocker].add(s.pid)

    roots = sorted(
        pid
        for pid in waiters_of
        if pid == PREPARED_XACT_PID or not (by_pid.get(pid) and by_pid[pid].blocked_by)
    )
    waits_by_pid = defaultdict(list)
    for lw in snapshot.lock_waits:
        waits_by_pid[lw.pid].append(lw)

    findings: list[Finding] = []
    for root in roots:
        blocked: set[int] = set()
        stack = [root]
        while stack:
            for waiter in waiters_of.get(stack.pop(), ()):
                if waiter not in blocked and waiter != root:
                    blocked.add(waiter)
                    stack.append(waiter)

        wait_ages = [
            age
            for p in blocked
            if p in by_pid and (age := by_pid[p].query_age_s) is not None
        ]
        max_wait = max(wait_ages) if wait_ages else None
        severity = (
            Severity.CRITICAL
            if max_wait is not None and max_wait >= th.lock_wait_critical_s
            else Severity.HIGH
        )
        targets = sorted(
            {f"{lw.mode} on {lw.target}" for p in waiters_of[root] for lw in waits_by_pid[p]}
        )

        if root == PREPARED_XACT_PID:
            resource = "prepared transaction"
            root_desc = "a prepared (two-phase) transaction"
            fix = (
                "Find it in pg_prepared_xacts and COMMIT PREPARED or ROLLBACK PREPARED it; "
                "prepared transactions survive restarts and are never timed out."
            )
        else:
            rs = by_pid.get(root)
            resource = rs.label if rs else f"pid {root}"
            if rs is None:
                root_desc = f"pid {root} (not visible in pg_stat_activity)"
            else:
                root_desc = (
                    f"{rs.label}, state={rs.state or '?'}, "
                    f"transaction open {_fmt_s(rs.xact_age_s)}"
                )
                if q := _short_query(rs):
                    root_desc += f", last query: {q}"
            fix = (
                "End the root transaction (have the application COMMIT/ROLLBACK, or "
                f"SELECT pg_cancel_backend({root}); pg_terminate_backend if it is idle). "
                "Set lock_timeout on migrations and bulk writers so they fail instead of "
                "queueing others behind them."
            )

        message = (
            f"{len(blocked)} session(s) waiting behind {root_desc}. "
            f"Longest wait {_fmt_s(max_wait)}."
        )
        if targets:
            message += f" Waiting for: {'; '.join(targets)}."
        findings.append(
            Finding(
                rule_id="PG001",
                severity=severity,
                resource=resource,
                location=snapshot.source,
                message=message,
                remediation=fix,
            )
        )
    return findings, set(waiters_of)


def _idle_in_txn_findings(
    snapshot: PgSnapshot, blockers: set[int], th: Thresholds
) -> list[Finding]:
    timeout = snapshot.settings.idle_in_transaction_session_timeout
    findings = []
    for s in snapshot.sessions:
        if s.state not in IDLE_IN_TXN_STATES:
            continue
        if s.state_age_s is None or s.state_age_s < th.idle_in_txn_s:
            continue
        is_blocker = s.pid in blockers
        message = (
            f"{s.state} for {_fmt_s(s.state_age_s)} "
            f"(transaction open {_fmt_s(s.xact_age_s)})"
            f"{', blocking other sessions' if is_blocker else ''}."
        )
        if q := _short_query(s):
            message += f" Last query: {q}"
        if timeout in ("0", ""):
            setting = "idle_in_transaction_session_timeout is disabled (0) on this server"
        else:
            setting = f"idle_in_transaction_session_timeout is {timeout}"
        findings.append(
            Finding(
                rule_id="PG002",
                severity=Severity.HIGH if is_blocker else Severity.MEDIUM,
                resource=s.label,
                location=snapshot.source,
                message=message,
                remediation=(
                    "Fix the code path that opens a transaction and then waits (network calls, "
                    f"user input) before committing. {setting}; setting it for the application "
                    "role bounds the damage."
                ),
            )
        )
    return findings


def _saturation_findings(snapshot: PgSnapshot, th: Thresholds) -> list[Finding]:
    st = snapshot.settings
    clients = [s for s in snapshot.sessions if s.is_client]
    available = st.available_connections
    used = len(clients)
    ratio = used / available
    if ratio < th.conn_high:
        return []

    by_app = Counter((s.application_name or "-", s.usename or "?") for s in clients)
    top = ", ".join(f"{app}/{user}={n}" for (app, user), n in by_app.most_common(3))
    states = Counter(s.state or "unknown" for s in clients)
    state_text = ", ".join(f"{k}={v}" for k, v in sorted(states.items()))
    reserved = st.superuser_reserved_connections + st.reserved_connections
    findings = [
        Finding(
            rule_id="PG003",
            severity=Severity.CRITICAL if ratio >= th.conn_critical else Severity.HIGH,
            resource="max_connections",
            location=snapshot.source,
            message=(
                f"{used}/{available} usable connection slots in use ({ratio:.0%}); "
                f"max_connections={st.max_connections}, {reserved} reserved. "
                f"By state: {state_text}. Top application/user: {top}."
            ),
            remediation=(
                "New connections fail with 'too many clients' at 100%. Put a pooler "
                "(e.g. PgBouncer in transaction mode) in front, and size application pools "
                "so the sum across all replicas stays below the usable slots. Raising "
                "max_connections costs memory per backend and is not a fix on its own."
            ),
        )
    ]

    idle = states.get("idle", 0)
    if used and idle / used >= th.idle_share:
        findings.append(
            Finding(
                rule_id="PG004",
                severity=Severity.MEDIUM,
                resource="max_connections",
                location=snapshot.source,
                message=(
                    f"{idle}/{used} client connections ({idle / used:.0%}) are idle: slots are "
                    "held by pools or leaked connections, not by running queries."
                ),
                remediation=(
                    "Lower per-instance pool max size and idle timeout, check for connections "
                    "that are opened but never returned, and multiply pool size by replica "
                    "count when budgeting connections."
                ),
            )
        )
    return findings


def analyze_snapshot(snapshot: PgSnapshot, thresholds: Thresholds | None = None) -> list[Finding]:
    """Return all findings for ``snapshot``."""
    th = thresholds or Thresholds()
    by_pid = {s.pid: s for s in snapshot.sessions}
    findings, blockers = _blocking_findings(snapshot, by_pid, th)
    findings += _idle_in_txn_findings(snapshot, blockers, th)
    findings += _saturation_findings(snapshot, th)
    return findings


def diagnose(
    snapshot: PgSnapshot,
    *,
    target: str,
    thresholds: Thresholds | None = None,
    fail_on: Severity = Severity.LOW,
) -> ToolReport:
    """Analyze ``snapshot`` and wrap the findings in a ``ToolReport``."""
    return ToolReport.from_findings(
        tool="pg-diag",
        target=target,
        documents_scanned=len(snapshot.sessions),
        findings=analyze_snapshot(snapshot, thresholds),
        fail_on=fail_on,
    )
