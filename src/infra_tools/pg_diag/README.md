# pg-diag

Read-only PostgreSQL diagnosis for the three problems that most often turn a healthy database into an outage without any query being slow on its own:

- **Blocking lock chains.** One transaction holds a row or table lock and everything behind it queues.
- **Connection saturation.** Client backends approach `max_connections`, and new connections fail with `too many clients`.
- **Idle in transaction.** An application opened a transaction and stopped talking to the database while it still holds locks and an old snapshot.

`pg-diag` takes one snapshot of `pg_stat_activity`, `pg_locks` and the relevant settings inside a single read-only transaction, then runs a pure analyzer over it. A snapshot can be saved as JSON and analyzed later with `--fixture`.

## Rules

| Rule | Default severity | Fires when |
|---|---|---|
| PG001 | HIGH (CRITICAL if a waiter has waited ≥ `--lock-wait-critical-seconds`, default 60) | A session blocks others and is not itself blocked (a *root blocker*). One finding per root, counting direct and transitive waiters via `pg_blocking_pids()`. |
| PG002 | MEDIUM (HIGH if the session is also blocking others) | `state` is `idle in transaction` or `idle in transaction (aborted)` for ≥ `--idle-in-txn-seconds` (default 60). Reports whether `idle_in_transaction_session_timeout` is set. |
| PG003 | HIGH at ≥ 80%, CRITICAL at ≥ 95% | Client backends / usable slots, where usable = `max_connections − superuser_reserved_connections − reserved_connections`. Background workers, autovacuum and WAL senders are not counted, because they do not use `max_connections` slots. |
| PG004 | MEDIUM | Reported with PG003 when ≥ 50% of client backends are `idle`: the slots are held by pools or leaked connections, not by work. |

Blocking by a prepared (two-phase) transaction shows up as `pid 0` in `pg_blocking_pids()`. It is reported as a PG001 root named `prepared transaction`.

## Usage

```bash
# Connection: PG_DIAG_DSN, --dsn, or standard libpq variables (PGHOST, PGUSER, ...).
# Keep the password in PGPASSWORD or ~/.pgpass so it is not in shell history or `ps`.
export PG_DIAG_DSN="host=127.0.0.1 port=5432 dbname=app user=diag"

uv run pg-diag inspect                          # table output, exit 1 on any finding
uv run pg-diag inspect --format json --fail-on high
uv run pg-diag inspect --no-query-text          # do not collect SQL text at all
uv run pg-diag snapshot > incident.json         # save now, analyze later
uv run pg-diag inspect --fixture incident.json
uv run pg-diag rules
```

### Required privileges

A role with `pg_monitor` (or `pg_read_all_stats`) sees every session's state and query text. Without it, `pg_stat_activity` hides other roles' `query` and some state, and the diagnosis will be incomplete. `pg-diag` sets `statement_timeout=5s`, connects with `application_name=pg-diag`, runs in a `READ ONLY` transaction, and reads only system views.

Under full saturation, `pg-diag` itself may be refused a connection. Use a role that can use reserved slots: superuser, or `pg_use_reserved_connections` with `reserved_connections` on PostgreSQL 16+.

## Example output

Real output from PostgreSQL 18.7 in Docker (`COLUMNS=100`, `--idle-in-txn-seconds 5`). The scenario:
- `billing-worker` ran an `UPDATE` inside an open transaction and stopped.
- Two `orders-api` sessions tried to update the same row.
- A `reports-api` pool held 75 idle connections.

```text
pg-diag target=postgresql://127.0.0.1:55432/postgres scanned=86 findings=4 
status=FAIL

HIGH      PG001  pid 309 (postgres@postgres, app=billing-worker)
  location: postgresql://127.0.0.1:55432/postgres
  message:  2 session(s) waiting behind pid 309 (postgres@postgres, 
app=billing-worker), state=idle in transaction, transaction open 8s, last query:
UPDATE accounts SET balance = balance - 10 WHERE id = 1. Longest wait 8s. 
Waiting for: ShareLock on transactionid 790.
  fix:      End the root transaction (have the application COMMIT/ROLLBACK, or 
SELECT pg_cancel_backend(309); pg_terminate_backend if it is idle). Set 
lock_timeout on migrations and bulk writers so they fail instead of queueing 
others behind them.

HIGH      PG002  pid 309 (postgres@postgres, app=billing-worker)
  location: postgresql://127.0.0.1:55432/postgres
  message:  idle in transaction for 8s (transaction open 8s), blocking other 
sessions. Last query: UPDATE accounts SET balance = balance - 10 WHERE id = 1
  fix:      Fix the code path that opens a transaction and then waits (network 
calls, user input) before committing. idle_in_transaction_session_timeout is 
disabled (0) on this server; setting it for the application role bounds the 
damage.

HIGH      PG003  max_connections
  location: postgresql://127.0.0.1:55432/postgres
  message:  78/97 usable connection slots in use (80%); max_connections=100, 3 
reserved. By state: active=2, idle=75, idle in transaction=1. Top 
application/user: reports-api/postgres=75, orders-api/postgres=2, 
billing-worker/postgres=1.
  fix:      New connections fail with 'too many clients' at 100%. Put a pooler 
(e.g. PgBouncer in transaction mode) in front, and size application pools so the
sum across all replicas stays below the usable slots. Raising max_connections 
costs memory per backend and is not a fix on its own.

MEDIUM    PG004  max_connections
  location: postgresql://127.0.0.1:55432/postgres
  message:  75/78 client connections (96%) are idle: slots are held by pools or 
leaked connections, not by running queries.
  fix:      Lower per-instance pool max size and idle timeout, check for 
connections that are opened but never returned, and multiply pool size by 
replica count when budgeting connections.

Summary: HIGH=3  MEDIUM=1
```

Exit code 1. After the transaction was rolled back and the pool closed, the same command printed `scanned=8 findings=0 status=PASS` and exited 0.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No finding at or above `--fail-on` (default `low`) |
| 1 | At least one finding at or above `--fail-on` |
| 2 | Could not connect, query failed, or the fixture is missing or invalid (clean one-line error, no traceback) |

## Tests

- `tests/unit/test_pg_diag.py`: synthetic snapshots covering transitive chains, the CRITICAL wait threshold, prepared-transaction roots, idle-in-transaction severity, the saturation boundaries (77/97 = none, 78/97 = HIGH, 93/97 = CRITICAL), `reserved_connections`, the idle-share rule, and CLI exit codes, including an unreachable server.
- `tests/integration/test_pg_diag_integration.py`: runs against a real PostgreSQL when `PG_DIAG_TEST_DSN` is set (CI uses a `postgres:18` service container). Each problem is created for real:
  - **Lock chain:** an idle-in-transaction `UPDATE` plus two blocked writers. After rollback the test checks that the chain finding is gone.
  - **Saturation:** idle connections opened up to 85% of the usable slots.
  - **Privacy:** a live CLI run whose output must not contain the DSN password.

To check that the tests can actually fail, I broke the analyzer on purpose: once by not counting transitive waiters, once by not counting idle connections. 5 tests failed (2 integration, 3 unit) and passed again once the analyzer was restored.

```bash
docker run -d --rm --name pgdiag-it -p 127.0.0.1:55432:5432 -e POSTGRES_PASSWORD=pgdiag-test postgres:18
PG_DIAG_TEST_DSN=postgresql://postgres:pgdiag-test@127.0.0.1:55432/postgres uv run pytest -v tests/integration/test_pg_diag_integration.py
docker rm -f pgdiag-it
```

## Limitations

- A single snapshot. A lock chain that forms and clears between two snapshots is not seen; run it repeatedly, or from an alert, during an incident.
- Wait time for a blocked session is the age of its current query (`now() − query_start`), which includes any time the query ran before it started waiting.
- Saturation is measured against server limits only. Limits enforced by a pooler (PgBouncer `max_client_conn`, `default_pool_size`) or per-role/per-database `CONNECTION LIMIT` are not read.
- `pg-diag`'s own connection is excluded from the counts.
- Not covered: long-running transactions holding back vacuum (xmin horizon) and replication lag.
