"""Read-only SQL access enforced inside SQLite.

Enforcement does not parse SQL text with regular expressions. It uses
SQLite's authorizer callback, which the engine invokes while compiling a
statement for every table and column read, every function call and every
other operation. Anything that is not an allowed column read, a SELECT or a
function from a small allow-list is denied. The connection is also opened in
read-only mode, and a progress handler bounds execution time.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .policy import DENY_INVALID_ARGUMENTS, DENY_SQL_ERROR, DENY_SQL_OPERATION, Decision

SAFE_FUNCTIONS = frozenset({
    "count", "sum", "avg", "min", "max", "total", "abs", "round", "lower", "upper",
    "length", "coalesce", "ifnull", "nullif", "substr", "substring", "trim", "instr",
    "date", "time", "datetime", "julianday", "strftime", "group_concat",
})
MAX_SQL_CHARS = 4000
MAX_VM_CALLBACKS = 2000  # progress handler fires every 10,000 VM steps


@dataclass
class QueryOutcome:
    allowed: bool
    reason: str
    detail: str = ""
    header: list[str] = field(default_factory=list)
    rows: list[tuple] = field(default_factory=list)
    truncated: bool = False
    touched: set[tuple[str, str]] = field(default_factory=set)

    @property
    def tables(self) -> set[str]:
        return {t for t, _ in self.touched}


def sql_fingerprint(sql: str) -> str:
    return hashlib.sha256(sql.encode("utf-8", errors="replace")).hexdigest()[:16]


def run_query(db_path: Path, sql: str, column_check: Callable[[str, str], Decision], max_rows: int) -> QueryOutcome:
    if not isinstance(sql, str) or not sql.strip() or len(sql) > MAX_SQL_CHARS:
        return QueryOutcome(False, DENY_INVALID_ARGUMENTS, "sql must be a non-empty string under 4000 characters")

    denials: list[str] = []
    touched: set[tuple[str, str]] = set()

    def authorizer(action: int, arg1, arg2, dbname, _source) -> int:
        if action == sqlite3.SQLITE_SELECT:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_READ:
            if dbname not in ("main", None):
                denials.append(f"{DENY_SQL_OPERATION}:schema {dbname}")
                return sqlite3.SQLITE_DENY
            touched.add((arg1, arg2 or ""))
            decision = column_check(arg1, arg2 or "")
            if not decision.allowed:
                denials.append(f"{decision.reason}:{decision.resource}")
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_FUNCTION:
            if (arg2 or "").lower() in SAFE_FUNCTIONS:
                return sqlite3.SQLITE_OK
            denials.append(f"{DENY_SQL_OPERATION}:function {arg2}")
            return sqlite3.SQLITE_DENY
        denials.append(f"{DENY_SQL_OPERATION}:action {action}")
        return sqlite3.SQLITE_DENY

    steps = 0

    def progress() -> int:
        nonlocal steps
        steps += 1
        return 1 if steps > MAX_VM_CALLBACKS else 0

    conn = sqlite3.connect(Path(db_path).resolve().as_uri() + "?mode=ro", uri=True)
    try:
        conn.set_authorizer(authorizer)
        conn.set_progress_handler(progress, 10_000)
        try:
            cur = conn.execute(sql)
            rows = cur.fetchmany(max_rows + 1)
        except (sqlite3.DatabaseError, sqlite3.Warning, sqlite3.ProgrammingError) as exc:
            if denials:
                reason, _, detail = denials[0].partition(":")
                return QueryOutcome(False, reason, detail, touched=touched)
            return QueryOutcome(False, DENY_SQL_ERROR, type(exc).__name__ + ": " + str(exc)[:200], touched=touched)
        header = [d[0] for d in (cur.description or [])]
    finally:
        conn.close()
    truncated = len(rows) > max_rows
    return QueryOutcome(True, "ALLOW_GRANTED", header=header, rows=rows[:max_rows], truncated=truncated, touched=touched)


def columns_touched(db_path: Path, sql: str) -> set[tuple[str, str]]:
    """Record the (table, column) pairs a query reads, allowing everything. Used for ground truth."""
    allow_all = lambda t, c: Decision(True, "ALLOW_GRANTED", f"col:{t}.{c}")  # noqa: E731
    out = run_query(db_path, sql, allow_all, 10_000)
    return {(t, c) for t, c in out.touched if c}


def format_rows(header: list[str], rows: list[tuple], truncated: bool) -> str:
    lines = ["\t".join(header)]
    lines += ["\t".join("" if v is None else str(v) for v in row) for row in rows]
    if truncated:
        lines.append(f"... truncated at {len(rows)} rows by policy")
    return "\n".join(lines)
