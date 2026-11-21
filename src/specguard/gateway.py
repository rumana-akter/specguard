"""The sandboxed tool interface that an agent talks to.

Every request goes through ``ToolGateway.call(tool, args)``. The gateway
validates arguments, canonicalises paths, asks the policy engine, performs the
operation only if allowed, and writes one audit record per call. Unknown tools
and unexpected arguments are denied (default deny). No tool can read or change
the policy, the inventory or the audit log.
"""

from __future__ import annotations

import posixpath
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from . import dbguard, executor
from .audit import AuditLog
from .inventory import Inventory
from .policy import (
    ALLOW, DENY_INVALID_ARGUMENTS, DENY_INVALID_PATH, DENY_NONCANONICAL_PATH, DENY_NOT_GRANTED,
    DENY_UNKNOWN_RESOURCE, DENY_UNKNOWN_TOOL, ESCALATION_RECORDED, UNAVAILABLE_TOOLCHAIN,
    Decision, Policy, PolicyEngine,
)

MAX_WRITE_BYTES = 64 * 1024
_WORD = re.compile(r"[a-z0-9]+")
_RESOURCE_ID = re.compile(r"^(file|kb|col|db|action):[A-Za-z0-9_./*\-]{1,200}$")

TOOL_ARGS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    # tool: (required args, optional args)
    "read_file": (frozenset({"path"}), frozenset()),
    "list_dir": (frozenset({"path"}), frozenset()),
    "write_file": (frozenset({"path", "content"}), frozenset()),
    "search_kb": (frozenset({"query"}), frozenset({"k"})),
    "read_kb": (frozenset({"id"}), frozenset()),
    "db_schema": (frozenset(), frozenset()),
    "query_db": (frozenset({"sql"}), frozenset()),
    "run_action": (frozenset({"name"}), frozenset()),
    "request_access": (frozenset({"resource", "justification"}), frozenset()),
}


@dataclass
class ToolResult:
    status: str  # "allowed", "denied", "unavailable", "escalated", "failed"
    reason: str
    content: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == "allowed"


def canonical_path(inv: Inventory, raw: Any, want_dir: bool = False) -> tuple[str | None, str]:
    if not isinstance(raw, str) or not raw or "\x00" in raw or len(raw) > 512:
        return None, DENY_INVALID_PATH
    text = raw.replace("\\", "/")
    if text.startswith("/") or re.match(r"^[A-Za-z]:", text) or text.startswith("~"):
        return None, DENY_INVALID_PATH
    norm = posixpath.normpath(text)
    if norm == ".." or norm.startswith("../"):
        return None, DENY_INVALID_PATH
    index = inv.dirs if want_dir else inv.files
    if norm in index:
        return norm, ALLOW
    if norm.lower() in inv.lower_index:
        # On case-insensitive file systems this would open a real file under a
        # different spelling and could dodge case-sensitive patterns.
        return None, DENY_NONCANONICAL_PATH
    return None, DENY_UNKNOWN_RESOURCE


def tokens(text: str) -> set[str]:
    return set(_WORD.findall(text.lower()))


class ToolGateway:
    def __init__(self, policy: Policy, inventory: Inventory, audit: AuditLog | None = None,
                 *, execute_actions: bool = True, session: str | None = None) -> None:
        self._engine = PolicyEngine(policy, inventory)
        self._inv = inventory
        self._audit = audit or AuditLog()
        self._execute = execute_actions
        self._session = session or uuid.uuid4().hex[:12]
        self._overlay: dict[str, str] = {}
        self.escalations: list[dict[str, str]] = []

    @property
    def policy_digest(self) -> str:
        return self._engine.policy.digest

    @property
    def audit(self) -> AuditLog:
        return self._audit

    # Public entry point -------------------------------------------------
    def call(self, tool: str, args: dict[str, Any] | None = None) -> ToolResult:
        args = dict(args or {})
        start = time.perf_counter_ns()
        audit_extra: dict[str, Any] = {}
        resource = ""
        if tool not in TOOL_ARGS:
            result = ToolResult("denied", DENY_UNKNOWN_TOOL)
        else:
            required, optional = TOOL_ARGS[tool]
            if not required <= set(args) or set(args) - required - optional:
                result = ToolResult("denied", DENY_INVALID_ARGUMENTS)
            else:
                handler = getattr(self, f"_t_{tool}")
                result, resource, audit_extra = handler(**args)
        duration_us = (time.perf_counter_ns() - start) // 1000
        result.meta["duration_us"] = duration_us
        p = self._engine.policy
        self._audit.record(
            session=self._session, task_id=p.task_id, mode=p.mode, policy_digest=p.digest,
            tool=tool if tool in TOOL_ARGS else "<unknown>", resource=resource,
            status=result.status, reason=result.reason,
            bytes_out=len(result.content.encode()) if result.content else 0,
            duration_us=duration_us, **audit_extra,
        )
        return result

    # Helpers ------------------------------------------------------------
    @staticmethod
    def _deny(d: Decision) -> ToolResult:
        return ToolResult("denied", d.reason)

    # Files --------------------------------------------------------------
    def _t_read_file(self, path):
        canon, why = canonical_path(self._inv, path)
        if canon is None:
            return ToolResult("denied", why), "file:<invalid>", {}
        d = self._engine.file(canon, "read")
        extra = {"label": d.label.name.lower() if d.label is not None else None}
        if not d.allowed:
            return self._deny(d), d.resource, extra
        text = self._overlay.get(canon)
        if text is None:
            text = self._inv.read_text(canon)
        if text is None:
            return ToolResult("allowed", ALLOW, "[binary file not displayed]", {"delivered": []}), d.resource, extra
        return ToolResult("allowed", ALLOW, text, {"delivered": [d.resource]}), d.resource, extra

    def _t_list_dir(self, path):
        canon, why = canonical_path(self._inv, path, want_dir=True)
        if canon is None:
            return ToolResult("denied", why), "dir:<invalid>", {}
        prefix = "" if canon == "." else canon + "/"
        visible: set[str] = set()
        for f in self._inv.files:
            if f.startswith(prefix) and self._engine.file(f, "read").allowed:
                rest = f[len(prefix):]
                visible.add(rest.split("/", 1)[0] + ("/" if "/" in rest else ""))
        rid = f"dir:{canon}"
        if not visible:
            return ToolResult("denied", DENY_NOT_GRANTED), rid, {}
        # Only entries the agent may read are listed; others are not revealed.
        return ToolResult("allowed", ALLOW, "\n".join(sorted(visible)), {"delivered": []}), rid, {}

    def _t_write_file(self, path, content):
        canon, why = canonical_path(self._inv, path)
        if canon is None:
            return ToolResult("denied", why), "file:<invalid>", {}
        d = self._engine.file(canon, "write")
        if not d.allowed:
            return self._deny(d), d.resource, {}
        if not isinstance(content, str) or len(content.encode()) > MAX_WRITE_BYTES:
            return ToolResult("denied", DENY_INVALID_ARGUMENTS), d.resource, {}
        self._overlay[canon] = content
        return ToolResult("allowed", ALLOW, None, {"written": canon}), d.resource, {"text_len": len(content)}

    # Knowledge base -------------------------------------------------------
    def _t_search_kb(self, query, k=3):
        if not isinstance(query, str) or not isinstance(k, int) or not 1 <= k <= 10:
            return ToolResult("denied", DENY_INVALID_ARGUMENTS), "kb:<search>", {}
        q = tokens(query)
        # Authorization first: unauthorised articles are removed before
        # ranking, so they cannot influence scores, counts or snippets.
        scored = []
        for art in self._inv.articles.values():
            if not self._engine.kb(art.id).allowed:
                continue
            words = tokens(art.title + " " + " ".join(art.topics) + " " + art.body)
            score = len(q & words) + 2 * len(q & tokens(" ".join(art.topics)))
            if score:
                scored.append((-score, art.id, art))
        scored.sort()
        hits = [a for _, _, a in scored[:k]]
        if not hits:
            return ToolResult("allowed", ALLOW, "(no matching articles you are permitted to read)", {"delivered": [], "returned": []}), "kb:<search>", {}
        body = "\n\n".join(f"## {a.id}: {a.title}\n{a.body.strip()}" for a in hits)
        ids = [a.id for a in hits]
        return ToolResult("allowed", ALLOW, body, {"delivered": [f"kb:{i}" for i in ids], "returned": ids}), "kb:<search>", {"text_len": len(query)}

    def _t_read_kb(self, id):
        if not isinstance(id, str):
            return ToolResult("denied", DENY_INVALID_ARGUMENTS), "kb:<invalid>", {}
        d = self._engine.kb(id)
        extra = {"label": d.label.name.lower() if d.label is not None else None}
        if not d.allowed:
            # Never echo an unknown, agent-supplied identifier into the audit log.
            rid = d.resource if id in self._inv.articles else "kb:<unknown>"
            return self._deny(d), rid, extra
        art = self._inv.articles[id]
        return ToolResult("allowed", ALLOW, f"## {art.id}: {art.title}\n{art.body.strip()}", {"delivered": [d.resource], "returned": [id]}), d.resource, extra

    # Database -------------------------------------------------------------
    def _t_db_schema(self):
        lines = []
        for t in self._inv.tables.values():
            cols = [c for c in t.column_names if self._engine.column(t.name, c).allowed]
            if cols:
                lines.append(f"{t.name}({', '.join(cols)})")
        text = "\n".join(lines) if lines else "(no tables granted)"
        return ToolResult("allowed", ALLOW, text, {"delivered": []}), "db:<schema>", {}

    def _t_query_db(self, sql):
        out = dbguard.run_query(self._inv.db_path, sql, self._engine.column, self._engine.policy.max_rows)
        extra = {
            "sql_fp": dbguard.sql_fingerprint(sql) if isinstance(sql, str) else None,
            "columns": sorted(f"{t}.{c or '<table>'}" for t, c in out.touched),
        }
        resource = "db:" + ",".join(sorted(out.tables)) if out.tables else "db:<query>"
        if not out.allowed:
            return ToolResult("denied", out.reason, None, {"detail": out.detail}), resource, extra
        content = dbguard.format_rows(out.header, out.rows, out.truncated)
        meta = {"delivered": [f"db:{t}" for t in sorted(out.tables)], "rows": len(out.rows), "truncated": out.truncated}
        return ToolResult("allowed", ALLOW, content, meta), resource, extra

    # Execution ------------------------------------------------------------
    def _t_run_action(self, name):
        if not isinstance(name, str):
            return ToolResult("denied", DENY_INVALID_ARGUMENTS), "action:<invalid>", {}
        d = self._engine.action(name)
        if not d.allowed:
            rid = d.resource if name in self._inv.actions else "action:<unknown>"
            return self._deny(d), rid, {}
        outcome = executor.run(self._inv.actions[name], self._engine.policy, self._inv, dict(self._overlay), self._execute)
        if outcome.status == "unavailable":
            return ToolResult("unavailable", UNAVAILABLE_TOOLCHAIN, outcome.output, {"delivered": []}), d.resource, {}
        status = "allowed" if outcome.status == "ok" else "failed"
        meta = {"delivered": [d.resource], "exit_code": outcome.exit_code, "exec_status": outcome.status,
                "workspace_files": outcome.files_in_workspace}
        return ToolResult(status, ALLOW, outcome.output, meta), d.resource, {}

    # Missing permissions ----------------------------------------------------
    def _t_request_access(self, resource, justification):
        if not isinstance(resource, str) or not isinstance(justification, str):
            return ToolResult("denied", DENY_INVALID_ARGUMENTS), "request:<invalid>", {}
        # Recorded for a human to review. Never granted inside the session.
        # The resource string is agent-supplied; log it only if it is a well-formed id.
        safe = resource if _RESOURCE_ID.match(resource) else "<unparsed>"
        self.escalations.append({"resource": safe})
        msg = ("Access request recorded for human review. It does not change this session's policy; "
               "a new spec must be approved and compiled to widen scope.")
        return ToolResult("escalated", ESCALATION_RECORDED, msg), f"request:{safe}", {"text_len": len(justification)}
