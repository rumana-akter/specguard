"""Immutable policy objects and the deterministic decision engine.

The engine is ordinary Python code that runs outside the language model. The
agent can only reach it through the tool gateway, which exposes no operation
that changes a policy. A policy is a frozen dataclass of frozensets, and its
SHA-256 digest is written into every audit record so that any change to the
policy during a session would be visible in the log.

Limitation: in-process immutability is not a security boundary. Code running
in the same Python process could still bypass it. A deployment would run the
engine in a separate process (for example behind an MCP server) and confine
the agent process with an OS mechanism such as Capsicum or Landlock.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from . import globmatch
from .inventory import Inventory
from .labels import Label

# Reason codes. Stable strings so that tests, audit logs and reports agree.
ALLOW = "ALLOW_GRANTED"
DENY_NOT_GRANTED = "DENY_NOT_GRANTED"
DENY_UNKNOWN_RESOURCE = "DENY_UNKNOWN_RESOURCE"
DENY_INVALID_PATH = "DENY_INVALID_PATH"
DENY_NONCANONICAL_PATH = "DENY_NONCANONICAL_PATH"
DENY_CONTROL_PLANE = "DENY_CONTROL_PLANE"
DENY_DATASTORE_DIRECT = "DENY_DATASTORE_DIRECT"
DENY_PROTECTED_WRITE = "DENY_PROTECTED_WRITE"
DENY_ABOVE_CEILING = "DENY_ABOVE_CEILING"
DENY_REQUIRES_HUMAN = "DENY_REQUIRES_HUMAN_APPROVAL"
DENY_UNKNOWN_TOOL = "DENY_UNKNOWN_TOOL"
DENY_INVALID_ARGUMENTS = "DENY_INVALID_ARGUMENTS"
DENY_SQL_OPERATION = "DENY_SQL_OPERATION"
DENY_SQL_ERROR = "DENY_SQL_ERROR"
UNAVAILABLE_TOOLCHAIN = "UNAVAILABLE_TOOLCHAIN"
ESCALATION_RECORDED = "ESCALATION_RECORDED"


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    resource: str
    label: Label | None = None


@dataclass(frozen=True)
class Policy:
    mode: str  # "unrestricted", "static" or "spec"
    task_id: str
    read: tuple[str, ...]  # glob patterns over repository paths
    write: tuple[str, ...]
    kb: frozenset[str]  # article ids, or {"*"}
    columns: frozenset[str]  # "table.column", "table.*" or "*.*"
    actions: frozenset[str]
    max_label: Label
    max_rows: int
    enforce_invariants: bool = True  # False only for the unrestricted baseline
    origin: str = field(default="", compare=False)

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "task_id": self.task_id,
            "read": sorted(self.read),
            "write": sorted(self.write),
            "kb": sorted(self.kb),
            "columns": sorted(self.columns),
            "actions": sorted(self.actions),
            "max_label": self.max_label.name.lower(),
            "max_rows": self.max_rows,
            "enforce_invariants": self.enforce_invariants,
        }

    @property
    def digest(self) -> str:
        blob = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(blob).hexdigest()


class PolicyEngine:
    """Pure decision functions: same policy, inventory and request give the same answer."""

    def __init__(self, policy: Policy, inventory: Inventory) -> None:
        self._policy = policy
        self._inv = inventory

    @property
    def policy(self) -> Policy:
        return self._policy

    # Files --------------------------------------------------------------
    def file(self, path: str, op: str) -> Decision:
        if op not in ("read", "write"):
            raise ValueError(op)
        rid = f"file:{path}"
        info = self._inv.files.get(path)
        if info is None:
            return Decision(False, DENY_UNKNOWN_RESOURCE, rid)
        p = self._policy
        if p.enforce_invariants:
            if globmatch.match_any(self._inv.control_plane, path):
                return Decision(False, DENY_CONTROL_PLANE, rid, info.label)
            if globmatch.match_any(self._inv.datastores, path):
                return Decision(False, DENY_DATASTORE_DIRECT, rid, info.label)
            if op == "write" and globmatch.match_any(self._inv.protected_write, path):
                return Decision(False, DENY_PROTECTED_WRITE, rid, info.label)
            if info.label > p.max_label:
                return Decision(False, DENY_ABOVE_CEILING, rid, info.label)
        patterns = p.read if op == "read" else p.write
        if globmatch.match_any(patterns, path):
            return Decision(True, ALLOW, rid, info.label)
        return Decision(False, DENY_NOT_GRANTED, rid, info.label)

    # Knowledge base -------------------------------------------------------
    def kb(self, article_id: str) -> Decision:
        rid = f"kb:{article_id}"
        art = self._inv.articles.get(article_id)
        if art is None:
            return Decision(False, DENY_UNKNOWN_RESOURCE, rid)
        p = self._policy
        if p.enforce_invariants and art.label > p.max_label:
            return Decision(False, DENY_ABOVE_CEILING, rid, art.label)
        if "*" in p.kb or article_id in p.kb:
            return Decision(True, ALLOW, rid, art.label)
        return Decision(False, DENY_NOT_GRANTED, rid, art.label)

    # Database -------------------------------------------------------------
    def column(self, table: str, column: str) -> Decision:
        """Decide a read of ``table.column``. An empty column means a table-level reference."""
        rid = f"col:{table}.{column or '<table>'}"
        t = self._inv.tables.get(table)
        if t is None:
            return Decision(False, DENY_UNKNOWN_RESOURCE, rid)
        p = self._policy
        if not column:
            granted = any(self.column(table, c).allowed for c in t.column_names)
            return Decision(granted, ALLOW if granted else DENY_NOT_GRANTED, rid, t.label)
        label = t.column_label(column)
        if label is None:
            return Decision(False, DENY_UNKNOWN_RESOURCE, rid)
        if p.enforce_invariants and label > p.max_label:
            return Decision(False, DENY_ABOVE_CEILING, rid, label)
        if {"*.*", f"{table}.*", f"{table}.{column}"} & p.columns:
            return Decision(True, ALLOW, rid, label)
        return Decision(False, DENY_NOT_GRANTED, rid, label)

    # Actions --------------------------------------------------------------
    def action(self, name: str) -> Decision:
        rid = f"action:{name}"
        act = self._inv.actions.get(name)
        if act is None:
            return Decision(False, DENY_UNKNOWN_RESOURCE, rid)
        p = self._policy
        if p.enforce_invariants and act.danger == "high":
            return Decision(False, DENY_REQUIRES_HUMAN, rid)
        if name in p.actions:
            return Decision(True, ALLOW, rid)
        return Decision(False, DENY_NOT_GRANTED, rid)
