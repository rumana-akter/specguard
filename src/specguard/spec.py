"""Task-specification parser.

A task specification is a TOML file written by a human (developer, QA
engineer or tech lead) before the agent starts. It names the components a
task touches and any extra resources it needs. SpecGuard treats the spec as
trusted input and the agent's later requests as untrusted.

Parsing is strict: unknown sections or keys are errors, because a typo in a
security-relevant file should fail loudly instead of silently changing scope.
"""

from __future__ import annotations

import posixpath
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .labels import Label


class SpecError(ValueError):
    """Raised when a task specification is malformed or unsafe."""


_ID_RE = re.compile(r"^[A-Z][A-Z0-9]*-\d+$")
_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
_DB_NEED_RE = re.compile(
    rf"^\s*({_IDENT})\s*\(\s*(\*|{_IDENT}(?:\s*,\s*{_IDENT})*)\s*\)\s*$"
)

KINDS = frozenset({"development", "qa"})

_SCHEMA: dict[str, frozenset[str]] = {
    "task": frozenset({"id", "title", "kind", "summary", "components"}),
    "access": frozenset({"read", "write", "kb_topics", "db", "actions"}),
    "constraints": frozenset({"max_label", "max_rows", "max_context_tokens"}),
    "acceptance": frozenset({"criteria"}),
}
_REQUIRED_TASK_KEYS = ("id", "title", "kind", "summary")


@dataclass(frozen=True)
class DbNeed:
    """A table plus the columns a task needs, e.g. ``calibration(device_id, gain)``."""

    table: str
    columns: tuple[str, ...]  # ("*",) means every column the ceiling allows

    def __str__(self) -> str:
        return f"{self.table}({', '.join(self.columns)})"


def parse_db_need(text: str) -> DbNeed:
    if not isinstance(text, str):
        raise SpecError(f"db entry must be a string, got {text!r}")
    m = _DB_NEED_RE.match(text)
    if not m:
        raise SpecError(f"db entry must look like 'table(col1, col2)' or 'table(*)': {text!r}")
    cols = tuple(c.strip() for c in m.group(2).split(","))
    return DbNeed(table=m.group(1), columns=cols)


def check_relative_path(text: str, where: str) -> str:
    """Reject absolute paths, backslashes, traversal and control characters."""
    if not isinstance(text, str) or not text:
        raise SpecError(f"{where}: path must be a non-empty string")
    if "\\" in text or "\x00" in text or any(ord(ch) < 32 for ch in text):
        raise SpecError(f"{where}: path contains forbidden characters: {text!r}")
    if text.startswith("/") or re.match(r"^[A-Za-z]:", text):
        raise SpecError(f"{where}: absolute paths are not allowed: {text!r}")
    norm = posixpath.normpath(text)
    if norm != text.rstrip("/") or norm == ".." or norm.startswith("../"):
        raise SpecError(f"{where}: path must be normalised and stay inside the repository: {text!r}")
    return norm


@dataclass(frozen=True)
class TaskSpec:
    id: str
    title: str
    kind: str
    summary: str
    components: tuple[str, ...]
    read: tuple[str, ...]
    write: tuple[str, ...]
    kb_topics: tuple[str, ...]
    db: tuple[DbNeed, ...]
    actions: tuple[str, ...]
    max_label: Label
    max_rows: int
    max_context_tokens: int
    acceptance: tuple[str, ...]
    source: str = "<string>"


def _str_list(section: dict[str, Any], key: str, where: str) -> tuple[str, ...]:
    value = section.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise SpecError(f"{where}.{key} must be a list of non-empty strings")
    return tuple(v.strip() for v in value)


def _int(section: dict[str, Any], key: str, default: int, lo: int, hi: int) -> int:
    value = section.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
        raise SpecError(f"constraints.{key} must be an integer between {lo} and {hi}")
    return value


def parse_spec_data(data: dict[str, Any], source: str = "<string>") -> TaskSpec:
    unknown_sections = set(data) - set(_SCHEMA)
    if unknown_sections:
        raise SpecError(f"unknown section(s): {sorted(unknown_sections)}")
    for name, allowed in _SCHEMA.items():
        section = data.get(name, {})
        if not isinstance(section, dict):
            raise SpecError(f"[{name}] must be a table")
        unknown = set(section) - allowed
        if unknown:
            raise SpecError(f"unknown key(s) in [{name}]: {sorted(unknown)}")

    task = data.get("task")
    if not task:
        raise SpecError("missing [task] section")
    for key in _REQUIRED_TASK_KEYS:
        if not isinstance(task.get(key), str) or not task[key].strip():
            raise SpecError(f"task.{key} is required and must be a non-empty string")
    if not _ID_RE.match(task["id"]):
        raise SpecError(f"task.id must look like 'ABC-123': {task['id']!r}")
    if task["kind"] not in KINDS:
        raise SpecError(f"task.kind must be one of {sorted(KINDS)}")

    access = data.get("access", {})
    constraints = data.get("constraints", {})
    acceptance = data.get("acceptance", {})

    read = tuple(check_relative_path(p, "access.read") for p in _str_list(access, "read", "access"))
    write = tuple(check_relative_path(p, "access.write") for p in _str_list(access, "write", "access"))
    db = tuple(parse_db_need(x) for x in _str_list(access, "db", "access"))

    try:
        max_label = Label.parse(constraints.get("max_label", "internal"))
    except ValueError as exc:
        raise SpecError(f"constraints.max_label: {exc}") from None
    if max_label >= Label.SECRET:
        raise SpecError("constraints.max_label cannot be 'secret': secrets are never granted by a task spec")

    return TaskSpec(
        id=task["id"],
        title=task["title"].strip(),
        kind=task["kind"],
        summary=task["summary"].strip(),
        components=_str_list(task, "components", "task"),
        read=read,
        write=write,
        kb_topics=_str_list(access, "kb_topics", "access"),
        db=db,
        actions=_str_list(access, "actions", "access"),
        max_label=max_label,
        max_rows=_int(constraints, "max_rows", 50, 1, 1000),
        max_context_tokens=_int(constraints, "max_context_tokens", 4000, 256, 200_000),
        acceptance=_str_list(acceptance, "criteria", "acceptance"),
        source=source,
    )


def parse_spec_text(text: str, source: str = "<string>") -> TaskSpec:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise SpecError(f"{source}: invalid TOML: {exc}") from None
    return parse_spec_data(data, source)


def load_spec(path: Path) -> TaskSpec:
    return parse_spec_text(Path(path).read_text(encoding="utf-8"), source=str(path))
