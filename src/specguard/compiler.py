"""Policy compilation for the three experimental conditions.

* ``compile_spec``      condition C: task-specification-based restrictions.
* ``compile_static``    condition B: predefined role permissions.
* ``unrestricted``      condition A: no restrictions.

``compile_spec`` is deterministic and does not consult a language model. Every
need that cannot be granted is reported as an ``Exclusion`` with a reason, so
missing permissions are visible before the agent starts instead of surfacing
later as unexplained failures.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass

from . import globmatch
from .inventory import CONTROL_DIR, Inventory
from .labels import Label
from .policy import Policy
from .spec import DbNeed, TaskSpec, parse_db_need


@dataclass(frozen=True)
class Exclusion:
    need: str
    reason: str


@dataclass(frozen=True)
class CompiledPolicy:
    policy: Policy
    excluded: tuple[Exclusion, ...]
    warnings: tuple[str, ...]


def _file_block_reason(inv: Inventory, path: str, ceiling: Label, op: str) -> str | None:
    if globmatch.match_any(inv.control_plane, path):
        return "CONTROL_PLANE"
    if globmatch.match_any(inv.datastores, path):
        return "DATASTORE_DIRECT"
    if op == "write" and globmatch.match_any(inv.protected_write, path):
        return "PROTECTED_WRITE"
    label = inv.files[path].label
    if label >= Label.SECRET:
        return "SECRET_NEVER_GRANTED"
    if label > ceiling:
        return "ABOVE_CEILING"
    return None


def _expand(inv: Inventory, pattern: str) -> list[str]:
    if globmatch.is_pattern(pattern):
        return [p for p in inv.files if globmatch.match(pattern, p)]
    return [pattern] if pattern in inv.files else []


def _expand_columns(inv: Inventory, need: DbNeed, ceiling: Label, excluded: list[Exclusion], cols: set[str]) -> None:
    table = inv.tables.get(need.table)
    if table is None:
        excluded.append(Exclusion(f"db:{need}", "UNKNOWN_TABLE"))
        return
    names = table.column_names if need.columns == ("*",) else need.columns
    for col in names:
        label = table.column_label(col)
        if label is None:
            excluded.append(Exclusion(f"col:{need.table}.{col}", "UNKNOWN_COLUMN"))
        elif label >= Label.SECRET:
            excluded.append(Exclusion(f"col:{need.table}.{col}", "SECRET_NEVER_GRANTED"))
        elif label > ceiling:
            excluded.append(Exclusion(f"col:{need.table}.{col}", "ABOVE_CEILING"))
        else:
            cols.add(f"{need.table}.{col}")


def _dedupe(items: list[Exclusion]) -> tuple[Exclusion, ...]:
    seen: dict[tuple[str, str], Exclusion] = {}
    for e in items:
        seen.setdefault((e.need, e.reason), e)
    return tuple(seen.values())


def compile_spec(spec: TaskSpec, inv: Inventory) -> CompiledPolicy:
    excluded: list[Exclusion] = []
    warnings: list[str] = []
    read: set[str] = set()
    write: set[str] = set()
    kb: set[str] = set()
    cols: set[str] = set()
    actions: set[str] = set()
    ceiling = spec.max_label

    comps = []
    for name in spec.components:
        comp = inv.components.get(name)
        if comp is None:
            excluded.append(Exclusion(f"component:{name}", "UNKNOWN_COMPONENT"))
        else:
            comps.append(comp)

    # Files: component files, explicit reads, write targets and the task's own spec.
    file_needs = [f for c in comps for f in c.files] + list(spec.read) + list(spec.write) + [f"specs/{spec.id}.toml"]
    for pattern in file_needs:
        matches = _expand(inv, pattern)
        if not matches:
            excluded.append(Exclusion(f"file:{pattern}", "UNKNOWN_RESOURCE"))
        for path in matches:
            reason = _file_block_reason(inv, path, ceiling, "read")
            if reason:
                excluded.append(Exclusion(f"file:{path}", reason))
            else:
                read.add(path)
    for pattern in spec.write:
        for path in _expand(inv, pattern):
            reason = _file_block_reason(inv, path, ceiling, "write")
            if reason:
                excluded.append(Exclusion(f"file:{path}:write", reason))
            elif path in read:
                write.add(path)

    # Knowledge base: articles whose topics intersect the task's topics.
    topics = {t for c in comps for t in c.kb_topics} | set(spec.kb_topics)
    covered: set[str] = set()
    for art in inv.articles.values():
        hit = topics & set(art.topics)
        if not hit:
            continue
        covered |= hit
        if art.label >= Label.SECRET:
            excluded.append(Exclusion(f"kb:{art.id}", "SECRET_NEVER_GRANTED"))
        elif art.label > ceiling:
            excluded.append(Exclusion(f"kb:{art.id}", "ABOVE_CEILING"))
        else:
            kb.add(art.id)
    for topic in sorted(topics - covered):
        warnings.append(f"no knowledge-base article has topic '{topic}'")

    # Database columns.
    for need in [t for c in comps for t in c.tables] + list(spec.db):
        _expand_columns(inv, need, ceiling, excluded, cols)

    # Actions.
    for name in [a for c in comps for a in c.actions] + list(spec.actions):
        act = inv.actions.get(name)
        if act is None:
            excluded.append(Exclusion(f"action:{name}", "UNKNOWN_ACTION"))
            continue
        if act.danger == "high":
            excluded.append(Exclusion(f"action:{name}", "REQUIRES_HUMAN_APPROVAL"))
            continue
        too_sensitive = [
            p for pat in act.inputs for p in _expand(inv, pat)
            if inv.files[p].label > ceiling and not globmatch.match_any(inv.datastores, p)
        ]
        if too_sensitive:
            excluded.append(Exclusion(f"action:{name}", "INPUTS_ABOVE_CEILING"))
            continue
        actions.add(name)

    policy = Policy(
        mode="spec",
        task_id=spec.id,
        read=tuple(sorted(read)),
        write=tuple(sorted(write)),
        kb=frozenset(kb),
        columns=frozenset(cols),
        actions=frozenset(actions),
        max_label=ceiling,
        max_rows=spec.max_rows,
        origin=spec.source,
    )
    return CompiledPolicy(policy, _dedupe(excluded), tuple(warnings))


def load_roles(inv: Inventory) -> dict:
    path = inv.root / CONTROL_DIR / "static_roles.toml"
    return tomllib.loads(path.read_text(encoding="utf-8")).get("roles", {})


def compile_static(role: str, inv: Inventory, task_id: str) -> CompiledPolicy:
    roles = load_roles(inv)
    if role not in roles:
        raise KeyError(f"unknown static role {role!r}")
    r = roles[role]
    ceiling = Label.parse(r.get("max_label", "confidential"))
    excluded: list[Exclusion] = []
    cols: set[str] = set()
    for text in r.get("db", []):
        _expand_columns(inv, parse_db_need(text), ceiling, excluded, cols)
    kb = frozenset(a.id for a in inv.articles.values() if a.label <= ceiling)
    policy = Policy(
        mode="static",
        task_id=task_id,
        read=tuple(sorted(r.get("read", []))),
        write=tuple(sorted(r.get("write", []))),
        kb=kb,
        columns=frozenset(cols),
        actions=frozenset(r.get("actions", [])),
        max_label=ceiling,
        max_rows=int(r.get("max_rows", 200)),
        origin=f"static_roles.toml#{role}",
    )
    return CompiledPolicy(policy, _dedupe(excluded), ())


def unrestricted(inv: Inventory, task_id: str) -> CompiledPolicy:
    policy = Policy(
        mode="unrestricted",
        task_id=task_id,
        read=("**",),
        write=("**",),
        kb=frozenset({"*"}),
        columns=frozenset({"*.*"}),
        actions=frozenset(inv.actions),
        max_label=Label.SECRET,
        max_rows=10_000,
        enforce_invariants=False,
        origin="unrestricted",
    )
    return CompiledPolicy(policy, (), ())
