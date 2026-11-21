"""Resource inventory with sensitivity labels.

The inventory is the trusted description of what exists in the repository:
files, knowledge-base articles, database tables and columns, and runnable
actions. Labels come from `.specguard/inventory.toml`, which is part of the
control plane and is never readable or writable through the agent tools.

Anything that is not in the inventory is treated as unknown and denied.
"""

from __future__ import annotations

import os
import posixpath
import re
import sqlite3
import tomllib
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from . import globmatch
from .fixtures import ensure_db
from .labels import Label
from .spec import DbNeed, parse_db_need

SKIP_DIRS = frozenset({".git", "__pycache__", "build", ".pytest_cache"})
CONTROL_DIR = ".specguard"


class InventoryError(ValueError):
    pass


@dataclass(frozen=True)
class FileInfo:
    path: str
    label: Label
    kind: str


@dataclass(frozen=True)
class Article:
    id: str
    title: str
    topics: tuple[str, ...]
    label: Label
    path: str
    body: str


@dataclass(frozen=True)
class Table:
    name: str
    label: Label
    columns: tuple[tuple[str, Label], ...]

    def column_label(self, column: str) -> Label | None:
        for name, label in self.columns:
            if name == column:
                return label
        return None

    @property
    def column_names(self) -> tuple[str, ...]:
        return tuple(name for name, _ in self.columns)


@dataclass(frozen=True)
class Component:
    name: str
    files: tuple[str, ...]
    kb_topics: tuple[str, ...]
    tables: tuple[DbNeed, ...]
    actions: tuple[str, ...]


@dataclass(frozen=True)
class Action:
    name: str
    argv: tuple[str, ...]
    inputs: tuple[str, ...]
    requires: tuple[str, ...]
    danger: str  # "low" or "high"


@dataclass(frozen=True)
class Inventory:
    root: Path
    files: Mapping[str, FileInfo]
    dirs: frozenset[str]
    articles: Mapping[str, Article]
    tables: Mapping[str, Table]
    components: Mapping[str, Component]
    actions: Mapping[str, Action]
    control_plane: tuple[str, ...]
    protected_write: tuple[str, ...]
    datastores: tuple[str, ...]
    db_path: Path
    lower_index: Mapping[str, str]

    def read_text(self, path: str) -> str | None:
        """Return file text, or None for binary files."""
        data = (self.root / path).read_bytes()
        if b"\x00" in data:
            return None
        return data.decode("utf-8", errors="replace")

    def label_of(self, resource: str) -> Label | None:
        kind, _, name = resource.partition(":")
        if kind == "file":
            info = self.files.get(name.rsplit(":", 1)[0] if name.endswith((":read", ":write")) else name)
            return info.label if info else None
        if kind == "kb":
            art = self.articles.get(name)
            return art.label if art else None
        if kind == "col":
            table, _, col = name.partition(".")
            t = self.tables.get(table)
            return t.column_label(col) if t else None
        return None


def _parse_front_matter(text: str, path: str) -> tuple[dict, str]:
    m = re.match(r"\A\+\+\+\r?\n(.*?)\r?\n\+\+\+\r?\n(.*)\Z", text, re.S)
    if not m:
        raise InventoryError(f"{path}: knowledge-base article needs a +++ TOML front matter block")
    try:
        meta = tomllib.loads(m.group(1))
    except tomllib.TOMLDecodeError as exc:
        raise InventoryError(f"{path}: bad front matter: {exc}") from None
    return meta, m.group(2)


def _walk(root: Path) -> list[str]:
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not os.path.islink(os.path.join(dirpath, d)))
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            if os.path.islink(full):
                continue  # symlinks are never inventoried, so they can never be granted
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            found.append(rel)
    return found


def load_inventory(root: Path) -> Inventory:
    root = Path(root).resolve()
    cfg_path = root / CONTROL_DIR / "inventory.toml"
    if not cfg_path.exists():
        raise InventoryError(f"missing {cfg_path}")
    cfg = tomllib.loads(cfg_path.read_text(encoding="utf-8"))
    defaults = cfg.get("defaults", {})
    unlisted = Label.parse(defaults.get("unlisted_file_label", "confidential"))
    unlisted_table = Label.parse(defaults.get("unlisted_table_label", "confidential"))
    db_rel = defaults.get("database", "data/sensorhub.db")
    db_path = ensure_db(root / db_rel)

    rules = [(r["pattern"], Label.parse(r["label"]), r.get("kind", "other")) for r in cfg.get("files", [])]

    files: dict[str, FileInfo] = {}
    articles: dict[str, Article] = {}
    for rel in _walk(root):
        label, kind = unlisted, "unclassified"
        for pattern, rlabel, rkind in rules:
            if globmatch.match(pattern, rel):
                label, kind = rlabel, rkind
                break
        if globmatch.match("kb/*.md", rel):
            meta, body = _parse_front_matter((root / rel).read_text(encoding="utf-8"), rel)
            art = Article(
                id=meta["id"],
                title=meta["title"],
                topics=tuple(meta.get("topics", [])),
                label=Label.parse(meta["label"]),
                path=rel,
                body=body,
            )
            if art.id in articles:
                raise InventoryError(f"duplicate knowledge-base id {art.id}")
            articles[art.id] = art
            label, kind = art.label, "kb"
        files[rel] = FileInfo(rel, label, kind)

    dirs = {"."}
    for rel in files:
        parent = posixpath.dirname(rel)
        while parent:
            dirs.add(parent)
            parent = posixpath.dirname(parent)

    table_cfg = cfg.get("db", {}).get("tables", {})
    tables: dict[str, Table] = {}
    conn = sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        names = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        for name in names:
            tcfg = table_cfg.get(name, {})
            tlabel = Label.parse(tcfg["label"]) if "label" in tcfg else unlisted_table
            overrides = {k: Label.parse(v) for k, v in tcfg.get("columns", {}).items()}
            cols = [r[1] for r in conn.execute(f'PRAGMA table_info("{name}")')]
            tables[name] = Table(name, tlabel, tuple((c, max(tlabel, overrides.get(c, tlabel))) for c in cols))
    finally:
        conn.close()

    components = {
        name: Component(
            name=name,
            files=tuple(c.get("files", [])),
            kb_topics=tuple(c.get("kb_topics", [])),
            tables=tuple(parse_db_need(t) for t in c.get("tables", [])),
            actions=tuple(c.get("actions", [])),
        )
        for name, c in cfg.get("components", {}).items()
    }

    actions: dict[str, Action] = {}
    act_path = root / CONTROL_DIR / "actions.toml"
    if act_path.exists():
        for name, a in tomllib.loads(act_path.read_text(encoding="utf-8")).get("actions", {}).items():
            danger = a.get("danger", "high")
            if danger not in ("low", "high"):
                raise InventoryError(f"action {name}: danger must be 'low' or 'high'")
            actions[name] = Action(name, tuple(a["argv"]), tuple(a.get("inputs", [])), tuple(a.get("requires", [])), danger)

    control = tuple(defaults.get("control_plane", [f"{CONTROL_DIR}/**"]))
    if f"{CONTROL_DIR}/**" not in control:
        control = control + (f"{CONTROL_DIR}/**",)

    return Inventory(
        root=root,
        files=MappingProxyType(files),
        dirs=frozenset(dirs),
        articles=MappingProxyType(articles),
        tables=MappingProxyType(tables),
        components=MappingProxyType(components),
        actions=MappingProxyType(actions),
        control_plane=control,
        protected_write=tuple(defaults.get("protected_write", [])),
        datastores=tuple(defaults.get("datastores", [])),
        db_path=db_path,
        lower_index=MappingProxyType({p.lower(): p for p in list(files) + list(dirs)}),
    )
