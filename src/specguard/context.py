"""Task-relevant context selection and context-volume accounting.

Token counts use a documented approximation (one token per four characters)
so that results do not depend on a particular tokenizer. Absolute values are
therefore rough; comparisons between conditions use the same estimator.
"""

from __future__ import annotations

from dataclasses import dataclass

from .gateway import tokens
from .inventory import Inventory
from .policy import PolicyEngine
from .spec import TaskSpec


def approx_tokens(text: str) -> int:
    return (len(text) + 3) // 4


@dataclass(frozen=True)
class ContextItem:
    resource: str
    tokens: int
    score: float
    included: bool
    why: str


def select_context(spec: TaskSpec, engine: PolicyEngine, inv: Inventory) -> list[ContextItem]:
    """Rank permitted text resources for a task and fill the spec's token budget.

    Selection only ever chooses from what the policy already permits, so it
    reduces context volume but cannot widen access.
    """
    query = tokens(spec.title + " " + spec.summary)
    comp_files = {f for c in spec.components if c in inv.components for f in inv.components[c].files}
    candidates: list[tuple[float, str, int, str]] = []
    for path, info in inv.files.items():
        if info.kind == "kb" or not engine.file(path, "read").allowed:
            continue
        text = inv.read_text(path)
        if text is None:
            continue
        score = len(query & tokens(text)) / 10
        why = "term overlap"
        if path in spec.write:
            score, why = score + 3, "write target"
        elif path in comp_files:
            score, why = score + 2, "component file"
        elif path == f"specs/{spec.id}.toml":
            score, why = score + 4, "task specification"
        candidates.append((score, f"file:{path}", approx_tokens(text), why))
    for art in inv.articles.values():
        if not engine.kb(art.id).allowed:
            continue
        score = len(query & tokens(art.title + " " + art.body)) / 10 + 1
        candidates.append((score, f"kb:{art.id}", approx_tokens(art.body), "topic match"))
    candidates.sort(key=lambda c: (-c[0], c[1]))
    used = 0
    items = []
    for score, rid, tok, why in candidates:
        fits = used + tok <= spec.max_context_tokens
        if fits:
            used += tok
        items.append(ContextItem(rid, tok, round(score, 2), fits, why))
    return items


def reachable_tokens(engine: PolicyEngine, inv: Inventory) -> int:
    """Total approximate tokens of all text the policy lets the agent read."""
    total = 0
    for path, info in inv.files.items():
        if info.kind == "kb":
            continue  # counted once below via the knowledge-base tools
        if engine.file(path, "read").allowed:
            text = inv.read_text(path)
            if text is not None:
                total += approx_tokens(text)
    for art in inv.articles.values():
        if engine.kb(art.id).allowed:
            total += approx_tokens(art.body)
    return total
