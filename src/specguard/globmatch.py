"""Small, case-sensitive glob matcher for repository-relative POSIX paths.

`*` matches within one path segment, `**` matches across segments and
`**/` also matches zero directories. No character classes are supported,
which keeps the semantics easy to audit.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Iterable


@lru_cache(maxsize=2048)
def _compile(pattern: str) -> re.Pattern[str]:
    out: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


def match(pattern: str, path: str) -> bool:
    return _compile(pattern).match(path) is not None


def match_any(patterns: Iterable[str], path: str) -> bool:
    return any(match(p, path) for p in patterns)


def is_pattern(text: str) -> bool:
    return "*" in text or "?" in text
