"""Hash-chained audit trail that records decisions, never content.

Each record is built from an allow-list of fields. File contents, query
results, SQL text and free-text justifications are never stored: SQL is
recorded as a truncated SHA-256 fingerprint plus the columns it touched, and
free text as its length only. Each record carries the hash of the previous
one, so editing or deleting a record breaks verification.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

FIELDS = frozenset({
    "seq", "ts", "session", "task_id", "mode", "policy_digest", "tool", "resource",
    "status", "reason", "label", "bytes_out", "sql_fp", "columns", "text_len",
    "duration_us", "prev", "hash",
})
GENESIS = "0" * 64


def _entry_hash(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    blob = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(blob).hexdigest()


class AuditLog:
    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else None
        self.entries: list[dict[str, Any]] = []
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text("", encoding="utf-8")

    def record(self, **fields: Any) -> dict[str, Any]:
        unknown = set(fields) - FIELDS
        if unknown:
            raise ValueError(f"audit fields not allowed: {sorted(unknown)}")
        entry = {k: v for k, v in fields.items() if v is not None}
        entry["seq"] = len(self.entries) + 1
        entry["ts"] = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        entry["prev"] = self.entries[-1]["hash"] if self.entries else GENESIS
        entry["hash"] = _entry_hash(entry)
        self.entries.append(entry)
        if self.path:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry


def verify_chain(entries: Iterable[dict[str, Any]]) -> tuple[bool, int | None]:
    """Return (True, None) if intact, else (False, seq of the first bad record)."""
    prev = GENESIS
    for entry in entries:
        if entry.get("prev") != prev or entry.get("hash") != _entry_hash(entry):
            return False, entry.get("seq")
        prev = entry["hash"]
    return True, None


def load(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
