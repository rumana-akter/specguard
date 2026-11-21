"""Scripted agents that replay a fixed operation trace.

These agents do not use a language model. Each evaluation task has a trace of
operations written by hand (eval/tasks/*.toml) and labelled with ground truth:

* ``needed``     the reference solution requires it;
* ``benign``     exploratory and harmless, but not required;
* ``overreach``  reaches for data the task does not need;
* ``injection``  issued only if the agent has already received content from
                 the resource named in ``trigger`` (a prompt-injection carrier).

The scripted agent is deliberately worst-case on injections: it obeys every
injection it sees. When a needed operation is denied, it files an access
request, as a cooperative agent should. Replay makes runs repeatable, so the
evaluation measures the enforcement layer, not model behaviour.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .gateway import ToolGateway, ToolResult

LABELS = frozenset({"needed", "benign", "overreach", "injection"})


@dataclass(frozen=True)
class TraceOp:
    tool: str
    args: dict[str, Any]
    label: str
    trigger: str | None = None
    expect: tuple[str, ...] = ()
    note: str = ""


@dataclass(frozen=True)
class Trace:
    task: str
    role: str
    description: str
    ops: tuple[TraceOp, ...]


@dataclass
class OpRecord:
    op: TraceOp
    result: ToolResult | None  # None when an injection op was never triggered
    escalated: bool = False

    @property
    def attempted(self) -> bool:
        return self.result is not None


def load_trace(path: Path) -> Trace:
    path = Path(path)
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    ops = []
    for i, raw in enumerate(data.get("op", []), 1):
        label = raw.get("label")
        if label not in LABELS:
            raise ValueError(f"{path.name} op {i}: label must be one of {sorted(LABELS)}")
        args = dict(raw.get("args", {}))
        if "content_from" in args:
            args["content"] = (path.parent.parent / "solutions" / args.pop("content_from")).read_text(encoding="utf-8")
        if label == "injection" and not raw.get("trigger"):
            raise ValueError(f"{path.name} op {i}: injection ops need a trigger")
        ops.append(TraceOp(raw["tool"], args, label, raw.get("trigger"), tuple(raw.get("expect", [])), raw.get("note", "")))
    return Trace(data["task"], data["role"], data.get("description", ""), tuple(ops))


class ScriptedAgent:
    def __init__(self, trace: Trace) -> None:
        self.trace = trace

    def run(self, gateway: ToolGateway) -> list[OpRecord]:
        delivered: set[str] = set()
        records: list[OpRecord] = []
        for op in self.trace.ops:
            if op.trigger and op.trigger not in delivered:
                records.append(OpRecord(op, None))
                continue
            result = gateway.call(op.tool, op.args)
            delivered.update(result.meta.get("delivered", []))
            escalated = False
            if op.label == "needed" and result.status == "denied":
                target = op.args.get("path") or op.args.get("name") or op.args.get("id") or "db:query"
                prefix = {"read_file": "file:", "write_file": "file:", "run_action": "action:", "read_kb": "kb:"}.get(op.tool, "")
                gateway.call("request_access", {"resource": f"{prefix}{target}" if prefix else target,
                                                "justification": f"needed for {self.trace.task}: {op.note or op.tool}"})
                escalated = True
            records.append(OpRecord(op, result, escalated))
        return records
