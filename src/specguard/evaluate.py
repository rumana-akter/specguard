"""Evaluation harness comparing three access conditions on the same tasks.

A  unrestricted   every resource and action is available.
B  static         predefined role permissions (developer or qa).
C  spec           permissions compiled from the task specification.

All three replay the same scripted traces against the same fictional
repository, so differences come only from the access policy. Ground truth is
the label on each trace operation. See docs/evaluation.md for definitions.
"""

from __future__ import annotations

import csv
import json
import platform
import re
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .agents import OpRecord, ScriptedAgent, Trace, load_trace
from .audit import AuditLog, verify_chain
from .compiler import CompiledPolicy, compile_spec, compile_static, unrestricted
from .context import approx_tokens, reachable_tokens
from .dbguard import columns_touched
from .gateway import ToolGateway
from .inventory import Inventory
from .labels import Label
from .policy import PolicyEngine
from .spec import load_spec

MODES = ("unrestricted", "static", "spec")
CANARY_RE = re.compile(r"CANARY-[A-Z]+-[A-Z0-9]+")


def build_policy(mode: str, trace: Trace, inv: Inventory) -> CompiledPolicy:
    if mode == "spec":
        return compile_spec(load_spec(inv.root / "specs" / f"{trace.task}.toml"), inv)
    if mode == "static":
        return compile_static(trace.role, inv, trace.task)
    if mode == "unrestricted":
        return unrestricted(inv, trace.task)
    raise ValueError(mode)


def needed_resources(trace: Trace, inv: Inventory) -> set[str]:
    out: set[str] = set()
    for op in trace.ops:
        if op.label != "needed":
            continue
        a = op.args
        if op.tool == "read_file":
            out.add(f"file:{a['path']}:read")
        elif op.tool == "write_file":
            out.add(f"file:{a['path']}:write")
        elif op.tool == "search_kb":
            out.update(f"kb:{i}" for i in op.expect)
        elif op.tool == "read_kb":
            out.add(f"kb:{a['id']}")
        elif op.tool == "query_db":
            out.update(f"col:{t}.{c}" for t, c in columns_touched(inv.db_path, a["sql"]))
        elif op.tool == "run_action":
            out.add(f"action:{a['name']}")
    return out


def granted_resources(engine: PolicyEngine, inv: Inventory) -> set[str]:
    out: set[str] = set()
    for path in inv.files:
        if engine.file(path, "read").allowed:
            out.add(f"file:{path}:read")
        if engine.file(path, "write").allowed:
            out.add(f"file:{path}:write")
    out.update(f"kb:{a}" for a in inv.articles if engine.kb(a).allowed)
    for t in inv.tables.values():
        out.update(f"col:{t.name}.{c}" for c in t.column_names if engine.column(t.name, c).allowed)
    out.update(f"action:{n}" for n in inv.actions if engine.action(n).allowed)
    return out


def is_sensitive(resource: str, inv: Inventory) -> bool:
    if resource.startswith("action:"):
        return inv.actions[resource[7:]].danger == "high"
    label = inv.label_of(resource)
    return label is not None and label >= Label.CONFIDENTIAL


@dataclass
class RunResult:
    row: dict[str, Any]
    records: list[OpRecord]
    compiled: CompiledPolicy
    gateway: ToolGateway


def run_one(mode: str, trace: Trace, inv: Inventory, *, execute: bool = True, audit_path: Path | None = None) -> RunResult:
    compiled = build_policy(mode, trace, inv)
    engine = PolicyEngine(compiled.policy, inv)
    gateway = ToolGateway(compiled.policy, inv, AuditLog(audit_path), execute_actions=execute,
                          session=f"{mode}-{trace.task}")
    records = ScriptedAgent(trace).run(gateway)

    def by(label: str) -> list[OpRecord]:
        return [r for r in records if r.op.label == label]

    needed = by("needed")
    false_denials = [r for r in needed if r.result.status == "denied"]
    kb_missing = 0
    for r in needed:
        if r.op.tool == "search_kb" and r.result.ok:
            kb_missing += len(set(r.op.expect) - set(r.result.meta.get("returned", [])))
    unauthorized = [r for r in by("overreach") + by("injection") if r.attempted]
    injections = [r for r in by("injection") if r.attempted]
    delivered_text = "\n".join(r.result.content or "" for r in records if r.attempted and r.result.status in ("allowed", "failed"))
    canaries = sorted(set(CANARY_RE.findall(delivered_text)))
    high_risk_run = sum(
        1 for r in records if r.attempted and r.op.tool == "run_action"
        and r.result.status in ("allowed", "failed") and inv.actions.get(r.op.args["name"]) is not None
        and inv.actions[r.op.args["name"]].danger == "high"
    )
    need_set = needed_resources(trace, inv)
    grant_set = granted_resources(engine, inv)
    over = grant_set - need_set
    durations = [e["duration_us"] for e in gateway.audit.entries]
    durations_noexec = [e["duration_us"] for e in gateway.audit.entries if e["tool"] != "run_action"]
    audit_text = json.dumps(gateway.audit.entries)
    chain_ok, _ = verify_chain(gateway.audit.entries)
    exec_status = ";".join(
        f"{r.op.args['name']}={r.result.meta.get('exec_status', r.result.status)}"
        for r in needed if r.op.tool == "run_action"
    )

    row = {
        "task": trace.task,
        "mode": mode,
        "completable": int(not false_denials and kb_missing == 0),
        "needed_ops": len(needed),
        "false_denials": len(false_denials) + kb_missing,
        "benign_ops": len(by("benign")),
        "benign_denied": sum(1 for r in by("benign") if r.result.status == "denied"),
        "unauthorized_attempts": len(unauthorized),
        "unauthorized_allowed": sum(1 for r in unauthorized if r.result.status in ("allowed", "failed")),
        "injection_triggered": len(injections),
        "injection_allowed": sum(1 for r in injections if r.result.status in ("allowed", "failed")),
        "canary_exposures": len(canaries),
        "canaries": " ".join(canaries),
        "high_risk_actions_run": high_risk_run,
        "escalations": len(gateway.escalations),
        "needed_resources": len(need_set),
        "granted_resources": len(grant_set),
        "overgranted": len(over),
        "sensitive_granted": sum(1 for g in grant_set if is_sensitive(g, inv)),
        "undergranted": len(need_set - grant_set),
        "excluded_at_compile": len(compiled.excluded),
        "reachable_tokens": reachable_tokens(engine, inv),
        "delivered_tokens": approx_tokens(delivered_text),
        "tool_calls": len(gateway.audit.entries),
        "mean_call_us": round(statistics.mean(durations), 1) if durations else 0.0,
        "mean_call_us_noexec": round(statistics.mean(durations_noexec), 1) if durations_noexec else 0.0,
        "audit_chain_ok": int(chain_ok),
        "audit_canary_leaks": len(CANARY_RE.findall(audit_text)),
        "exec_status": exec_status,
    }
    return RunResult(row, records, compiled, gateway)


def load_traces(eval_dir: Path) -> list[Trace]:
    return [load_trace(p) for p in sorted((Path(eval_dir) / "tasks").glob("*.toml"))]


def summarise(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for mode in MODES:
        rs = [r for r in rows if r["mode"] == mode]
        if not rs:
            continue
        out.append({
            "mode": mode,
            "tasks": len(rs),
            "completable": sum(r["completable"] for r in rs),
            "false_denials": sum(r["false_denials"] for r in rs),
            "benign_denied": sum(r["benign_denied"] for r in rs),
            "unauthorized_attempts": sum(r["unauthorized_attempts"] for r in rs),
            "unauthorized_allowed": sum(r["unauthorized_allowed"] for r in rs),
            "injection_triggered": sum(r["injection_triggered"] for r in rs),
            "injection_allowed": sum(r["injection_allowed"] for r in rs),
            "canary_exposures": sum(r["canary_exposures"] for r in rs),
            "high_risk_actions_run": sum(r["high_risk_actions_run"] for r in rs),
            "escalations": sum(r["escalations"] for r in rs),
            "mean_granted": round(statistics.mean(r["granted_resources"] for r in rs), 1),
            "mean_overgranted": round(statistics.mean(r["overgranted"] for r in rs), 1),
            "mean_sensitive_granted": round(statistics.mean(r["sensitive_granted"] for r in rs), 1),
            "mean_reachable_tokens": round(statistics.mean(r["reachable_tokens"] for r in rs)),
            "mean_delivered_tokens": round(statistics.mean(r["delivered_tokens"] for r in rs)),
            "mean_call_us": round(statistics.mean(r["mean_call_us"] for r in rs), 1),
            "mean_call_us_noexec": round(statistics.mean(r["mean_call_us_noexec"] for r in rs), 1),
        })
    return out


def bench_decisions(inv: Inventory, trace: Trace, rounds: int = 200) -> dict[str, float]:
    """Mean microseconds per file-read decision over every inventoried file."""
    out = {}
    paths = list(inv.files)
    for mode in MODES:
        engine = PolicyEngine(build_policy(mode, trace, inv).policy, inv)
        start = time.perf_counter_ns()
        for _ in range(rounds):
            for p in paths:
                engine.file(p, "read")
        out[mode] = round((time.perf_counter_ns() - start) / 1000 / (rounds * len(paths)), 3)
    return out


def write_reports(rows, summary, bench, out_dir: Path, execute: bool) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "eval_results.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    env = {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "actions_executed": execute,
        "decision_bench_us": bench,
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    (out_dir / "environment.json").write_text(json.dumps(env, indent=2), encoding="utf-8")
    cols = list(summary[0])
    lines = [
        "# SpecGuard evaluation output",
        "",
        "Generated by `python -m specguard eval`. These numbers come from scripted trace replay against a",
        "fictional repository with hand-written ground truth. They measure the access-control layer, not",
        "the behaviour or task success of any language model. See docs/evaluation.md for definitions and",
        "threats to validity.",
        "",
        f"Environment: Python {env['python']} on {env['platform']}; actions executed: {execute}.",
        "",
        "## Totals per condition",
        "",
        "| " + " | ".join(cols) + " |",
        "|" + "---|" * len(cols),
    ]
    lines += ["| " + " | ".join(str(s[c]) for c in cols) + " |" for s in summary]
    per_task_cols = ["task", "mode", "completable", "false_denials", "unauthorized_attempts",
                     "unauthorized_allowed", "injection_allowed", "canary_exposures", "granted_resources",
                     "overgranted", "sensitive_granted", "escalations", "exec_status"]
    lines += ["", "## Per task", "", "| " + " | ".join(per_task_cols) + " |", "|" + "---|" * len(per_task_cols)]
    lines += ["| " + " | ".join(str(r[c]) for c in per_task_cols) + " |" for r in rows]
    lines += ["", "## Decision micro-benchmark", "",
              "Mean microseconds per file-read decision (all inventoried files, 200 rounds):", ""]
    lines += [f"- {m}: {v} us" for m, v in bench.items()]
    lines += ["", "Timings depend on the machine and are indicative only."]
    (out_dir / "eval_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_eval(inv: Inventory, eval_dir: Path, out_dir: Path, *, execute: bool = True) -> tuple[list[dict], list[dict]]:
    traces = load_traces(eval_dir)
    rows = []
    for trace in traces:
        for mode in MODES:
            res = run_one(mode, trace, inv, execute=execute,
                          audit_path=out_dir / "audit" / f"{trace.task}_{mode}.jsonl")
            rows.append(res.row)
    summary = summarise(rows)
    bench = bench_decisions(inv, traces[0])
    write_reports(rows, summary, bench, out_dir, execute)
    return rows, summary
