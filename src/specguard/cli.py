"""Command-line demonstration interface.

    python -m specguard setup                 build the synthetic database
    python -m specguard inventory             list resources and labels
    python -m specguard plan SH-101           compile a spec and show the policy
    python -m specguard demo SH-101 [--mode]  replay a task and show decisions
    python -m specguard eval [--no-exec]      run the A/B/C comparison
    python -m specguard audit-verify FILE     check an audit log's hash chain
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import Counter
from pathlib import Path

from . import audit as audit_mod
from .agents import load_trace
from .compiler import compile_spec
from .context import select_context
from .evaluate import MODES, run_eval, run_one
from .fixtures import build_sensorhub_db
from .inventory import load_inventory
from .paths import default_eval_dir, default_repo, project_root
from .policy import PolicyEngine
from .spec import load_spec

COLOURS = {"allowed": "32", "denied": "31", "unavailable": "33", "escalated": "33", "failed": "35", "skipped": "90"}


def _c(text: str, status: str, enabled: bool) -> str:
    return f"\033[{COLOURS.get(status, '0')}m{text}\033[0m" if enabled else text


def _target(op) -> str:
    a = op.args
    for key in ("path", "name", "id", "query", "sql"):
        if key in a:
            value = " ".join(str(a[key]).split())
            return value if len(value) <= 70 else value[:67] + "..."
    return ""


def cmd_setup(args) -> int:
    path = build_sensorhub_db(args.repo / "data" / "sensorhub.db")
    print(f"built synthetic database: {path}")
    return 0


def cmd_inventory(args) -> int:
    inv = load_inventory(args.repo)
    print(f"Repository: {inv.root}\n\nFiles:")
    for p, info in sorted(inv.files.items()):
        print(f"  {info.label.name.lower():<13}{info.kind:<13}{p}")
    print("\nKnowledge base:")
    for a in inv.articles.values():
        print(f"  {a.label.name.lower():<13}{a.id:<9}{a.title}  topics={','.join(a.topics)}")
    print("\nDatabase columns:")
    for t in inv.tables.values():
        print(f"  {t.name}: " + ", ".join(f"{c}[{l.name.lower()}]" for c, l in t.columns))
    print("\nActions:")
    for a in inv.actions.values():
        print(f"  {a.name:<13}danger={a.danger}")
    return 0


def cmd_plan(args) -> int:
    inv = load_inventory(args.repo)
    spec = load_spec(inv.root / "specs" / f"{args.task}.toml")
    compiled = compile_spec(spec, inv)
    p = compiled.policy
    print(f"{spec.id}: {spec.title}\nkind={spec.kind} ceiling={p.max_label.name.lower()} max_rows={p.max_rows}")
    print(f"policy digest: {p.digest}\n")
    print("Granted file reads:  " + ", ".join(p.read))
    print("Granted file writes: " + (", ".join(p.write) or "(none)"))
    print("Granted KB articles: " + (", ".join(sorted(p.kb)) or "(none)"))
    print("Granted DB columns:  " + (", ".join(sorted(p.columns)) or "(none)"))
    print("Granted actions:     " + (", ".join(sorted(p.actions)) or "(none)"))
    print("\nNeeds that could not be granted (resolved before the agent starts):")
    for e in compiled.excluded or []:
        print(f"  - {e.need}: {e.reason}")
    if not compiled.excluded:
        print("  (none)")
    for w in compiled.warnings:
        print(f"  warning: {w}")
    print(f"\nContext bundle (budget {spec.max_context_tokens} approx. tokens):")
    for item in select_context(spec, PolicyEngine(p, inv), inv):
        mark = "+" if item.included else "-"
        print(f"  {mark} {item.resource:<45}{item.tokens:>6} tok  score={item.score:<5} {item.why}")
    return 0


def cmd_demo(args) -> int:
    inv = load_inventory(args.repo)
    trace = load_trace(args.eval_dir / "tasks" / f"{args.task}.toml")
    colour = sys.stdout.isatty() and not args.no_color and os.environ.get("NO_COLOR") is None
    modes = MODES if args.mode == "all" else (args.mode,)
    print(f"{trace.task}: {trace.description}\n")
    for mode in modes:
        res = run_one(mode, trace, inv, execute=not args.no_exec)
        print(f"=== condition: {mode}   (policy {res.compiled.policy.digest[:12]})")
        for i, rec in enumerate(res.records, 1):
            status = rec.result.status if rec.attempted else "skipped"
            reason = rec.result.reason if rec.attempted else "injection not seen"
            extra = "  -> access request filed" if rec.escalated else ""
            line = f"  {i:>2}. {rec.op.label:<10}{rec.op.tool:<12}{_target(rec.op):<72}{status.upper():<12}{reason}{extra}"
            print(_c(line, status, colour))
        r = res.row
        print(f"  summary: completable={bool(r['completable'])} false_denials={r['false_denials']} "
              f"unauthorized_allowed={r['unauthorized_allowed']}/{r['unauthorized_attempts']} "
              f"canaries_exposed={r['canary_exposures']} granted={r['granted_resources']} "
              f"overgranted={r['overgranted']} escalations={r['escalations']}\n")
    return 0


def cmd_eval(args) -> int:
    inv = load_inventory(args.repo)
    rows, summary = run_eval(inv, args.eval_dir, args.out, execute=not args.no_exec)
    cols = ["mode", "completable", "false_denials", "unauthorized_allowed", "injection_allowed",
            "canary_exposures", "mean_overgranted", "mean_sensitive_granted", "mean_reachable_tokens", "mean_call_us_noexec"]
    print("  ".join(f"{c:>22}" if i else f"{c:<14}" for i, c in enumerate(cols)))
    for s in summary:
        vals = [f"{s['completable']}/{s['tasks']}"] + [s[c] for c in cols[2:]]
        print(f"{s['mode']:<14}" + "".join(f"  {str(v):>22}" for v in vals))
    print(f"\nwrote {args.out / 'eval_results.csv'} and {args.out / 'eval_summary.md'}")
    statuses = Counter(x for r in rows for x in r["exec_status"].split(";") if x)
    print("action execution statuses: " + ", ".join(f"{k} x{v}" for k, v in sorted(statuses.items())))
    return 0


def cmd_audit_verify(args) -> int:
    entries = audit_mod.load(args.file)
    ok, seq = audit_mod.verify_chain(entries)
    print(f"{len(entries)} records; chain {'intact' if ok else f'BROKEN at seq {seq}'}")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="specguard", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", type=Path, default=default_repo(), help="fictional repository root")
    ap.add_argument("--eval-dir", type=Path, default=default_eval_dir(), help="evaluation traces")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("setup").set_defaults(func=cmd_setup)
    sub.add_parser("inventory").set_defaults(func=cmd_inventory)
    p = sub.add_parser("plan")
    p.add_argument("task")
    p.set_defaults(func=cmd_plan)
    d = sub.add_parser("demo")
    d.add_argument("task")
    d.add_argument("--mode", choices=(*MODES, "all"), default="all")
    d.add_argument("--no-exec", action="store_true", help="do not run actions, only decide them")
    d.add_argument("--no-color", action="store_true")
    d.set_defaults(func=cmd_demo)
    e = sub.add_parser("eval")
    e.add_argument("--out", type=Path, default=project_root() / "results")
    e.add_argument("--no-exec", action="store_true")
    e.set_defaults(func=cmd_eval)
    a = sub.add_parser("audit-verify")
    a.add_argument("file", type=Path)
    a.set_defaults(func=cmd_audit_verify)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
