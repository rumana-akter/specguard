"""Checks on the evaluation harness itself, not claims about agents."""

import pytest

from specguard.agents import load_trace
from specguard.evaluate import MODES, load_traces, needed_resources, run_eval, run_one

VOLATILE = {"mean_call_us", "mean_call_us_noexec", "exec_status"}


@pytest.fixture(scope="module")
def results(inv, eval_dir):
    rows = {}
    for trace in load_traces(eval_dir):
        for mode in MODES:
            rows[(trace.task, mode)] = run_one(mode, trace, inv, execute=False).row
    return rows


def test_traces_are_well_formed(eval_dir):
    traces = load_traces(eval_dir)
    assert len(traces) == 6
    for t in traces:
        assert any(op.label == "needed" for op in t.ops)
        assert t.role in ("developer", "qa")


def test_ground_truth_needs_are_resolvable(inv, eval_dir):
    for trace in load_traces(eval_dir):
        for res in needed_resources(trace, inv):
            kind = res.split(":", 1)[0]
            assert kind in ("file", "kb", "col", "action")


def test_unrestricted_completes_everything_but_exposes_data(results):
    for (task, mode), r in results.items():
        if mode == "unrestricted":
            assert r["completable"] == 1 and r["false_denials"] == 0
            assert r["unauthorized_allowed"] == r["unauthorized_attempts"]
            assert r["canary_exposures"] > 0


def test_spec_condition_blocks_all_unauthorized_operations(results):
    for (task, mode), r in results.items():
        if mode == "spec":
            assert r["unauthorized_allowed"] == 0
            assert r["injection_allowed"] == 0
            assert r["canary_exposures"] == 0
            assert r["sensitive_granted"] == 0


def test_known_false_denials_are_reported_not_hidden(results):
    # SH-106: the spec omits devices.site_code. SH-105: the developer role cannot write config/.
    assert results[("SH-106", "spec")]["false_denials"] == 1
    assert results[("SH-106", "spec")]["escalations"] == 1
    assert results[("SH-105", "static")]["false_denials"] == 1
    assert results[("SH-106", "static")]["false_denials"] == 0


def test_audit_logs_are_intact_and_content_free(results):
    for r in results.values():
        assert r["audit_chain_ok"] == 1
        assert r["audit_canary_leaks"] == 0


def test_evaluation_is_repeatable(inv, eval_dir):
    trace = load_trace(eval_dir / "tasks" / "SH-101.toml")
    a = run_one("spec", trace, inv, execute=False).row
    b = run_one("spec", trace, inv, execute=False).row
    assert {k: v for k, v in a.items() if k not in VOLATILE} == {k: v for k, v in b.items() if k not in VOLATILE}


def test_run_eval_writes_reports(inv, eval_dir, tmp_path):
    rows, summary = run_eval(inv, eval_dir, tmp_path, execute=False)
    assert len(rows) == 18 and [s["mode"] for s in summary] == list(MODES)
    assert (tmp_path / "eval_results.csv").exists() and (tmp_path / "eval_summary.md").exists()
