import json
import shutil

import pytest

from specguard import policy as P
from specguard.audit import AuditLog, load, verify_chain
from specguard.gateway import ToolGateway


@pytest.fixture
def gw(inv, spec_policy):
    return lambda task: ToolGateway(spec_policy(task), inv, execute_actions=True)


def test_unknown_tool_and_bad_arguments_are_denied(inv, gw):
    g = gw("SH-101")
    assert g.call("rm_rf", {"path": "."}).reason == P.DENY_UNKNOWN_TOOL
    assert g.call("read_file", {}).reason == P.DENY_INVALID_ARGUMENTS
    assert g.call("read_file", {"path": "README.md", "follow": True}).reason == P.DENY_INVALID_ARGUMENTS
    assert g.call("search_kb", {"query": "x", "k": 1000}).reason == P.DENY_INVALID_ARGUMENTS


def test_no_tool_can_modify_policy(inv, gw):
    g = gw("SH-101")
    before = g.policy_digest
    for args in ({"path": ".specguard/inventory.toml", "content": "x"}, {"path": "specs/SH-101.toml", "content": "x"}):
        assert g.call("write_file", args).status == "denied"
    assert g.call("request_access", {"resource": "file:secrets/ota_signing_key.txt", "justification": "please"}).status == "escalated"
    assert g.call("read_file", {"path": "secrets/ota_signing_key.txt"}).status == "denied"
    assert g.policy_digest == before
    assert {e["policy_digest"] for e in g.audit.entries} == {before}


def test_read_and_write_go_through_overlay(inv, gw):
    g = gw("SH-101")
    original = (inv.root / "firmware/src/filter.c").read_text(encoding="utf-8")
    assert g.call("write_file", {"path": "firmware/src/filter.c", "content": "/* new */\n"}).ok
    assert g.call("read_file", {"path": "firmware/src/filter.c"}).content == "/* new */\n"
    assert (inv.root / "firmware/src/filter.c").read_text(encoding="utf-8") == original


def test_write_requires_write_grant(inv, gw):
    g = gw("SH-101")
    assert g.call("write_file", {"path": "firmware/Makefile", "content": "x"}).reason == P.DENY_NOT_GRANTED


def test_list_dir_hides_entries_outside_scope(inv, gw):
    out = gw("SH-105").call("list_dir", {"path": "config"})
    assert out.ok and out.content.split() == ["device_config.toml"]
    assert gw("SH-105").call("list_dir", {"path": "secrets"}).status == "denied"


def test_kb_search_filters_before_ranking(inv, gw, static_policy):
    spec_hits = gw("SH-104").call("search_kb", {"query": "alarm incident outage customer"}).meta["returned"]
    assert "KB-005" not in spec_hits and "KB-004" in spec_hits
    static_hits = ToolGateway(static_policy("qa"), inv).call("search_kb", {"query": "alarm incident outage customer"}).meta["returned"]
    assert "KB-005" in static_hits


def test_db_schema_shows_only_granted_columns(inv, gw):
    text = gw("SH-103").call("db_schema", {}).content
    assert "calibration(device_id, sensor_type, offset_c, gain, calibrated_on)" in text
    assert "technician" not in text and "customers" not in text and "api_tokens" not in text


def test_high_risk_action_needs_human(inv, gw):
    assert gw("SH-101").call("run_action", {"name": "deploy-ota"}).reason == P.DENY_REQUIRES_HUMAN


def test_style_check_runs_in_workspace_without_secrets(inv, gw):
    g = gw("SH-101")
    out = g.call("run_action", {"name": "style-check"})
    assert out.status == "allowed", out.content
    assert "style check: 0 problem(s)" in out.content
    assert out.meta["workspace_files"] > 0
    assert "CANARY" not in out.content


@pytest.mark.skipif(shutil.which("make") is None or shutil.which("cc") is None, reason="C toolchain not installed")
def test_unit_test_action_runs_c_tests(inv, gw):
    out = gw("SH-101").call("run_action", {"name": "unit-test"})
    assert out.status == "allowed" and "all tests passed" in out.content


def test_unit_test_reports_missing_toolchain(inv, gw, monkeypatch):
    monkeypatch.setattr("specguard.executor.shutil.which", lambda _name: None)
    out = gw("SH-101").call("run_action", {"name": "unit-test"})
    assert out.status == "unavailable" and out.reason == P.UNAVAILABLE_TOOLCHAIN


def test_audit_never_contains_content(inv, open_policy, tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    g = ToolGateway(open_policy, inv, log)
    assert "CANARY" in g.call("read_file", {"path": "secrets/ota_signing_key.txt"}).content
    assert "CANARY" in g.call("query_db", {"sql": "SELECT token FROM api_tokens WHERE token = 'CANARY-SECRET-TOKEN0001'"}).content
    g.call("read_kb", {"id": "CANARY-SECRET-OTAKEY7F3A"})
    g.call("request_access", {"resource": "CANARY-SECRET-OTAKEY7F3A", "justification": "CANARY-SECRET-OTAKEY7F3A"})
    g.call("write_file", {"path": "docs/architecture.md", "content": "CANARY-SECRET-OTAKEY7F3A"})
    raw = (tmp_path / "a.jsonl").read_text(encoding="utf-8")
    assert "CANARY" not in raw
    assert all(e["policy_digest"] == open_policy.digest for e in load(tmp_path / "a.jsonl"))


def test_audit_chain_detects_tampering(inv, gw):
    g = gw("SH-101")
    for path in ("README.md", "firmware/src/filter.c", "secrets/ota_signing_key.txt"):
        g.call("read_file", {"path": path})
    entries = [dict(e) for e in g.audit.entries]
    assert verify_chain(entries) == (True, None)
    entries[2]["status"] = "allowed"
    assert verify_chain(entries) == (False, 3)
    assert verify_chain(entries[:1] + entries[2:])[0] is False


def test_audit_rejects_unknown_fields():
    with pytest.raises(ValueError):
        AuditLog().record(tool="read_file", content="secret")


def test_audit_records_decisions(inv, gw):
    g = gw("SH-101")
    g.call("read_file", {"path": "config/production_endpoints.toml"})
    e = g.audit.entries[-1]
    assert (e["tool"], e["status"], e["reason"], e["label"]) == ("read_file", "denied", P.DENY_ABOVE_CEILING, "confidential")
    json.dumps(e)
