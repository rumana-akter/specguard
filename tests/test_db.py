import pytest

from specguard import policy as P
from specguard.dbguard import columns_touched, run_query
from specguard.policy import PolicyEngine


@pytest.fixture
def qa_engine(inv, spec_policy):
    return PolicyEngine(spec_policy("SH-103"), inv)


def q(inv, engine, sql, max_rows=50):
    return run_query(inv.db_path, sql, engine.column, max_rows)


def test_granted_columns_are_readable(inv, qa_engine):
    out = q(inv, qa_engine, "SELECT device_id, offset_c FROM calibration WHERE abs(offset_c) > 0.5")
    assert out.allowed and out.header == ["device_id", "offset_c"] and len(out.rows) == 2


@pytest.mark.parametrize("sql, reason", [
    ("SELECT * FROM calibration", P.DENY_ABOVE_CEILING),                    # includes technician
    ("SELECT technician FROM calibration", P.DENY_ABOVE_CEILING),
    ("SELECT name FROM customers", P.DENY_ABOVE_CEILING),
    ("SELECT token FROM api_tokens", P.DENY_ABOVE_CEILING),
    ("SELECT count(*) FROM alarm_events", P.DENY_NOT_GRANTED),             # table-level reference
    ("SELECT device_id FROM calibration WHERE device_id IN (SELECT device_id FROM devices)", P.DENY_NOT_GRANTED),
    ("SELECT gain FROM calibration UNION SELECT note FROM maintenance_notes", P.DENY_NOT_GRANTED),
    ("SELECT name FROM sqlite_master", P.DENY_UNKNOWN_RESOURCE),
    ("SELECT load_extension('x')", P.DENY_SQL_OPERATION),
    ("PRAGMA table_info(customers)", P.DENY_SQL_OPERATION),
    ("ATTACH DATABASE 'x.db' AS x", P.DENY_SQL_OPERATION),
    ("DELETE FROM calibration", P.DENY_SQL_OPERATION),
    ("UPDATE calibration SET gain = 1", P.DENY_SQL_OPERATION),
    ("CREATE TABLE t(x)", P.DENY_SQL_OPERATION),
])
def test_disallowed_queries_are_denied_by_the_engine(inv, qa_engine, sql, reason):
    out = q(inv, qa_engine, sql)
    assert not out.allowed
    assert out.reason == reason


def test_multiple_statements_are_rejected(inv, qa_engine):
    out = q(inv, qa_engine, "SELECT gain FROM calibration; DELETE FROM calibration")
    assert not out.allowed


def test_row_limit_truncates(inv, qa_engine):
    out = q(inv, qa_engine, "SELECT device_id FROM sensor_readings", max_rows=5)
    assert out.allowed and len(out.rows) == 5 and out.truncated


def test_runaway_query_is_stopped(inv, open_policy):
    e = PolicyEngine(open_policy, inv)
    out = run_query(inv.db_path, "SELECT count(*) FROM sensor_readings a, sensor_readings b, sensor_readings c", e.column, 10)
    assert not out.allowed and out.reason == P.DENY_SQL_ERROR


def test_columns_touched_records_reads(inv):
    got = columns_touched(inv.db_path, "SELECT d.site_code FROM devices d JOIN alarm_events a ON a.device_id = d.device_id")
    assert got == {("devices", "site_code"), ("devices", "device_id"), ("alarm_events", "device_id")}
