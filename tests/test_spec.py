import pytest

from specguard.labels import Label
from specguard.spec import DbNeed, SpecError, load_spec, parse_db_need, parse_spec_text

VALID = """
[task]
id = "SH-900"
title = "t"
kind = "qa"
summary = "s"
components = ["firmware.alarm"]

[access]
read = ["docs/architecture.md"]
db = ["calibration(device_id, gain)", "alarm_events(*)"]

[constraints]
max_label = "internal"
max_rows = 10
"""


def test_valid_spec_parses():
    spec = parse_spec_text(VALID)
    assert spec.id == "SH-900"
    assert spec.max_label == Label.INTERNAL
    assert spec.db == (DbNeed("calibration", ("device_id", "gain")), DbNeed("alarm_events", ("*",)))
    assert spec.max_rows == 10


def test_all_bundled_specs_parse(inv):
    specs = [load_spec(p) for p in sorted((inv.root / "specs").glob("*.toml"))]
    assert [s.id for s in specs] == [f"SH-10{i}" for i in range(1, 7)]


@pytest.mark.parametrize("patch, message", [
    ('[task]\nid = "x"\ntitle = "t"\nkind = "qa"\nsummary = "s"', "task.id"),
    ('[task]\nid = "SH-1"\ntitle = "t"\nkind = "ops"\nsummary = "s"', "task.kind"),
    ('[task]\nid = "SH-1"\ntitle = "t"\nkind = "qa"\nsummary = "s"\nowner = "me"', "unknown key"),
    ('[task]\nid = "SH-1"\ntitle = "t"\nkind = "qa"\nsummary = "s"\n[extras]\na = 1', "unknown section"),
    ('[task]\nid = "SH-1"\ntitle = "t"\nkind = "qa"\nsummary = "s"\n[constraints]\nmax_label = "secret"', "cannot be 'secret'"),
    ('[task]\nid = "SH-1"\ntitle = "t"\nkind = "qa"\nsummary = "s"\n[constraints]\nmax_label = "top"', "max_label"),
    ('[task]\nid = "SH-1"\ntitle = "t"\nkind = "qa"\nsummary = "s"\n[constraints]\nmax_rows = 0', "max_rows"),
    ('[task]\nid = "SH-1"\ntitle = "t"\nkind = "qa"\nsummary = "s"\n[access]\nread = ["../outside.txt"]', "inside the repository"),
    ('[task]\nid = "SH-1"\ntitle = "t"\nkind = "qa"\nsummary = "s"\n[access]\nread = ["/etc/passwd"]', "absolute"),
    ('[task]\nid = "SH-1"\ntitle = "t"\nkind = "qa"\nsummary = "s"\n[access]\nread = ["C:/x.txt"]', "absolute"),
    ('[task]\nid = "SH-1"\ntitle = "t"\nkind = "qa"\nsummary = "s"\n[access]\nread = ["a\\\\b"]', "forbidden"),
    ('[task]\nid = "SH-1"\ntitle = "t"\nkind = "qa"\nsummary = "s"\n[access]\ndb = ["calibration"]', "db entry"),
    ("not toml = = =", "invalid TOML"),
])
def test_invalid_specs_are_rejected(patch, message):
    with pytest.raises(SpecError, match=message):
        parse_spec_text(patch)


def test_db_need_rejects_sql_injection_like_text():
    with pytest.raises(SpecError):
        parse_db_need("calibration(device_id); DROP TABLE x")
