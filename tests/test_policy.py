import dataclasses

import pytest

from specguard import policy as P
from specguard.compiler import compile_spec
from specguard.gateway import canonical_path
from specguard.labels import Label
from specguard.policy import PolicyEngine
from specguard.spec import load_spec, parse_spec_text


def test_spec_policy_is_minimal_for_sh101(spec_policy):
    p = spec_policy("SH-101")
    assert set(p.read) == {
        "firmware/Makefile", "firmware/src/filter.c", "firmware/src/filter.h",
        "firmware/tests/test_main.c", "specs/SH-101.toml",
    }
    assert set(p.write) == {"firmware/src/filter.c", "firmware/src/filter.h", "firmware/tests/test_main.c"}
    assert p.columns == frozenset()
    assert p.actions == {"unit-test", "style-check"}


def test_compile_reports_unsatisfiable_needs(inv):
    spec = parse_spec_text("""
[task]
id = "SH-901"
title = "t"
kind = "qa"
summary = "s"
components = ["firmware.alarm", "no.such.component"]
[access]
read = ["secrets/ota_signing_key.txt", "config/production_endpoints.toml", "missing.txt", ".specguard/inventory.toml"]
db = ["customers(email)", "api_tokens(token)", "devices(*)", "nope(x)", "calibration(nope)"]
actions = ["deploy-ota", "no-such-action"]
kb_topics = ["incident", "astrology"]
""")
    compiled = compile_spec(spec, inv)
    got = {(e.need, e.reason) for e in compiled.excluded}
    assert ("component:no.such.component", "UNKNOWN_COMPONENT") in got
    assert ("file:secrets/ota_signing_key.txt", "SECRET_NEVER_GRANTED") in got
    assert ("file:config/production_endpoints.toml", "ABOVE_CEILING") in got
    assert ("file:missing.txt", "UNKNOWN_RESOURCE") in got
    assert ("file:.specguard/inventory.toml", "CONTROL_PLANE") in got
    assert ("col:customers.email", "ABOVE_CEILING") in got
    assert ("col:api_tokens.token", "SECRET_NEVER_GRANTED") in got
    assert ("col:devices.customer_id", "ABOVE_CEILING") in got  # partial table: the rest is granted
    assert ("db:nope(x)", "UNKNOWN_TABLE") in got
    assert ("col:calibration.nope", "UNKNOWN_COLUMN") in got
    assert ("action:deploy-ota", "REQUIRES_HUMAN_APPROVAL") in got
    assert ("action:no-such-action", "UNKNOWN_ACTION") in got
    assert ("kb:KB-005", "ABOVE_CEILING") in got
    assert any("astrology" in w for w in compiled.warnings)
    assert "devices.model" in compiled.policy.columns


def test_compilation_is_deterministic(inv):
    spec = load_spec(inv.root / "specs" / "SH-106.toml")
    assert compile_spec(spec, inv).policy.digest == compile_spec(spec, inv).policy.digest


def test_policy_is_immutable(spec_policy):
    p = spec_policy("SH-101")
    with pytest.raises(dataclasses.FrozenInstanceError):
        p.read = ("**",)
    with pytest.raises(AttributeError):
        p.actions.add("deploy-ota")


def test_default_deny_for_unlisted_resources(inv, spec_policy):
    e = PolicyEngine(spec_policy("SH-101"), inv)
    assert e.file("docs/architecture.md", "read").reason == P.DENY_NOT_GRANTED
    assert e.file("does/not/exist.c", "read").reason == P.DENY_UNKNOWN_RESOURCE
    assert e.kb("KB-404").reason == P.DENY_UNKNOWN_RESOURCE
    assert e.column("calibration", "gain").reason == P.DENY_NOT_GRANTED
    assert e.action("format-disk").reason == P.DENY_UNKNOWN_RESOURCE


def test_invariants_hold_even_if_patterns_are_broad(inv, spec_policy):
    broad = dataclasses.replace(spec_policy("SH-101"), read=("**",), write=("**",), columns=frozenset({"*.*"}),
                                actions=frozenset(inv.actions))
    e = PolicyEngine(broad, inv)
    assert e.file("secrets/ota_signing_key.txt", "read").reason == P.DENY_ABOVE_CEILING
    assert e.file(".specguard/inventory.toml", "read").reason == P.DENY_CONTROL_PLANE
    assert e.file("data/sensorhub.db", "read").reason == P.DENY_DATASTORE_DIRECT
    assert e.file("specs/SH-101.toml", "write").reason == P.DENY_PROTECTED_WRITE
    assert e.column("api_tokens", "token").reason == P.DENY_ABOVE_CEILING
    assert e.action("deploy-ota").reason == P.DENY_REQUIRES_HUMAN


def test_static_role_overgrants_compared_with_spec(inv, static_policy, spec_policy):
    s = PolicyEngine(static_policy("developer"), inv)
    c = PolicyEngine(spec_policy("SH-101"), inv)
    assert s.file("config/production_endpoints.toml", "read").allowed
    assert not c.file("config/production_endpoints.toml", "read").allowed
    assert not s.file("secrets/deploy_credentials.txt", "read").allowed


def test_unrestricted_allows_everything(inv, open_policy):
    e = PolicyEngine(open_policy, inv)
    assert e.file("secrets/ota_signing_key.txt", "read").allowed
    assert e.column("api_tokens", "token").allowed
    assert e.action("deploy-ota").allowed
    assert open_policy.max_label == Label.SECRET


@pytest.mark.parametrize("raw, reason", [
    ("../outside.txt", P.DENY_INVALID_PATH),
    ("firmware/../../outside.txt", P.DENY_INVALID_PATH),
    ("/etc/passwd", P.DENY_INVALID_PATH),
    ("C:/Windows/win.ini", P.DENY_INVALID_PATH),
    ("~/.ssh/id_rsa", P.DENY_INVALID_PATH),
    ("firmware/src/filter.c\x00.txt", P.DENY_INVALID_PATH),
    ("", P.DENY_INVALID_PATH),
    (123, P.DENY_INVALID_PATH),
    ("Secrets/OTA_signing_key.txt", P.DENY_NONCANONICAL_PATH),
    ("FIRMWARE/src/filter.c", P.DENY_NONCANONICAL_PATH),
    ("firmware/src/nope.c", P.DENY_UNKNOWN_RESOURCE),
])
def test_path_canonicalisation_rejects_tricks(inv, raw, reason):
    canon, why = canonical_path(inv, raw)
    assert canon is None and why == reason


def test_equivalent_spellings_resolve_to_the_same_file(inv):
    assert canonical_path(inv, "firmware/./src/../src/filter.c")[0] == "firmware/src/filter.c"
    assert canonical_path(inv, "firmware\\src\\filter.c")[0] == "firmware/src/filter.c"
