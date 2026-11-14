"""Unit tests for OpenAPI changelog (AC3)."""

from pathlib import Path

from prcheck.openapi import (
    Change,
    compare_specs,
    diff_spec_text,
    infer_semver,
    load_spec,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _pair():
    old_s = load_spec((FIXTURES / "openapi_v1.yaml").read_text(), "v1")
    new_s = load_spec((FIXTURES / "openapi_v2.yaml").read_text(), "v2")
    return old_s, new_s


def test_endpoint_added__nonbreaking():
    old_s, new_s = _pair()
    changes = compare_specs(old_s, new_s)
    ep = [c for c in changes if c.kind == "endpoint"]
    added = [c for c in ep if "added" in c.summary]
    removed = [c for c in ep if "removed" in c.summary]
    assert any(c.path == "/owners" and c.method == "post" for c in added)
    assert not [c for c in added if c.breaking], "new endpoint must be non-breaking"
    assert any(c.path == "/legacy" for c in removed)
    assert [c for c in removed if c.breaking], "removed endpoint must be breaking"


def test_parameter_required_change_breaking():
    old_s, new_s = _pair()
    changes = compare_specs(old_s, new_s)
    param = [c for c in changes if c.kind == "parameter"]
    req = [c for c in param if "now required" in c.summary]
    assert req, "expected a required-param change"
    assert req[0].breaking is True


def test_parameter_added_nonbreaking():
    old_s, new_s = _pair()
    changes = compare_specs(old_s, new_s)
    added = [c for c in changes if c.kind == "parameter" and "added" in c.summary]
    assert added and any("filter" in c.summary for c in added)
    assert not [c for c in added if c.breaking]


def test_schema_added_property_nonbreaking_and_removed_breaking():
    old_s, new_s = _pair()
    changes = compare_specs(old_s, new_s)
    sc = [c for c in changes if c.kind == "schema"]
    prop_added = [c for c in sc if c.schema == "Pet" and "property `ownerId` added" in c.summary]
    assert prop_added and not prop_added[0].breaking
    prop_mod = [c for c in sc if c.schema == "Owner" and "property `id` modified" in c.summary]
    assert prop_mod and prop_mod[0].breaking  # int -> str type change


def test_diff_spec_text_semver():
    changes, semver = diff_spec_text(
        (FIXTURES / "openapi_v1.yaml").read_text(),
        (FIXTURES / "openapi_v2.yaml").read_text(),
    )
    assert semver["from"] == "1.4.0"
    assert semver["to"] == "2.0.0"
    assert semver["breaking_changes"] is True
    assert semver["suggested_bump"] == "major"
    assert isinstance(changes, list) and len(changes) > 0
    # each change has all keys needed by renderer
    for c in changes:
        assert set(c) >= {"type", "path", "method", "schema", "summary", "breaking", "severity"}


def test_infer_semver_immutable_additions():
    old_s, new_s = _pair()
    # simulate only additive changes
    fake = [
        Change("endpoint", "/x", "get", summary="added", breaking=False),
        Change("schema", schema="A", summary="added", breaking=False),
    ]
    assert infer_semver("1.0.0", "1.1.0", fake)["suggested_bump"] == "minor"
    fake2 = [
        Change("operation", "/x", "get", summary="summary changed", breaking=False),
    ]
    assert infer_semver("1.0.0", "1.0.1", fake2)["suggested_bump"] == "patch"
