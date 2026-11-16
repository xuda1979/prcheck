"""Unit tests for OpenAPI changelog (AC3)."""

from pathlib import Path

from prcheck.openapi import (
    Change,
    SpecVersion,
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


def test_swagger2_param_schema_change():
    """Swagger-2 params declare `type` at the param level, not `schema`."""
    old = load_spec(
        "swagger: '2.0'\n"
        "info: {title: t, version: '1.0.0'}\n"
        "paths:\n"
        "  /x:\n"
        "    get:\n"
        "      parameters:\n"
        "        - name: limit\n"
        "          in: query\n"
        "          type: integer\n",
        "old",
    )
    new = load_spec(
        "swagger: '2.0'\n"
        "info: {title: t, version: '1.1.0'}\n"
        "paths:\n"
        "  /x:\n"
        "    get:\n"
        "      parameters:\n"
        "        - name: limit\n"
        "          in: query\n"
        "          type: string\n",
        "new",
    )
    changes = compare_specs(old, new)
    schema_changed = [
        c for c in changes if c.kind == "parameter" and "schema type/schema changed" in c.summary
    ]
    assert schema_changed, "expected a schema-type change for the swagger2 param"
    assert schema_changed[0].breaking is True


def test_schema_property_newly_required_breaking():
    old_s = load_spec(
        "openapi: 3.0.0\n"
        "info: {title: t, version: '1.0.0'}\n"
        "paths: {}\n"
        "components:\n"
        "  schemas:\n"
        "    Box:\n"
        "      type: object\n"
        "      properties:\n"
        "        a: {type: string}\n",
        "old",
    )
    new_s = load_spec(
        "openapi: 3.0.0\n"
        "info: {title: t, version: '2.0.0'}\n"
        "paths: {}\n"
        "components:\n"
        "  schemas:\n"
        "    Box:\n"
        "      type: object\n"
        "      properties:\n"
        "        a: {type: string}\n"
        "      required: [a]\n",
        "new",
    )
    changes = compare_specs(old_s, new_s)
    req = [c for c in changes if c.kind == "schema" and "now required" in c.summary]
    assert req and req[0].breaking is True and req[0].severity == "high"


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


def test_load_spec_rejects_malformed_docs():
    """Structurally invalid specs fail loudly instead of empty changelogs."""
    import pytest

    for bad, name in [
        ("openapi: 3.0.0\ninfo: {title: t, version: 1.0.0}\npaths: []\n", "t"),
        ("openapi: 3.0.0\ninfo: {title: t, version: 1.0.0}\ncomponents: 5\n", "t"),
        ("openapi: 3.0.0\ninfo: {title: t, version: 1.0.0}\n"
         "components:\n  schemas: 3\npaths: {}\n", "t"),
        ("swagger: '2.0'\ninfo: {title: t, version: 1.0.0}\ndefinitions: []\n", "t"),
        ("---\n- a\n- b\n", "listdoc"),
        ("foo: bar\n", "noroot"),
    ]:
        with pytest.raises(ValueError):
            load_spec(bad, name)


def test_load_spec_accepts_minimal_valid_docs():
    """Minimal but structurally valid specs still load (empty paths ok)."""
    s3 = load_spec("openapi: 3.0.0\ninfo: {title: t, version: 1.0.0}\npaths: {}\n", "ok3")
    assert s3.version == SpecVersion.OPENAPI_3
    s2 = load_spec("swagger: '2.0'\ninfo: {title: t, version: 1.0.0}\npaths: {}\n", "ok2")
    assert s2.version == SpecVersion.SWAGGER_2


def test_property_change_classification():
    """Primitive type change is breaking; unknown structure is non-breaking."""
    old = load_spec(
        "openapi: 3.0.0\ninfo: {title: t, version: 1.0.0}\npaths: {}\n"
        "components:\n  schemas:\n    A:\n      type: object\n"
        "      properties:\n        x: {type: integer}\n"
        "        y: {type: string}\n",
        "old",
    )
    new = load_spec(
        "openapi: 3.0.0\ninfo: {title: t, version: 1.0.0}\npaths: {}\n"
        "components:\n  schemas:\n    A:\n      type: object\n"
        "      properties:\n        x: {type: string}\n"  # int -> str: breaking
        "        y: {format: email}\n",                # type unchanged: not classif. breaking
        "new",
    )
    changes = compare_specs(old, new)
    by_prop = {}
    for c in changes:
        if c.kind == "schema" and c.detail:
            by_prop[c.detail] = c
    assert by_prop["x"].breaking is True
    assert by_prop["y"].breaking is False


def test_no_whole_properties_attribute_noise():
    """'properties'/'required' are reported at property level, not as a flat
    attribute change, so the changelog has no duplicate/misclassified entries."""
    old_s, new_s = _pair()
    changes = compare_specs(old_s, new_s)
    flat_attrs = [
        c for c in changes
        if c.kind == "schema" and "attribute `properties` changed" in c.summary
    ]
    assert not flat_attrs


def test_iter_operations_guards_nonmapping_path_item():
    spec = load_spec(
        "openapi: 3.0.0\ninfo: {title: t, version: 1.0.0}\n"
        "paths:\n  /a:\n    - notanitem\n  /b:\n    get:\n      operationId: gb\n",
        "g",
    )
    ops = list(spec.iter_operations())
    assert ops == [("/b", "get", {"operationId": "gb"})]
