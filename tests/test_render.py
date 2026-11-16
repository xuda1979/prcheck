"""Unit tests for Markdown + SARIF rendering (AC4)."""

import json

from prcheck.render import render_markdown, render_sarif
from prcheck.rules import analyze_to_issues
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures" / "example_pr.diff"


def test_markdown_pr_comment_shape():
    issues, _ = analyze_to_issues(FIXTURE.read_text())
    md = render_markdown(issues, stat={"files_changed": 5, "insertions": 42, "deletions": 9})
    assert "## 🔒 PR Security & Data Checklist" in md
    assert "### Security checklist" in md
    assert "### Data checklist" in md
    assert "### Behavior checklist" in md
    assert any("- [ ]" in line for line in md.splitlines())
    # file:line citation present
    assert "src/app.py:" in md
    # count table
    assert "| Category |" in md


def test_markdown_gate_blocker():
    issues, _ = analyze_to_issues(FIXTURE.read_text())
    md = render_markdown(issues, high_blocked=True)
    assert "BLOCKED" in md


def test_sarif_valid_json_and_rule_defs():
    issues, _ = analyze_to_issues(FIXTURE.read_text())
    sarif = render_sarif(issues)
    doc = json.loads(sarif)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "prcheck"
    assert len(run["results"]) == len(issues)
    # a high finding maps to sarif error level
    assert any(r.get("level") == "error" for r in run["results"] if r["ruleId"] in {"R001-a", "R002"})
    assert run["tool"]["driver"]["rules"]


def test_sarif_has_locations():
    issues, _ = analyze_to_issues(FIXTURE.read_text())
    doc = json.loads(render_sarif(issues))
    res = doc["runs"][0]["results"][0]
    loc = res["locations"][0]["physicalLocation"]
    assert "artifactLocation" in loc
    assert "region" in loc and loc["region"]["startLine"] >= 1


def test_sarif_every_result_rule_is_defined():
    """Every result ruleId must resolve to a driver rule (code-scanner compat)."""
    issues, _ = analyze_to_issues(FIXTURE.read_text())
    doc = json.loads(render_sarif(issues))
    run = doc["runs"][0]
    defined = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert defined, "SARIF run must define at least one rule"
    referenced = {r["ruleId"] for r in run["results"]}
    assert referenced and referenced <= defined


# -------------------------------------------------------------------------
# OpenAPI changelog folded into SARIF (task #15)
# -------------------------------------------------------------------------

_V1 = Path(__file__).parent / "fixtures" / "openapi_v1.yaml"
_V2 = Path(__file__).parent / "fixtures" / "openapi_v2.yaml"


def _fixture_changes():
    from prcheck.engine import run_analysis

    result = run_analysis(
        "",
        base_spec_text=_V1.read_text(),
        new_spec_text=_V2.read_text(),
        base_spec_name=str(_V1),
        new_spec_name=str(_V2),
    )
    return result.openapi_changes


def test_sarif_includes_openapi_breaking_changes():
    """Breaking OpenAPI changes surface as `error` SARIF results."""
    changes = _fixture_changes()
    assert changes, "fixture pair must produce a changelog"
    doc = json.loads(render_sarif([], openapi_changes=changes, spec_name="spec.yaml"))
    run = doc["runs"][0]
    results = {r["ruleId"]: r for r in run["results"]}
    defined = {r["id"] for r in run["tool"]["driver"]["rules"]}

    breaking_ids = [r["ruleId"] for r in run["results"] if r["level"] == "error"]
    assert breaking_ids, "at least one breaking change must be a SARIF error"
    for rid in breaking_ids:
        assert rid.endswith("-breaking")
        assert rid in defined

    # breaking results annotate the spec file, and keep their summary
    breaking = results[breaking_ids[0]]
    assert breaking["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "spec.yaml"
    assert "breaking" not in breaking["message"]["text"]  # marker not leaked into message


def test_sarif_openapi_rules_defined_for_all_results():
    """Every OpenAPI SARIF result ruleId must be declared on the driver."""
    changes = _fixture_changes()
    doc = json.loads(render_sarif([], openapi_changes=changes))
    run = doc["runs"][0]
    defined = {r["id"] for r in run["tool"]["driver"]["rules"]}
    referenced = {r["ruleId"] for r in run["results"]}
    assert referenced and referenced <= defined


def test_sarif_openapi_non_breaking_level():
    """Non-breaking OpenAPI changes map to warning/note, never error."""
    changes = _fixture_changes()
    doc = json.loads(render_sarif([], openapi_changes=changes))
    for r in doc["runs"][0]["results"]:
        if not r["ruleId"].endswith("-breaking"):
            assert r["level"] != "error"


def test_sarif_openapi_defaults_empty():
    """Without OpenAPI changes the SARIF log is unchanged in shape."""
    issues, _ = analyze_to_issues(FIXTURE.read_text())
    base = json.loads(render_sarif(issues))
    default = json.loads(render_sarif(issues, openapi_changes=[], spec_name="spec.yaml"))
    assert default == base
