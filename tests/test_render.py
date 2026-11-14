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
    highs = [i for i in issues if i.severity == "high"]
    assert any(r.get("level") == "error" for r in run["results"] if r["ruleId"] in {"R001-a", "R002"})
    assert run["tool"]["driver"]["rules"]


def test_sarif_has_locations():
    issues, _ = analyze_to_issues(FIXTURE.read_text())
    doc = json.loads(render_sarif(issues))
    res = doc["runs"][0]["results"][0]
    loc = res["locations"][0]["physicalLocation"]
    assert "artifactLocation" in loc
    assert "region" in loc and loc["region"]["startLine"] >= 1
