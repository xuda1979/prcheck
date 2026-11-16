"""Unit tests for the rules engine (AC1, AC2)."""

from pathlib import Path

from prcheck.rules import RULES, analyze_to_issues

FIXTURE = Path(__file__).parent / "fixtures" / "example_pr.diff"


def test_categories_present_and_lines():
    """AC1: given a diff, checklist items span security/data/behavior with file:line."""
    issues, files = analyze_to_issues(FIXTURE.read_text())
    assert len(files) == 6
    cats = {i.category for i in issues}
    assert {"security", "data", "behavior"} <= cats
    for i in issues:
        assert i.path.endswith((".py", ".toml"))
        assert ":" in i.location
        assert i.line >= 1


def test_no_auth_route_flagged_high():
    """AC2: an unauth'd new route diff is marked high."""
    issues, _ = analyze_to_issues(FIXTURE.read_text())
    high = [i for i in issues if i.severity == "high" and i.rule_id == "R001-a"]
    assert high, "expected a high-severity R001-a finding"
    assert any("/public/stats" in i.snippet for i in high)
    assert any("src/app.py" == i.path for i in high)


def test_hardcoded_secret_high():
    issues, _ = analyze_to_issues(FIXTURE.read_text())
    sev = [i for i in issues if i.rule_id == "R002" and i.severity == "high"]
    assert sev
    assert sev[0].path == "src/keys.py"


def test_dependency_rule_fires_on_manifest():
    issues, _ = analyze_to_issues(FIXTURE.read_text())
    deps = [i for i in issues if i.rule_id == "R006-deps"]
    # the pyproject manifest should have <= matched lines; package.json-style only
    assert any("pyproject.toml" == i.path for i in deps)


def test_existing_rule_library_integrity():
    # every rule id is unique and has valid category/severity
    assert len(RULES) == len({r.id for r in RULES.values()})
    for r in RULES.values():
        assert r.category in ("security", "data", "behavior")
        assert r.severity in ("info", "low", "medium", "high")


def test_issue_frozen_fields():
    from dataclasses import asdict

    issues, _ = analyze_to_issues(FIXTURE.read_text())
    assert issues
    d = asdict(issues[0])
    assert sorted(d.keys()) == sorted(
        ["rule_id", "category", "severity", "summary", "path", "line", "snippet", "hint", "refs"]
    )
