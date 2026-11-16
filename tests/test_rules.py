"""Unit tests for the rules engine (AC1, AC2)."""

from pathlib import Path

import pytest

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


def test_dependency_rule_fires_on_unquoted_requirements_pins():
    """requirements.txt pins written without quotes still produce findings.

    Regression: the pyproject-style pattern required an opening quote, so a
    bare `cryptography>=41.0.0` line slipped through silently.
    """
    src = (
        "cryptography>=41.0.0\n"
        "requests~=2.31\n"
        "boto3==1.28.0\n"
        "# comment-only line\n"
        "flask\n"  # unpinned: must NOT fire
    )
    issues, _ = analyze_to_issues(_inline_diff(src, path="requirements.txt"))
    deps = [i for i in issues if i.rule_id == "R006-deps"]
    assert [i.line for i in deps] == [1, 2, 3], deps
    assert all("requirements.txt" == i.path for i in deps)
    lines = {i.snippet for i in deps}
    assert "flask" not in lines, "an unpinned dependency must not match"


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


# Every rule id that has no representation in the example_pr.diff fixture.
# These are pinned directly so a broken/regressed regex cannot pass CI silently.
_UNCOVERED_RULE_CASES = [
    (
        "B002",
        "behavior",
        "low",
        "timeout = 30\nretries = 3\nresponse = requests.get(url, timeout=15)\n",
    ),
    (
        "B003",
        "behavior",
        "medium",
        "status_code = 500\nreturn Response(status=403)\nraise ApiError(404)\n",
    ),
    (
        "R004",
        "security",
        "medium",
        "eval(code)\n"
        "data = pickle.loads(raw)\n"
        "yaml.unsafe_load(text)\n",
    ),
    (
        "R009",
        "security",
        "medium",
        "user_id = request.view_args['id']\naccount_id: 42\n",
    ),
    (
        "R010",
        "security",
        "low",
        'url = "http://example.com/path"\n',
    ),
    (
        "R011-session",
        "security",
        "medium",
        "SESSION_COOKIE_SECURE = False\napp.config['SESSION_COOKIE_HTTPONLY'] = None\n"
        "SameSite=None\n",
    ),
    (
        "R012-cmd",
        "security",
        "high",
        "os.system(\"restart.sh \" + cfg.url)\n"
        "os.popen('ls -l ' + user_input)\n"
        "subprocess.run('grep ' + term, shell=True)\n"
        "subprocess.Popen(f'curl {url}', shell=True)\n"
        "subprocess.check_call(cmd, shell=shell_enabled)\n"
        "subprocess.run([\"sh\", \"-c\", user_cmd])\n",
    ),
]


def _inline_diff(src: str, path: str = "x.py") -> str:
    lines = "".join("+" + ln + "\n" for ln in src.splitlines())
    return (
        f"--- a/{path}\n+++ b/{path}\n@@ -0,0 +1,{len(src.splitlines())} @@\n"
        f"{lines}"
    )


@pytest.mark.parametrize("rule_id,category,severity,lines", _UNCOVERED_RULE_CASES)
def test_uncovered_rules_fire_correctly(rule_id, category, severity, lines):
    """AC1 scope: each rule without fixture coverage still fires on classic input."""
    issues, _ = analyze_to_issues(_inline_diff(lines))
    hits = [i for i in issues if i.rule_id == rule_id]
    assert hits, f"{rule_id} did not fire on:\n{lines}"
    for i in hits:
        assert i.category == category, (rule_id, i.category)
        assert i.severity == severity, (rule_id, i.severity)


def test_every_rule_has_test_exposure():
    """No rule may be silent across the whole suite (fixture + pinned cases)."""
    rids = {r.id for r in RULES.values()}
    exposed = {
        "B001", "B002", "B003", "B004", "B005",
        "D001", "D002-db", "D003", "D004",
        "R001-a", "R001-b", "R002", "R003", "R004", "R005",
        "R006-deps", "R007-cors", "R008", "R009", "R010", "R011-session",
        "R012-cmd",
    }
    assert exposed <= rids
    uncovered = rids - exposed
    assert not uncovered, f"rules with no test exposure: {sorted(uncovered)}"
