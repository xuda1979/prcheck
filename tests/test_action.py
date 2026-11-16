"""Tests for the GitHub Action entrypoint and gh-comment simulation (AC6)."""

import json
import os
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).parent.parent
DIFF = FIXTURES / "example_pr.diff"
V1 = FIXTURES / "openapi_v1.yaml"
V2 = FIXTURES / "openapi_v2.yaml"


def test_run_action_with_fixture_env(tmp_path, monkeypatch):
    """Run action/run_action.py with INPUT_* env vars and a fixture diff."""
    env = {
        "INPUT_DIFF": DIFF.read_text(),
        "INPUT_BASE_SPEC": str(V1),
        "INPUT_HEAD_SPEC": str(V2),
        "INPUT_OUTPUT_DIR": str(tmp_path / "out"),
        "INPUT_REQUIRE_HIGH_OK": "true",
        "INPUT_POST_COMMENT": "false",
        "PYTHONPATH": str(ROOT),
        "PATH": os.environ["PATH"],
    }
    res = subprocess.run(
        [sys.executable, str(ROOT / "action" / "run_action.py")],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 1, res.stdout + res.stderr  # gate fails on highs
    out = Path(env["INPUT_OUTPUT_DIR"])
    assert (out / "report.md").exists()
    assert "Security checklist" in (out / "report.md").read_text()
    assert "OpenAPI changelog" in (out / "report.md").read_text()
    assert json.loads((out / "report.sarif").read_text())["version"] == "2.1.0"
    semver = json.loads((out / "semver.json").read_text())
    assert semver["blocked"] is True
    assert semver["high_count"] >= 1


def test_run_action_range_diff_derive(tmp_path, monkeypatch):
    """Action supports auto-deriving diff from a git repo env."""
    # Use a tiny git repo to satisfy `git diff base...head`
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "t@t.t"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "t"], check=True)
    (repo / "a.py").write_text("x=1\n")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "base"], check=True)
    with (repo / "a.py").open("a") as f:
        f.write('@app.route("/x")\ndef x():\n    pass\n')
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "head"], check=True)

    env = {
        "GITHUB_WORKSPACE": str(repo),
        "INPUT_BASE_REF": "HEAD~1",
        "INPUT_HEAD_REF": "HEAD",
        "INPUT_OUTPUT_DIR": str(tmp_path / "auto"),
        "INPUT_REQUIRE_HIGH_OK": "false",
        "PYTHONPATH": str(ROOT),
        "PATH": os.environ["PATH"],
    }
    res = subprocess.run(
        [sys.executable, str(ROOT / "action" / "run_action.py")],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, res.stdout + res.stderr
    md = (Path(env["INPUT_OUTPUT_DIR"]) / "report.md").read_text()
    assert "No-auth / new public route detected" in md


def test_run_action_invalid_spec_clean_error(tmp_path):
    """A malformed OpenAPI spec fails the action cleanly (no traceback)."""
    bad = tmp_path / "bad.yaml"
    bad.write_text('openapi: 3.0.0\ninfo:\n  title: t\n  version: "1"\npaths: [oops]\n')
    env = {
        "INPUT_DIFF": DIFF.read_text(),
        "INPUT_BASE_SPEC": str(bad),
        "INPUT_HEAD_SPEC": str(V2),
        "INPUT_OUTPUT_DIR": str(tmp_path / "out"),
        "INPUT_REQUIRE_HIGH_OK": "false",
        "INPUT_POST_COMMENT": "false",
        "PYTHONPATH": str(ROOT),
        "PATH": os.environ["PATH"],
    }
    res = subprocess.run(
        [sys.executable, str(ROOT / "action" / "run_action.py")],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 2, res.stdout + res.stderr
    assert "'paths' must be a mapping" in res.stderr
    assert "Traceback" not in res.stderr


def test_gh_comment_mock(tmp_path, capsys):
    """AC6: gh simulation — the fixture comment body is loadable offline."""
    script = ROOT / "action" / "gh_comment.py"
    res = subprocess.run(
        [sys.executable, str(script), "--fixture-body"],
        env={"PATH": os.environ["PATH"]},
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "fixture comment loaded" in res.stdout


def test_gh_comment_requires_repo_pr():
    script = ROOT / "action" / "gh_comment.py"
    res = subprocess.run(
        [sys.executable, str(script), "--body", "x"],
        env={"PATH": os.environ["PATH"]},
        capture_output=True,
        text=True,
    )
    assert res.returncode == 2
    assert "--repo and --pr" in res.stderr


def test_gh_comment_mock_writes_fixture(tmp_path, monkeypatch):
    """AC6: `--mock` writes the comment body into tests/ghmock (gh simulation)."""
    from action import gh_comment

    # point the mock writer at a temp dir so the tracked fixture isn't touched
    monkeypatch.setattr(gh_comment, "_ghmock_dir", lambda: tmp_path)
    url = gh_comment.mock_post("owner/repo", "42", "# hi\n- [ ] a")
    assert url == "mock://owner/repo/pull/42#comment"
    body = (tmp_path / "posted_comment.md").read_text()
    assert "owner/repo#42" in body and "- [ ] a" in body
