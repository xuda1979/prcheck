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


def test_run_action_inline_comments_off_by_default(tmp_path):
    """POST_INLINE_COMMENT=true without a PR is a clean no-op warning."""
    env = {
        "INPUT_DIFF": DIFF.read_text(),
        "INPUT_OUTPUT_DIR": str(tmp_path / "out"),
        "INPUT_REQUIRE_HIGH_OK": "false",
        "INPUT_POST_INLINE_COMMENT": "true",
        "PYTHONPATH": str(ROOT),
        "PATH": os.environ["PATH"],
    }
    res = subprocess.run(
        [sys.executable, str(ROOT / "action" / "run_action.py")],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "POST_INLINE_COMMENT=true but" in res.stderr
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


# --- inline review comments (task #11) ---------------------------------

def _mk_issue(rule_id, severity, path, line, summary, snippet=""):
    from prcheck.issues import Issue
    return Issue(rule_id, "security", severity, summary, path, line, snippet)


def test_review_comments_merge_by_location():
    """Findings at the same path:line merge into one comment body."""
    from action.gh_comment import review_comments_for_issues

    issues = [
        _mk_issue("R002", "high", "src/a.py", 10, "hardcoded secret", "key='x'"),
        _mk_issue("R003", "low", "src/a.py", 10, "minor", ""),
        _mk_issue("D001", "medium", "src/b.py", 3, "pii log", "log(user.email)"),
    ]
    comments = review_comments_for_issues(issues)
    assert len(comments) == 2
    by_path = {c["path"]: c for c in comments}
    assert by_path["src/a.py"]["line"] == 10
    body = by_path["src/a.py"]["body"]
    assert "<!-- prcheck-inline -->" in body
    assert "R002" in body and "R003" in body       # merged
    assert "key='x'" in body                        # high snippet present
    assert by_path["src/b.py"]["body"].startswith("<!-- prcheck-inline -->")


def test_review_comments_low_info_no_snippet():
    """Low/info findings are listed without a snippet blurb."""
    from action.gh_comment import review_comments_for_issues

    comments = review_comments_for_issues(
        [_mk_issue("B001", "info", "x.py", 1, "minor note", "some snippet text")]
    )
    assert "some snippet text" not in comments[0]["body"]


def test_post_review_comments_skips_existing_and_posts(monkeypatch):
    """Idempotency: same marker body is skipped; new ones are POSTed."""
    import urllib.error

    from action import gh_comment

    posted = []

    def fake_urlopen(req, timeout=None):
        started = {c["body"] for c in _EXISTING_COMMENTS}
        if req.method == "GET":
            return FakeResp(json.dumps(_EXISTING_COMMENTS).encode())
        # POST
        payload = json.loads(req.data.decode())
        posted.append({"path": payload["path"], "line": payload["line"],
                       "body": payload["body"][:20]})
        return FakeResp(json.dumps({"html_url": f"https://x#{len(posted)}"}).encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setenv("GITHUB_TOKEN", "tok")

    existing_body = (gh_comment._INLINE_MARKER + "\n\n- [R1] old")
    _EXISTING_COMMENTS[:] = [{"body": existing_body}]
    new_body = gh_comment._INLINE_MARKER + "\n\n- [R2] fresh"
    urls = gh_comment.post_review_comments(
        "owner/repo", "7", "abc123",
        [{"body": new_body, "path": "a.py", "line": 1},
         {"body": existing_body, "path": "b.py", "line": 2}],
    )
    assert len(urls) == 1
    assert posted[0]["path"] == "a.py" and posted[0]["line"] == 1


def test_post_review_comments_tolerates_http_errors(monkeypatch, capsys):
    """One failing comment doesn't abort posting the rest."""
    import urllib.error

    from action import gh_comment

    fail_after = {"n": 0}

    def fake_urlopen(req, timeout=None):
        if req.method == "GET":
            return FakeResp(b"[]")
        if fail_after["n"] == 0:
            fail_after["n"] += 1
            raise urllib.error.HTTPError(
                "http://x", 422, "Unprocessable", None, None
            )
        return FakeResp(b'{"html_url": "https://x/ok"}')

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    urls = gh_comment.post_review_comments(
        "owner/repo", "7", "abc123",
        [{"body": gh_comment._INLINE_MARKER + "\nb1", "path": "a.py", "line": 1},
         {"body": gh_comment._INLINE_MARKER + "\nb2", "path": "a.py", "line": 2}],
    )
    assert urls == ["https://x/ok"]
    assert "HTTP 422" in capsys.readouterr().err


class FakeResp:
    def __init__(self, body):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._body


_EXISTING_COMMENTS: list = []


# --- report comment upsert (task #14) -----------------------------------

def test_with_report_marker_idempotent():
    """The report marker is appended once, never doubled."""
    from action.gh_comment import _REPORT_MARKER, _with_report_marker

    once = _with_report_marker("# report")
    assert once.endswith(_REPORT_MARKER)
    assert once.count(_REPORT_MARKER) == 1
    again = _with_report_marker(once)
    assert again == once


def test_update_or_post_comment_patches_existing(monkeypatch):
    """A prior report marker comment is PATCHed in place, not re-POSTed."""
    import urllib.request

    from action import gh_comment

    calls = []

    def fake_urlopen(req, timeout=None):
        if req.method == "GET":
            marker = gh_comment._REPORT_MARKER
            comments = [{"id": 91, "body": "old report" + marker}]
            return FakeResp(json.dumps(comments).encode())
        # PATCH — payload body must carry the marker exactly once
        payload = json.loads(req.data.decode())
        calls.append((req.method, req.full_url, payload["body"]))
        assert "/repos/owner/repo/issues/comments/91" in req.full_url
        assert payload["body"].count(gh_comment._REPORT_MARKER) == 1
        return FakeResp(json.dumps({"html_url": "https://x/patched"}).encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    url = gh_comment.update_or_post_comment("owner/repo", "7", "# fresh")
    assert url == "https://x/patched"
    assert len(calls) == 1
    assert calls[0][0] == "PATCH"


def test_update_or_post_comment_posts_fresh_when_none(monkeypatch):
    """No marker comment yet -> POST a brand-new report comment."""
    import urllib.request

    from action import gh_comment

    posts = []

    def fake_urlopen(req, timeout=None):
        if req.method == "GET":
            return FakeResp(b"[]")
        payload = json.loads(req.data.decode())
        posts.append((req.method, req.full_url, payload["body"]))
        assert req.full_url.endswith("/issues/7/comments")
        return FakeResp(json.dumps({"html_url": "https://x/new"}).encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    url = gh_comment.update_or_post_comment("owner/repo", "7", "# fresh")
    assert url == "https://x/new"
    assert posts[0][0] == "POST"
    assert gh_comment._REPORT_MARKER in posts[0][2]


def test_update_or_post_comment_falls_back_when_list_fails(monkeypatch):
    """A failed comment-list GET degrades to posting a fresh comment."""
    import urllib.error
    import urllib.request

    from action import gh_comment

    def fake_urlopen(req, timeout=None):
        if req.method == "GET":
            raise urllib.error.HTTPError("http://x", 403, "Forbidden", None, None)
        return FakeResp(json.dumps({"html_url": "https://x/new"}).encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    url = gh_comment.update_or_post_comment("owner/repo", "7", "# fresh")
    assert url == "https://x/new"


# --- Action main() end-to-end comment paths (PR/commit discovery) --------

class _FakeGH:
    """Records API calls; serves canned responses for action main() tests."""

    def __init__(self, issue_comments=None):
        self.issue_comments = issue_comments if issue_comments is not None else []
        self.calls = []  # (method, full_url, json_payload or None)
        self._n = 0

    def __call__(self, req, timeout=None):
        payload = json.loads(req.data.decode("utf-8")) if req.data else None
        self.calls.append((req.method, req.full_url, payload))
        if req.method == "GET" and req.full_url.endswith("/issues/7/comments"):
            return FakeResp(json.dumps(self.issue_comments).encode())
        if req.method == "GET" and req.full_url.endswith("/pulls/9/comments"):
            return FakeResp(b"[]")
        self._n += 1
        return FakeResp(
            json.dumps({"html_url": f"https://example.com/ok#{self._n}"}).encode()
        )


def test_main_posts_report_comment_via_pr_number(tmp_path, monkeypatch, capsys):
    """INPUT_POST_COMMENT=true drives the GET->POST upsert in main() (AC7)."""
    import urllib.request

    from action import gh_comment, run_action

    out_dir = tmp_path / "out"
    fake = _FakeGH()  # no prior report comment -> POST
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    monkeypatch.setenv("INPUT_DIFF", DIFF.read_text())
    monkeypatch.setenv("INPUT_OUTPUT_DIR", str(out_dir))
    monkeypatch.setenv("INPUT_REQUIRE_HIGH_OK", "false")
    monkeypatch.setenv("INPUT_POST_COMMENT", "true")
    monkeypatch.setenv("INPUT_POST_INLINE_COMMENT", "false")
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("PR_NUMBER", "7")

    rc = run_action.main()
    assert rc == 0, capsys.readouterr().err

    assert (out_dir / "report.md").exists()
    assert (out_dir / "report.sarif").exists()
    assert json.loads((out_dir / "semver.json").read_text())["blocked"] is False

    methods = [c[0] for c in fake.calls]
    assert methods == ["GET", "POST"], fake.calls
    get_url = fake.calls[0][1]
    assert get_url.endswith("/repos/owner/repo/issues/7/comments")
    posted_payload = fake.calls[-1][2]
    assert posted_payload["body"].count(gh_comment._REPORT_MARKER) == 1
    assert "Security checklist" in posted_payload["body"]
    assert "comment posted" in capsys.readouterr().out


def test_main_patches_existing_report_comment(tmp_path, monkeypatch, capsys):
    """main() finds a prior marker comment and PATCHes it in place."""
    import urllib.request

    from action import gh_comment, run_action

    marker = gh_comment._REPORT_MARKER
    fake = _FakeGH(issue_comments=[{"id": 91, "body": "old report" + marker}])
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    monkeypatch.setenv("INPUT_DIFF", DIFF.read_text())
    monkeypatch.setenv("INPUT_OUTPUT_DIR", str(tmp_path / "out"))
    monkeypatch.setenv("INPUT_REQUIRE_HIGH_OK", "false")
    monkeypatch.setenv("INPUT_POST_COMMENT", "true")
    monkeypatch.setenv("INPUT_POST_INLINE_COMMENT", "false")
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("PR_NUMBER", "7")

    rc = run_action.main()
    assert rc == 0
    methods = [c[0] for c in fake.calls]
    assert methods == ["GET", "PATCH"], fake.calls
    patch_url = fake.calls[-1][1]
    assert patch_url.endswith("/repos/owner/repo/issues/comments/91")
    assert fake.calls[-1][2]["body"].count(marker) == 1


def test_main_posts_inline_comments_from_event_path(tmp_path, monkeypatch, capsys):
    """POST_INLINE_COMMENT=true uses GITHUB_EVENT_PATH for PR + commit SHA."""
    import urllib.request

    from action import gh_comment, run_action

    event = tmp_path / "event.json"
    event.write_text(json.dumps({
        "action": "synchronize",
        "number": 9,
        "pull_request": {"number": 9, "head": {"sha": "abc123def"}},
        "repository": {"full_name": "owner/repo"},
    }))
    fake = _FakeGH()
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    monkeypatch.setenv("INPUT_DIFF", DIFF.read_text())
    monkeypatch.setenv("INPUT_OUTPUT_DIR", str(tmp_path / "out"))
    monkeypatch.setenv("INPUT_REQUIRE_HIGH_OK", "false")
    monkeypatch.setenv("INPUT_POST_COMMENT", "false")
    monkeypatch.setenv("INPUT_POST_INLINE_COMMENT", "true")
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.delenv("PR_NUMBER", raising=False)
    monkeypatch.delenv("GITHUB_SHA", raising=False)

    rc = run_action.main()
    assert rc == 0, capsys.readouterr().err

    posts = [c for c in fake.calls if c[0] == "POST"]
    assert posts, "expected inline comment POSTs"
    for _, url, payload in posts:
        assert "/pulls/9/comments" in url
        assert payload["commit_id"] == "abc123def", payload
        assert payload["body"].startswith(gh_comment._INLINE_MARKER)
        assert payload["path"] and payload["line"] >= 1
    methods = [c[0] for c in fake.calls]
    assert methods[0] == "GET", "existing review comments listed before POSTs"
    out = capsys.readouterr().out
    assert f"posted {len(posts)} inline comments" in out
