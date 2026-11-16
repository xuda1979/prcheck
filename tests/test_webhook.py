"""Tests for the P3 webhook bridge (bonus phase, uses the shared engine)."""

import json
import urllib.error
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def test_handle_event_with_diff_and_openapi(monkeypatch, tmp_path):
    from action.webhook import handle_event

    diff = (FIXTURES / "example_pr.diff").read_text()
    v1 = (FIXTURES / "openapi_v1.yaml").read_text()
    v2 = (FIXTURES / "openapi_v2.yaml").read_text()
    monkeypatch.setenv("INPUT_REQUIRE_HIGH_OK", "true")
    out = handle_event(
        {
            "diff": diff,
            "repo": "owner/repo",
            "pr": "7",
            "base_spec": v1,
            "head_spec": v2,
        }
    )
    res = out["result"]
    assert res["stat"]["files_changed"] == 6
    cats = {i["category"] for i in res["issues"]}
    assert {"security", "data", "behavior"} <= cats
    assert res["openapi"], "expected OpenAPI changelog entries"
    assert res["semver"]["suggested_bump"] == "major"
    assert out["gate"]["blocked"] is True
    assert out["gate"]["high_count"] >= 1


def test_wsgi_app_endpoint(monkeypatch):
    import io

    from action.webhook import wsgi_app

    payload = json.dumps({"diff": (FIXTURES / "example_pr.diff").read_text()
                          if (FIXTURES / "example_pr.diff").exists() else ""}).encode()
    captured = {}

    def start_response(status, headers):
        captured["status"] = status

    body_iter = wsgi_app(
        {"REQUEST_METHOD": "POST", "CONTENT_LENGTH": str(len(payload)),
         "wsgi.input": io.BytesIO(payload)},
        start_response,
    )
    data = json.loads(b"".join(body_iter).decode())
    assert captured["status"].startswith("200")
    assert "result" in data and "gate" in data


def test_webhook_cli_bad_spec_clean_error(tmp_path, monkeypatch):
    """`python -m action.webhook` with a bad spec is a clean error, not a traceback."""
    import subprocess
    import sys

    bad = tmp_path / "bad.yaml"
    bad.write_text('openapi: 3.0.0\ninfo:\n  title: t\n  version: "1"\npaths: [oops]\n')
    payload = tmp_path / "payload.json"
    payload.write_text(json.dumps({"diff": "", "base_spec": str(bad),
                                   "head_spec": str(FIXTURES / "openapi_v2.yaml")}))
    res = subprocess.run(
        [sys.executable, "-m", "action.webhook", str(payload)],
        env={"PYTHONPATH": str(Path(__file__).parent.parent), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )
    assert res.returncode == 1
    assert "'paths' must be a mapping" in res.stderr
    assert "Traceback" not in res.stderr


class FakeResponse:
    def __init__(self, body, status=200):
        self._body = body.encode("utf-8")
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._body


class FakeHTTPError(urllib.error.HTTPError):
    def __init__(self, code, reason, body=b""):
        super().__init__("http://example.invalid", code, reason, None, None)
        self._body = body

    def read(self):
        return self._body


def test_fetch_diff_from_url_success(monkeypatch):
    """diff_url is fetched with the diff media type and returned as text."""
    from action import webhook

    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["url"] = req.full_url
        seen["accept"] = req.headers.get("Accept")
        seen["auth"] = req.headers.get("Authorization")
        return FakeResponse("--- a/x\n+++ b/x\n@@ -1 +1 @@\n+ok\n")

    monkeypatch.setattr(webhook.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    text = webhook.fetch_diff_from_url("https://api.github.com/repos/o/r/pulls/7")
    assert "+ok\n" in text
    assert seen["url"] == "https://api.github.com/repos/o/r/pulls/7"
    assert seen["accept"] == "application/vnd.github.v3.diff"
    assert seen["auth"] is None


def test_fetch_diff_from_url_sends_token(monkeypatch):
    """A GH_TOKEN is attached to the diff request when present."""
    from action import webhook

    seen = {}
    monkeypatch.setenv("GITHUB_TOKEN", "sekret")

    def fake_urlopen(req, timeout=None):
        seen["auth"] = req.headers.get("Authorization")
        return FakeResponse("+ok\n")

    monkeypatch.setattr(webhook.urllib.request, "urlopen", fake_urlopen)
    webhook.fetch_diff_from_url("https://api.github.com/repos/o/r/pulls/9")
    assert seen["auth"] == "token sekret"


def test_handle_event_fetches_diff_from_url(monkeypatch):
    """PR data flows in via diff_url with no inline diff (hosted-app path)."""
    from action import webhook

    diff = (FIXTURES / "example_pr.diff").read_text()
    monkeypatch.setattr(
        webhook.urllib.request, "urlopen", lambda req, timeout=None: FakeResponse(diff)
    )
    monkeypatch.delenv("INPUT_REQUIRE_HIGH_OK", raising=False)

    out = webhook.handle_event({"diff_url": "https://api.github.com/repos/o/r/pulls/7"})
    assert out["result"]["stat"]["files_changed"] == 6
    cats = {i["category"] for i in out["result"]["issues"]}
    assert {"security", "data", "behavior"} <= cats


def test_handle_event_inline_diff_wins_over_url(monkeypatch):
    """An inline diff short-circuits the (possibly lazy) diff_url fetch."""
    from action import webhook

    seen = {"called": False}

    def boom(req, timeout=None):  # pragma: no cover - must not be called
        seen["called"] = True
        raise AssertionError("diff_url should not be fetched when diff is inline")

    monkeypatch.setattr(webhook.urllib.request, "urlopen", boom)
    out = webhook.handle_event({"diff": "+nothing\n", "diff_url": "https://x/y"})
    assert seen["called"] is False
    assert out["result"]["stat"]["files_changed"] == 0


def test_fetch_diff_from_url_http_error_clean(monkeypatch):
    """HTTP-level failures become a clean ValueError, not a raw traceback."""
    from action import webhook

    monkeypatch.setattr(
        webhook.urllib.request,
        "urlopen",
        lambda req, timeout=None: (_ for _ in ()).throw(
            FakeHTTPError(404, "Not Found", b'{"message":"Not Found"}')
        ),
    )
    with pytest.raises(ValueError, match="HTTP 404 Not Found"):
        webhook.fetch_diff_from_url("https://api.github.com/repos/o/r/pulls/404")


def test_webhook_cli_missing_payload_usage(tmp_path):
    """No payload arg is a usage error, not an IndexError traceback."""
    import subprocess
    import sys

    res = subprocess.run(
        [sys.executable, "-m", "action.webhook"],
        env={"PYTHONPATH": str(Path(__file__).parent.parent), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )
    assert res.returncode == 1
    assert "usage:" in res.stderr
    assert "Traceback" not in res.stderr
