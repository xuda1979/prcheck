"""Tests for the P3 webhook bridge (bonus phase, uses the shared engine)."""

import json
from pathlib import Path

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
