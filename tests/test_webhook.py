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
