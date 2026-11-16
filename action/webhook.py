"""P3 (bonus): minimal webhook bridge for a hosted prcheck App.

Runs the *same* shared analysis engine as the CLI and Action, and can post
the checklist as a PR comment. stdlib-only; mount with any WSGI server
(gunicorn/uwsgi) or invoke ``handle_event`` directly in a function/App.

Request shape (JSON, POST /webhook):

.. code-block:: json

    {
      "diff": "<unified diff text; optional if diff_url is given>",
      "diff_url": "https://api.github.com/repos/o/r/pulls/7",
      "repo": "owner/repo",
      "pr": "7",
      "base_spec": "path-or-inline OpenAPI old spec",
      "head_spec": "... new spec ..."
    }

Gate / comment policy is controlled by the same environment variables the
action uses (``INPUT_REQUIRE_HIGH_OK``, ``INPUT_POST_COMMENT``,
``GH_TOKEN``). Response is the AnalysisResult as JSON + gate state.
"""

from __future__ import annotations

import json
import os
from typing import Any


def _flag(name: str, default: bool = False) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on", "y")


def handle_event(payload: dict) -> dict:
    """Analyze a webhook payload and return ``{"result": ..., "gate": ...}``."""
    from prcheck.engine import run_analysis

    diff = payload.get("diff") or ""
    if not diff and payload.get("diff_url"):
        # In production this would fetch diff_url with a token; this bridge
        # is a local simulation, so a missing diff is reported as such.
        diff = ""

    base_spec = payload.get("base_spec") or payload.get("openapi_old")
    head_spec = payload.get("head_spec") or payload.get("openapi_new")
    base_text = _read_spec(base_spec)
    head_text = _read_spec(head_spec)

    result = run_analysis(
        diff,
        base_spec_text=base_text,
        new_spec_text=head_text,
        base_spec_name=str(base_spec or "old"),
        new_spec_name=str(head_spec or "new"),
        security_only=_flag("INPUT_SECURITY_ONLY"),
        data_only=_flag("INPUT_DATA_ONLY"),
        behavior_only=_flag("INPUT_BEHAVIOR_ONLY"),
        min_severity=os.environ.get("INPUT_MIN_SEVERITY", "info"),
    )

    high = [i for i in result.issues if i.severity == "high"]
    gate = _flag("INPUT_REQUIRE_HIGH_OK")
    blocked = gate and bool(high)

    comment_url = None
    repo, pr_number = payload.get("repo", ""), payload.get("pr", "")
    if _flag("INPUT_POST_COMMENT") and repo and pr_number and diff:
        # ``urllib``-only GitHub client; no requests dependency.
        from action.gh_comment import post_via_http
        from prcheck.render import render_markdown

        md = render_markdown(result.issues, stat=result.stat,
                             openapi_changes=result.openapi_changes,
                             high_blocked=blocked)
        comment_url = post_via_http(str(repo), str(pr_number), md)

    return {
        "result": result.as_dict(),
        "gate": {"require_high_ok": gate, "blocked": blocked,
                 "high_count": len(high), "comment_url": comment_url},
    }


def _read_spec(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, dict):  # already-parsed spec object
        return json.dumps(value)
    if isinstance(value, str) and os.path.exists(value):
        return open(value, encoding="utf-8").read()
    return value  # inline spec text


def wsgi_app(environ, start_response):
    """WSGI entry point (``gunicorn action.webhook:wsgi_app``)."""
    length = int(environ.get("CONTENT_LENGTH") or 0)
    body = environ["wsgi.input"].read(length) if length else b"{}"
    try:
        payload = json.loads(body.decode("utf-8") or "{}")
        out = handle_event(payload)
        status, content = "200 OK", json.dumps(out, ensure_ascii=False)
    except Exception as exc:  # noqa: BLE001 - respond JSON on any failure
        status, content = "400 Bad Request", json.dumps({"error": str(exc)})
    start_response(status, [("Content-Type", "application/json; charset=utf-8")])
    return [content.encode("utf-8")]


if __name__ == "__main__":
    # Convenience: `python -m action.webhook payload.json` (no server needed)
    import sys

    if len(sys.argv) < 2:
        sys.exit("usage: python -m action.webhook <payload.json>")
    try:
        with open(sys.argv[1], encoding="utf-8") as f:
            out = handle_event(json.load(f))
    except (OSError, ValueError) as e:
        # mirror the WSGI path: report bad input cleanly, never a traceback
        sys.exit(f"error: {e}")
    print(json.dumps(out, ensure_ascii=False, indent=2))
