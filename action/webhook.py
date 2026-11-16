"""P3 (bonus): minimal webhook bridge for a hosted prcheck App.

Runs the *same* shared analysis engine as the CLI and Action, and can post
the checklist as a PR comment. stdlib-only; mount with any WSGI server
(gunicorn/uwsgi) or invoke ``handle_event`` directly in a function/App.

Two payload shapes are accepted:

1. The prcheck bridge shape (see module docstring example / README):

   ``{"diff": ..., "diff_url": ..., "repo": ..., "pr": ...,
      "base_spec": ..., "head_spec": ...}``

2. A raw GitHub ``pull_request`` webhook event (what GitHub sends a hosted
   App): ``number``, ``pull_request.diff_url``/``html_url``, and
   ``repository.full_name`` are extracted automatically.

When ``WEBHOOK_SECRET`` is set, incoming requests are HMAC-verified against
the ``X-Hub-Signature-256`` header (GitHub's
``webhook_secret``/``WEBHOOK_SECRET`` contract), so forged events are
rejected with a clean 401 instead of being analyzed.

Gate / comment policy is controlled by the same environment variables the
action uses (``INPUT_REQUIRE_HIGH_OK``, ``INPUT_POST_COMMENT``,
``GH_TOKEN``). Response is the AnalysisResult as JSON + gate state.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import urllib.error
import urllib.request
from typing import Any


def _flag(name: str, default: bool = False) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on", "y")


def verify_signature(secret: str, body: bytes, signature_header: str) -> bool:
    """Constant-time check of a GitHub ``X-Hub-Signature-256`` header.

    ``signature_header`` is the raw header value, e.g.
    ``sha256=9a7f...``. Returns False when the header is missing, malformed,
    or does not match the HMAC-SHA256 of ``body`` under ``secret``.
    """
    if not signature_header:
        return False
    try:
        scheme, _, expected = signature_header.partition("=")
        if scheme != "sha256" or not expected:
            return False
        actual = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(actual, expected)
    except (TypeError, ValueError):
        return False


def parse_pull_request_event(event: dict) -> dict:
    """Flatten a raw GitHub ``pull_request`` event into the bridge shape.

    Extracts the diff URL, repo and PR number GitHub puts in a real
    ``pull_request`` webhook payload. Non-PR events come back empty so the
    caller can reject them cleanly.
    """
    if event.get("action") is None and "pull_request" not in event:
        # not a GitHub pull_request event; if it already is the flat bridge
        # shape (repo/pr/diff_url at top level) pass it through unchanged.
        if event.get("pr"):
            return {k: event[k] for k in ("repo", "pr", "diff_url") if k in event}
        return {"repo": "", "pr": ""}
    number = event.get("number") or (event.get("pull_request") or {}).get("number")
    pr = event.get("pull_request") or {}
    repo = event.get("repository") or {}
    return {
        "diff_url": pr.get("diff_url") or pr.get("url") or "",
        "repo": repo.get("full_name") or "",
        "pr": str(number) if number is not None else event.get("pr", "") or "",
    }


def fetch_diff_from_url(diff_url: str) -> str:
    """Fetch a PR diff from a GitHub URL (e.g. ``.../pulls/7``).

    Requests the unified diff via the ``Accept: application/vnd.github.v3.diff``
    media type so the response body is diff text directly. Uses
    ``GH_TOKEN``/``GITHUB_TOKEN`` when present (private repos), otherwise makes
    an unauthenticated request (public repos). Failures raise ``ValueError``
    with a clean message, matching the CLI's malformed-spec error handling.
    """
    headers = {
        "Accept": "application/vnd.github.v3.diff",
        "User-Agent": "prcheck-webhook",
    }
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"
    req = urllib.request.Request(diff_url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 (explicit GitHub API)
            return resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        detail = (e.read() or b"").decode("utf-8", "replace") if e.read is not None else ""
        raise ValueError(
            f"failed to fetch diff from {diff_url}: HTTP {e.code} {e.reason}"
            + (f" — {detail[:300]}" if detail else "")
        ) from e
    except urllib.error.URLError as e:
        raise ValueError(f"failed to fetch diff from {diff_url}: {e.reason}") from e


def _resolve_diff(payload: dict) -> str:
    """Diff source precedence: inline ``diff`` wins, else fetch ``diff_url``."""
    diff = payload.get("diff") or ""
    if diff:
        return diff
    if payload.get("diff_url"):
        return fetch_diff_from_url(str(payload["diff_url"]))
    return ""


def handle_event(payload: dict) -> dict:
    """Analyze a webhook payload and return ``{"result": ..., "gate": ...}``."""
    from prcheck.engine import run_analysis

    diff = _resolve_diff(payload)

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
        from action.gh_comment import update_or_post_comment
        from prcheck.render import render_markdown

        md = render_markdown(result.issues, stat=result.stat,
                             openapi_changes=result.openapi_changes,
                             high_blocked=blocked)
        comment_url = update_or_post_comment(str(repo), str(pr_number), md)

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
    """WSGI entry point (``gunicorn action.webhook:wsgi_app``).

    Also accepts raw GitHub ``pull_request`` webhook events and, when
    ``WEBHOOK_SECRET`` is set, verifies ``X-Hub-Signature-256`` before
    analysis so unauthenticated callers can't trigger payload fetches or
    comment posts.
    """
    length = int(environ.get("CONTENT_LENGTH") or 0)
    body = environ["wsgi.input"].read(length) if length else b"{}"
    secret = os.environ.get("WEBHOOK_SECRET", "").strip()
    if secret:
        sig = (environ.get("HTTP_X_HUB_SIGNATURE_256") or "").strip()
        if not verify_signature(secret, body, sig):
            start_response(
                "401 Unauthorized",
                [("Content-Type", "application/json; charset=utf-8")],
            )
            return [json.dumps({"error": "invalid X-Hub-Signature-256"}).encode("utf-8")]
    try:
        payload = json.loads(body.decode("utf-8") or "{}")
        if payload.get("pull_request") or payload.get("action") is not None:
            # raw GitHub pull_request event → flatten to the bridge shape
            merged = dict(payload)
            merged.update(parse_pull_request_event(payload))
            payload = merged
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
