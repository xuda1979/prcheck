"""Post (or draft) the Markdown report as a GitHub PR comment.

Invoked from the GitHub Action with either a token in ``GH_TOKEN`` /
``GITHUB_TOKEN`` plus ``--repo owner/repo --pr N``, or with ``--fixture-body``
for local "gh simulation" demos (no network).

The CLI never requires this module at test time; tests exercise the diff /
OpenAPI engines directly against fixtures.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def _api_base() -> str:
    return os.environ.get("GITHUB_API_URL", "https://api.github.com")


def _token() -> str:
    tok = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    if not tok:
        raise RuntimeError(
            "no GH_TOKEN / GITHUB_TOKEN set; either provide one or use --fixture-body"
        )
    return tok


def post_via_gh_cli(repo: str, pr_number: str, body: str, *, draft: bool = False) -> str:
    """Post a comment using the ``gh`` CLI (real-world path)."""
    cmd = [
        "gh", "api", "-X", "POST",
        f"/repos/{repo}/issues/{pr_number}/comments",
        "-f", f"body={body.decode() if isinstance(body, bytes) else body}",
        "--jq", ".html_url",
    ]
    if cwd := os.environ.get("GITHUB_WORKSPACE"):
        res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    else:
        res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"gh comment failed: {res.stderr}")
    return res.stdout.strip()


def post_via_http(repo: str, pr_number: str, body: str) -> str:
    """Post a comment directly through https://api.github.com."""
    api = f"{_api_base()}/repos/{repo}/issues/{pr_number}/comments"
    payload = _default_api_call("POST", api, {"body": body})
    return payload.get("html_url", api)


# Marker so inline comments posted by this tool can be recognized and skipped
# on re-runs (idempotency), instead of piling duplicate comments onto a line.
_INLINE_MARKER = "<!-- prcheck-inline -->"

# Marker appended to the full-report PR comment. Re-runs (a `pull_request`
# synchronize event after a new push) find the marker in the existing issue
# comments and PATCH that comment in place instead of stacking a duplicate.
_REPORT_MARKER = "\n\n<!-- prcheck-report -->"


def _with_report_marker(body: str) -> str:
    """Guarantee the report marker is present exactly once."""
    if _REPORT_MARKER in body:
        return body
    return body + _REPORT_MARKER


def update_or_post_comment(repo: str, pr_number: str, body: str) -> str:
    """Post the full-report comment, updating a previous report in place.

    Lists the PR's issue comments; if one carries the report marker, PATCH it
    to the new body (so every push refreshes a single comment). Otherwise POST
    a fresh comment. Returns the comment's HTML URL.
    """
    body = _with_report_marker(body)
    list_url = f"{_api_base()}/repos/{repo}/issues/{pr_number}/comments"
    try:
        comments = _default_api_call("GET", list_url)
    except urllib.error.HTTPError:
        # Listing failure is best-effort: fall back to posting a new comment.
        comments = []
    existing = next(
        (c for c in comments if _REPORT_MARKER in c.get("body", "")), None
    )
    if existing:
        url = f"{_api_base()}/repos/{repo}/issues/comments/{existing['id']}"
        payload = _default_api_call("PATCH", url, {"body": body})
        return payload.get("html_url", url)
    return post_via_http(repo, pr_number, body)


# Status codes that warrant a bounded retry: transient server-side failures
# (504/502/503/500) and rate limiting (429; GitHub also rate-limits with 403
# plus `X-RateLimit-Remaining: 0`). 4xx client errors are not retried.
_RETRYABLE_ERROR_CODES = {429, 500, 502, 503, 504}

# Total attempts before giving up on a retryable response.
_MAX_ATTEMPTS = 3

# Backoff used when the API gives no Retry-After / reset hint.
_BASE_BACKOFF_SECONDS = 1.0


def _sleep(seconds: float) -> None:
    """Injectable delay so tests can run without real waiting."""
    time.sleep(seconds)


def _retry_after(req_hdrs, resp_headers) -> float | None:
    """Extract a retry delay hint from either side of the exchange.

    Prefers GitHub's ``Retry-After`` (seconds); falls back to
    ``X-RateLimit-Reset`` (epoch seconds) minus current time.
    """
    sentinel = object()
    ra = resp_headers.get("Retry-After", sentinel)
    if ra is not sentinel and ra:
        try:
            return max(0.0, float(ra))
        except (TypeError, ValueError):
            pass
    for headers in (req_hdrs, resp_headers):
        reset = headers.get("X-RateLimit-Reset", sentinel)
        if reset is sentinel or not reset:
            continue
        try:
            return max(0.0, float(reset) - time.time())
        except (TypeError, ValueError):
            continue
    return None


def _default_api_call(
    method: str, url: str, data: dict | None = None
) -> dict:
    """Shared urllib call to the GitHub API returning parsed JSON.

    Retries bounded times on rate-limit responses (429, or 403 when
    ``X-RateLimit-Remaining`` is 0) and on transient 5xx errors, honoring
    ``Retry-After`` / ``X-RateLimit-Reset`` hints with an exponential fallback.
    Any error is re-raised unmodified once attempts are exhausted, so callers
    keep their existing handling.
    """
    body = json.dumps(data).encode("utf-8") if data is not None else None
    for attempt in range(_MAX_ATTEMPTS):
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Authorization": f"token {_token()}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "prcheck-action",
            },
            method=method,
        )
        try:
            with urllib.request.urlopen(req) as resp:  # noqa: S310 (explicit GitHub API)
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            retryable = e.code in _RETRYABLE_ERROR_CODES or (
                e.code == 403
                and (e.headers or {}).get("X-RateLimit-Remaining") == "0"
            )
            if not retryable or attempt == _MAX_ATTEMPTS - 1:
                raise
            delay = _retry_after(req.headers, e.headers or {})
            if delay is None:
                delay = _BASE_BACKOFF_SECONDS * (2 ** attempt)
            print(
                f"[prcheck] GitHub API HTTP {e.code} on {method} {url}; "
                f"retrying in {delay:.1f}s (attempt "
                f"{attempt + 2}/{_MAX_ATTEMPTS})",
                file=sys.stderr,
            )
            _sleep(delay)
    raise AssertionError("unreachable")  # pragma: no cover


def fetch_pr_state(repo: str, pr_number: str) -> dict:
    """Read the PR's live mergeability / review / draft state.

    Returns a dict with at least ``mergeable``, ``mergeable_state``,
    ``draft``, ``merged`` and ``state`` (the raw API fields snake_cased by
    GitHub). Callers use it to surface a concrete ``NOT_MERGEABLE`` / blocked
    reason in the report instead of guessing from the diff alone.
    """
    url = f"{_api_base()}/repos/{repo}/pulls/{pr_number}"
    payload = _default_api_call("GET", url)
    return {
        "mergeable": payload.get("mergeable"),
        "mergeable_state": payload.get("mergeable_state"),
        "draft": bool(payload.get("draft")),
        "merged": bool(payload.get("merged")),
        "state": payload.get("state"),
    }


# Label applied to a PR whose prcheck gate is failing. The label is prefixed so
# operators can distinguish tool-managed labels from hand-curated ones.
BLOCKER_LABEL = "prcheck:blocked"


def sync_blocker_label(repo: str, pr_number: str, blocked: bool) -> str | None:
    """Add/remove the blocker label so the PR list shows a failing gate.

    Returns the label name when the label is now present, ``None`` when it was
    removed. The GitHub issue-label API is idempotent: adding an existing label
    returns 200 (not a duplicate); removing a missing label is a 200 no-op.
    """
    url = f"{_api_base()}/repos/{repo}/issues/{pr_number}/labels"
    if blocked:
        _default_api_call("POST", url, {"labels": [BLOCKER_LABEL]})
        return BLOCKER_LABEL
    try:
        _default_api_call("DELETE", f"{url}/{BLOCKER_LABEL}")
    except urllib.error.HTTPError as e:
        # 404 means the label wasn't there — already in the desired state.
        if e.code != 404:
            raise
    return None


def review_comments_for_issues(issues: list) -> list[dict]:
    """Turn engine issues into inline comment payloads.

    One comment per (path, line), with every finding at that location merged
    into the body (deduplicated). Only high/medium findings carry a snippet;
    low/info findings are listed without it so the comment stays readable.
    """
    by_loc: dict[tuple[str, int], list] = {}
    for issue in issues:
        by_loc.setdefault((issue.path, issue.line), []).append(issue)

    out: list[dict] = []
    for (path, line), items in sorted(by_loc.items()):
        lines = []
        for item in sorted(items, key=lambda i: i.severity, reverse=True):
            snippet = (item.snippet or "").strip()
            if item.severity in ("medium", "high") and snippet:
                lines.append(f"- **[{item.rule_id}] {item.summary}** `{snippet[:80]}`")
            else:
                lines.append(f"- [{item.rule_id}] {item.summary}")
        out.append(
            {
                "body": _INLINE_MARKER + "\n\n" + "\n".join(lines),
                "path": path,
                "line": line,
            }
        )
    return out


def list_review_comment_bodies(
    repo: str, pr_number: str, commit_id: str
) -> set[str]:
    """Return the marker-prefixed bodies of review comments already posted.

    Used to skip re-posting a finding that a previous run (same marker) already
    anchored at a line. Returns an empty set when the list call fails so the
    caller still posts (best-effort idempotency, never a hard failure).
    """
    marker = _INLINE_MARKER + "\n\n"
    url = f"{_api_base()}/repos/{repo}/pulls/{pr_number}/comments"
    try:
        payload = _default_api_call("GET", url)
    except urllib.error.HTTPError:
        return set()
    return {
        c["body"]
        for c in payload
        if c.get("body", "").startswith(marker)
    }


def post_review_comments(
    repo: str, pr_number: str, commit_id: str, comments: list[dict]
) -> list[str]:
    """Post inline review comments, skipping ones already on the PR.

    Each comment is posted independently so one failing API call (e.g. a
    downstream ``Not Found`` on a moved line) doesn't block the rest.
    Returns the posted HTML URLs.
    """
    posted: list[str] = []
    existing = list_review_comment_bodies(repo, pr_number, commit_id)
    for comment in comments:
        if comment["body"] in existing:
            continue
        url = f"{_api_base()}/repos/{repo}/pulls/{pr_number}/comments"
        try:
            payload = _default_api_call(
                "POST", url, {
                    "body": comment["body"],
                    "commit_id": commit_id,
                    "path": comment["path"],
                    "line": comment["line"],
                }
            )
        except urllib.error.HTTPError as e:
            print(f"[prcheck] inline comment skipped for "
                  f"{comment['path']}:{comment['line']}: HTTP {e.code} "
                  f"{e.reason}", file=sys.stderr)
            continue
        posted.append(payload.get("html_url", url))
    return posted


def _ghmock_dir() -> Path:
    p = Path(__file__).resolve().parent.parent / "tests" / "ghmock"
    p.mkdir(parents=True, exist_ok=True)
    return p


def fixture_body_path() -> Path:
    return _ghmock_dir() / "posted_comment.md"


def _load_fixture_body() -> str:
    """For offline demo/testing: stream the report to a fixture PR comment."""
    f = fixture_body_path()
    return f.read_text() if f.exists() else ""


def mock_post(repo: str, pr_number: str, body: str) -> str:
    """Offline 'gh simulation': persist the comment body with metadata."""
    path = fixture_body_path()
    path.write_text(
        f"<!-- gh-mock comment for {repo}#{pr_number} (no network) -->\n\n{body}",
        encoding="utf-8",
    )
    return f"mock://{repo}/pull/{pr_number}#comment"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Post prcheck report as a PR comment")
    ap.add_argument("--repo", help="owner/repo")
    ap.add_argument("--pr", help="pull request number")
    ap.add_argument("--body", help="Markdown body to post")
    ap.add_argument("--body-file", help="read body from this file")
    ap.add_argument("--fixture-body", action="store_true",
                    help="simplified local demo (no network)")
    ap.add_argument("--mock", action="store_true",
                    help="write body into tests/ghmock instead of posting")
    ap.add_argument("--gh-cli", action="store_true",
                    help="post via the `gh` CLI instead of the HTTP API")
    args = ap.parse_args(argv)

    if args.fixture_body:
        body = _load_fixture_body()
        print(f"fixture comment loaded: {len(body)} chars")
        return 0

    body = args.body
    if args.body_file:
        body = Path(args.body_file).read_text(encoding="utf-8")
    if not body:
        print("nothing to post", file=sys.stderr)
        return 2
    if args.mock:
        url = mock_post(args.repo or "", args.pr or "", body)
        print(f"[mock] PR comment written -> {url}")
        return 0
    if not (args.repo and args.pr):
        print("--repo and --pr are required (or use --fixture-body/--mock)", file=sys.stderr)
        return 2

    url = (
        post_via_gh_cli(args.repo, args.pr, body)
        if args.gh_cli
        else post_via_http(args.repo, args.pr, body)
    )
    print(f"comment posted: {url}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
