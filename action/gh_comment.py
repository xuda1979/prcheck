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
    import urllib.request

    api = f"{_api_base()}/repos/{repo}/issues/{pr_number}/comments"
    req = urllib.request.Request(
        api,
        data=json.dumps({"body": body}).encode("utf-8"),
        headers={
            "Authorization": f"token {_token()}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "prcheck-action",
        },
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:  # noqa: S310 (explicit GitHub API)
        payload = json.loads(resp.read().decode("utf-8"))
        return payload.get("html_url", api)


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
