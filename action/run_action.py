"""GitHub Action entrypoint for prcheck.

Inputs (from action.yml / env):

  INPUT_DIFF            inline diff (optional; overrides auto-generate)
  INPUT_BASE_SPEC       path to old OpenAPI spec
  INPUT_HEAD_SPEC       path to new OpenAPI spec
  INPUT_OUTPUT_DIR      where to write report artifacts
  INPUT_REQUIRE_HIGH_OK "true"/"false" gate
  INPUT_SECURITY_ONLY   "" or "true"
  INPUT_CATEGORIES      deprecated, kept for compatibility
  INPUT_POST_COMMENT    "true"/"false"  post a PR comment (needs GH_TOKEN)
  PR_NUMBER / GITHUB_EVENT_PATH  used to discover the PR

The entrypoint:

1. derives the changed-file diff from `git diff base...head` when no inline
   diff is supplied,
2. runs the same engines the CLI uses,
3. writes report.md / report.sarif into OUTPUT_DIR,
4. optionally posts the report as a PR comment,
5. exits non-zero when the gate blocks.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from prcheck import __version__


def _env_flag(name: str, default: bool = False) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on", "y")


def _discover_pr_number() -> str | None:
    n = os.environ.get("PR_NUMBER")
    if n:
        return n
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    if event_path and Path(event_path).exists():
        try:
            data = json.loads(Path(event_path).read_text(encoding="utf-8"))
            return str(data.get("number") or (data.get("pull_request") or {}).get("number") or "")
        except Exception:
            return None
    return None


def _default_diff_text() -> str:
    """Build a diff from git base...head when available."""
    workspace = os.environ.get("GITHUB_WORKSPACE", ".")
    base = os.environ.get("INPUT_BASE_REF", "origin/main")
    head = os.environ.get("INPUT_HEAD_REF", "HEAD")
    try:
        res = subprocess.run(
            ["git", "-C", workspace, "diff", f"{base}...{head}"],
            capture_output=True,
            text=True,
        )
        if res.returncode == 0:
            return res.stdout
        # fall back to `git diff base` (no merge base)
        res = subprocess.run(
            ["git", "-C", workspace, "diff", base],
            capture_output=True,
            text=True,
        )
        return res.stdout if res.returncode == 0 else ""
    except Exception:
        return ""


def main() -> int:
    workdir = Path(os.environ.get("GITHUB_WORKSPACE", Path.cwd()))

    diff_text = os.environ.get("INPUT_DIFF", "") or _default_diff_text()
    if not diff_text.strip():
        sys.stderr.write("prcheck-action: no diff input (INPUT_DIFF or git diff)\n")
        # not fatal: report empty analysis so the gate is meaningful
        diff_text = ""

    # We generate analysis the same way the CLI does (shared engine).
    from prcheck.render import render_markdown, render_sarif
    from prcheck.engine import run_analysis

    base_spec_text = new_spec_text = None
    base_spec = os.environ.get("INPUT_BASE_SPEC", "")
    head_spec = os.environ.get("INPUT_HEAD_SPEC", "")
    if base_spec and head_spec:
        base_path = Path(base_spec)
        head_path = Path(head_spec)
        if not base_path.is_absolute():
            base_path = workdir / base_path
        if not head_path.is_absolute():
            head_path = workdir / head_path
        if base_path.exists() and head_path.exists():
            base_spec_text = base_path.read_text(encoding="utf-8")
            new_spec_text = head_path.read_text(encoding="utf-8")
        else:
            sys.stderr.write(
                f"prcheck-action: openapi specs missing "
                f"({base_path}, {head_path}); skipping changelog\n"
            )

    result = run_analysis(
        diff_text,
        base_spec_text=base_spec_text,
        new_spec_text=new_spec_text,
        base_spec_name=str(base_spec),
        new_spec_name=str(head_spec),
        security_only=_env_flag("INPUT_SECURITY_ONLY"),
        data_only=_env_flag("INPUT_DATA_ONLY"),
        behavior_only=_env_flag("INPUT_BEHAVIOR_ONLY"),
        min_severity=os.environ.get("INPUT_MIN_SEVERITY", "info"),
    )
    issues = result.issues
    stat = result.stat
    openapi_changes = result.openapi_changes
    semver = result.semver

    high_issues = [i for i in issues if i.severity == "high"]
    gate = _env_flag("INPUT_REQUIRE_HIGH_OK")
    blocked = gate and bool(high_issues)

    out_dir = Path(os.environ.get("INPUT_OUTPUT_DIR", "prcheck-reports"))
    if not out_dir.is_absolute():
        out_dir = workdir / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    md = render_markdown(
        issues,
        stat=stat,
        openapi_changes=openapi_changes,
        high_blocked=blocked,
    )
    (out_dir / "report.md").write_text(md, encoding="utf-8")
    (out_dir / "report.sarif").write_text(render_sarif(issues), encoding="utf-8")

    semver_path = out_dir / "semver.json"
    semver_path.write_text(
        json.dumps(
            {
                "version": __version__,
                "semver": semver,
                "blocked": blocked,
                "high_count": len(high_issues),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"prcheck-action: wrote {out_dir / 'report.md'} and report.sarif; "
          f"high={len(high_issues)} blocked={blocked}")

    # optional PR comment
    if _env_flag("INPUT_POST_COMMENT"):
        pr = _discover_pr_number()
        repo = os.environ.get("GITHUB_REPOSITORY", "")
        if pr and repo:
            from action.gh_comment import post_via_http

            try:
                url = post_via_http(repo, pr, md)
                print(f"prcheck-action: comment posted -> {url}")
            except Exception as e:  # pragma: no cover
                sys.stderr.write(f"prcheck-action: comment failed: {e}\n")
        else:
            sys.stderr.write("prcheck-action: POST_COMMENT=true but no PR is "
                             "detected (GITHUB_EVENT_PATH / PR_NUMBER)\n")

    return 1 if blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())
