"""prcheck CLI: analyze a PR diff + OpenAPI changelog, gate, output reports."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Optional

from . import __version__
from .diff import compute_stats, parse_diff
from .issues import Issue, SEVERITY_ORDER
from .llm import Summarizer
from .openapi import diff_spec_text, load_spec
from .render import render_markdown, render_sarif
from .rules import run_rules


def _read(path: str | Path) -> str:
    p = Path(path)
    if not p.exists():
        sys.exit(f"error: {path}: no such file")
    return p.read_text(encoding="utf-8", errors="replace")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="prcheck",
        description="PR security checklist + OpenAPI changelog generator.",
        epilog="Reads a git/gh PR diff and writes a checklist (Markdown / SARIF), "
               "plus an OpenAPI breaking-change report.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("diff", nargs="?", help="path to PR diff file (or use -D/-d)")
    p.add_argument("-d", "--diff-file", dest="diff_file", help="path to PR diff")
    p.add_argument(
        "--openapi-old",
        help="old OpenAPI spec file (yaml/json) to diff from",
    )
    p.add_argument(
        "--openapi-new",
        help="new OpenAPI spec file (yaml/json) to diff against",
    )
    p.add_argument(
        "-o",
        "--output",
        help="write Markdown report to this file (default: stdout)",
    )
    p.add_argument(
        "--sarif",
        help="write SARIF log to this path",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="dump structured findings as JSON to stdout (overrides -o)",
    )
    p.add_argument(
        "--security-only",
        action="store_true",
        help="only emit Security category findings",
    )
    p.add_argument(
        "--data-only",
        action="store_true",
        help="only emit Data category findings",
    )
    p.add_argument(
        "--behavior-only",
        action="store_true",
        help="only emit Behavior category findings",
    )
    p.add_argument(
        "--min-severity",
        choices=("info", "low", "medium", "high"),
        default="info",
        help="minimum severity to report",
    )
    p.add_argument(
        "--require-high-ok",
        action="store_true",
        help="exit non-zero if any unresolved high-severity finding exists",
    )
    p.add_argument(
        "--exit-code",
        choices=("pass", "fail-at-high", "fail-at-medium"),
        default="pass",
        help="exit policy for CI gate",
    )
    p.add_argument(
        "--llm-summary",
        action="store_true",
        help="include optional mock LLM summary (default off; no network)",
    )
    p.add_argument(
        "--mock-llm",
        action="store_true",
        dest="mock_llm_flag",
        help="explicitly use the deterministic mock summarizer",
    )
    p.add_argument(
        "--base-dir",
        help="base directory to resolve relative path refs (default: cwd)",
    )
    p.add_argument(
        "--cache-dir",
        default=".prcheck-cache",
        help="directory for the incremental analysis cache (default .prcheck-cache)",
    )
    p.add_argument(
        "--no-cache",
        action="store_true",
        help="disable the analysis cache",
    )
    return p


def _filter_issues(
    issues: list[Issue],
    *,
    security_only=False,
    data_only=False,
    behavior_only=False,
    min_severity="info",
) -> list[Issue]:
    rank = SEVERITY_ORDER.get(min_severity, 0)
    out = []
    for i in issues:
        if security_only and i.category != "security":
            continue
        if data_only and i.category != "data":
            continue
        if behavior_only and i.category != "behavior":
            continue
        if SEVERITY_ORDER.get(i.severity, 0) < rank:
            continue
        out.append(i)
    return out


def _load_openapi_changes(old_path: str, new_path: str) -> tuple[list[dict], dict]:
    old_spec = load_spec(_read(old_path), old_path)
    new_spec = load_spec(_read(new_path), new_path)
    from .openapi import compare_specs, infer_semver

    changes = compare_specs(old_spec, new_spec)
    semver = infer_semver(old_spec.version_string, new_spec.version_string, changes)
    return [c.to_dict() for c in changes], semver


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    diff_text = ""
    if args.diff or args.diff_file:
        src = args.diff_file or (args.diff if args.diff else "")
        # if the bare `diff` arg points to a file, read it
        if os.path.exists(src):
            diff_text = _read(src)
        elif src == "-":
            diff_text = sys.stdin.read()
        else:
            # support `prcheck "git diff..."` style inline text? keep file-only.
            sys.exit(f"error: cannot read diff source: {src}")
    elif not sys.stdin.isatty():
        diff_text = sys.stdin.read()
    else:
        sys.exit("error: no diff input (provide a diff file or pipe stdin)")

    from .cache import AnalysisCache, payload_key

    # NB: optional LLM summary is NOT part of the cache key (mock, costless)
    spec_texts = []
    if args.openapi_old and args.openapi_new:
        try:
            spec_texts = [_read(args.openapi_old), _read(args.openapi_new)]
        except SystemExit:
            spec_texts = []
    option_tag = "|".join(
        [
            str(args.security_only),
            str(args.data_only),
            str(args.behavior_only),
            args.min_severity,
        ]
    )
    key = payload_key(diff_text, spec_texts, option_tag)
    cache = AnalysisCache(args.cache_dir, enabled=not args.no_cache)

    cached = cache.get(key)
    if cached is not None:
        files = parse_diff(diff_text)
        issues = [Issue(**f) for f in cached["findings"]]
        stat = cached["stats"]
        openapi_changes = cached["openapi"]
        semver: Optional[dict] = cached.get("semver")
        print(f"[cache] hit {key}", file=sys.stderr)
    else:
        files = parse_diff(diff_text)
        issues = run_rules(files)
        issues = _filter_issues(
            issues,
            security_only=args.security_only,
            data_only=args.data_only,
            behavior_only=args.behavior_only,
            min_severity=args.min_severity,
        )
        stat = compute_stats(files)

        openapi_changes: list[dict] = []
        semver = None
        if args.openapi_old and args.openapi_new and spec_texts:
            old_spec = load_spec(spec_texts[0], args.openapi_old)
            new_spec = load_spec(spec_texts[1], args.openapi_new)
            from .openapi import compare_specs, infer_semver

            changes = compare_specs(old_spec, new_spec)
            semver = infer_semver(old_spec.version_string, new_spec.version_string, changes)
            openapi_changes = [c.to_dict() for c in changes]

        cache.put(
            key,
            {
                "findings": [i.__dict__ for i in issues],
                "stats": stat,
                "openapi": openapi_changes,
                "semver": semver,
            },
        )

    high_issues = [i for i in issues if i.severity == "high"]
    gate_failed = args.require_high_ok and bool(high_issues)

    if args.json:
        payload = {
            "version": __version__,
            "stats": stat,
            "findings": [i.__dict__ for i in issues],
            "openapi": openapi_changes,
            "semver": semver,
            "gate": {"require_high_ok": args.require_high_ok, "blocked": gate_failed},
        }
        json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
        print()
    else:
        md = render_markdown(
            issues,
            stat=stat,
            openapi_changes=openapi_changes,
            high_blocked=gate_failed,
        )
        if args.llm_summary:
            md += "\n---\n" + Summarizer(enabled=True).summarize(issues, stat) + "\n"
        if args.output:
            Path(args.output).write_text(md, encoding="utf-8")
            print(f"wrote markdown report -> {args.output}")
        else:
            print(md, end="")

    if args.sarif:
        log = render_sarif(issues)
        Path(args.sarif).write_text(log, encoding="utf-8")
        print(f"wrote sarif log -> {args.sarif}")

    # exit policy
    if args.exit_code == "fail-at-high" and high_issues:
        return 1
    if args.exit_code == "fail-at-medium" and any(
        i.severity in ("high", "medium") for i in issues
    ):
        return 1
    if gate_failed:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
