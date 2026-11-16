"""Integration tests for the CLI (AC4, AC5, AC6)."""

import json
import os
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
DIFF = FIXTURES / "example_pr.diff"
V1 = FIXTURES / "openapi_v1.yaml"
V2 = FIXTURES / "openapi_v2.yaml"


def _run(args, env_extra=None, **kw):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).parent.parent)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "prcheck", *args],
        capture_output=True,
        text=True,
        env=env,
        **kw,
    )


def test_cli_markdown_stdout():
    r = _run(["-d", str(DIFF)])
    assert r.returncode == 0, r.stderr
    assert "PR Security" in r.stdout
    assert "Security checklist" in r.stdout


def test_cli_markdown_to_file(tmp_path):
    out = tmp_path / "report.md"
    r = _run(["-d", str(DIFF), "-o", str(out)])
    assert r.returncode == 0
    assert out.exists()
    assert "Security checklist" in out.read_text()


def test_cli_sarif(tmp_path):
    out = tmp_path / "out.sarif"
    r = _run(["-d", str(DIFF), "--sarif", str(out)])
    assert r.returncode == 0
    assert json.loads(out.read_text())["version"] == "2.1.0"


def test_cli_security_only():
    r = _run(["-d", str(DIFF), "--security-only", "--json"])
    data = json.loads(r.stdout)
    cats = {f["category"] for f in data["findings"]}
    assert cats == {"security"} or cats.issubset({"security"})


def test_cli_require_high_gate():
    r = _run(["-d", str(DIFF), "--require-high-ok"])
    assert r.returncode == 1
    assert "BLOCKED" in r.stdout


def test_cli_exit_pass_without_gate():
    r = _run(["-d", str(DIFF)])
    assert r.returncode == 0


def test_cli_openapi_changelog(tmp_path):
    out = tmp_path / "oa.md"
    r = _run(["-d", str(DIFF), "--openapi-old", str(V1), "--openapi-new", str(V2), "-o", str(out)])
    assert r.returncode == 0, r.stderr
    md = out.read_text()
    assert "OpenAPI changelog" in md
    assert "Breaking changes" in md
    assert "Non-breaking changes" in md


def test_cli_openapi_json():
    r = _run(["-d", str(DIFF), "--openapi-old", str(V1), "--openapi-new", str(V2), "--json"])
    data = json.loads(r.stdout)
    assert data["openapi"] and data["semver"]["suggested_bump"] == "major"


def test_cli_stdin_pipe():
    r = _run(["-d", "-"], cwd=str(Path(__file__).parent.parent), input=DIFF.read_text())
    assert r.returncode == 0
    assert "Security checklist" in r.stdout


def test_cli_version():
    r = _run(["--version"])
    assert r.stdout.strip() == f"prcheck {__import__('prcheck').__version__}"


def test_cli_llm_summary_section():
    """--llm-summary appends the mock (offline) summary, listing high items."""
    r = _run(["-d", str(DIFF), "--llm-summary", "--no-cache"])
    assert r.returncode == 0, r.stderr
    assert "Mock LLM summary" in r.stdout
    assert "HIGH security" in r.stdout
    # Off by default: no summary without the flag
    r2 = _run(["-d", str(DIFF), "--no-cache"])
    assert "Mock LLM summary" not in r2.stdout


def test_cli_requires_both_openapi_flags():
    """Only one of --openapi-old/--openapi-new is a config error."""
    r = _run(["-d", str(DIFF), "--openapi-old", str(V1)])
    assert r.returncode == 1
    assert "must be used together" in r.stderr
    r2 = _run(["-d", str(DIFF), "--openapi-new", str(V2)])
    assert r2.returncode == 1
    assert "must be used together" in r2.stderr


def _fake_gh(tmp_path, diff_text, *, fail=False):
    """A fake `gh` on PATH: prints diff_text for `pr diff`, or errors.

    Also appends the invocation args to FAKE_GH_LOG (if set) so tests can
    assert which repo/PR the CLI asked for.
    """
    script = """import os, sys
args = sys.argv[1:]
log = os.environ.get('FAKE_GH_LOG')
if log:
    with open(log, 'a') as f:
        f.write(repr(args) + '\\n')
if args[:2] != ['pr', 'diff']:
    sys.stderr.write('unexpected args: %r\\n' % args)
    sys.exit(3)
if __FAIL__:
    sys.stderr.write('gh: could not resolve to a Pull Request\\n')
    sys.exit(1)
sys.stdout.write(__DIFF__)
"""
    script = script.replace("__FAIL__", "True" if fail else "False")
    script = script.replace("__DIFF__", repr(diff_text))
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "gh").write_text(f"#!/usr/bin/env python3\n{script}")
    (bindir / "gh").chmod(0o755)
    return bindir


def test_cli_fetch_pr_diff_via_gh(tmp_path):
    """SPEC FR1: `--repo/--pr` fetch the diff through a (fake) gh on PATH."""
    log = tmp_path / "gh.log"
    bindir = _fake_gh(tmp_path, DIFF.read_text())
    r = _run(
        ["--repo", "owner/repo", "--pr", "42", "--json", "--no-cache"],
        env_extra={"PATH": f"{bindir}:{os.environ['PATH']}", "FAKE_GH_LOG": str(log)},
    )
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    assert data["stats"]["files_changed"] == 6
    invoked = log.read_text().strip()
    assert "'--repo', 'owner/repo'" in invoked and "'42'" in invoked
    assert any(f["category"] == "security" for f in data["findings"]), (
        "expected security findings from the fetched diff"
    )


def test_cli_fetch_pr_missing_gh(tmp_path):
    """Missing `gh` on PATH is a clear error, not a traceback."""
    bindir = tmp_path / "empty"  # keep PYTHONPATH; no gh binary here
    bindir.mkdir()
    env = {**os.environ, "PATH": str(bindir)}
    r = _run(
        ["--repo", "owner/repo", "--pr", "42"],
        env_extra={"PATH": str(bindir)},
    )
    assert r.returncode == 1
    assert "gh` not found" in r.stderr


def test_cli_fetch_pr_failure_propagates(tmp_path):
    """A failing `gh pr diff` surfaces gh's stderr as the error."""
    bindir = _fake_gh(tmp_path, "", fail=True)
    r = _run(
        ["--repo", "owner/repo", "--pr", "42"],
        env_extra={"PATH": f"{bindir}:{os.environ['PATH']}"},
    )
    assert r.returncode == 1
    assert "could not resolve to a Pull Request" in r.stderr


def test_cli_mock_llm_alias():
    """--mock-llm is an alias for --llm-summary (deterministic mock summary)."""
    r = _run(["-d", str(DIFF), "--mock-llm", "--no-cache"])
    assert r.returncode == 0, r.stderr
    assert "Mock LLM summary" in r.stdout
    assert "HIGH security" in r.stdout


def test_cli_base_dir_resolves_relative_paths(tmp_path):
    """--base-dir resolves relative diff/spec/output/cache refs against a root."""
    import shutil

    shutil.copy(DIFF, tmp_path / "pr.diff")  # base-dir-relative diff input
    sub = tmp_path / "sub"
    sub.mkdir()
    cache_dir = tmp_path / "cache"
    r = _run(
        [
            "--base-dir",
            str(tmp_path),
            "pr.diff",  # bare positional relative to --base-dir
            "--sarif",
            "out.sarif",
            "--cache-dir",
            str(cache_dir),
            "--no-cache",
        ],
        cwd=str(sub),  # cwd differs from the base dir to prove resolution
    )
    assert r.returncode == 0, r.stderr
    assert "Security checklist" in r.stdout
    assert (tmp_path / "out.sarif").exists(), "relative --sarif path should resolve under --base-dir"
    assert json.loads((tmp_path / "out.sarif").read_text())["version"] == "2.1.0"


def test_cli_repo_pr_conflicts_with_diff_file():
    """--repo/--pr and a diff file are mutually exclusive sources."""
    r = _run(["--repo", "owner/repo", "--pr", "42", "-d", str(DIFF)])
    assert r.returncode == 1
    assert "cannot be combined" in r.stderr


def test_cli_repo_requires_pr():
    """A bare --repo (no --pr) is a config error, not a confusing gh call."""
    r = _run(["--repo", "owner/repo"])
    assert r.returncode == 1
    assert "--repo requires --pr" in r.stderr


def test_cli_invalid_openapi_spec_clean_error(tmp_path):
    """A structurally invalid spec is a clean error, not a traceback."""
    bad = tmp_path / "bad.yaml"
    bad.write_text('openapi: 3.0.0\ninfo:\n  title: t\n  version: "1"\npaths: [oops]\n')
    r = _run(
        ["-d", str(DIFF), "--openapi-old", str(bad), "--openapi-new", str(V2), "--no-cache"]
    )
    assert r.returncode == 1
    assert "'paths' must be a mapping" in r.stderr
    assert "Traceback" not in r.stderr


def test_cli_invalid_openapi_yaml_clean_error(tmp_path):
    """Unparseable YAML in a spec is also a clean error, not a traceback."""
    bad = tmp_path / "bad.yaml"
    bad.write_text("openapi: 3.0.0\ninfo: [unclosed\n")
    r = _run(
        ["-d", str(DIFF), "--openapi-old", str(bad), "--openapi-new", str(V2), "--no-cache"]
    )
    assert r.returncode == 1
    assert "invalid YAML" in r.stderr
    assert "Traceback" not in r.stderr
