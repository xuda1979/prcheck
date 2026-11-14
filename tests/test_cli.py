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


def _run(args, **kw):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).parent.parent)
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
