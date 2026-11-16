"""Unit tests for the content-addressed analysis cache (FR #6)."""

import os
import subprocess
import sys
from pathlib import Path

from prcheck.cache import AnalysisCache, payload_key


def test_cache_key_stable_and_sensitive(tmp_path):
    a = payload_key("diff1", ["specA"], "sec-opt")
    b = payload_key("diff1", ["specA"], "sec-opt")
    assert a == b
    assert payload_key("diff2", ["specA"], "sec-opt") != a
    assert payload_key("diff1", ["specB"], "sec-opt") != a
    assert payload_key("diff1", ["specA"], "other") != a


def test_cache_roundtrip(tmp_path):
    c = AnalysisCache(tmp_path / "c", enabled=True)
    key = payload_key("x", ["y"], "z")
    assert c.get(key) is None
    c.put(key, {"findings": [], "stats": {"files_changed": 1}})
    assert c.hit(key)
    got = c.get(key)
    assert got["stats"]["files_changed"] == 1


def test_cache_disabled(tmp_path):
    c = AnalysisCache("whatever", enabled=False)
    key = payload_key("x", [], "")
    assert c.get(key) is None
    c.put(key, {})
    assert c.get(key) is None


def test_engine_version_salts_key():
    # output-affecting engine changes must invalidate existing cache entries
    from prcheck import cache as cache_mod

    v = cache_mod.ENGINE_VERSION
    assert v, "ENGINE_VERSION must be set"
    assert payload_key("d", [], "") != payload_key("e", [], "")
    before = payload_key("same", [], "")
    cache_mod.ENGINE_VERSION = v + "-x"
    try:
        after = cache_mod.payload_key("same", [], "")
        assert after != before, "engine-version salt must change the key"
    finally:
        cache_mod.ENGINE_VERSION = v


def test_cli_uses_cache_and_reports_hit(tmp_path):
    """Integration: second run for identical input reads from cache."""
    fixtures = Path(__file__).parent / "fixtures"
    cache_dir = tmp_path / "cache"
    run = lambda *a: subprocess.run(  # noqa: E731
        [sys.executable, "-m", "prcheck", *a],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).parent.parent)},
    )
    first = run("-d", str(fixtures / "example_pr.diff"), "--cache-dir", str(cache_dir))
    assert first.returncode == 0, first.stderr
    assert "[cache] hit" not in first.stderr
    second = run("-d", str(fixtures / "example_pr.diff"), "--cache-dir", str(cache_dir))
    assert second.returncode == 0, second.stderr
    assert "[cache] hit" in second.stderr
    # same report content on cache hit
    assert first.stdout == second.stdout
