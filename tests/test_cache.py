"""Unit tests for the content-addressed analysis cache (FR #6)."""

import json
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
