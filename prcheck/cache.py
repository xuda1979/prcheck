"""Content-addressed analysis cache.

Requirement #6: "same base is not re-analyzed". The engine is a pure function
of (diff text, OpenAPI specs, filter options), so we key roughly on a SHA-256
of those inputs. On a cache hit we replay the stored JSON payload instead of
re-parsing the diff and re-running rules.

Cache location: ``--cache-dir`` (default ``.prcheck-cache``). Set
``--no-cache`` to disable.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

# Bump whenever the rule engine / OpenAPI comparison changes in a way that
# changes output for the same input; stale cache entries then simply miss.
ENGINE_VERSION = "6"


def _hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


def payload_key(diff_text: str, spec_texts: list[str], option_tag: str) -> str:
    raw = "\x00".join([ENGINE_VERSION, diff_text, *spec_texts, option_tag])
    return _hash(raw)


class AnalysisCache:
    """Simple JSON cache keyed on input content hashes."""

    def __init__(self, cache_dir: str | Path | None, enabled: bool = True):
        self.enabled = enabled
        if not enabled or not cache_dir:
            self.dir: Path | None = None
            return
        self.dir = Path(cache_dir)
        os.makedirs(self.dir, exist_ok=True)

    def _path(self, key: str) -> Path:
        assert self.dir is not None
        return self.dir / f"{key}.json"

    def get(self, key: str) -> dict | None:
        if not self.enabled or self.dir is None:
            return None
        p = self._path(key)
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    def put(self, key: str, payload: dict) -> None:
        if not self.enabled or self.dir is None:
            return
        tmp = self._path(key).with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self._path(key))

    def hit(self, key: str) -> bool:
        if not self.enabled or self.dir is None:
            return False
        return self._path(key).exists()
