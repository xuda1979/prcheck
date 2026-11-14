"""Unified diff parser.

Parses the output of ``git diff`` / ``gh pr diff`` into structured file/hunk
objects with precise per-line numbers in the *new* file (used for
``file:line`` citations in the generated checklist).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterator, Optional

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$")
_GIT_HEADER_RE = re.compile(r"^diff --git ")
_BINARY_RE = re.compile(r"^Binary files .* differ$")


class DiffParseError(ValueError):
    """Raised when a diff blob cannot be parsed at all."""


@dataclass
class DiffLine:
    """A single line inside a parsed hunk body."""

    kind: str  # "add" | "remove" | "context"
    text: str  # line content without the +/-/space marker
    new_lineno: Optional[int] = None  # line number in the NEW file
    old_lineno: Optional[int] = None  # line number in the OLD file


@dataclass
class Hunk:
    new_start: int
    new_count: int
    old_start: int
    old_count: int
    header: str
    lines: list[DiffLine] = field(default_factory=list)

    @property
    def added(self) -> int:
        return sum(1 for l in self.lines if l.kind == "add")

    @property
    def removed(self) -> int:
        return sum(1 for l in self.lines if l.kind == "remove")


@dataclass
class FileDiff:
    old_path: str = ""
    new_path: str = ""
    status: str = "modified"  # added | removed | modified | renamed | binary
    hunks: list[Hunk] = field(default_factory=list)

    @property
    def added(self) -> int:
        return sum(h.added for h in self.hunks)

    @property
    def removed(self) -> int:
        return sum(h.removed for h in self.hunks)

    def added_lines(self) -> Iterator[DiffLine]:
        """Yield added lines (with new-file line numbers)."""
        for hunk in self.hunks:
            for line in hunk.lines:
                if line.kind == "add":
                    yield line

    def added_texts(self) -> Iterator[tuple[int, str]]:
        for line in self.added_lines():
            yield line.new_lineno or 0, line.text


def _strip_path(raw: str) -> str:
    """Turn ``b/src/x.py`` into ``src/x.py``; handle ``/dev/null``."""
    raw = raw.strip()
    if raw == "/dev/null":
        return ""
    # git mangles paths with spaces as `b/a b/file`; just strip the prefix.
    if raw.startswith("a/") or raw.startswith("b/"):
        return raw[2:]
    return raw


def parse_diff(text: str) -> list[FileDiff]:
    """Parse a unified diff blob into :class:`FileDiff` objects."""
    files: list[FileDiff] = []
    cur: Optional[FileDiff] = None
    cur_hunk: Optional[Hunk] = None
    new_no = old_no = 0
    saw_hunk = False

    for raw in text.splitlines():
        # --- headers ---------------------------------------------------
        if _GIT_HEADER_RE.match(raw):
            cur = FileDiff()
            files.append(cur)
            cur_hunk = None
            continue
        if raw.startswith("--- "):
            if cur is None:
                cur = FileDiff()
                files.append(cur)
            cur.old_path = _strip_path(raw[4:])
            continue
        if raw.startswith("+++ "):
            if cur is None:
                cur = FileDiff()
                files.append(cur)
            cur.new_path = _strip_path(raw[4:])
            continue
        if raw.startswith("new file mode") or raw.startswith("new mode"):
            if cur is not None:
                cur.status = "added"
            continue
        if raw.startswith("deleted file mode") or raw.startswith("old mode"):
            if cur is not None:
                cur.status = "removed"
            continue
        if raw.startswith("rename from ") or raw.startswith("rename to "):
            if cur is not None:
                cur.status = "renamed"
            continue
        if _BINARY_RE.match(raw):
            if cur is not None:
                cur.status = "binary"
            continue
        if raw.startswith("\\ No newline") or raw.startswith("index ") \
                or raw.startswith("similarity ") or raw.startswith("dissimilarity "):
            continue
        if raw.startswith("@@ "):
            m = _HUNK_RE.match(raw)
            if not m:
                continue
            old_start = int(m.group(1))
            old_count = int(m.group(2) or "1")
            new_start = int(m.group(3))
            new_count = int(m.group(4) or "1")
            hdr = m.group(5) or ""
            cur_hunk = Hunk(new_start, new_count, old_start, old_count, hdr)
            if cur is None:
                cur = FileDiff()
                files.append(cur)
            cur.hunks.append(cur_hunk)
            new_no = new_start
            old_no = old_start
            saw_hunk = True
            continue

        # --- hunk body ---------------------------------------------------
        if cur_hunk is None:
            # A stray context line outside any hunk (e.g. no-newline marker).
            continue
        if saw_hunk:
            if raw.startswith("+"):
                cur_hunk.lines.append(DiffLine("add", raw[1:], new_no, None))
                new_no += 1
            elif raw.startswith("-"):
                cur_hunk.lines.append(DiffLine("remove", raw[1:], None, old_no))
                old_no += 1
            elif raw.startswith(" ") or raw == "":
                cur_hunk.lines.append(DiffLine("context", raw[1:] if raw else "", new_no, old_no))
                new_no += 1
                old_no += 1

    # Normalize status based on paths (headers are not always present).
    for fd in files:
        if not fd.old_path and (fd.status == "modified" and fd.hunks):
            fd.status = "added"
        if not fd.new_path:
            fd.status = "removed"
    return files


def compute_stats(files: list[FileDiff]) -> dict:
    """Aggregate files-changed / insertions / deletions counters."""
    return {
        "files_changed": len([f for f in files if f.status not in ("binary",) or f.hunks]),
        "insertions": sum(f.added for f in files),
        "deletions": sum(f.removed for f in files),
        "files": [
            {
                "path": f.new_path or f.old_path,
                "status": f.status,
                "added": f.added,
                "removed": f.removed,
            }
            for f in files
        ],
    }
