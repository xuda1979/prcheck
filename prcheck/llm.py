"""Optional LLM summarizer — default OFF.

The design goal (per low-compute rule) is a local rules engine. This module
provides an extensible stub that can summarize the structured findings. The
default implementation is a deterministic "mock" that returns a canned summary,
so CI and tests never require network access or model weights.

Enable with ``--llm-summary``; pass custom prompt/hooks by subclassing
:class:`Summarizer`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .issues import Issue


@dataclass
class Summarizer:
    """Mock summarizer (default OFF in CLI)."""

    enabled: bool = False

    def summarize(self, issues: Iterable[Issue], stat: dict) -> str:
        """Return a deterministic summary (mock; no LLM call made)."""
        issues = list(issues)
        if not issues:
            return "_No findings to summarize._"
        high = [i for i in issues if i.severity == "high"]
        security_high = [i for i in high if i.category == "security"]
        lines = [
            (
                "Mock LLM summary: found "
                f"{len(issues)} findings, {len(high)} high"
                f" ({len(security_high)} security-high) in "
                f"{stat.get('files_changed', '?')} changed files."
            )
        ]
        for i in high[:5]:
            lines.append(f"- HIGH {i.category}: {i.summary} @ {i.location}")
        return "\n".join(lines)
