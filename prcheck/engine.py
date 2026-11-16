"""Shared analysis pipeline: diff rules + OpenAPI changelog.

Used by the CLI, the GitHub Action and the (optional) webhook bridge so the
rule set and the semver inference never drift between entry points.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .diff import compute_stats, parse_diff
from .issues import Issue, filter_issues
from .openapi import compare_specs, infer_semver, load_spec


@dataclass
class AnalysisResult:
    issues: list[Issue] = field(default_factory=list)
    stat: dict = field(default_factory=dict)
    openapi_changes: list[dict] = field(default_factory=list)
    semver: dict | None = None

    def as_dict(self) -> dict:
        return {
            "issues": [i.__dict__ for i in self.issues],
            "stat": self.stat,
            "openapi": self.openapi_changes,
            "semver": self.semver,
        }


def run_analysis(
    diff_text: str,
    *,
    base_spec_text: str | None = None,
    new_spec_text: str | None = None,
    base_spec_name: str = "",
    new_spec_name: str = "",
    security_only: bool = False,
    data_only: bool = False,
    behavior_only: bool = False,
    min_severity: str = "info",
) -> AnalysisResult:
    """Run the rules engine and (optionally) the OpenAPI changelog."""
    from .rules import run_rules

    files = parse_diff(diff_text)
    issues = run_rules(files)
    issues = filter_issues(
        issues,
        security_only=security_only,
        data_only=data_only,
        behavior_only=behavior_only,
        min_severity=min_severity,
    )
    stat = compute_stats(files)

    openapi_changes: list[dict] = []
    semver: dict | None = None
    if base_spec_text is not None and new_spec_text is not None:
        old_s = load_spec(base_spec_text, base_spec_name or "old")
        new_s = load_spec(new_spec_text, new_spec_name or "new")
        changes = compare_specs(old_s, new_s)
        openapi_changes = [c.to_dict() for c in changes]
        semver = infer_semver(old_s.version_string, new_s.version_string, changes)

    return AnalysisResult(
        issues=issues,
        stat=stat,
        openapi_changes=openapi_changes,
        semver=semver,
    )
