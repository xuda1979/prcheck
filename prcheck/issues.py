"""Issue (checklist finding) data model and severities/triaging."""

from __future__ import annotations

from dataclasses import dataclass, field


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}

CATEGORY_LABELS = {
    "security": "Security",
    "data": "Data",
    "behavior": "Behavior",
}


@dataclass
class Issue:
    """A single checklist finding referenced to ``path:line``."""

    rule_id: str
    category: str            # security | data | behavior
    severity: str            # info | low | medium | high
    summary: str
    path: str
    line: int
    snippet: str = ""
    hint: str = ""
    refs: list[str] = field(default_factory=list)

    @classmethod
    def from_rule(cls, rule, path: str, line: int, snippet: str) -> "Issue":
        return cls(
            rule_id=rule.id,
            category=rule.category,
            severity=rule.severity,
            summary=rule.summary,
            path=path,
            line=line,
            snippet=snippet[:200],
            hint=rule.hint,
        )

    @property
    def location(self) -> str:
        return f"{self.path}:{self.line}"

    def sev_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)


def severity_filter(issues: list[Issue], min_severity: str = "info") -> list[Issue]:
    rank = SEVERITY_ORDER.get(min_severity, 0)
    return [i for i in issues if i.sev_rank() >= rank]


def group_by_category(issues: list[Issue]) -> dict[str, list[Issue]]:
    from .issues import CATEGORY_LABELS

    out: dict[str, list[Issue]] = {c: [] for c in CATEGORY_LABELS}
    for i in issues:
        out.setdefault(i.category, []).append(i)
    return out


def summary_table(issues: list[Issue]) -> dict[str, dict[str, int]]:
    """{category: {severity: count}} for the report head."""
    out: dict[str, dict[str, int]] = {}
    for i in issues:
        c = out.setdefault(i.category, {"info": 0, "low": 0, "medium": 0, "high": 0})
        if i.severity not in c:
            c[i.severity] = 0
        c[i.severity] += 1
    return out
