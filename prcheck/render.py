"""Rendering: Markdown report, SARIF 2.1.0, and plain text summary."""

from __future__ import annotations

import json
from io import StringIO
from typing import Iterable

from .issues import CATEGORY_LABELS, SEVERITY_ORDER, Issue, group_by_category, summary_table

_EMOJI = {"high": "🔴", "medium": "🟠", "low": "🟡", "info": "⚪"}

# -------------------------------------------------------------------------
# Markdown
# -------------------------------------------------------------------------


def render_markdown(
    issues: Iterable[Issue],
    *,
    stat: dict | None = None,
    openapi_changes: list | None = None,
    high_blocked: bool = False,
    include_blocker: bool = True,
    generator_name: str = "prcheck",
) -> str:
    """Build a GitHub-flavored Markdown checklist report (PR comment ready)."""
    issues = list(issues)
    stat = stat or {}
    buf = StringIO()
    buf.write("## 🔒 PR Security & Data Checklist\n\n")
    if stat:
        buf.write(
            f"_Analyzed {stat.get('files_changed', 0)} files, "
            f"+{stat.get('insertions', 0)} / -{stat.get('deletions', 0)} lines._\n\n"
        )
    counts = summary_table(issues)
    if counts:
        buf.write("| Category | High | Medium | Low | Info |\n")
        buf.write("|---|---|---|---|---|\n")
        for cat in CATEGORY_LABELS:
            c = counts.get(cat)
            if not c:
                continue
            buf.write(
                f"| {CATEGORY_LABELS[cat]} | {c['high']} | {c['medium']} "
                f"| {c['low']} | {c['info']} |\n"
            )
        buf.write("\n")

    if openapi_changes:
        _render_openapi(buf, openapi_changes)

    by_cat = group_by_category(issues)
    for cat in ("security", "data", "behavior"):
        cat_issues = by_cat.get(cat, [])
        if not cat_issues:
            continue
        buf.write(f"### {CATEGORY_LABELS[cat]} checklist\n\n")
        buf.write(f"{len(cat_issues)} item(s) to review:\n\n")
        for i in sorted(cat_issues, key=lambda x: (-x.sev_rank(), x.location)):
            buf.write(
                f"- [ ] {_EMOJI.get(i.severity, '')} [`{i.rule_id}`] "
                f"**{i.summary}** — {i.location}\n"
            )
            if i.snippet:
                buf.write(f"  ```text\n  {i.snippet}\n  ```\n")
            if i.hint:
                buf.write(f"  _hint: {i.hint}_\n")
        buf.write("\n")

    if not issues and not openapi_changes:
        buf.write("No issues found.\n\n")

    if high_blocked and include_blocker:
        buf.write("> ⛔ **Gate: BLOCKED** — unresolved High-severity items "
                  "must be resolved before merging.\n")
    return buf.getvalue()


def _render_openapi(buf: StringIO, changes: list) -> None:
    """Emit the OpenAPI changelog section."""
    breaking = [c for c in changes if c.get("breaking")]
    nonbreaking = [c for c in changes if not c.get("breaking")]
    buf.write("### 🧭 OpenAPI changelog\n\n")
    if breaking:
        buf.write(f"**Breaking changes:** {len(breaking)}\n\n")
        for c in breaking:
            buf.write(f"- {_emoji_for(c.get('severity', 'medium'))} `{c['type']}`"
                      f" `{c.get('path', '')}` — {c.get('summary', '')}\n")
        buf.write("\n")
    if nonbreaking:
        buf.write(f"**Non-breaking changes:** {len(nonbreaking)}\n\n")
        for c in nonbreaking:
            ref = c.get('path') or c.get('schema') or c.get('endpoint') or ''
            buf.write(f"- `{c['type']}` `{ref}` — {c.get('summary', '')}\n")
        buf.write("\n")


def _emoji_for(sev: str) -> str:
    return _EMOJI.get(sev, "🟡")


# -------------------------------------------------------------------------
# SARIF 2.1.0
# -------------------------------------------------------------------------


def render_sarif(
    issues: Iterable[Issue],
    *,
    tool_name: str = "prcheck",
    sarif_version: str = "2.1.0",
) -> str:
    """Produce a SARIF log for CI emitters (GitHub code scanning compatible)."""
    issues = list(issues)
    results = []
    for i in issues:
        results.append(
            {
                "ruleId": i.rule_id,
                "level": _sarif_level(i.severity),
                "message": {"text": f"{i.summary} ({i.hint})".strip()},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": i.path},
                            "region": {
                                "startLine": i.line,
                                "snippet": {"text": i.snippet or ""},
                            },
                        }
                    }
                ],
                "properties": {"category": i.category, "severity": i.severity},
            }
        )
    rules = [
        {
            "id": rid,
            "shortDescription": {"text": r.summary},
            "fullDescription": {"text": r.summary + (" " + r.hint if r.hint else "")},
            "properties": {"category": r.category, "severity": r.severity, "tags": [r.category]},
        }
        for rid, r in sorted(_import_rules().items())
    ]
    log = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": sarif_version,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "informationUri": "https://github.com/future-org/04-github-prcheck",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(log, indent=2)


def _sarif_level(sev: str) -> str:
    # SARIF accepts "none" | "note" | "warning" | "error"
    return {"high": "error", "medium": "warning", "low": "note", "info": "note"}.get(
        sev, "note"
    )


def _import_rules():
    from .rules import RULES

    return RULES
