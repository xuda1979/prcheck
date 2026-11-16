"""Local rule engine: diff -> security / data / behavior checklist findings.

Every rule produces :class:`Finding` objects that carry a category
(security | data | behavior), a fixed severity (info/low/medium/high),
a human-readable summary, and one or more ``file:line`` citations.

Rules are pure local logic (regex / token heuristics) so the tool runs with
zero network access and no training data.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Iterable

from .diff import FileDiff, parse_diff
from .issues import Issue

# -------------------------------------------------------------------------
# rule definitions
# -------------------------------------------------------------------------

# (id, category, severity, summary, pattern, hint)
_RULE_TUPLES = [
    (
        "R001-a",
        "security",
        "high",
        "No-auth / new public route detected",
        r"@(?:app|bp|blueprint)\.(?:route|get|post|put|delete|patch|head|options)"
        r"\s*\(\s*[\'\"][^\'\"\n]*[\'\"]\s*(?:,[^)\n]*)?\)",
        "New unauth'd endpoint",
    ),
    (
        "R001-b",
        "security",
        "medium",
        "New route — verify authentication guard",
        r"@\S+\.route\([^)]*\)|@\S+\.(?:get|post|put|delete|patch)\(",
        "Route decorator - check auth",
    ),
    (
        "R002",
        "security",
        "high",
        "Hardcoded credential/key/secret in diff",
        r"(?i)\b(?:api[_-]?key|secret|token|passw(?:ord|d)|password|credential|pwd|auth[_-]?key|private[_-]?key)\b"
        r"\s*(?:=|:)\s*[\"\'][A-Za-z0-9_@#$%^&*+!./\\-]{6,}[\"\']",
        "Possible secret committed",
    ),
    (
        "R003",
        "security",
        "medium",
        "TLS / certificate check disabled",
        r"(?i)(?:verify\s*=\s*False|ssl_verify_disabled|CURLOPT_SSL_VERIFYPEER\s*,\s*0"
        r"|SSL_CERT_REQUIRED\s*=\s*CERT_NONE|ssl\._create_unverified_context)",
    ),
    (
        "R004",
        "security",
        "medium",
        "eval / exec / pickling of untrusted input",
        r"(?i)\b(?:eval|exec|compile)\s*\(|pickle\.loads\(|yaml\.unsafe_load\(|dill\.loads\(|joblib\.load\(",
    ),
    (
        "R005",
        "security",
        "medium",
        "Potential SQL injection (string-built queries)",
        r"(?i)\b(?:execute|executemany|query)\(\s?(?:f[\'\"])|"
        r"(?:\"[^\"]*\{[^\"]*\}\")?\s*%|"
        r"(?:SELECT|INSERT|UPDATE|DELETE)[^\n;]*\+[^\n;]*|"
        r"(?:SELECT|INSERT|UPDATE|DELETE)[^\n;]*\b(?:\.format\(|f[\'\"])",
    ),
    (
        "R006-deps",
        "security",
        "medium",
        "Dependency added / changed",
        # "name": "1.2.3",  or  "name": ">=1.0,<2",  (package.json / requirements style)
        r"^\s*[\"\'][A-Za-z0-9_.\-]+[\"\']\s*:\s*[\"\'][^\"\']*[\d][^\"\']*[\"\']\s*,?\s*$|"
        # "name>=1.0", "name>=1.0.0", "name==1.2", "name ~= 3"  (pyproject style)
        r"^\s*[\"\'][A-Za-z0-9_.\-]+[\>\=\<\~\!\^]{1,2}[\d\.]+[\"\']?\s*,?\s*$|"
        # name>=1.0,  name~=2.1,  name == 3.0   (unquoted requirements.txt pins)
        r"^\s*[A-Za-z0-9_.\-]+\s*(?:>=|<=|==|~=|!=|>|<|\^)\s*\d[\dA-Za-z._\-,\[\]~!^<>= ]*\s*(?:#.*)?$",
    ),
    (
        "R007-cors",
        "security",
        "medium",
        "CORS policy configured / relaxed",
        r"(?i)\b(?:CORS|cors_origins?|allow_origins?|Access-Control-Allow-Origin)\b",
    ),
    (
        "R008",
        "security",
        "high",
        "Privilege / authorization logic changed",
        r"(?i)\b(?:is_admin|can_access|authorize|permission|current_user\.role|requires_role|admin_required|rbac)\b",
    ),
    (
        "R009",
        "security",
        "medium",
        "IDOR risk: object ids exposed in request path/query",
        r"(?i)\b(?:get_note|get_user|get_org|all_\w+_by_user|\.find_by_user)?\b(?:user_id|org_id|account_id)"
        r"\s*[=:]\s*[\w.\']+\b",
    ),
    (
        "R010",
        "security",
        "low",
        "Insecure http URL used",
        r"(?i)\bhttp://[^\s\"\'\\)]+",
    ),
    (
        "R011-session",
        "security",
        "medium",
        "SESSION_COOKIE_SECURE / SameSite relaxed or removed",
        r"(?i)\bsession_cookie_(?:secure|httponly)\s*=\s*(?:False|None)\b|SameSite\s*=\s*None",
    ),
    (
        "R012-cmd",
        "security",
        "high",
        "Command executed via shell (possible OS command injection)",
        # Direct shell entry points; subprocess with shell=True; any shell or
        # subprocess exec built by string concatenation / interpolation.
        r"\b(?:os|commands)\.(?:system|popen)\s*\(|"
        r"\bsubprocess\.(?:call|run|Popen|check_call|check_output)\s*\([^\n]*shell\s*=\s*(?:True|\w+)|"
        r"\b(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_call|check_output))"
        r"\s*\([^\n]*(?:\+|\s*%\s*[\'\"]|f[\'\"])",
        "Prefer argument lists over shell strings; validate/quote any variable input",
    ),
    # ---- data -----------------------------------------------------
    (
        "D001",
        "data",
        "low",
        "New PII field added to model/schema",
        r"(?i)\b(?:email|phone|ssn|passport|address|credit_card|card_number|birth[_-]?date|health[_-]?data)\b",
    ),
    (
        "D002-db",
        "data",
        "medium",
        "Database schema / migration change",
        r"(?i)\b(?:create_table|add_column|migration|ALTER\s+TABLE|DROP\s+TABLE|add_foreign_key)\b",
    ),
    (
        "D003",
        "data",
        "medium",
        "Sensitive data logged / printed",
        r"(?i)\b(?:logger|log|logging?\.)?\.?(?:debug|info|warning|error)\(\s*(?:f[\'\"])?[^\'\"\n]*(?:password|token|secret|api_key|credit_card)\w*|"
        r"\bprint\s*\([^\n]*(?:password|token|secret|api_key|credit_card)\w*",
    ),
    (
        "D004",
        "data",
        "medium",
        "Data removed / destructive change",
        r"(?i)\b(?:removed?\s+(?:field|column|endpoint)|DROP\s+TABLE|DROP\s+COLUMN|DELETE\s+FROM)\b",
    ),
    # ---- behavior -----------------------------------------------------
    (
        "B001",
        "behavior",
        "medium",
        "Exception handling changed / swallowed",
        r"(?i)\bexcept\s+(?:Exception|BaseException)?\s*(?:as\s+\w+)?\s*:\s*(?:pass|return\s+None)\b|"
        r"(?<!\w)\bpass\b[^\n]*$",
    ),
    (
        "B002",
        "behavior",
        "low",
        "Retry/timeout/time config changed",
        r"(?i)\b(?:timeout|retries?|max_retries)\s*\=\s*\d+",
    ),
    (
        "B003",
        "behavior",
        "medium",
        "HTTP status / response code change",
        r"(?i)\b(?:status_code|status|HTTP_)(?:\s*\=|\s*:\s*)\s*\d{3}\b|"
        r"\b(?:return|raise).{0,40}\b(?:404|403|500|502)\b",
    ),
    (
        "B004",
        "behavior",
        "medium",
        "New library/import affecting behavior",
        r"^\s*(?:import|from)\s+[\w.]+",
    ),
    (
        "B005",
        "behavior",
        "low",
        "System-level call changed",
        r"(?i)\b(?:chmod|chown|umask|subprocess|Popen|kill|restart)\b",
    ),
]

_PATTERN_CACHE: dict[str, re.Pattern] = {}

def _pat(pattern: str) -> re.Pattern:
    if pattern not in _PATTERN_CACHE:
        _PATTERN_CACHE[pattern] = re.compile(pattern)
    return _PATTERN_CACHE[pattern]


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str
    summary: str
    pattern: str
    hint: str = ""

    @property
    def regex(self) -> re.Pattern:
        return _pat(self.pattern)


RULES: dict[str, Rule] = {t[0]: Rule(*t) for t in _RULE_TUPLES}


# -------------------------------------------------------------------------
# matching engine
# -------------------------------------------------------------------------

# all rules are active by default (rules.py is the single source of truth)
def _match_single_line(rule: Rule, line_text: str) -> bool:
    return bool(rule.regex.search(line_text))


def run_rules(files: Iterable[FileDiff], opts=None) -> list[Issue]:
    """Run all rules over parsed diff files and build the finding list."""
    del opts
    issues: list[Issue] = []
    for fd in files:
        path = fd.new_path or fd.old_path
        if not path:
            continue
        if _should_skip_path(path):
            continue
        for lineno, text in fd.added_texts():
            for rule in RULES.values():
                if _should_skip_rule(path, rule):
                    continue
                if _match_single_line(rule, text):
                    issues.append(
                        Issue.from_rule(rule, path, lineno, text.strip())
                    )
    return issues


def _should_skip_path(path: str) -> bool:
    """Never flag lockfiles or vendored data files."""
    base = path.replace("\\", "/").split("/")[-1]
    if base in ("Pipfile.lock", "poetry.lock", "yarn.lock", "package-lock.json",
                "Cargo.lock", "go.sum", "composer.lock", "Gemfile.lock", "pnpm-lock.yaml"):
        return True
    if path.endswith((".min.js", ".min.css", ".map", ".svg", ".png", ".jpg", ".ico")):
        return True
    return False


def _should_skip_rule(path: str, rule: Rule) -> bool:
    """Apply per-rule path filters (e.g. deps rules only on lock/manifest)."""
    p = path.replace("\\", "/").lower()
    if rule.id == "R006-deps" and not any(
        fnmatch.fnmatch(p, pat)
        for pat in ("*.txt", "requirements*.txt", "pyproject.toml", "package.json", "setup.py")
    ):
        return True
    return False


def analyze_to_issues(diff_text: str) -> tuple[list[Issue], list[FileDiff]]:
    """Parse diff text and directly produce issues (tests + CLI share this)."""
    files = parse_diff(diff_text)
    issues = run_rules(files)
    return issues, files
