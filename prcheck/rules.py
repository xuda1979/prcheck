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
        # Plain keyword form:  password = "…",  api_key = "…",  'secret': "…"
        # The trailing \b after the keyword demands a token boundary, so a bare
        # `KEY=` inside a longer underscore-joined name cannot match here.
        r"(?i)\b(?:api[_-]?key|secret|token|passw(?:ord|d)|password|credential|pwd|auth[_-]?key|private[_-]?key)\b"
        r"\s*(?:=|:)\s*[\"\'][A-Za-z0-9_@#$%^&*+!./\\-]{6,}[\"\']|"
        # Compound-name form:  SECRET_KEY = "…",  DJANGO_SECRET_KEY,  ACCESS_TOKEN,
        # MYSQL_PASSWORD,  JWT_SECRET,  client_secret,  secret['secret'] = "…",
        # aws_access_key_id / AWS_SECRET_ACCESS_KEY / CONSUMER_KEY.
        # The keyword appears as an underscore-joined identifier component (either
        # preceded by `_` or at the very start of the identifier), with an optional
        # key-ish suffix (base / id / hash / access_key …), then the separator.
        # Tolerates an opening `[`/`'`/`"` between identifier and `=` for
        # dict/config forms.
        r"(?:(?<=_)|(?<![A-Za-z0-9_]))(?:passw(?:ord|d)|password|pwd|token|secret|credential"
        r"|api[_-]?key|auth[_-]?key|private[_-]?key|signing[_-]?key|encryption[_-]?key"
        r"|access[_-]?key|consumer[_-]?key"
        r"|jwt[_-]?secret|client[_-]?secret)"
        r"(?:[_-](?:key(?:_base)?|base|id|token|secret|pass|passwd|hash|access[_-]?key))?[\]\"\']*[ \t]*"
        r"[:=]\s*[\"\'][A-Za-z0-9_@#$%^&*+!./\\-]{6,}[\"\']",
        "Possible secret committed",
    ),
    (
        "R003",
        "security",
        "medium",
        "TLS / certificate check disabled",
        r"(?i)^(?:(?!\bjwt\.(?:decode|verify)\s*\().)*?\bverify\s*=\s*False|"
        r"verify_mode\s*=\s*ssl\.CERT_NONE|check_hostname\s*=\s*False"
        r"|ssl_verify_disabled|CURLOPT_SSL_VERIFYPEER\s*,\s*0"
        r"|SSL_CERT_REQUIRED\s*=\s*CERT_NONE|ssl\._create_unverified_context",
    ),
    (
        "R004",
        "security",
        "medium",
        "eval / exec / pickling of untrusted input",
        r"(?i)(?<![A-Za-z0-9_.])(?:eval|exec|compile)\s*\(|"
        r"\b(?:pickle|cPickle|_pickle|dill|marshal|joblib)\.(?:load|loads)\s*\(|"
        r"\b(?:pickle|cPickle|_pickle|dill)\.Unpickler\s*\(|"
        r"\byaml\.(?:full_load(?:_all)?|unsafe_load(?:_all)?)\s*\(|"
        r"\byaml\.load(?:_all)?\s*\((?![^)\n]*\bLoader\s*=\s*yaml\.(?:SafeLoader|BaseLoader)\b)|"
        r"\b(?:numpy|np)\.load\s*\([^)\n]*allow_pickle\s*=\s*True\b|"
        r"\btorch\.load\s*\(|"
        r"\b(?:pandas|pd)\.read_pickle\s*\(|"
        r"\bshelve\.open\s*\(",
    ),
    (
        "R005",
        "security",
        "medium",
        "Potential SQL injection (string-built queries)",
        r"(?i)\b(?:execute|executemany|query)\(\s?(?:f[\'\"])|"
        # quoted statement string using the %-interpolation operator
        r"[\"'][^\"'\n]*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|JOIN)\b[^\"'\n]*[\"']\s*%|"
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
        # subprocess exec built by string concatenation / interpolation; and
        # shell array invocation with an "-c" command string
        # (e.g. subprocess.run(["sh", "-c", user_cmd])).
        r"\b(?:os|commands)\.(?:system|popen)\s*\(|"
        r"\bsubprocess\.(?:call|run|Popen|check_call|check_output)\s*\([^\n]*shell\s*=\s*(?:True|\w+)|"
        r"\b(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_call|check_output))"
        r"\s*\([^\n]*(?:\+|\s*%\s*[\'\"]|f[\'\"])|"
        r"\bsubprocess\.(?:call|run|Popen|check_call|check_output)\s*\(\s*\["
        r"\s*[\"'][^\"']*\b(?:sh|bash|zsh|ksh|csh|tcsh|dash|ash|fish|pwsh|powershell)\b"
        r"[\"' \t-]*\s*,\s*[\"']-c[\"']",
        "Prefer argument lists over shell strings; validate/quote any variable input",
    ),
    (
        "R013-path",
        "security",
        "high",
        "File path built from request/user input",
        # File-serving sinks whose argument is not a quoted literal (a variable,
        # request arg, or expression — reviewer must verify it is allowlisted),
        # plus open()/Path() calls built by f-string / concatenation or taking a
        # bare identifier. Literal single-quoted paths stay quiet.
        r"(?i)\b(?:send_file|send_from_directory|FileResponse|StaticFiles)"
        r"\s*\(\s*(?!['\"])[^)\n]+\)|"
        r"\b(?:open|os\.open|Path)\s*\(\s*(?:f['\"]|['\"][^)\n]*\+)[^)\n]*\)|"
        # bare-identifier arg that smells user-controlled (uid / user_file /
        # request path / upload name …); require at least one lowercase letter so
        # SCREAMING_CASE config constants (LOGFILE, DATA_DIR) stay quiet — the
        # global (?i) flag folds case, so that check must re-enable sensitivity
        # with the scoped (?-i:…) flag.
        r"\b(?:open|os\.open|Path)\s*\(\s*(?!['\"])(?-i:(?=[A-Za-z_]\w*[a-z]))[A-Za-z_]\w*"
        r"(?:user|username|name|path|file|arg|req|request|query|param|"
        r"upload|input|dir|id|fn|fname|filename|body|content)[\w.\[\]]*\s*(?:,|\))",
        "Validate/normalize user-controlled paths; never serve files outside an allowlisted directory",
    ),
    (
        "R014-xss",
        "security",
        "medium",
        "XSS sink: unescaped user/HTML string rendered",
        r"(?i)\b(?:innerHTML|outerHTML|document\.write|insertAdjacentHTML|"
        r"lxml\.html\.fromstring|Jinja2\s*\.\s*Template|mark_safe|"
        r"dangerouslySetInnerHTML)\s*[=(+]|"
        r"(?:\bjQuery|\$)\s*\([^)\n]*\)\s*\.html\s*\(\s*[^\s)\n]",
        "Escape or sanitize content rendered into HTML; prefer frameworks that autoescape",
    ),
    (
        "R015-crypto",
        "security",
        "medium",
        "Weak / legacy crypto primitive used",
        # hashlib.md5 / hashlib.sha1 / bare md5( / sha1( as one-liner calls, and
        # DES/RC4 cipher references. Used for checksums alone these are benign,
        # but PR reviewers should confirm no security context (signatures, PW
        # hashing, key derivation) relies on them.
        r"(?i)\b(?:hashlib\.)?(?:md5|sha1)\s*\(|"
        r"\b(?:DES|RC4|ARC4)\b|\bCrypto\.Cipher\.(?:DES|ARC4)\b",
        "MD5/SHA1/DES/RC4 are legacy; use SHA-2/3 or a KDF (bcrypt, argon2, PBKDF2)",
    ),
    (
        "R016-random",
        "security",
        "medium",
        "random module used to generate a security value",
        # A security-value keyword (token / password / salt …) and a random.* call
        # on the same line, in either order. `random.randint(x)` used for plain
        # logic (no keyword) and the safe `secrets` module stay quiet.
        r"(?i)\b(?:password|passwd|pw|token|secret|api[_-]?key|otp|nonce|salt|verif)\b[^\n]*"
        r"\brandom\.(?:random|randint|choice|choices|getrandbits|shuffle|sample)\s*\(|"
        r"\brandom\.(?:random|randint|choice|choices|getrandbits|shuffle|sample)\s*\([^\n]*"
        r"\b(?:password|passwd|pw|token|secret|api[_-]?key|otp|nonce|salt|verif)\b",
        "Use the cryptographically secure secrets module instead of random",
    ),
    (
        "R017-redirect",
        "security",
        "medium",
        "Open redirect: redirect target derived from request input",
        # redirect( ... ) whose argument is not a quoted literal or url_for() and
        # mentions request input or a redirect-target name. Only matches one line.
        # request.url (the current request's own URL) is excluded - not attacker
        # controlled - via the (?<!request\.) lookbehind on the url keyword.
        r"(?i)\bredirect\s*\(\s*(?!['\"])(?!url_for)[^\n)]*"
        r"(?:request\.(?:args|values|form|headers)|\bnext\b|next_url|return_url|"
        r"redirect_to|(?<!request\.)\burl\b)",
        "Whitelist redirect targets; never trust a full URL from the client",
    ),
    (
        "R018-debug",
        "security",
        "low",
        "Debug mode / verbose logging enabled",
        # Debug flag assigned a truthy value (Flask app.run/app.debug, Django-style
        # uppercase DEBUG constant) or a logger configured at DEBUG level. Must be
        # an explicit truthy value so `app.debug = False` and env-driven
        # `DEBUG = os.environ.get(...)` assignments stay quiet; the scoped
        # (?-i:DEBUG) re-enables case sensitivity so lowercase identifiers like
        # `debug = True` do not fire.
        r"(?i)\b(?:app|application)\.debug\s*=\s*(?:True|1\b)|"
        r"(?-i:DEBUG)\b\s*=\s*(?:True|1\b)|"
        r"\b(?:app|application)\.run\s*\([^\n]*\bdebug\s*=\s*(?:True|1\b)|"
        r"\blevel\s*=\s*logging\.DEBUG\b|\bsetLevel\s*\(\s*logging\.DEBUG\b",
        "Disable debug mode and DEBUG-level logging before production",
    ),
    (
        "R019-csrf",
        "security",
        "medium",
        "CSRF protection disabled / relaxed",
        # CSRF disabled via an explicit False/0 assignment: csrf.enable(False),
        # a *_csrf_enabled = False flag, an app.config['CSRF_ENABLED'] = False
        # setting (Flask-WTF / Django-style), or a JSON dict value. The plain
        # enabling call `CSRFProtect(app).init_app(app)` uses no False so it
        # stays quiet.
        r"(?i)\bcsrf\s*\.\s*(?:enable|protect|init|init_app)\s*\(\s*False\b|"
        r"\w*(?:csrf|crsf)_(?:enabled|protected)\s*=\s*(?:False|0\b)|"
        r"\b(?:app|application)\.config\s*\[\s*['\"](?:WTF_)?CSRF_(?:ENABLED|PROTECTION)['\"]\s*\]\s*=\s*(?:False|0\b)|"
        r"['\"](?:WTF_)?CSRF_ENABLED['\"]\s*:\s*(?:False|0\b)",
        "Keep CSRF protection enabled; only a tokenless public API may disable it",
    ),
    (
        "R020-pem",
        "security",
        "high",
        "Committed private key material (PEM or unsupported format)",
        # PEM private-key headers. The alternation is conservative: only a
        # *private* or *encrypted private* key block heading fires — public
        # keys, certificates and CRLs never match, and END markers are excluded
        # so only freshly added key material (not pre-existing headers) is
        # flagged. The unencrypted form of an encrypted key is just a private
        # key, so any private key variety matches; non-PEM "opaque" formats are
        # vendored into ssl._create_unverified_context and don't use this marker.
        r"-----BEGIN\s+(?:(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)\s+)?PRIVATE\s+KEY"
        r"(?:\s+BLOCK)?-----",
        "Private key material must not be committed; rotate and load from a secret store",
    ),
    (
        "R021-ssrf",
        "security",
        "high",
        "Outbound HTTP fetch fed by request-derived URL (SSRF)",
        # (A) an HTTP client call whose URL argument is request input
        # (request.args / request.form / request.json / …) — a quoted literal
        # fails the (?!['\"]) guard, so static URLs stay quiet.
        r"(?i)\b(?:requests|httpx|urllib\.request|urllib2|urllib3)\.(?:get|post|put|patch|delete|head|options|request|urlopen)"
        r"\s*\(\s*(?!['\"])([^\n)]*?request\.(?:args|values|form|headers|json|get_json\b))|"
        # (B) same clients but with a url-ish variable/attr as the URL argument
        # (url / target_url / callback / webhook …). The url-ish word must be the
        # terminal identifier component, matched case-sensitively (scoped
        # (?-i:...)) so SCREAMING_CASE constants (API_URL, BASE_URL) stay quiet;
        # the lowercase lookahead rejects all-caps ids outright, and url_for is
        # excluded by name. Concatenated URLs (url + '/state') still fire.
        r"\b(?:requests|httpx|urllib\.request|urllib2|urllib3)\.(?:get|post|put|patch|delete|head|options|request)"
        r"\s*\(\s*(?!['\"])(?!url_for)(?=[\w.]*[a-z])(?:[\w.]*?)?"
        r"(?-i:(?:url|uri|link|endpoint|target|callback|webhook))[\w.\[\]]*"
        r"(?:\s*\+\s*[^)\n]*?)?\s*(?:,|\))|"
        # (C) bare urlopen( fed request input (after `from urllib.request import urlopen`)
        r"\burlopen\s*\(\s*(?!['\"])([^\n)]*?request\.(?:args|values|form|headers|json|get_json\b))|"
        # (D) bare urlopen( with a url-ish variable
        r"\burlopen\s*\(\s*(?!['\"])(?!url_for)(?=[\w.]*[a-z])(?:[\w.]*?)?"
        r"(?-i:(?:url|uri|link|endpoint|target|callback|webhook))[\w.\[\]]*"
        r"(?:\s*\+\s*[^)\n]*?)?\s*(?:,|\))|"
        # (E1) session/client-object receiver (.get/.post/… on aiohttp
        # ClientSession / httpx Client/AsyncClient / requests.Session, incl. the
        # chained ClientSession().get form) fed request input. The receiver must
        # END in `session|client` (empty `()` allowed) and sit immediately
        # before the method, so session_data.get / client_id.get / cache.get
        # stay quiet. The optional quoted method-name argument covers
        # `client.request('GET', url)`.
        r"\b(?:(?:[a-zA-Z][\w]*\.)*\w*(?:session|client)(?:\(\s*\))?)\s*\.\s*"
        r"(?:get|post|put|patch|delete|head|options|request)\s*\(\s*"
        r"(?:(?:['\"][^'\")]*['\"])\s*,?\s*)?"
        r"(?!['\"])([^\n)]*?request\.(?:args|values|form|headers|json|get_json\b))|"
        # (E2) session/client-object receiver fed a url-ish variable
        r"\b(?:(?:[a-zA-Z][\w]*\.)*\w*(?:session|client)(?:\(\s*\))?)\s*\.\s*"
        r"(?:get|post|put|patch|delete|head|options|request)\s*\(\s*"
        r"(?:(?:['\"][^'\")]*['\"])\s*,?\s*)?"
        r"(?!['\"])(?!url_for)(?=[\w.]*[a-z])(?:[\w.]*?)?"
        r"(?-i:(?:url|uri|link|endpoint|target|callback|webhook))[\w.\[\]]*"
        r"(?:\s*\+\s*[^)\n]*?)?\s*(?:,|\))|"
        # (E3) aiohttp.request(method, url) functional form fed request input
        r"\baiohttp\.request\s*\(\s*"
        r"(?:(?:['\"][^'\")]*['\"])\s*,?\s*)?"
        r"(?!['\"])([^\n)]*?request\.(?:args|values|form|headers|json|get_json\b))|"
        # (E4) aiohttp.request(method, url) fed a url-ish variable
        r"\baiohttp\.request\s*\(\s*"
        r"(?:(?:['\"][^'\")]*['\"])\s*,?\s*)?"
        r"(?!['\"])(?!url_for)(?=[\w.]*[a-z])(?:[\w.]*?)?"
        r"(?-i:(?:url|uri|link|endpoint|target|callback|webhook))[\w.\[\]]*"
        r"(?:\s*\+\s*[^)\n]*?)?\s*(?:,|\))",
        "Never fetch a URL taken from request input; validate host/protocol against an allowlist",
    ),
    (
        "R022-ssti",
        "security",
        "high",
        "Template rendered from request input or a template-named variable (SSTI)",
        # (A1) render_template_string(...) fed request input — a quoted literal
        #      fails the (?!['\"]) guard, so inline templates stay quiet.
        r"(?i)\brender_template_string\s*\(\s*(?!['\"])([^\n)]*?request\.(?:args|values|form|headers|json))|"
        # (A2) render_template_string(var) with a template-ish variable name
        #      (tmpl / template / tpl / markup). The word must be the terminal id
        #      component, matched case-sensitively (scoped (?-i:...)) so
        #      SCREAMING_CASE constants (STATIC_TPL) stay quiet; the lowercase
        #      lookahead rejects all-caps ids outright.
        r"\brender_template_string\s*\(\s*(?!['\"])(?=[\w.]*[a-z])(?:[\w.]*?)?"
        r"(?-i:(?:tmpl|template|tpl|markup))[\w.\[\]]*(?:\s*,|\s*\))|"
        # (B1) bare jinja2/django.template Template(...) fed request input
        #      (after `from jinja2 import Template` / django.template.Template);
        #      (?<!string\.) keeps stdlib string.Template quiet.
        r"(?<!string\.)\bTemplate\s*\(\s*(?!['\"])([^\n)]*?request\.(?:args|values|form|headers|json))|"
        # (B2) bare Template(var) with a template-ish variable
        r"(?<!string\.)\bTemplate\s*\(\s*(?!['\"])(?=[\w.]*[a-z])(?:[\w.]*?)?"
        r"(?-i:(?:tmpl|template|tpl|markup))[\w.\[\]]*(?:\s*,|\s*\))",
        "Never render a template obtained from request input; compile approved templates only",
    ),
    (
        "R023-xxe",
        "security",
        "medium",
        "XML parser fed request-derived data (XXE / entity expansion risk)",
        # (A) stdlib / lxml / xmltodict XML sink fed request input (raw-body
        #     webhooks are the classic XXE path). A quoted literal fails the
        #     (?!['\"]) guard, so static documents stay quiet.
        r"(?i)\b(?:xml\.etree\.ElementTree\.(?:fromstring|parse|XML)|xml\.sax\.(?:parse|parseString)"
        r"|xml\.dom\.(?:minidom|pulldom)\.(?:parse|parseString)|lxml\.(?:etree|objectify)\.(?:fromstring|parse|XML)"
        r"|xmltodict\.parse)\s*\(\s*(?!['\"])([^\n)]*?request\.(?:args|values|form|headers|json|data|get_data\b|files))|"
        # (B) same sinks with an xml-named variable (xml_body / user_xml /
        #     xml_payload …). The word must be the terminal id component,
        #     matched case-sensitively (scoped (?-i:xml)) so SCREAMING_CASE
        #     constants (STATIC_XML) stay quiet; the lowercase lookahead rejects
        #     all-caps ids outright.
        r"\b(?:xml\.etree\.ElementTree\.(?:fromstring|parse|XML)|xml\.sax\.(?:parse|parseString)"
        r"|xml\.dom\.(?:minidom|pulldom)\.(?:parse|parseString)|lxml\.(?:etree|objectify)\.(?:fromstring|parse|XML)"
        r"|xmltodict\.parse)\s*\(\s*(?!['\"])(?=[\w.]*[a-z])(?:[\w.]*?)?"
        r"(?-i:xml)[\w.\[\]]*(?:\s*,|\s*\))|"
        # (C) aliased imports (ET / etree / ElementTree / sax / minidom /
        #     pulldom / objectify / xmltodict) fed request input or an xml-named
        #     variable. (?<!defusedxml\.) keeps the safe defusedxml parser quiet.
        r"(?<!defusedxml\.)\b(?:etree|ElementTree|ET|objectify|sax|minidom|pulldom|xmltodict)"
        r"\s*\.\s*(?:fromstring|parse|parseString|XML)\s*\(\s*(?!['\"])(?:"
        r"([^\n)]*?request\.(?:args|values|form|headers|json|data|get_data\b|files))|"
        r"(?=[\w.]*[a-z])(?:[\w.]*?)?(?-i:xml)[\w.\[\]]*(?:\s*,|\s*\)))",
        "Parse untrusted XML with a hardened parser (defusedxml); disable external entity expansion",
    ),
    (
        "R024-jwt",
        "security",
        "medium",
        "JWT signature verification disabled or alg=none accepted",
        # (A1) jwt.decode/verify(..., verify=False) turns off the signature check.
        # (A2) jwt.decode/verify(..., options={'verify_signature': False}) — the
        #      dict key may be quoted. A bare `options` dict name is not itself
        #      the flag, so it must appear inline inside the jwt call.
        r"(?i)\bjwt\.(?:decode|verify)\s*\([^\n)]*\bverify\s*=\s*False|"
        r"\bjwt\.(?:decode|verify)\s*\([^\n)]*?\boptions\s*=\s*\{"
        r"[^}\n]*?[\"']?verify_signature[\"']?\s*:\s*False|"
        # (A3) jwt.decode/verify(..., algorithms=['none']) or algorithms='none'
        #      accepts unsigned tokens (CWE-347 / alg-confusion root cause).
        r"\bjwt\.(?:decode|verify)\s*\([^\n)*]*algorithms?\s*=\s*(?:\[[^\]\n]*?|[\"'])[\"']none[\"']|"
        # (A4) standalone algorithms=['none'] declaration (line-level catch).
        r"\balgorithms?\s*[=:]\s*\[[^\]\n]*?[\"']none[\"']",
        "Always verify JWTs (never verify=False / verify_signature=False); pin algorithms, reject none",
    ),
    (
        "R025-pw",
        "security",
        "high",
        "Password field assigned request input or a raw variable (plaintext credential storage)",
        # Fires when a password/passwd/pwd field (terminal word, optional closing
        # brackets; colon form deliberately NOT matched so `password: str` type
        # annotations stay quiet) is assigned:
        #   (A) request-derived input (request.form/json/args/… incl. .get() calls),
        #   (B) a bare variable chain — rejected when the expression contains a
        #       call (hashing/setter), a hash-named identifier (pw_hash, hashed,
        #       hash_password), an env/config source (os.environ/getenv/config/
        #       cfg/settings), or a SCREAMING_CASE constant (DB_PASSWORD). The
        #       constant guard is scoped (?-i:[A-Z]...) so the global (?i) doesn't
        #       fold it into matching every identifier.
        r"(?i)\b(?:password|passwd|pwd)\b[\]\"\']*\s*=\s*"
        r"(?!['\"]|None\b|True\b|False\b)"
        r"(?:"
        r"request\.(?:[a-z_]\w*\.)*[a-z_]\w*(?:\[[^)\n]*\]|"
        r"\.(?:get|get_json|getlist|getvalue|get_data)\s*\([^)\n]*\))?"
        r"|"
        r"(?![\w.\[\]'\"]*\([^)\n]*\))(?![\w.\[\]'\"]*\b\w*hashe?\w*\b)"
        r"(?![\w.\[\]'\"]*\b(?:environ|getenv|get_env|config|cfg|settings)\b)"
        r"(?![\w.\[\]'\"]*(?-i:[A-Z][A-Z0-9_]+))[\w.\[\]'\"]*[a-z][\w.\[\]'\"]*"
        r")",
        "Store only a salted hash of a password (bcrypt/argon2/PBKDF2); never assign raw input or a bare variable",
    ),
    (
        "R026-upload",
        "security",
        "high",
        "User-supplied file save without validation (unrestricted upload / path in save target)",
        # (A) request.files/request.FILES storage saved directly — the classic
        #     `request.files['x'].save(dest)` (CWE-434): the storage object is
        #     saved straight from the request with no extension check.
        r"(?i)(?:"
        r"\brequest\s*\.\s*(?:files|FILES)\s*(?:\[\s*[^)\]\n]+\s*\]"
        r"|\s*\.\s*get\s*\([^)\n]*\))?\s*\.\s*save\s*\("
        r"|"
        # (B) any .save(…) whose target is user-influenced: a filename attribute
        #     (file.filename / request.files['f'].filename), os.path.join with a
        #     filename component, or a request-data token (request.args/form/json/
        #     … — NOT request.user/session, so ORM `save(owner=...request.user)`
        #     stays quiet). ORM no-arg save() and literal-path saves (Pillow/PDF)
        #     stay quiet because the reference is required.
        r"\b[\w.]*[a-z][\w.]*\.save\s*\(\s*(?=[^)\n]*\bfilename\b|"
        r"os\.path\.join\s*\([^)\n]*\bfilename\b|"
        r"[^)\n]*request\.(?:args|values|form|headers|json|data|get_json|get_data)\b)"
        r")",
        "Validate file type/size and control the destination path; never save request files to a user-influenced or derived path",
    ),
    (
        "R027-massassig",
        "security",
        "medium",
        "Mass assignment: request dict fed wholesale into create/update/constructor",
        # Fires when a request-supplied dict / form payload is fed WHOLESALE (not
        # field-by-field) into an object construction or update sink (CWE-915):
        #   (A) Django-style Model.objects.<create|bulk_create|get_or_create|
        #       update_or_create|update>(...) — also Model.query chains — whose
        #       argument list contains a request dict, via **splat or as a whole
        #       positional/keyword (defaults=request.POST.dict()).
        #   (B) any receiver .update(...) / .update_from_dict(...) /
        #       .update_from_request(...) fed a request dict.  Receiver must not
        #       be request.<accessor> itself (request.form.update(...) quiet).
        #   (C) a model-style capitalized constructor X(...) fed a request dict
        #       wholesale.  The scoped (?-i:...) keeps case meaningful — the
        #       global (?i) would otherwise fold [A-Z] to match lowercase
        #       receivers like requests.post( or aiohttp.request(.  *Form /
        #       *Serializer / *Schema class names stay quiet (whitelist-style
        #       form population).  request.<accessor> followed by '[' or .get(
        #       is an indexed field read, NOT a wholesale dict — stays quiet.
        r"(?i)(?:"
        r"\b[A-Za-z_]\w*(?::[A-Za-z_]\w+)*\.(?:objects|query)"
        r"(?:\([^)\n]*\))?(?:\.[A-Za-z_]\w*(?:\([^)\n]*\))?)*"
        r"\.(?:create|bulk_create|get_or_create|update_or_create|update)\s*\("
        r"(?=[^)\n]*(?:\*\*\s*)?\brequest\.(?:POST|form|json|args|data|values|get_json|get_data)"
        r"(?!\[|\.\s*get\b|\.\s*getlist\b|\.\s*getvalue\b)"
        r"(?:\.\s*(?:dict|to_dict))?(?![\[.\w]))"
        r"|"
        r"(?<![\w.])(?!request\.)[A-Za-z_]\w*(?:\.[A-Za-z_]\w*(?:\([^)\n]*\))?)*"
        r"\.\s*(?:update|update_from_dict|update_from_request)\s*\("
        r"(?=[^)\n]*(?:\*\*\s*)?\brequest\.(?:POST|form|json|args|data|values|get_json|get_data)"
        r"(?!\[|\.\s*get\b|\.\s*getlist\b|\.\s*getvalue\b)"
        r"(?:\.\s*(?:dict|to_dict))?(?![\[.\w]))"
        r"|"
        r"\b(?!\w*(?:[Ff]orm|[Ss]erializer|[Ss]chema)\b)(?-i:[A-Z][A-Za-z0-9_]*)"
        r"\s*\(\s*(?=\*\*\s*request\.|[^)\n]*(?:\*\*\s*)?\brequest\.(?:POST|form|json|args|data|values|get_json|get_data)"
        r"(?!\[|\.\s*get\b|\.\s*getlist\b|\.\s*getvalue\b)"
        r"(?:\.\s*(?:dict|to_dict))?(?![\[.\w]))"
        r")",
        "Whitelist settable fields; never bind a request dict wholesale onto a model or constructor — unexposed or privileged fields (is_admin, role) become user-settable",
    ),
    (
        "R028-nosql",
        "security",
        "medium",
        "NoSQL injection: request dict fed wholesale into a Mongo query / $where",
        # Fires when a Mongo-family query call is fed an attacker-controlled
        # document on a single added line (CWE-943):
        #   (A) a pymongo-style dotted receiver ending in .find / .find_one /
        #       find_one_and_delete / find_one_and_replace /
        #       find_one_and_update / count_documents / distinct / aggregate
        #       whose argument list contains a WHOLESALE request dict
        #       (request.POST/form/json/args/data/values/get_json/get_data —
        #       optional .dict()/.to_dict(), optional ** splat).  Indexed
        #       reads (request.form['k'] / .get()) are field reads, not
        #       operator-injectable whole documents — quiet.
        #   (B) the same query family whose argument list contains a $where key
        #       built from ANY request-derived fragment (request.args['x'] …)
        #       — raw JS / operator injection into the query.
        # Receivers allow dotted chains with optional subscript segments
        # (db["users"].find).  ElementTree .find/literals, jQuery/JS .find
        # callbacks, Django ORM .aggregate, write ops (insert_one/update_one),
        # request accessors as receivers and standalone request reads stay quiet.
        r"(?i)(?:"
        # (A) query call whose args contain a wholesale request dict.
        r"(?<![\w.])(?!request\.)[A-Za-z_]\w*(?:\s*\[[^)\n]*\]\s*)?"
        r"(?:\.[A-Za-z_]\w*(?:\s*\[[^)\n]*\]\s*)?)*"
        r"\.\s*(?:find_one_and_delete|find_one_and_replace|find_one_and_update|"
        r"find_one|count_documents|distinct|aggregate|find)\s*\("
        r"(?=[^)\n]*(?:\*\*\s*)?\brequest\.(?:POST|form|json|args|data|values|"
        r"get_json|get_data)(?!\[|\.\s*get\b|\.\s*getlist\b|\.\s*getvalue\b)"
        r"(?:\.\s*(?:dict|to_dict))?(?![\[.\w]))"
        r"|"
        # (B) query call carrying a $where built from request-derived input.
        r"(?<![\w.])(?!request\.)[A-Za-z_]\w*(?:\s*\[[^)\n]*\]\s*)?"
        r"(?:\.[A-Za-z_]\w*(?:\s*\[[^)\n]*\]\s*)?)*"
        r"\.\s*(?:find_one_and_delete|find_one_and_replace|find_one_and_update|"
        r"find_one|count_documents|distinct|aggregate|find)\s*\("
        r"(?=[^)\n]*\$where[^)\n]*\brequest\.(?:POST|form|json|args|data|values|"
        r"get_json|get_data))"
        r")",
        "Never feed a raw request dict into a Mongo-family query; sanitize/whitelist filter keys (esp. $where, $gt, $regex) or attacker-controlled operators reach the query",
    ),
    (
        "R029-ldap",
        "security",
        "medium",
        "LDAP injection: request-derived input in an LDAP search filter / dn",
        # Fires when an LDAP search call is fed request-derived input as (part
        # of) its filter/dn arguments on a single added line (CWE-90):
        #   (A) a python-ldap-style search family — .search_s / .search_st /
        #       .search_ext / .search_ext_s — with ANY receiver, whose argument
        #       list contains a request-derived token (request.POST/form/json/
        #       args/data/values/cookies/headers/get_json/get_data; indexed
        #       reads and .get() ARE injection payloads here — a filter string
        #       built from a field read is exactly the vulnerable case).
        #   (B) an ldap3-style bare .search whose receiver chain contains an
        #       ldap- or conn-named segment (ldap, ldap3, ldap_conn, conn,
        #       connection, …) and whose argument list contains a
        #       request-derived token.  This keeps search-engine / generic
        #       .search receivers (es.search, client.search, index.search,
        #       results.search, arr.search callbacks, db.search) quiet.
        # A same-line escape_filter_chars / escape_dn_chars call marks the
        # payload as sanitized (python-ldap/ldap3 escaping helpers) and
        # suppresses the finding.
        r"(?i)(?!.*\bescape_(?:filter|dn)_chars\b)(?:"
        # (A) python-ldap search family: any receiver, request token in args.
        r"(?<![\w.])(?!request\.)[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*"
        r"\.\s*(?:search_st|search_ext_s|search_ext|search_s)\s*\("
        r"(?=[^)\n]*\brequest\.(?:POST|form|json|args|data|values|cookies|headers|"
        r"get_json|get_data))"
        r"|"
        # (B) ldap3-style bare .search with an ldap/conn-named receiver chain.
        r"(?<![\w.])(?!request\.)(?:[A-Za-z_]\w*\.)*?(?:\bldap\w*|conn\w*)"
        r"(?:\.[A-Za-z_]\w*)*?\.\s*search\s*\("
        r"(?=[^)\n]*\brequest\.(?:POST|form|json|args|data|values|cookies|headers|"
        r"get_json|get_data))"
        r")",
        "LDAP search filters/dns built from request input allow filter injection; escape with ldap.filter.escape_filter_chars / ldap.dn.escape_dn_chars (python-ldap) or ldap3.utils.conv escape helpers",
    ),
    (
        "R030-xpath",
        "security",
        "medium",
        "XPath injection: request-derived input in an XPath query",
        # Fires when an XPath query call is fed request-derived input as its
        # query expression on a single added line (CWE-643):
        #   (A) an lxml-style element .xpath(...) method call with any receiver
        #       (dotted chains may include intermediate call segments, e.g.
        #       parser.parse(f).xpath) whose argument list contains a
        #       request-derived token (request.POST/form/json/args/data/values/
        #       cookies/headers/get_json/get_data); indexed reads and .get()
        #       ARE injection payloads here — a predicate string built from a
        #       field read is exactly the vulnerable case.
        #   (B) a compiled XPath expression constructor — (lxml.)etree.XPath /
        #       XPathEvaluator — whose argument list contains a request-derived
        #       token.
        # Literal / non-request queries (SCREAMING constants, bare variables),
        # standalone request reads, ElementTree find/findall, browser
        # $x(console) and Selenium By.XPATH lookups stay quiet.
        r"(?i)(?:"
        # (A) lxml-style element .xpath() fed a request-derived query.
        r"(?<![\w.])(?!request\.)[A-Za-z_]\w*"
        r"(?:\.[A-Za-z_]\w*(?:\s*\([^)\n]*\))?)*"
        r"\.\s*xpath\s*\("
        r"(?=[^)\n]*\brequest\.(?:POST|form|json|args|data|values|cookies|headers|"
        r"get_json|get_data))"
        r"|"
        # (B) compiled XPath expression constructor fed a request-derived query.
        r"(?<![\w.])(?:(?:lxml\.)?etree\.)?XPath(?:Evaluator)?\s*\("
        r"(?=[^)\n]*\brequest\.(?:POST|form|json|args|data|values|cookies|headers|"
        r"get_json|get_data))"
        r")",
        "XPath expressions built from request input allow predicate injection; whitelist/validate the query or bind values via the safe API (e.g. variables dict) instead of concatenating input",
    ),
    (
        "R031-ssrf-js",
        "security",
        "high",
        "Client-side SSRF: JS fetch/axios/got/Node/XMLHttpRequest fed a request-derived URL",
        # Fires when a JS HTTP-for-fetch sink is fed request-derived input or a
        # url-named variable (CWE-918):
        #   (A) fetch / axios(.<verb>) / got / Node http(s).get|request /
        #       request-lib calls whose FIRST argument is a request-derived
        #       accessor (req/request/ctx/event -> .field / ['field']) or a
        #       url-named variable (name contains url/uri/link/endpoint/target/
        #       callback/webhook, but is not a SCREAMING_CASE constant).
        #   (B) XMLHttpRequest-family .open(method, url) whose 2nd (url) arg is
        #       request-derived / url-named; receiver must be an xhr-named
        #       variable or an XMLHttpRequest(...) construction.
        # Literal quoted URLs, SCREAMING_CASE constants and non-JS receivers
        # (db.fetch, router.get, api.get, window.open, socket.connect) stay
        # quiet.
        r"(?i)(?:"
        # (A) JS fetch / axios / got / Node http(s) / request-lib sinks whose FIRST
        #     argument is request-derived (req/request/ctx/event accessor) or a
        #     url-named variable.  Literal quoted URLs, SCREAMING_CASE constants and
        #     non-JS fetchers (db.fetch, router.get, api.get) stay quiet.
        r"(?:\bfetch\s*\(|\b(?:axios|got)(?:\.\w+)?\s*\(|"
        r"\b(?:http|https)\.(?:get|request)\s*\(|\brequest\s*\()"
        r"\s*(?!['\"])(?=[^,)\n]*(?:"
        r"\b(?:req|request|ctx|event)\b\s*(?:\.|\[)|"
        r"(?-i:(?=[A-Za-z_]\w*[a-z]))[A-Za-z_]\w*(?:url|uri|link|endpoint|"
        r"target|callback|webhook)[A-Za-z0-9_]*"
        r"))"
        r"|"
        # (B) XMLHttpRequest-family .open(method, url) whose URL (2nd) argument is
        #     request-derived / url-named.  Literal URLs and non-xhr .open receivers
        #     (socket, file, connection) stay quiet.
        r"\b(?:xhr\w*|XMLHttpRequest\s*\([^)\n]*\))\s*\.\s*open\s*\([^\n]*?,\s*"
        r"(?!['\"])(?=[^,)\n]*(?:"
        r"\b(?:req|request|ctx|event)\b\s*(?:\.|\[)|"
        r"(?-i:(?=[A-Za-z_]\w*[a-z]))[A-Za-z_]\w*(?:url|uri|link|endpoint|"
        r"target|callback|webhook)[A-Za-z0-9_]*"
        r"))"
        r")",
        "A URL built from request input reaches an external-fetch CLI (fetch/axios/got/Node http or XMLHttpRequest); validate/whitelist the URL before use (SSRF/CWE-918)",
    ),
    (
        "R032-cmd-node",
        "security",
        "high",
        "OS command injection: Node child_process exec/spawn fed a non-literal shell command",
        # Fires when a Node child_process call builds a shell command from a
        # variable / request input / interpolation on a single added line
        # (CWE-78):
        #   (A) child_process/cp/proc/process-qualified exec|execSync and bare
        #       execSync fed a NON-LITERAL first argument (a lowercase bare
        #       identifier or a `${...}`-interpolated backtick template).  exec
        #       always runs a shell, so any non-constant command string is an
        #       injection point.  Quoted literals and SCREAMING_CASE constants
        #       stay quiet; unqualified exec( is left to R004 (Python builtin
        #       exec() isn't double-flagged).
        #   (B) qualified exec|execFile|execSync|execFileSync whose command
        #       string is concatenated / interpolated (first arg may start with
        #       a quoted literal), plus destructured unqualified exec( ONLY when
        #       a backtick template literal renders the command (JS-unique;
        #       Python f-strings are R004's domain).
        #   (C) spawn/spawnSync/execFile/execFileSync with the shell ENABLED
        #       (shell: true or a shell variable); shell: false stays quiet.
        #   (D) sh -c array invocation (spawn('/bin/sh', ['-c', cmd]) /
        #       execFile of a shell) — mirrors R012's shell "-c" detection for
        #       the Node spawn family.
        r"(?i)(?:"
        # (A) qualified exec/execSync and bare execSync fed a non-literal command.
        r"(?:(?:\bchild_process\s*\.\s*|\b(?:cp|proc|process)\s*\.\s*)"
        r"(?:exec|execSync)\s*\(|\bexecSync\s*\()"
        r"\s*(?!['\"])(?:"
        r"(?-i:(?=[A-Za-z_]\w*[a-z]))[A-Za-z_]\w*"
        r"|`[^`\n]*\$\{"
        r")"
        r"|"
        # (B) qualified exec family with concatenated / templated command string,
        #     plus destructured unqualified exec( with a backtick interpolation.
        r"(?:\bchild_process\s*\.\s*|\b(?:cp|proc|process)\s*\.\s*)"
        r"(?:exec|execFile|execSync|execFileSync)\s*\([^\n]*(?:\+|\$\{|`[^`\n]*\$\{)|"
        r"\bexec\s*\(`[^`\n]*\$\{"
        r"|"
        # (C) spawn family executing through an enabled shell.
        r"\b(?:spawn|spawnSync|execFile|execFileSync)\s*\([^\n]*"
        r"shell\s*:\s*['\"]?(?!false\b)\w+"
        r"|"
        # (D) sh -c array invocation.
        r"\b(?:spawn|spawnSync|exec|execSync|execFile|execFileSync)\s*\([^\n]*"
        r"\b(?:sh|bash|zsh|ksh|csh|tcsh|dash|ash|fish|pwsh|powershell)\b[^\n]*['\"]-c['\"]"
        r")",
        "A Node child_process call builds its shell command from a variable / request input / interpolation; exec always runs a shell — validate or whitelist the command and avoid shell:true / sh -c patterns (command injection/CWE-78)",
    ),
    (
        "R033-protopoll",
        "security",
        "high",
        "Prototype pollution: merge/assign of a request-derived object or direct __proto__ assignment",
        # Fires on a single added line when (CWE-1321):
        #   (A) a JS merge/extend sink — Object.assign, lodash _ merge|mergeWith|
        #       defaultsDeep|extend, jQuery/$ .extend — has a request-derived
        #       argument (req/request/ctx/event accessor -> .field / ['field'] /
        #       ?.field, incl. spread ...req.query and JSON.parse(req.body)
        #       anywhere in the argument list).
        #   (B) a direct __proto__ key assignment (obj['__proto__'] = … or
        #       obj.__proto__ = …) whose RHS is request-derived.
        # A request-derived payload is required (no bare-variable heuristic) so
        # literal objects, SCREAMING_CASE constants, pandas df.merge, git merge,
        # __proto__ reads / null resets, safe deep-clones and plain
        # spread-into-literal stay quiet.
        r"(?i)(?:"
        # (A) merge/extend sinks — Object.assign / lodash (_|lodash) merge family /
        #     jQuery ($|jQuery) .extend — fed a request-derived object argument
        #     (accessor .field / ['field'] / ?.field; spread and JSON.parse(...)
        #     anywhere in the argument list count).
        r"(?:(?<![\w.])Object\s*\.\s*assign\s*\(|"
        r"(?<![\w.])(?:_|lodash)\s*\.\s*(?:merge(?:With)?|defaultsDeep|extend)\s*\(|"
        r"(?<![\w.])(?:\$|jQuery)\s*\.\s*extend\s*\()"
        r"(?=[^\n]*\b(?:req|request|ctx|event)\b\s*(?:\?\.|\.|\[))"
        r"|"
        # (B) direct __proto__ key assignment fed a request-derived value.
        r"(?:\w+\s*\[\s*['\"]__proto__['\"]\s*\]\s*=|\.\s*__proto__\s*=)"
        r"(?=[^\n]*\b(?:req|request|ctx|event)\b\s*(?:\?\.|\.|\[))"
        r")",
        "A JS merge/extend (Object.assign / lodash merge family / jQuery extend) is fed a request-derived object, or a __proto__ key is assigned request-derived data — an attacker can pollute the prototype of these objects (prototype pollution/CWE-1321)",
    ),
    (
        "R034-redos",
        "security",
        "high",
        "Regex injection / ReDoS: a request-derived pattern is fed into a regex-compiling sink",
        # Fires on a single added line when (CWE-1333):
        #   (A) a Python re-module sink — re.compile/re.search/re.match/re.fullmatch/
        #       re.split/re.findall/re.finditer/re.sub/re.subn — is fed a
        #       request-derived FIRST argument (req/request/ctx/event accessor ->
        #       .field / ['field'] / ?.field, incl. .get() calls and chained
        #       request.data.re, keyword pattern=…) on the same line.
        #   (B) a JS RegExp constructor — new RegExp(…)/RegExp(…) — has a
        #       request-derived argument anywhere in its argument list (flags may
        #       follow).
        # The request-derived payload is required (no bare-variable heuristic) so
        # literal patterns, SCREAMING_CASE constants, bare pattern variables, string
        # methods (.match/.search on strings), f-string patterns, regex literals and
        # non-request-derived calls stay quiet.  The Python branch guards against the
        # literal-first-argument FP: "re.search(r'\d+', request.body.text)" is
        # subject-derived, not pattern-derived, so the scan stops at the first
        # top-level comma (never crosses `,` or `;` when hunting the accessor).  A
        # quote immediately after the opening paren (with optional string-prefix
        # letter) also suppresses the Python branch.
        r"(?i)(?:"
        # (A) Python re-module sinks fed a request-derived FIRST argument (the
        #     pattern).  A literal first argument (quote with optional string
        #     prefix) suppresses; the accessor scan never crosses a comma/semicolon,
        #     so a request-derived SUBJECT as second argument (re.search(r'\d+',
        #     request.body.text)) stays quiet.
        r"\bre\.(?:compile|search|match|fullmatch|split|findall|finditer|sub|subn)\s*\("
        r"(?![A-Za-z]?['\"])"
        r"(?=[^\n,;]*\b(?:req|request|ctx|event)\b\s*(?:\?\.|\.|\[))"
        r"|"
        # (B) JS RegExp constructor fed a request-derived pattern (flags may follow;
        #     a request accessor anywhere in the argument list counts).
        r"(?:(?:\bnew\s+)?(?<![\w.])RegExp)\s*\("
        r"(?=[^\n]*\b(?:req|request|ctx|event)\b\s*(?:\?\.|\.|\[))"
        r")",
        "A Python re-module call (compile/search/match/fullmatch/split/findall/finditer/sub/subn) compiles a request-derived first argument as the pattern, or a JS RegExp constructor is built from a request-derived pattern — user-controlled regexes can cause catastrophic backtracking or denial of service (regex injection/ReDoS/CWE-1333)",
    ),
    (
        "R035-hdrinj",
        "security",
        "high",
        "HTTP response header injection: a request-derived value is written into a response header",
        # Fires on a single added line when (CWE-113):
        #   (A) Python subscript-assign on a header-ish object —
        #       response.headers['X-Foo'] = req.query.v / resp['X-Trace'] =
        #       request.headers.get(...) / res.headers['K'] = … — the object is
        #       exactly a response/resp/res variable (directly subscripted) or a
        #       `.headers` attribute on one, and the VALUE after `=` is
        #       request-derived (req/request/ctx/event accessor -> .field /
        #       ['field'] / ?.field).
        #   (B) Python call sinks — response.set_header / response.add_header /
        #       response.set_cookie, plus bare set_cookie / add_header /
        #       set_header — with a request-derived argument (header NAME or
        #       VALUE) in the call.
        #   (C) Node/JS sinks — res.setHeader / res.header / res.append /
        #       res.set / res.cookie / res.writeHead / xhr.setRequestHeader —
        #       with a request-derived argument anywhere in the argument list.
        # A request-derived payload is required (no bare-variable heuristic) so
        # literal headers ("Content-Type: application/json", 'X': 'static'),
        # .headers READS (res.headers.get(...)), generic dict writes
        # (cache['X'] = req... / session['user'] = ... / self.headers[...] /
        # os.environ[...]), helper receivers (auth.set_cookie) and non-header
        # setters (res.send / res.json / response.write) stay quiet.
        r"(?i)(?:"
        # (A) Python subscript-assign on a header-ish object: object is exactly a
        #     response/resp/res variable (directly subscripted) or a `.headers`
        #     attribute on one — then a key, `=`, and a request-derived VALUE.
        r"(?:(?:[\w.\]'\"\\]+\s*)?(?:response|resp|res)\s*\.\s*headers"
        r"|(?:response|resp|res))"
        r"\s*\[[^\]\n]*\]\s*=\s*"
        r"(?=[^\n]*\b(?:req|request|ctx|event)\b\s*(?:\?\.|\.|\[))"
        r"|"
        # (B) Python call sinks.  response.set_header / response.add_header /
        #     response.set_cookie and bare set_cookie / add_header / set_header
        #     calls, each requiring a request-derived argument (name or value).
        r"(?:\b(?:response|resp|res)\s*\.\s*(?:(?:set|add)_?header|set_cookie)\s*\("
        r"|(?<![A-Za-z0-9_.])(?:set_cookie|add_header|set_header)\s*\()"
        r"(?=[^\n]*\b(?:req|request|ctx|event)\b\s*(?:\?\.|\.|\[))"
        r"|"
        # (C) Node/JS sinks — res.setHeader / res.header / res.append / res.set /
        #     res.cookie / res.writeHead / xhr.setRequestHeader — with a
        #     request-derived argument anywhere in the argument list.
        r"\b(?:res|xhr)\s*\.\s*(?:setHeader|header|append|set|cookie|writeHead|"
        r"setRequestHeader)\s*\("
        r"(?=[^\n]*\b(?:req|request|ctx|event)\b\s*(?:\?\.|\.|\[))"
        r")",
        "A request-derived value is written into an HTTP response header via a header-setting sink — response.headers/resp[] subscript-assign or set_header/add_header/set_cookie in Python, res.setHeader/header/append/set/cookie/writeHead or xhr.setRequestHeader in Node — an attacker can inject CRLF to smuggle headers or split responses (HTTP response header injection/CWE-113)",
    ),
    (
        "R036-loginj",
        "security",
        "high",
        "Log injection / log forging: a request-derived value is written to a logging or console sink",
        # Fires on a single added line when (CWE-117): a request-derived value is
        # written unfiltered into a logging/console sink — Python logger/log/logging
        # module .debug/.info/.warning/.warn/.error/.exception/.critical calls
        # (optionally on a receiver like app.logger/self.logger or on a
        # logging.getLogger(name).method(…) chain), Python print(...), Node/JS
        # console.log/warn/error/info/debug/trace, or Java System.out/err
        # .println/.print/.printf. The request source must appear INSIDE the
        # sink's argument list (scan stops at the first `)`) so accessors that
        # merely follow later on the line (a ternary condition, a separate call)
        # stay quiet; a request accessor is required so static log literals, log
        # of a bare variable, logging.basicConfig/setLevel config, .getLogger()
        # factory calls, other receivers (parser.error, pprint.pprint) and
        # non-sink assignments stay quiet. D003 handles sensitive-KEYWORD
        # content; this rule handles request-DERIVED content.
        r"(?i)(?:"
        # Python dotted loggers — optional receiver prefix (app.logger,
        # self.logger), or the logging.getLogger(name).method(…) chain.
        r"(?:(?:\b[A-Za-z_]\w*\s*\.\s*)?\b(?:logger|log|logging)\s*\.\s*"
        r"(?:debug|info|warning|warn|error|exception|critical)\s*\("
        r"|\blogging\s*\.\s*getLogger\s*\([^)\n]*\)\s*\.\s*"
        r"(?:debug|info|warning|warn|error|exception|critical)\s*\("
        # Python print, Node/JS console.*, Java System.out/err.
        r"|\bprint\s*\("
        r"|\bconsole\s*\.\s*(?:log|warn|error|info|debug|trace)\s*\("
        r"|\bSystem\s*\.\s*(?:out|err)\s*\.\s*(?:println|print|printf)\s*\("
        r")"
        # request-derived source inside the sink's argument list — scan only up
        # to the first closing paren so accessors later on the line stay quiet.
        r"(?=[^)\n]*\b(?:req|request|ctx|event)\b\s*(?:\?\.|\.|\[))"
        r")",
        "A request-derived value is written unfiltered to a logging or console sink — Python logger/log/logging .debug/.info/.warning/.error/.exception/.critical or print(), Node/JS console.log/warn/error/info, Java System.out/err.println — an attacker can inject CRLF/control chars to forge fake log lines or poison log-based monitoring (log injection / log forging/CWE-117)",
    ),
    (
        "R037-credurl",
        "security",
        "high",
        "Hardcoded credential embedded in a URL / connection-string literal",
        # Fires on a single added line when (CWE-798): a URL/DSN literal embeds
        # real credentials. (A) URI userinfo: scheme://user[:password]@host — the
        # colons+@ requirements make a NON-EMPTY password mandatory, so a bare
        # user@host (no password, e.g. https://user@example.com) and a host:port
        # (https://example.com:8080) stay quiet; the {}% exclusions keep dynamic
        # templates (f"…{user}:{pwd}@…", "…%s@…" % creds) quiet. (B) a credential
        # query param: scheme://host/path?…&password=…&… (covers jdbc
        # mysql://…?user=x&password=y). The `"` restriction on [^"'\s]* bounds
        # the scan to the quoted literal, so a later unrelated
        # password=variable= on the same line cannot be pulled in; empty values
        # (?key=) need 4+ value chars. R001/R002 own key/value assignment forms
        # (KEY = "…"); this rule owns credential-in-literal form.
        r"(?i)(?:"
        r"\b[a-z][a-z0-9+.\-]{0,40}://[^\"'\s@/{}&?%]*:[^\"'\s@/{}&?%]+@[^\"'\s/?#{}]+"
        r"|\b[a-z][a-z0-9+.\-]{0,40}://[^\"'\s]*"
        r"\b(?:password|passwd|pwd|secret|secret_key|token|api_key)=[A-Za-z0-9_.\-!@$^*+~]{4,}"
        r")",
        "A URL or connection string embeds a plaintext credential (postgres://user:pass@host / mysql URL / jdbc?user=..&password=.. / ?token=..) — an attacker with read access to the repo captures the secret; move credentials to env vars/secret manager and keep only placeholders in code (hardcoded credential/CWE-798)",
    ),
    (
        "R038-perm",
        "security",
        "high",
        "Insecure file permissions / umask disabled on sensitive path",
        # Fires on a single added line when a world-writable octal mode literal
        # (0o777/0o666/0o1777, incl. setuid/setgid forms like 0o4777) reaches a
        # chmod/open/write call, an explicit makedirs/mkdir mode=, or a
        # quoted argv-array chmod token; or when umask() gets a zero mask
        # (0/0o0 — permission masking disabled, every subsequently created
        # file is governed solely by the caller's umask and default 0o666/777,
        # typically world-*writable). 0o600/0o644/0o755 and symbolic
        # S_IRUSR|S_IWUSR stay quiet; decimal 777 is not octal and stays
        # quiet (shell-style 0777 in a quoted chmod token is octal-ish and
        # fires via branch D). B005 owns the existence-level "system call
        # changed" flag; this rule flags the specific insecure-mode pattern.
        r"(?i)(?:"
        r"\b(?:os\.chmod|os\.open|fs\.chmod(?:Sync)?|fs\.open(?:Sync)?|"
        r"fs\.writeFile(?:Sync)?|chmod)"
        r"\s*\([^)\n]*\b0[oO]?(?:[1-7]?777|666)\b[^)\n]*\)"
        r"|"
        r"\b(?:os\.)?(?:makedirs|mkdir)\s*\([^)\n]*\bmode\s*=\s*0[oO]?(?:[1-7]?777|666)\b"
        r"|"
        r"\b(?:os\.|process\.)?umask\s*\(\s*0(?:o?0)?\b"
        r"|"
        r"\[\s*[\"']chmod[\"']\s*,[^\]\n]*[\"']0?(?:[1-7]?777|666)[\"']"
        r")",
        "A world-writable permission (chmod 0o777/0o666/0o1777, makedirs/mkdir mode=…, quoted chmod '777') or a disabled umask allows any local user to read/modify the file — restrict to owner-only (0o600/0o700) and keep a restrictive umask (e.g. 0o022/0o077); avoid setuid/setgid bits on world-writable files (insecure permissions/CWE-732)",
    ),
    (
        "R039-nav",
        "security",
        "high",
        "Client-side navigation to a dynamic or executable-scheme URL (DOM XSS / open redirect)",
        # Fires on a single added line when a navigation sink is fed an unsafe
        # URL (CWE-79/CWE-601):
        #   (A) an executable-scheme literal — javascript: or html-capable
        #       data:text/html / data:application/xhtml — reaches a navigation
        #       sink: window.open(...), location.assign/replace(...),
        #       location/window.location/document.location (.href) assignment,
        #       jQuery .attr('href', ...), or a generic element .href =. The
        #       argument scan is bounded ([^;\n]* / [^)\n]*) so a scheme
        #       literal in an unrelated later statement stays quiet; static
        #       literals (/login, https://…) and location.hash/reload stay
        #       quiet.
        #   (B) a request/URL-search-derived URL reaches a navigation sink —
        #       after the non-literal-arg guard (?!['\"]), the statement (up to
        #       ';') carries an attacker-facing source: request/req/ctx/event
        #       accessor, searchParams.get(...), or location.search.
        #   (C) a url-named variable (url/uri/link/endpoint/target/callback/
        #       webhook, case-insensitive like the JS-facing R031 so returnUrl
        #       fires) is fed to a navigation sink; the scoped lowercase
        #       lookahead rejects SCREAMING_CASE constants (API_URL/BASE_URL).
        # R014 owns DOM render sinks (innerHTML/…), R017 owns Python server
        # redirect(), R031 owns outbound fetch sinks; this rule owns
        # client-side navigation.
        r"(?i)(?:"
        # (A) executable-scheme literal into a navigation sink (bounded scan).
        r"\b(?:window\.)?location(?:\.href)?\s*=[^;\n]*?['\"](?:javascript:|data:(?:text/html|application/xhtml))"
        r"|\bdocument\.location(?:\.\w+)?\s*=[^;\n]*?['\"](?:javascript:|data:(?:text/html|application/xhtml))"
        r"|\bwindow\.open\s*\([^)\n]*?['\"](?:javascript:|data:(?:text/html|application/xhtml))"
        r"|\b(?:[a-z]\w*\.)?location\.(?:assign|replace)\s*\([^)\n]*?['\"](?:javascript:|data:(?:text/html|application/xhtml))"
        r"|\.attr\(\s*['\"]href['\"]\s*,[^)\n]*?['\"](?:javascript:|data:(?:text/html|application/xhtml))"
        r"|\.href\s*=[^;\n]*?['\"](?:javascript:|data:(?:text/html|application/xhtml))"
        r"|"
        # (B) request/URL-search-derived URL into a navigation sink.
        r"(?:"
        r"\bwindow\.open\s*\(\s*(?!['\"])"
        r"|\b(?:[a-z]\w*\.)?location\.(?:assign|replace)\s*\(\s*(?!['\"])"
        r"|\b(?:window\.)?location(?:\.href)?\s*=\s*(?!['\"])"
        r"|\bdocument\.location(?:\.\w+)?\s*=\s*(?!['\"])"
        r")[^;\n]*(?:"
        r"\b(?:request|req|ctx|event)\b\s*(?:\.|\[)"
        r"|\bsearchParams\b\s*\.\s*get\s*\("
        r"|(?-i:\blocation\.search\b)"
        r")"
        r"|"
        # (C) url-named variable fed to a navigation sink (R031-style,
        # case-insensitive so returnUrl/targetUrl fire; SCREAMING constants
        # rejected by the scoped lowercase lookahead).
        r"(?:"
        r"\bwindow\.open\s*\(\s*"
        r"|\b(?:[a-z]\w*\.)?location\.(?:assign|replace)\s*\(\s*"
        r"|\b(?:window\.)?location(?:\.href)?\s*=\s*"
        r"|\bdocument\.location(?:\.\w+)?\s*=\s*"
        r")(?!['\"])(?-i:(?=[A-Za-z_]\w*[a-z]))[\w.]*?(?:url|uri|link|endpoint|target|callback|webhook)[\w.\[\]]*"
        r")",
        "Navigating the browser to a javascript:/html-data: literal, a request/URL-search-derived URL, or a url-named variable can execute attacker script or redirect users to a malicious host — validate against an allowlist of hosts/schemes and build URLs only from server-known data before assignment to window.open/location (.href)/location.assign|replace",
    ),
    (
        "R040-tabnab",
        "security",
        "medium",
        "Reverse tabnabbing: anchor/window.open with target=_blank lacking rel=noopener",
        # (A) inline HTML/JSX anchor whose opening tag uses target="_blank"
        # but carries no rel= value containing noopener/noreferrer.
        # (B) window.open(url, "_blank") with no features string, or a features
        # string that lacks noopener/noreferrer.
        r"(?i)(?:"
        r"<a\b(?=[^>]*?\btarget\s*=\s*['\"]_blank['\"])(?![^>]*?\brel\s*=\s*['\"][^'\">]*?\b(?:noopener|noreferrer)\b)[^>]*?>"
        r"|\bwindow\.open\s*\(\s*[^,)]*?,\s*['\"]_blank['\"]\s*(?:\)|,\s*(?![^)]*\b(?:noopener|noreferrer)\b)[^)]*\))"
        r")",
        "Links/views opened in a new tab (_blank) control the new page and can navigate the opener to a phishing site — guard the hand-off with rel=noreferrer (covers noopener) or, for window.open, add noopener/noreferrer to the features string",
    ),
    (
        "R041-postmsg",
        "security",
        "medium",
        "postMessage with wildcard '*' or attacker-influenced targetOrigin",
        # (A) targetOrigin literal "*": any origin can receive / inject into the
        # cross-document message. (B) dynamic targetOrigin: the second argument
        # is no literal, no array (Web Worker transfer list), no e./location.
        # origin echo, but carries a request/ctx/search-derivation marker or a
        # url-ish keyword. SCREAMING_CASE constants stay quiet (R039/R040
        # convention); (?!\s) pins the lookahead to the argument head so a
        # backtracked "\s*" can't slip a safe origin past the guard.
        r"(?i)(?:"
        r"\bpostMessage\s*\(\s*[^;\n]*?,\s*['\"]\s*\*\s*['\"]"
        r"|"
        r"\bpostMessage\s*\(\s*[^;\n]*?,\s*(?!\s)"
        r"(?!['\"]|\[|\b(?:e|event|evt)\b\.origin\b|(?:window\.)?(?:document\.)?location\.origin\b)"
        r"[^,;)\n]*?(?:"
        r"\b(?:request|req|ctx|event)\b\s*(?:\.|\[)"
        r"|\b(?:URL)?searchparams\b\s*\.\s*get\s*\("
        r"|(?-i:\blocation\.search\b)"
        r"|(?-i:(?=[A-Za-z_]\w*[a-z]))[\w.\[\]]*?(?:origin|url|uri|link|href|endpoint|target|callback|webhook)[\w.\[\]]*"
        r")"
        r")",
        "postMessage(x, '*') leaks the message to every origin, and a targetOrigin built from request/URL-derived values lets a malicious site receive it — always pass an explicit https: origin (or the sender's e.origin after a check) and never let user input pick the destination window",
    ),
    (
        "R042-websock",
        "security",
        "medium",
        "WebSocket endpoint from cleartext ws:// literal or request/URL-derived URL",
        # (A) cleartext literal: new WebSocket('ws://…') — an unencrypted
        # connection sent in the clear (CWE-319). (B) dynamic URL: the argument
        # is no quoted literal / template / leading-space form, but carries a
        # request/ctx/query/params/searchParams/location.search derivation or a
        # url-ish keyword identifier — attacker-controlled WebSocket endpoint
        # (CWE-918/939), so origin/host checks can be redirected. SCREAMING
        # constants and `location.*` property reads (host/protocol/origin/href)
        # stay quiet (R039/R040 convention); (?!['\"`\s]) pins the argument
        # head so a backtracked \s* can't slip a safe value past the guard.
        r"(?i)(?:"
        r"(?:new\s+)?WebSocket\s*\(\s*['\"]ws://"
        r"|"
        r"(?:new\s+)?WebSocket\s*\(\s*(?!['\"`\s])"
        r"[^,;)\n]*?(?:"
        r"\b(?:request|req|ctx|query|params|payload|event)\b\s*(?:\.|\[)"
        r"|\b(?:URL)?searchparams\b\s*\.\s*get\s*\("
        r"|(?-i:\blocation\.search\b)"
        r"|(?-i:(?=[A-Za-z_]\w*[a-z]))[\w.\[\]]*?(?<!location\.)(?:url|uri|endpoint|socket|target|origin|link|href|callback|webhook)"
        r")"
        r")",
        "A WebSocket opened against 'ws://…' sends traffic unencrypted, and one opened against a request/URL-derived host lets an attacker redirect the connection (SSRF / endpoint poisoning) — always use wss:// against a pinned, allow-listed https: origin and never pass user input as the socket URL",
    ),
    (
        "R043-math-random",
        "security",
        "medium",
        "Math.random() used to generate a security value",
        # JS side of CWE-338: Math.random() is not cryptographically secure
        # (Python R016 covers the `random` module). Fires when a security-value
        # keyword (token / otp / nonce / session / jwt / csrf / password-family,
        # including compound *_token names) and a Math.random() call share a line,
        # in either order. crypto.getRandomValues / crypto.randomUUID /
        # crypto.randomBytes / crypto.randomInt and shuffles used as plain
        # utilities stay quiet.
        r"(?i)(?:"
        r"\b(?:password|passwd|pw|token|pin|secret|api[_-]?key|otp|nonce|salt|verif|session|session[_-]?id|csrf|jwt|pass[_-]?code|(?:csrf|auth|access|reset|refresh|session)[_-]?token)\b"
        r"[^\n]*Math\s*\.\s*random\s*\("
        r"|"
        r"Math\s*\.\s*random\s*\([^\n]*"
        r"\b(?:password|passwd|pw|token|pin|secret|api[_-]?key|otp|nonce|salt|verif|session|session[_-]?id|csrf|jwt|pass[_-]?code|(?:csrf|auth|access|reset|refresh|session)[_-]?token)\b"
        r")",
        "Math.random() is not cryptographically secure — an attacker who observes one output (or a partial PRNG seed) can predict tokens, OTPs and sessions (CWE-338). Use crypto.getRandomValues / crypto.randomUUID, or the server-side secrets module, for anything security-related",
    ),
    (
        "R044-storage",
        "security",
        "medium",
        "Security-sensitive token/credential persisted to localStorage/sessionStorage",
        # XSS-exposed persistence (CWE-922): any XSS then reads the token straight
        # off the storage and nothing in the browser can revoke or scope it the
        # way httpOnly cookies can. Fires on a single added line for a *write* to
        # localStorage/sessionStorage whose key or value is security-named:
        #   (A) setItem with a security-named key ('token', 'access_token',
        #       'jwt', 'session_id', 'csrf_token', 'user_token', …) — the
        #       R002-style compound-name idiom, so underscore-joined keys and
        #       plain 'token' fire while 'tokenizer'/'theme' stay quiet.
        #   (B) setItem with a generic key but a security-named *value*
        #       (accessToken / apiKey / payload-derived token).  Read-backs and
        #       key management (getItem/removeItem/clear, comparison, method
        #       names like localStorage.tokenizer()) stay quiet.
        #   (C1) bracket assignment: localStorage['session_id'] = … /
        #       sessionStorage['user_token'] = …
        #   (C2) dot-key write: localStorage.jwt = … / sessionStorage.accessToken
        #       = …  (a property write, not the read form localStorage.token).
        # Keys/stores that are clearly generic ('theme', 'cart', 'last_page',
        # 'visited') never match, and a value fed from localStorage.getItem()
        # itself (a move, not a new sink) stays quiet.
        r"(?i)\b(?:localStorage|sessionStorage)\b\s*(?:"
        # (A) setItem with a security-named key
        r"\.\s*setItem\s*\(\s*['\"`][^'\"`\n]*"
        r"(?:(?<=_)|(?<![A-Za-z0-9_]))(?:session(?:[_-]?id)?|jwt|csrf|"
        r"access[_-]?token|refresh[_-]?token|id[_-]?token|oauth[_-]?token|"
        r"auth(?:[_-]?token)?|credential|apikey|api[_-]?key|secret|"
        r"passw(?:ord|d)|private[_-]?key|token)(?:\b|(?=[_-]))"
        r"[^'\"`\n]*['\"`]"
        r"|"
        # (B) setItem with a generic key but a security-named value
        r"\.\s*setItem\s*\(\s*['\"`][^'\"`\n]*['\"`]\s*,\s*[^'\"`;\n]*"
        r"\b(?:session(?:[_-]?id)?|jwt|csrf|access[_-]?token|refresh[_-]?token|"
        r"id[_-]?token|oauth[_-]?token|auth(?:[_-]?token)?|credential|"
        r"apikey|api[_-]?key|secret|passw(?:ord|d)|private[_-]?key|token)\b"
        r"|"
        # (C1) bracket key write
        r"\[\s*['\"`][^'\"`\n]*"
        r"(?:(?<=_)|(?<![A-Za-z0-9_]))(?:session(?:[_-]?id)?|jwt|csrf|"
        r"access[_-]?token|refresh[_-]?token|id[_-]?token|oauth[_-]?token|"
        r"auth(?:[_-]?token)?|credential|apikey|api[_-]?key|secret|"
        r"passw(?:ord|d)|private[_-]?key|token)(?:\b|(?=[_-]))"
        r"[^'\"`\n]*['\"`]\s*\]\s*=(?!=)"
        r"|"
        # (C2) dot-key write
        r"\.\s*(?:session(?:[_-]?id)?|jwt|csrf|access[_-]?token|refresh[_-]?token|"
        r"id[_-]?token|oauth[_-]?token|auth(?:[_-]?token)?|credential|"
        r"apikey|api[_-]?key|secret|passw(?:ord|d)|private[_-]?key|token)"
        r"\b\s*=(?!=)"
        r")",
        "Tokens, sessions and credentials in localStorage/sessionStorage are readable by any injected script and survive to be exfiltrated — keep bearer material in an httpOnly, Secure, SameSite cookie (or a memory-only holder) so XSS cannot reach it (CWE-922)",
    ),
    (
        "R045-cookie",
        "security",
        "medium",
        "Security-sensitive token/credential written to document.cookie",
        # Client-side cookie writes (CWE-922): a cookie set from JavaScript via
        # document.cookie can never be httpOnly, so any XSS reads the bearer
        # material straight off document.cookie. Fires on a single added line
        # for a *write* (x =, += ; not ==) whose scanned right-hand side or key
        # mentions a security name.  The bounded [^;\n]*? scan only reaches the
        # same statement, so a security keyword in a later statement on the line
        # (gh_token = …; document.cookie = 'theme=dark';) stays quiet.  Two
        # identifier atoms keep false positives out of plain words:
        #   (A) standalone / snake_case / camel-head names — the R044/R002
        #       compound-name idiom ((?<=_) or non-identifier start), plus
        #       case-sensitive (?=(?-i:[A-Z])) so 'tokenStr' fires while
        #       'tokenizer'/'tokens'/'aTokens' (plural/suffix forms) stay
        #       quiet despite the global (?i) rule.
        #   (B) camel-tail names (userToken / getToken()/sessionId) — a
        #       lowercase letter must precede the match, and the tail ends at a
        #       non-identifier, end-of-line, or case-sensitive camel boundary.
        # Reads (x = document.cookie;), comparisons (==), other storage sinks
        # (R044's localStorage/sessionStorage), and generic keys are never
        # flagged here.
        r"(?i)\bdocument\s*\.\s*cookie\b\s*(?:=[^=]|[+\-]=)[^;\n]*?"
        r"(?:"
        r"(?:(?<=_)|(?<![A-Za-z0-9_]))(?:session(?!\s*storage)(?:[_-]?id)?|jwt|"
        r"csrf(?:[_-]?token)?|access[_-]?token|refresh[_-]?token|id[_-]?token|"
        r"oauth[_-]?token|auth(?:[_-]?token)?|credential|api[_-]?key|secret|"
        r"private[_-]?key|passw(?:ord|d)|token|sid)(?:\b|(?=[_-])|(?=(?-i:[A-Z])))"
        r"|"
        r"(?<=(?-i:[a-z]))(?:session(?!\s*storage)(?:[_-]?id)?|jwt|"
        r"csrf(?:[_-]?token)?|access[_-]?token|refresh[_-]?token|id[_-]?token|"
        r"oauth[_-]?token|auth(?:[_-]?token)?|credential|api[_-]?key|secret|"
        r"private[_-]?key|passw(?:ord|d)|token|sid)(?=$|[^A-Za-z0-9_]|(?=(?-i:[A-Z])))"
        r")",
        "Security values written to document.cookie can never be httpOnly — any XSS reads them straight off the cookie object, and the value mirrors any URL-derivable cookie your server could have scoped instead (CWE-922). Keep tokens in an httpOnly, Secure, SameSite cookie set server-side and never touch document.cookie for bearer material",
    ),
    (
        "R046-evaljs",
        "security",
        "medium",
        "Dynamic code execution from string (new Function / Function / string setTimeout|setInterval)",
        # JavaScript string-code execution (CWE-95-ish): R004 covers Python
        # eval()/exec(); nothing yet flags the JS family.  new Function(p) and
        # Function(p) compile and run a string as code — on a modern page that's
        # the same blast radius as eval, and it defeats any CSP that blocks
        # 'unsafe-eval' via a different syntax.  window.Function /
        # globalThis.Function / global.Function are the same sink.
        # setTimeout/setInterval with a *string* first argument (not a
        # callback/closure — those stay quiet) also eval the string.
        # Case-sensitive (the machine-code source is JS, and lower-case
        # `function` declarations / IIFEs must stay quiet), so no (?i) flag;
        # new FunctionString / myFunction / foo.Function /
        # Function.prototype.bind(x) / parser.setFunction(!) can't match.
        r"(?:"
        r"(?<![\w$.])Function\s*\("
        r"|(?:window|globalThis|global)\s*\.\s*Function\s*\("
        r"|\bset(?:Timeout|Interval)\s*\(\s*[\"'`]"
        r")",
        "Functions built from string source on the client are code fed to the JS engine — the same primitive as eval (CWE-95): if any part of the source reaches user/request input, that's arbitrary script execution. Prefer borrowable callbacks or modules, and keep CSP strict rather than letting a string-body Function be the fallible seam",
    ),
    (
        "R047-postmsg-recv",
        "security",
        "medium",
        "postMessage handler uses payload without validating event.origin",
        # Receiver-side complement to R041 (which flags the send side:
        # wildcard 'targetOrigin' / request-derived targetOrigin).  A
        # window message listener (window/document/globalThis/self/parent or
        # bare addEventListener('message', …), or a window-ish/bare onmessage
        # assignment) that consumes the payload — e.data / event['data'] —
        # without referencing event.origin / event.source / originalEvent on
        # the same line trusts a cross-origin sender by default (CWE-346).
        # A hard sender validation is often a compound/line-wrapped check, so
        # an in-line origin/source reference on the same line is enough to
        # silence the rule (no same-line reference = not auditable evidence,
        # stay quiet rather than guess).  Bare-boundary guards keep
        # `port.onmessage` / `worker.onmessage` / socket('message') handles
        # quiet: those aren't window message listeners.
        r"(?:"
        r"(?:(?:window|document|globalThis|self|parent)\s*\.\s*)?"
        r"addEventListener\s*\(\s*['\"]message['\"]\s*,"
        r"|(?:window|globalThis|self|parent)\s*\.\s*onmessage\s*="
        r"|(?<![A-Za-z0-9_.])onmessage\s*="
        r")"
        r"(?![^\n]*\.(?:origin|source|originalEvent)\b)"
        r"[^\n]*?(?:\.data\b|\[\s*['\"]data['\"]\s*\])",
        "A window message handler that consumes event.data without checking event.origin trusts any cross-origin page to script your handler (CWE-346): an attacker page postMessage()s a crafted payload straight into it. Validate event.origin against an explicit allow-list (or event.source, plus the MessageEvent.ports origin) before touching the payload, and never use '*'-style catch-alls",
    ),
    (
        "R048-cookieset",
        "security",
        "medium",
        "Server-side session/token cookie written without Secure/HttpOnly/SameSite flags",
        # CWE-614 / CWE-1004: a sensitive (session/token/credential) cookie
        # written server-side via a response set_cookie / res.cookie call whose
        # line carries none of the three hardening flags — without Secure it
        # rides cross-site in cleartext, without HttpOnly any XSS reads the
        # bearer material, without SameSite it's CSRF-emailable.  R045 owns the
        # client-side document.cookie domain and R011 owns Django-style
        # SESSION_COOKIE_* / SameSite=None config lines; both stay quiet here
        # via the response-receiver guard.  Same line-scoped contract as R045: a
        # flag set on a later line of a multi-line call is a compound write — no
        # in-line hardening keyword = no auditable evidence, stay quiet rather
        # than guess (the identifier atom set is shared with R044/R045).
        r"(?i)\b(?:response|resp|res|r|reply)\s*\.\s*(?:set_cookie\s*\(|cookie\s*\()"
        r"(?![^\n]*(?:httponly|http_only|samesite|secure)\s*[=:])"
        r"[^\n]*?"
        r"(?:(?<=_)|(?<![A-Za-z0-9_]))(?:session(?!\s*storage)(?:[_-]?id)?|jwt|"
        r"csrf(?:[_-]?token)?|access[_-]?token|refresh[_-]?token|id[_-]?token|"
        r"oauth[_-]?token|auth(?:[_-]?token)?|credential|api[_-]?key|secret|"
        r"private[_-]?key|passw(?:ord|d)|token|sid)(?:\b|(?=[_-])|(?=(?-i:[A-Z])))"
        r"|"
        r"(?<=(?-i:[a-z]))(?:session(?!\s*storage)(?:[_-]?id)?|jwt|"
        r"csrf(?:[_-]?token)?|access[_-]?token|refresh[_-]?token|id[_-]?token|"
        r"oauth[_-]?token|auth(?:[_-]?token)?|credential|api[_-]?key|secret|"
        r"private[_-]?key|passw(?:ord|d)|token|sid)(?=$|[^A-Za-z0-9_]|(?=(?-i:[A-Z])))",
        "A sensitive session/token cookie written server-side without Secure (sent in cleartext over HTTP), HttpOnly (readable by any XSS) or SameSite (CSRF-abusable) — CWE-614/CWE-1004. Set all three, matching the app's threat model: Secure over the TLS origin, HttpOnly so scripts can't read it, and SameSite=Strict/Lax (None only with Secure) on this response",
    ),
    (
        "R049-fixatn",
        "security",
        "high",
        "Session container (re)assigned a request-derived session identifier",
        # CWE-384: a session container indexed by a session-identifier key
        # (session['sid'], request.session['session_id'], flask.session['sid'])
        # or a session-object id-ish property (req.session.id / sessionID /
        # session_id / sid) being assigned request-derived input (Python
        # request.args/values/form/json/get_json/cookies/headers/GET/POST, Node
        # req.query/params/body/…).  Adopting a client-supplied session id lets
        # an attacker pre-pick the victim's session and fixate it after login.
        # The value must be request-derived so server-generated ids (uuid4(),
        # secrets.token_hex) stay quiet, and the key must be sid-ish so
        # session['theme'] = request.args.get('theme') stays quiet.  The
        # (?<![\w.]) guard stops client.session / db.session / flask_session
        # reading as the container, and \s*=\s*(?!=) rejects == / >= / <= / !=
        # comparisons.  Assignment via a method call (session.set/edit/update)
        # is a different construct — stay quiet rather than guess.
        r"(?i)(?<![\w.])"
        r"(?:(?:req|request|flask)\s*\.\s*)?session"
        r"(?:\[['\"](?:session(?:[_-]?id)?|sid|id[_-]?token)['\"]\]"
        r"|\.(?:id|sessionID|session_id|sid)\b)"
        r"\s*=\s*(?!=)"
        r"[^\n]*?(?:request|req)\.(?:args|values|form|json|get_json|cookies|headers|query|params|body|query_string|GET|POST)"
        r"\b",
        "A session id being adopted from request input — the fix to prevent session fixation (CWE-384). On login, always rotate to a NEW server-generated session id: session.regenerate()/migrate() (Django/Flask) or req.session.regenerate (Node), never re-assign the id from request args/form/json/headers/cookies. Regenerating after privilege change breaks any attacker-fixated id",
    ),
    (
        "R050-dynimp",
        "security",
        "high",
        "Dynamic import/require of a request-derived module path",
        # CWE-470: a module/package name loaded at runtime via a dynamic import
        # primitive (Python __import__ / importlib.import_module / import_module,
        # Node require(...) / import(...)) whose argument is request-derived.
        # For Node, loadable.module is a code-loading primitive — a request-fed
        # require() executes whatever package the caller names (arbitrary code),
        # and import_module/__import__ at least selects attacker-chosen code
        # paths.  The paren-scoped lookahead requires the request source
        # *inside the sink's own parens* (a [^)\n]* lookahead) so
        # require('fs').readFileSync(req.args...) and
        # import_module('os').system(req.args...) stay quiet; static literals
        # and plain variables are fine (require('express'), import_module(CONFIG)).

        r"(?i)"
        r"(?:(?<![A-Za-z0-9_.])(?:__import__|importlib\s*\.\s*import_module|import_module)\s*\("
        r"|(?<![A-Za-z0-9_.])(?:require|import)\s*\()"
        r"(?=[^)\n]*(?:request|req)\.(?:args|values|form|json|get_json|cookies|headers|files|query|query_params|params|body|query_string|url|baseUrl|originalUrl|path|data|GET|POST)\b)",
        "A module/package name loaded at runtime from request input — CWE-470 (Use of Externally-Controlled Input to Select Classes or Code). A request-fed require()/import() runs arbitrary attacker-named code (Node), and __import__/import_module picks attacker-chosen code paths. Load modules from a server-side allow-list (one constant import map keyed by a strict identifier), and never build the module specifier from request data, URL segments or headers",
    ),
    (
        "R051-hostpois",
        "security",
        "high",
        "Redirect target or URL built from the client-supplied Host header",
        # CWE-644 (OWASP Host Header Attack): request.host / request.host_url
        # and request|req.headers['Host'] / .Host / headers.get('Host') reflect
        # an attacker-controlled header, never the trusted server name.  Building
        # a redirect target, absolute URL or password-reset/callback link from it
        # lets the caller poison the link: open redirect to their domain,
        # emailed-reset caching to their host, or Vary-less Host cache
        # poisoning.  Requires BOTH a host source and a construction signal on
        # the same line — a redirect(...) call, an http/https literal, or an
        # assignment (not a comparison) to a url/redirect/link-ish name — so
        # allowed-host guards (if request.host not in ALLOWED_HOSTS),
        # comparisons, log lines and plain reads carry no in-line sink and stay
        # quiet (single-line evidence contract, same as R047/R048).
        r"(?i)"
        r"(?=[^\n]*(?:(?:request|req)\.host(?:_url)?\b"
        r"|(?:request|req)\.headers\.[Hh]ost\b"
        r"|(?:request|req)\.headers(?:\.get\s*)?\(\s*['\"][Hh]ost['\"]\s*\)"
        r"|(?:request|req)\.headers\s*\[\s*['\"][Hh]ost['\"]\s*\]))"
        r"(?=[^\n]*(?:\bredirect\s*\("
        r"|\bhttps?://"
        r"|\b(?:url|uri|href|link|redirect|callback|return_url|reset|verify|confirm|invite)\w*\s*=\s*(?!=)(?![^\n]*(?:==|!=))))",
        "A redirect or absolute URL built from the client-supplied Host header — CWE-644 (Improper Neutralization of a Host Header). Before using request.host/host_url for a redirect target, password-reset link or callback URL, validate it against an explicit allow-list of server hostnames (Django ALLOWED_HOSTS, a constant origin map), then build the URL from the validated value or a config constant — never from the raw header, and always add Vary: Host for caching",
    ),
    (
        "R052-hdritrust",
        "security",
        "high",
        "Security decision based on a client-spoofable forwarded/proxy header",
        # CWE-807 (Use of Untrusted Inputs in a Security Decision) / CWE-348
        # (Use of Less Trusted Source): X-Forwarded-For / X-Real-IP /
        # X-Client-IP / CF-Connecting-IP / True-Client-IP / X-Forwarded-Host /
        # X-Forwarded-Proto(-col) / X-Scheme / X-Forwarded-Port /
        # X-Forwarded-Url / X-Original-URL / X-Rewrite-URL / Forwarded are
        # injected by the caller unless a trusted reverse proxy strips or
        # overwrites them first — so reading one for an IP allowlist, rate
        # limit, auth, scheme or URL decision lets clients forge the value:
        # bypass IP-based access control, downgrade HTTPS checks, or poison
        # generated absolute URLs.  Requires BOTH the spoofable-header source
        # and an in-line decision signal: identity/scheme assignment (space
        # around '=' keeps name= keyword args quiet), request.environ /
        # request.remote_addr / request.ip re-assignment, comparison against a
        # trust list (ALLOWED/WHITELIST/INTERNAL/TRUSTED/BLOCK/DENY, dotted
        # names allowed), a security verb (abort/raise/rate_limit/RateLimiter/
        # authenticate/authorize/is_admin/csrf), an https scheme comparison, a
        # redirect(...) call, or an http(s) literal.  Log lines, plain reads
        # into generic variables, and display-only uses carry no decision
        # signal and stay quiet (single-line contract, same as R051).
        r"(?i)"
        r"(?=[^\n]*(?:(?:request|req)\.headers\s*\[\s*['\"](?:x-forwarded-for|x-real-ip|x-client-ip|cf-connecting-ip|true-client-ip|x-forwarded-host|x-forwarded-proto|x-forwarded-protocol|x-scheme|x-forwarded-port|x-forwarded-url|x-original-url|x-rewrite-url|forwarded)['\"]\s*\]"
        r"|(?:request|req)\.headers(?:\.get\s*)?\(\s*['\"](?:x-forwarded-for|x-real-ip|x-client-ip|cf-connecting-ip|true-client-ip|x-forwarded-host|x-forwarded-proto|x-forwarded-protocol|x-scheme|x-forwarded-port|x-forwarded-url|x-original-url|x-rewrite-url|forwarded)['\"]\s*\)"
        r"|(?:request|req)\.header\s*\(\s*['\"](?:x-forwarded-for|x-real-ip|x-client-ip|cf-connecting-ip|true-client-ip|x-forwarded-host|x-forwarded-proto|x-forwarded-protocol|x-scheme|x-forwarded-port|x-forwarded-url|x-original-url|x-rewrite-url|forwarded)['\"]\s*\)))"
        r"(?=[^\n]*(?:\b(?:ip|addr(?:ess)?|remote(?:_addr)?|client(?:_ip)?|user(?:_ip|_id)?|email|scheme|proto(?:col)?|secure|is_secure|trusted\w*|allowlist(?:ed)?|whitelist(?:ed)?|blocklist(?:ed)?|url|uri|href|link|path|target|callback|redirect|next)\w*\s*(?<=\s)=(?!=)"
        r"|(?:request|req)\.(?:environ\s*\[\s*['\"]REMOTE_ADDR['\"]\s*\]|remote_addr|ip|client|host)\s*=\s*(?!=)"
        r"|(?:==|!=|\b(?:not\s+)?in\b)\s*(?:\w+\.)*(?:allowed|whitelist|internal|trusted|block|deny)\w*"
        r"|\b(?:abort\s*\(|raise\s+\w+\b|rate_limit\w*\b|RateLimiter\b|authenticate\b|authorize\b|is_admin\b|csrf\b)"
        r"|\bredirect\s*\(|\bhttps?://|(?:==|!=)\s*['\"]https['\"]))",
        "An IP allowlist, rate-limit, authorization, scheme or URL decision that trusts a client-spoofable proxy header — CWE-807 / CWE-348. X-Forwarded-For / X-Real-IP / X-Client-IP / CF-Connecting-IP / True-Client-IP / X-Forwarded-Host / X-Forwarded-Proto(-col) / X-Scheme / X-Forwarded-Url / X-Original-URL / X-Rewrite-URL / Forwarded are written by the caller unless your reverse proxy strips them, so reading one for authentication, an IP allowlist, rate limiting or scheme handling lets clients forge the value: bypass IP-based access control, downgrade HTTPS checks, or poison generated absolute URLs. Strip request-supplied proxy headers on the trusted edge, then use the proxy-reported peer address (request.remote_addr / socket peer or PROXY protocol v2) and the internally-known scheme",
    ),
    (
        "R053-javaexec",
        "security",
        "high",
        "OS command executed via Java Runtime.exec / ProcessBuilder from non-literal input",
        # CWE-78 (Improper Neutralization of Special Elements in an OS Command):
        # the Java runtime always passes the exec argument to the shell, so an
        # argument built from request input, a variable, or string concatenation
        # lets the attacker inject command separators and run arbitrary OS
        # commands.  Catches Runtime.getRuntime().exec() and ProcessBuilder
        # construction where the command or an argument is a bare identifier
        # (request parameter, @RequestBody body, argv, env lookup, any variable
        # that could carry user data) or a string-literal concatenated with '+'
        # a variable.  Static all-literal commands, ProcessBuilder config-only
        # calls (redirectErrorStream / directory / command() alone), regex
        # pattern.exec(...), Node child_process.exec (R032 owns Node) and
        # Python subprocess (R012 owns Python) all lack the shell-driven Java
        # sink shape and stay quiet.  Java sources are case-sensitive
        # CamelCase, so no inline flag is used.  Single-line contract.
        r"(?:\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(\s*(?!new\b)[A-Za-z_]\w*[^)\n]*\)"
        r"|\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\([^)\n]*,\s*(?!new\b)[A-Za-z_]\w*[^)\n]*\)"
        r"|\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\([^)\n]*['\"]\s*\+\s*[A-Za-z_]\w*[^)\n]*\)"
        r"|\bProcessBuilder\s*\(\s*(?!new\b)[A-Za-z_]\w*[^)\n]*\)"
        r"|\bProcessBuilder\s*\([^)\n]*,\s*(?!new\b)[A-Za-z_]\w*[^)\n]*\)"
        r"|\bProcessBuilder\s*\([^)\n]*['\"]\s*\+\s*[A-Za-z_]\w*[^)\n]*\))",
        "Java Runtime.getRuntime().exec(...) / ProcessBuilder fed a non-literal command or argument — CWE-78 OS command injection. The Java runtime forwards the exec parameter to the shell (/bin/sh -c), so command separators in request.input, a request parameter, an @RequestBody body, env lookup, argv or a concatenated variable execute attacker code. Validate the command against an allow-list at the boundary, prefer exec-array executors that bypass the shell, and never interpolate request data into a shell string",
    ),
    (
        "R054-javadeser",
        "security",
        "high",
        "Java deserialization of a non-literal input stream (ObjectInputStream / XMLDecoder)",
        # CWE-502 (Deserialization of Untrusted Data): ObjectInputStream
        # readObject and XMLDecoder reconstruct object graphs straight from an
        # InputStream, so serialized data from a request (getInputStream /
        # getPart(...).getInputStream), an uploaded file, a socket, or any bare
        # variable/body buffer can be groomed into arbitrary gadget chains —
        # full pre-auth RCE on the JVM (this is what ysoserial exploits).  The
        # construction's stream argument must be attacker-touchable: either a
        # lowercase-started identifier or method chain (request accessor,
        # variable, factory call) directly, or one-or-more nested `new
        # StreamX(...)` wrappers ending on such a non-literal argument.
        # All-literal chains, ClassLoader/system-resource and this.getClass()
        # classpath loads (developer-bundled resources), follow-up method calls
        # like readObject() itself, declarations (ObjectInputStream ois = null)
        # and import/method-declaration uses carry no constructed sink and stay
        # quiet.  Java sources are case-sensitive CamelCase, so no inline flag
        # is used (same convention as R053).  Single-line contract.
        r"\b(?:ObjectInputStream|XMLDecoder)\s*\(\s*(?!new\b|this\s*\.\s*getClass\b)[a-z]\w*[^)\n]*\)"
        r"|\b(?:ObjectInputStream|XMLDecoder)\s*\((?:(?:new|final)\s+[\w.]+\(\s*)+?"
        r"(?!new\b|['\"\d]|this\s*\.\s*getClass\b)[a-z]\w*",
        "Java ObjectInputStream/XMLDecoder populated from a non-literal stream — CWE-502 unsafe deserialization. readObject() and XMLDecoder turn serialized bytes into live objects, so request input, an uploaded file or a socket stream fed to these sinks can be crafted into a gadget chain for pre-auth remote code execution (ysoserial). Never deserialize data you don't trust: reject serialized-object formats at the boundary, use a safe format (JSON/Protobuf), or at minimum ring-fence ObjectInputStream with a class allow-list and validate the stream's provenance",
    ),
    (
        "R055-spelinj",
        "security",
        "high",
        "Expression-language (SpEL / MVEL / OGNL / EL) evaluation of a non-literal expression string",
        # CWE-917 (Improper Neutralization of Special Elements used in an
        # Expression Language Statement): SpEL, MVEL, OGNL and
        # javax/jakarta Unified EL all compile and run the expression string
        # inside the JVM — so an expression built from request input can call
        # arbitrary static methods (Runtime.exec via T()/newInstance, OGNL's
        # @java.lang.Runtime@getRuntime().exec), i.e. pre-auth RCE.  Branch
        # layout (single-line contract; Java sources are case-sensitive
        # CamelCase, so no inline (?i) flag is used):
        #   BR1 SpEL — new (SpelExpressionParser|TemplateAwareExpressionParser)
        #        or a named parser receiver (parser / expressionParser /
        #        spelParser / spelExpressionParser / elParser /
        #        templateParser), then parseExpression(non-literal).  A
        #        SCREAMING_SNAKE constant concatenated with a variable
        #        (SPEL_TEMPLATE_PREFIX + userToken) still counts as a
        #        constructed expression.
        #   BR2 OGNL static — Ognl.getValue / Ognl.parseExpression (incl.
        #        OgnlUtil).
        #   BR3 MVEL static — MVEL.eval / compileExpression /
        #        executeExpression.
        #   BR4 javax.el — new ELProcessor() chain or elProcessor / elp
        #        receiver, then eval / setValue / getValue.
        #   BR5 ExpressionFactory.newInstance().createValueExpression /
        #        createMethodExpression, or named receivers expressionFactory /
        #        exprFactory / eFactory / factory — the expression is the
        #        SECOND argument, scoped to the first comma.
        #   BR6 literal-prefix + variable concat at the same receivers
        #        (elProcessor.eval("#{bean." + prop + "}")).
        # NLARG (the non-literal argument marker shared with the R072/R073/
        # R076 Java series) rejects quoted literals, new-expressions, null,
        # numbers and SCREAMING_SNAKE constants; every branch carries the
        # multi-part comment/literal boundary so comment / string-literal
        # reproductions die on it.  Literal expressions in every sink form,
        # constant expressions, null/number args, EL setValue writes addressed
        # to a literal, declarations, imports, script-engine eval receivers
        # (engine/groovyShell/interpreter/jshell — R072's domain) and
        # custom-receiver names echoing the parser vocabulary (QueryParser,
        # sqlParser, XmlParser, exprHandler, config.getExpression, lower-case
        # mvel.eval) stay quiet.
        r"(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)(?:(?:new\s+(?:SpelExpressionParser|TemplateAwareExpressionParser)\s*\([^)\n]*\)\s*\.\s*)|(?:\b(?:parser|expressionParser|spelParser|spelExpressionParser|elParser|templateParser)\b\s*\.\s*))parseExpression\s*\(\s*(?:(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)\s*[A-Za-z_]\w*|[A-Z][A-Z0-9_]{2,}\b\s*\+\s*[A-Za-z_]\w*)[^)\n]*\))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)\bOgnl(?:Util)?\s*\.\s*(?:getValue|parseExpression)\s*\(\s*(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)\s*[A-Za-z_]\w*[^)\n]*\))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)\bMVEL\s*\.\s*(?:eval|compileExpression|executeExpression)\s*\(\s*(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)\s*[A-Za-z_]\w*[^)\n]*\))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)(?:new\s+ELProcessor\s*\([^)\n]*\)\s*\.\s*|\b(?:elProcessor|elp)\b\s*\.\s*)(?:eval|setValue|getValue)\s*\(\s*(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)\s*[A-Za-z_]\w*[^)\n]*\))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)(?:\bExpressionFactory\s*\.\s*newInstance\s*\(\s*\)\s*\.\s*|\b(?:expressionFactory|exprFactory|eFactory|factory)\b\s*\.\s*)create(?:Value|Method)Expression\s*\([^),\n]*\s*,\s*(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)\s*[A-Za-z_]\w*[^)\n]*\))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)\b(?:Ognl(?:Util)?|MVEL|spelParser|expressionParser|eParser|parser|elProcessor|elp)\b\s*\.\s*(?:getValue|parseExpression|eval|compileExpression|executeExpression)\s*\([^)\n]*['\"]\s*\+\s*(?!['\" ]|\d|[A-Z][A-Z0-9_]{2,}\b)[A-Za-z_]\w*)"
        ,
        "An expression-language statement built from non-literal input — CWE-917. SpEL.parseExpression / MVEL.eval / OGNL.getValue / ELProcessor.eval compile the string inside the JVM: request input can reach static-method invocation (SpEL T(java.lang.Runtime).getRuntime().exec(), OGNL @java.lang.Runtime@getRuntime().exec()) and execute code before any whitelist check runs. Evaluate expressions only from a server-side constant allow-list, precompile and cache known templates, and never concatenate request data into the expression string; sandbox the evaluation context (property access / method filtering) as defense-in-depth",
    ),
    (
        "R056-jpaqli",
        "security",
        "high",
        "JPQL / HQL query built by string concatenation or a builder fed to EntityManager.createQuery / Hibernate session.createQuery",
        # CWE-943 (Improper Neutralization of Special Elements in Data Query
        # Logic): JPA EntityManager.createQuery / createNativeQuery /
        # createNamedQuery and Hibernate session/createSQLQuery compile the
        # given string as JPQL/HQL or SQL inside the JVM, so a query
        # assembled with '+' concatenation of a lowercase identifier (request
        # parameter, DTO field, config lookup, builder variable) or with a
        # lowercase identifier method-chain argument (queryBuilder.toString(),
        # sb.append(...).toString(), request.getParameter) yields an
        # injection point: native queries pass raw fragments to the DB, and
        # JPQL/HQL 1=1 tautologies / UNION / ORDER BY probes let an attacker
        # read or drop data.  The '+'-concat discriminator requires a literal
        # quote immediately before the '+' (or no quote earlier in the
        # argument) so all-literal math inside a JPQL string
        # ("... a+b ..."), concatenated UPPER_CASE constants and plain
        # string-building outside a query sink stay quiet; bare-identifier
        # arguments (cq/criteriaQuery/queryObject/QUERY_NAME) are the safe
        # Criteria API or named-constant forms and stay quiet.  Sinks with a
        # literal-first arg must be an actual Java query receiver (em /
        # entityManager / manager / session / currentSession /
        # sessionFactory.openSession() / entityManagerFactory
        # .createEntityManager() / request.getSession()).  Java sources are
        # case-sensitive CamelCase, so no inline flag (same convention as
        # R053/R054/R055).  Single-line contract.
        r"(?:\b(?:em|entityManager|manager|queryManager)\s*\.\s*(?:createQuery|createNamedQuery|createNativeQuery|createStoredProcedureQuery)"
        r"\s*\([^)\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*[^)\n]*\)"
        r"|\b(?:session|currentSession|statelessSession)\s*\.\s*(?:createQuery|createNativeQuery|createSQLQuery)"
        r"\s*\([^)\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*[^)\n]*\)"
        r"|(?:\bsessionFactory\s*\.\s*(?:getCurrentSession|openSession)\s*\(\s*\)|\bentityManagerFactory\s*\.\s*createEntityManager\s*\(\s*\)|\brequest\s*\.\s*getSession\s*\(\s*\))"
        r"\s*\.\s*(?:createQuery|createNativeQuery|createSQLQuery|createNamedQuery|createStoredProcedureQuery)"
        r"\s*\([^)\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*[^)\n]*\)"
        r"|\b(?:em|entityManager|manager|queryManager)\s*\.\s*(?:createQuery|createNamedQuery|createNativeQuery|createStoredProcedureQuery)"
        r"\s*\(\s*[^'\")\n]*\+\s*(?!['\"\d])[a-z_]\w*[^)\n]*\)"
        r"|\b(?:session|currentSession|statelessSession)\s*\.\s*(?:createQuery|createNativeQuery|createSQLQuery)"
        r"\s*\(\s*[^'\")\n]*\+\s*(?!['\"\d])[a-z_]\w*[^)\n]*\)"
        r"|(?:\bsessionFactory\s*\.\s*(?:getCurrentSession|openSession)\s*\(\s*\)|\bentityManagerFactory\s*\.\s*createEntityManager\s*\(\s*\)|\brequest\s*\.\s*getSession\s*\(\s*\))"
        r"\s*\.\s*(?:createQuery|createNativeQuery|createSQLQuery|createNamedQuery|createStoredProcedureQuery)"
        r"\s*\(\s*[^'\")\n]*\+\s*(?!['\"\d])[a-z_]\w*[^)\n]*\)"
        r"|\b(?:em|entityManager|manager|queryManager)\s*\.\s*(?:createQuery|createNamedQuery|createNativeQuery|createStoredProcedureQuery)"
        r"\s*\(\s*(?:request|req)\s*\."
        r"|\b(?:session|currentSession|statelessSession)\s*\.\s*(?:createQuery|createNativeQuery|createSQLQuery)\s*\(\s*(?:request|req)\s*\."
        r"|\b(?:em|entityManager|manager|queryManager)\s*\.\s*(?:createQuery|createNamedQuery|createNativeQuery|createStoredProcedureQuery)"
        r"\s*\(\s*[a-z_]\w*\s*\.\s*(?:toString|append|build|concat|format|valueOf|readLine|read|join|replace|getParameter|getHeader|getBody|getQueryString|getRequestURI|getRemoteAddr|getSimpleName|getName|getProperty|getenv|setLength|delete)\s*\("
        r"|\b(?:session|currentSession|statelessSession)\s*\.\s*(?:createQuery|createNativeQuery|createSQLQuery)"
        r"\s*\(\s*[a-z_]\w*\s*\.\s*(?:toString|append|build|concat|format|valueOf|readLine|read|join|replace|getParameter|getHeader|getBody|getQueryString|getRequestURI|getRemoteAddr|getSimpleName|getName|getProperty|getenv|setLength|delete)\s*\("
        r")",
        "A JPQL / HQL / native SQL query assembled by string concatenation or a builder and fed to EntityManager.createQuery / createNativeQuery / Hibernate session.createQuery — CWE-943 data-query injection. Concatenating lowercase request input (request.getParameter, DTO fields, config values) into the query string lets an attacker smuggle OR clauses / UNION fragments (read data) or 1=1 tautologies (drop data); native queries pass fragments opaquely to the DB. Use createQuery(parameterized) / PreparedStatement-style setParameter bindings or the Criteria API builder, keep query fragments static server-side constants, and never concat user data into the JPQL/HQL string",
    ),
    (
        "R057-ssrf",
        "security",
        "high",
        "Java URL / HTTP client built from a non-literal or request-derived URL",
        # CWE-918 (Server-Side Request Forgery): Java opens outbound
        # connections through java.net.URL.openConnection/openStream, Apache
        # HttpClient.HttpGet/HttpPost, java.net.http.HttpClient.send, Spring
        # RestTemplate.getForObject/exchange, Spring WebClient.get().uri and
        # OkHttp Request.Builder().url — so a URL assembled from request input
        # (request/req.getParameter/getHeader/URI.create(request...),
        # concatenation of a lowercase identifier) lets a caller make the
        # server fetch arbitrary internal endpoints: cloud metadata
        # (http://169.254.169.254/), inside-network services, and file://
        # reads.  The sinks above must receive a non-literal URL: a
        # request/req-accessor argument, a bare lowercase identifier passed
        # straight into new URL( ... ) and then opened, a builder-chain or
        # method-chain argument (sb.toString(), baseUrl + ...),
        # "...-literal" + lower-identifier concatenation, or a plain
        # (url|u)-named variable opened.  Literal "https://..." strings,
        # ALL_CAPS constants, bare HttpRequest objects, method-argument
        # accessors on config objects, imports and getResource()/classloader
        # lookups carry no fused sink and stay quiet.  Java sources are
        # case-sensitive CamelCase, so no inline flag is used (same convention
        # as R053-R056).  Single-line contract.
        r"(?:\bnew\s+URL\s*\(\s*(?!['\"])\s*(?:request|req)\b"
        r"|\bnew\s+URL\s*\([a-z_]\w*(?:\s*\.\s*(?:toString|append|build|concat|format|valueOf)\s*\(\s*[^)\n]*\)\s*)*\)\s*\.\s*openConnection"
        r"|\bnew\s+URL\s*\([^)\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*[^)\n]*\)"
        r"|\b(?:HttpURLConnection|HttpsURLConnection|URLConnection|URL)\s*\.\s*openConnection"
        r"\s*\([^)\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*[^)\n]*\)"
        r"|\bnew\s+(?:RestTemplate|WebClient|OkHttpClient|HttpClient|AsyncHttpClient)\s*\(\s*\)\s*\.\s*"
        r"(?:getForObject|getForEntity|exchange|execute|send|retrieve)\s*\([^)\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*[^)\n]*\)"
        r"|\b(?:restTemplate|webClient|client|httpClient|okHttpClient|rest)\s*\.\s*"
        r"(?:getForObject|getForEntity|exchange|execute|send|retrieve)\s*\([^)\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*[^)\n]*\)"
        r"|\.send\s*\([^;\n]*\b(?:request|req)\s*\.\s*(?:getParameter|getHeader|getRequestURI|getQueryString)\s*\("
        r"|\bURI\s*\.\s*create\s*\((?!['\"])\s*(?:request|req)\s*\."
        r"|\bnew\s+Http(?:Get|Post|Put|Delete|Uri)?\s*\(\s*(?!['\"])\s*(?:request|req)\b"
        r"|\b(?:request|req)\s*\.\s*(?:getParameter|getHeader|getQueryString|getRequestURI|getRequestURL)"
        r"\s*\([^)\n]*\)\s*[^)\n]*(?:URL|openConnection|HttpGet|HttpPost|URIBuilder)"
        r"|\b(?:url|u)\s*\.\s*openConnection\s*\("
        r"|\.(?:uri|url)\s*\([^)\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*"
        r")",
        "A Java outbound HTTP/URL sink fed a non-literal, request-derived or concatenated URL — CWE-918 server-side request forgery. URL.openConnection/openStream, HttpClient.newHttpClient().send, RestTemplate/WebClient/OkHttpClient calls and Apache HttpClient get/post must resolve the target before any network hop: a URL built from request.getParameter/URI.create(request...) or by string concatenation can be pointed at cloud metadata (169.254.169.254), internal services or file:// URIs, letting a caller read secrets or drive the server as a proxy. Resolve URLs only from a fixed server-side allow-list (scheme + host), reject non-http(s) schemes, and pass pre-validated absolute constants to the client instead of raw request-derived strings",
    ),
    (
        "R058-jdbcsqli",
        "security",
        "high",
        "JDBC / JdbcTemplate SQL query built by string concatenation or fed request-derived input",
        # CWE-89 (Improper Neutralization of Special Elements used in an SQL
        # Command): Statement.executeQuery/executeUpdate/execute,
        # Connection.prepareStatement and Spring JdbcTemplate.query/update/
        # execute compile the string as SQL inside the JDBC driver, so a
        # query assembled with '+' concatenation of a lowercase identifier
        # (request parameter, DTO field, config lookup, builder variable) or
        # passed a method-chain argument (queryBuilder.toString(), sb.append
        # (...).toString(), request.getParameter/getHeader) yields an
        # injection point: raw fragments cross into the DB and an attacker
        # can smuggle OR/UNION, comment-out closing quotes, or stack
        # statements.  prepareStatement with a fully-literal or fully-
        # parameterized (? binds) string is immune and stays quiet, as do
        # literal-only execute* / template calls, bare Statement objects
        # without an execute*, execute() with no argument, UPPER_CASE SQL
        # constants, ALL_UPPER concat operands, prepared-statement binding
        # calls (ps.setString), non-query string building outside a sink,
        # JdbcTemplate.execute(connection -> ...) lambda receivers, and
        # custom receivers named ex/executor/rowMapper.  The '+'-concat
        # discriminator requires a literal quote immediately before the '+'
        # (or the whole pre-'+' argument quoted) so in-string arithmetic
        # ("a+b" inside SQL) and ALL_CAPS concat operands stay quiet; the
        # bare-identifier chain branch needs an actual accessor call token
        # so a generic String argument (jdbcTemplate.query(sql, ...)) stays
        # quiet.  Java sources are case-sensitive CamelCase, so no inline
        # flag (same convention as R053-R057).  Single-line contract.
        r"(?:\b(?:stmt|statement|st|ps|pstmt|preparedStatement)\s*\.\s*(?:executeQuery|executeUpdate|executeLargeUpdate|execute)"
        r"\s*\([^;\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*[^)\n]*\)"
        r"|\b(?:stmt|statement|st|ps|pstmt|preparedStatement)\s*\.\s*(?:executeQuery|executeUpdate|executeLargeUpdate|execute)"
        r"\s*\(\s*(?!['\"\d)])\s*[a-z_]\w*"
        r"(?:\s*\.\s*(?:toString|append|build|concat|format|valueOf|readLine|read|join|replace|edit|getParameter|getHeader|getQueryString|getRequestURI|getRequestURL|getProperty|getenv|getUsername|getEmail|getTable|getSql|getCode|getBody)\s*\([^;\n]*\)\s*)+"
        r"|\b(?:conn|connection|con|db|dataSource|source|pool)\s*\.\s*prepareStatement\s*\([^;\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*[^)\n]*\)"
        r"|\b(?:conn|connection|con|db|dataSource|source|pool)\s*\.\s*prepareStatement\s*\(\s*(?!['\"\d)])\s*[a-z_]\w*"
        r"(?:\s*\.\s*(?:toString|append|build|concat|format|valueOf|edit|getParameter|getHeader|getQueryString|getRequestURI|getRequestURL|getProperty|getenv|getUsername|getEmail|getTable|getSql|getCode)\s*\([^;\n]*\)\s*)+"
        r"|\b(?:conn|connection|con|db|dataSource|source|pool)\s*\.\s*createStatement\s*\(\s*\)\s*\.\s*(?:executeQuery|executeUpdate|execute)"
        r"\s*\([^;\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*"
        r"|\b(?:conn|connection|con|db|dataSource|source|pool)\s*\.\s*createStatement\s*\(\s*\)\s*\.\s*(?:executeQuery|executeUpdate|execute)"
        r"\s*\(\s*(?!['\"\d)])\s*[a-z_]\w*"
        r"(?:\s*\.\s*(?:toString|append|build|concat|format|valueOf|readLine|read|join|replace|getParameter|getHeader|getQueryString|getRequestURI|getProperty|getenv|getUsername|getEmail|getTable|getSql|getCode)\s*\([^;\n]*\)\s*)+"
        r"|\b(?:jdbcTemplate|namedParameterJdbcTemplate|simpleJdbcTemplate|jdbc|jt)\s*\.\s*(?:query|queryForObject|queryForList|queryForMap|queryForRowSet|update|execute|batchUpdate)"
        r"\s*\([^;\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*[^)\n]*\)"
        r"|\b(?:jdbcTemplate|namedParameterJdbcTemplate|simpleJdbcTemplate|jdbc|jt)\s*\.\s*(?:query|queryForObject|queryForList|queryForMap|queryForRowSet|update|execute|batchUpdate)"
        r"\s*\(\s*(?!['\"\d)])\s*[a-z_]\w*"
        r"(?:\s*\.\s*(?:toString|append|build|concat|format|valueOf|readLine|read|join|replace|edit|getParameter|getHeader|getQueryString|getRequestURI|getRequestURL|getProperty|getenv|getUsername|getEmail|getTable|getSql|getCode|getBody)\s*\([^;\n]*\)\s*)+"
        r")",
        "A JDBC / Spring JdbcTemplate SQL sink fed a concatenated or request-derived query string — CWE-89 SQL injection. Statement.execute*, Connection.prepareStatement and JdbcTemplate.query/update/execute hand the string to the driver: request input concatenated with '+' or a builder/.toString() chain crosses into the DB, so an attacker can inject OR/UNION fragments, comment out the remainder, or stack statements (categoryA; DROP TABLE…). Use parameterized SQL — PreparedStatement with ? binds, JdbcTemplate query(sql, params, mapper) / named parameters (:name) — and keep every query fragment a fixed server-side constant; never concatenate user input into the SQL text",
    ),
    (
        "R059-xpathjava",
        "security",
        "high",
        "Java XPath expression built by string concatenation or fed request-derived input",
        # CWE-643 (Improper Neutralization of Data within XPath
        # Expressions): javax.xml.xpath XPathFactory.newInstance().newXPath()
        # .evaluate/compile, an xpath/xp-named receiver's evaluate/compile
        # and DOM4J document.selectNodes/selectSingleNode compile the query
        # string and walk the parsed XML document — a predicate assembled
        # with '+' concatenation of a lowercase identifier (request
        # parameter, DTO field, builder variable) or passed a method-chain
        # argument (sb.toString(), request.getParameter/getHeader/
        # getQueryString) lets an attacker smuggle boolean tautologies
        # (' or '1'='1), comment out the rest of the predicate, or read
        # sibling nodes outside the intended subtree.  Literal quoted
        # expressions, SCREAMING_SNAKE constants, bare String variables
        # (query/URLSearchParams-style) and ALL_CAPS concat operands stay
        # quiet, as do non-sink XPath construction (factory/newXPath alone),
        # variable-resolution setup, DOM traversal (getElementsByTagName),
        # Selenium By.xpath staged objects and Saxon/Ruby-style receivers
        # without an evaluate.  Java sources are case-sensitive CamelCase,
        # so no inline flag (same convention as R053-R058).  Single-line
        # contract.
        r"(?:"
        r"\bXPathFactory\s*\.\s*newInstance\s*\(\s*\)\s*\.\s*newXPath\s*\(\s*\)\s*\.\s*(?:evaluate|compile|evaluateExpression)"
        r"\s*\([^;\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*"
        r"|\bXPathFactory\s*\.\s*newInstance\s*\(\s*\)\s*\.\s*newXPath\s*\(\s*\)\s*\.\s*(?:evaluate|compile|evaluateExpression)"
        r"\s*\(\s*(?:request|req)\s*\.\s*(?:getParameter|getHeader|getQueryString|getRequestURI|getRequestURL)\s*\("
        r"|\bXPathFactory\s*\.\s*newInstance\s*\(\s*\)\s*\.\s*newXPath\s*\(\s*\)\s*\.\s*(?:evaluate|compile|evaluateExpression)"
        r"\s*\(\s*(?!['\"])\s*[a-z_]\w*\s*\.\s*(?:toString|append|build|concat|format|valueOf)\s*\("
        r"|\b(?:xpath|xp)[A-Za-z0-9_]*\s*\.\s*(?:evaluate|compile|evaluateExpression)\s*\([^;\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*"
        r"|\b(?:xpath|xp)[A-Za-z0-9_]*\s*\.\s*(?:evaluate|compile|evaluateExpression)\s*\(\s*(?:request|req)\b\s*\.\s*(?:getParameter|getHeader|getQueryString|getRequestURI|getRequestURL)\s*\("
        r"|\b(?:xpath|xp)[A-Za-z0-9_]*\s*\.\s*(?:evaluate|compile|evaluateExpression)\s*\(\s*(?!['\"])\s*[a-z_]\w*\s*\.\s*(?:toString|append|build|concat|format|valueOf)\s*\("
        r"|\b(?:document|doc|root)\s*\.\s*(?:selectNodes|selectSingleNode)\s*\([^;\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*"
        r"|\b(?:document|doc|root)\s*\.\s*(?:selectNodes|selectSingleNode)\s*\(\s*(?:request|req)\s*\.\s*(?:getParameter|getHeader|getQueryString|getRequestURI)\s*\("
        r")",
        "A Java XPath sink fed a concatenated or request-derived expression — CWE-643 XPath injection. XPathFactory.newInstance().newXPath().evaluate/compile, xpath/xp-named receivers and DOM4J document.selectNodes/selectSingleNode compile the query and run it against the parsed document: a predicate built with '+' concatenation or sb.toString() lets an attacker inject boolean tautologies (' or '1'='1) or wildcard child selects to read sibling/root nodes the app did not authorize. Build XPath predicates only from validated static fragments and parameterize/bind variables; whitelist the expression shape and never concatenate request input into the query string",
    ),
    (
        "R060-openredir",
        "security",
        "high",
        "Java URL redirect / Location header built from client-controlled input",
        # CWE-601 (URL Redirection to Untrusted Site): HttpServletResponse
        # .sendRedirect, setHeader("Location", ...), Spring RedirectView /
        # redirectView.setUrl and ModelAndView "redirect:" views issue an
        # HTTP 3xx to a URL the client then follows.  When the target is
        # assembled with '+' concatenation of a lowercase identifier
        # (parameter value, DTO field, builder variable) or is an unbounded
        # sink-context bare identifier (dest/target/nextUrl...), or passed
        # a request accessor result (request.getParameter/getHeader/
        # getRequestURI/getRequestURL/getQueryString), an attacker can steer
        # the redirect to an attacker-controlled host — classic open-redirect
        # used to launder phishing links past URL scanners.  Fully-literal
        # strings, SCREAMING_SNAKE constants, bare String variables, ALL_CAPS
        # concat operands ("/go" + SUFFIX), status-only calls (setStatus,
        # sendError), dispatcher forwards and non-redirect headers
        # (Cache-Control) stay quiet.  Java sources are case-sensitive
        # CamelCase, so no inline flag (same convention as R053-R059).
        # Single-line contract.
        r"(?:"
        r"\b(?:response|resp|res|httpResponse|httpServletResponse)\s*\.\s*sendRedirect\s*\([^;\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*"
        r"|\b(?:response|resp|res|httpResponse|httpServletResponse)\s*\.\s*sendRedirect\s*\(\s*(?:request|req)\b\s*\.\s*(?:getParameter|getHeader|getRequestURI|getRequestURL|getQueryString)\s*\("
        r"|\b(?:response|resp|res|httpResponse|httpServletResponse)\s*\.\s*sendRedirect\s*\(\s*\b(?:next|dest|target|returnTo|returnUrl|redirectTo|callback|goTo|lastPage|url)\w*\s*\)"
        r"|\b(?:response|resp|res|httpResponse|httpServletResponse)\s*\.\s*sendRedirect\s*\(\s*(?!['\"])\s*[a-z_]\w*\s*\.\s*(?:toString|append|build|concat|format|valueOf)\s*\("
        r"|\b(?:response|resp|res|httpResponse|httpServletResponse)\s*\.\s*setHeader\s*\(\s*['\"]Location['\"]\s*,\s*(?:request|req)\b\s*\.\s*(?:getParameter|getHeader|getRequestURI|getRequestURL|getQueryString)\s*\("
        r"|\b(?:response|resp|res|httpResponse|httpServletResponse)\s*\.\s*setHeader\s*\(\s*['\"]Location['\"]\s*,\s*[^,\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*"
        r"|\bnew\s+RedirectView\s*\([^;\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*[^)\n]*\)"
        r"|\bnew\s+RedirectView\s*\(\s*(?:request|req)\b\s*\.\s*(?:getParameter|getHeader|getRequestURI|getQueryString)\s*\("
        r"|\b(?:redirectView)\s*\.\s*setUrl\s*\(\s*(?:request|req)\b\s*\.\s*(?:getParameter|getHeader|getQueryString)\s*\("
        r"|\b(?:redirectView)\s*\.\s*setUrl\s*\([^;\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*"
        r"|\bnew\s+ModelAndView\s*\(\s*['\"]redirect:[^'\"]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*"
        r")",
        "A Java redirect sink fed a concatenated or request-derived URL — CWE-601 open redirect. HttpServletResponse.sendRedirect, response.setHeader(\"Location\", ...), Spring RedirectView / redirectView.setUrl and ModelAndView \"redirect:\" views send the browser to the target: server-side concatenation of a parameter/field value, an unbounded sink-context bare identifier (dest/target/nextUrl), a request accessor result (getParameter/getHeader/getRequestURI) or a builder/.toString() chain lets an attacker pick where victims land after login/logout — used to launder phishing links past scanners. Validate that the target is a same-origin relative path (starts with '/') or an allow-listed scheme+host before redirecting; never reflect request input into the Location",
    ),
    (
        "R061-ldapjndi",
        "security",
        "high",
        "Java LDAP / Spring LDAP search filter or base dn built from client-controlled input",
        # CWE-90 (Improper Neutralization of Special Elements used in an
        # LDAP Query): JNDI DirContext-family search — InitialDirContext/
        # InitialLdapContext/DirContext/LdapContext receiver .search(
        # baseDn, filter, ...) and Spring LdapTemplate.search /
        # searchForObject / searchForContext — hand the (base, filter)
        # pair to the LDAP server, which ANDs a user-supplied filter like
        # (uid=*) against the base.  A filter or base assembled with '+'
        # concatenation of a lowercase identifier (request parameter,
        # login/username/uid field), a request accessor result
        # (getParameter/getHeader/getQueryString) or a builder/.toString()
        # chain lets an attacker inject filter metacharacters — a closing
        # ')' plus (objectClass=*) or (& msg — to bypass authentication and
        # read entries outside the intended subtree.  Fully-literal
        # filters, SCREAMING_SNAKE constants, bare String variables, ALL_CAPS
        # concat operands ("(uid=" + USER_ID + ")"), in-string arithmetic,
        # non-search LDAP ops (authenticate, createSubcontext, close) and
        # non-LDAP receivers (table.search, query.search, re.search) stay
        # quiet.  Java sources are case-sensitive CamelCase, so no inline
        # flag (same convention as R053-R060).  Single-line contract.
        r"(?:"
        r"\b(?:ctx|ctxt|context|dirCtx|dirContext|ldapContext|initialDirContext|ldapTemplate|ldap)\w*\s*\.\s*(?:search|searchForObject|searchForContext)\s*\([^;\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*"
        r"|\b(?:ctx|ctxt|context|dirCtx|dirContext|ldapContext|initialDirContext|ldapTemplate|ldap)\w*\s*\.\s*(?:search|searchForObject|searchForContext)\s*\([^;\n]*(?:request|req)\b\s*\.\s*(?:getParameter|getHeader|getQueryString)\s*\("
        r"|\b(?:ctx|ctxt|context|dirCtx|dirContext|ldapContext|initialDirContext|ldapTemplate|ldap)\w*\s*\.\s*(?:search|searchForObject|searchForContext)\s*\([^;\n]*[a-z_]\w*\s*\.\s*(?:append|build|toString)\s*\("
        r")",
        "A Java LDAP / Spring LDAP search fed a concatenated or request-derived filter or base — CWE-90 LDAP injection. JNDI DirContext-family ctx/dirContext/ldapContext/initialDirContext .search and Spring LdapTemplate.search/searchForObject/searchForContext send the (base, filter) pair to the server: request input concatenated with '+' or a builder/.toString() chain crosses into the filter expression, so an attacker can inject ')(objectClass=*)' tautologies or '(uid=*)' wildcards to bypass auth or read sibling entries — LDAP treats the filter as an AND of expression terms and never encodes it. Escape / filter special characters (\\ * ( ) NUL) and use whitelisted attribute values or Spring's FilterCriteraBuilder/EqualsFilter for every user-derived term; never concatenate request input into the filter or base dn",
    ),
    (
        "R062-javaxxe",
        "security",
        "high",
        "Java XML parser fed client-controlled or concatenated input (XXE / entity expansion risk)",
        # CWE-611 (Improper Restriction of XML External Entity Reference):
        # JAXP DocumentBuilderFactory/SAXParserFactory chains — both the
        # inline DocumentBuilderFactory.newInstance().newDocumentBuilder()
        # and the staged form (a lowercase factory variable split across a
        # preceding line, e.g. factory.newDocumentBuilder().parse(...)) — and
        # DOM4J SAXReader (builder/documentBuilder/saxParser/reader/
        # xmlReader/saxReader receivers and `new SAXReader().read(...)`) are
        # compiled without hardening (disallow-doctype-decl absent), so they
        # expand external entities when the parsed document is
        # attacker-controlled.  A request accessor result
        # (getInputStream/getReader/getParameter/getPart/getHeader), an
        # upload stream (fileItem/part/upload/multipartFile.getInputStream),
        # a '+' concatenation of a lowercase identifier, a builder/.toString()
        # chain or an xml-named bare variable (xmlBody/userXml/payload) fed to
        # parse/read means the document tree (and any entity it references)
        # comes from the client, enabling local-file disclosure /
        # internal-network SSRF via crafted DOCTYPEs.  Factory
        # construction/setup lines (setFeature/setProperty hardening,
        # disallow-doctype-decl), nodeModel-building (builder.newDocument()),
        # validation, transformers/serializers, streaming char reads and
        # non-parse streams of upload entities stay quiet.  Java sources are
        # case-sensitive CamelCase, so no inline flag (same convention as
        # R053-R061).  Single-line contract.
        r"(?:"
        r"(?:[A-Z]\w*\s*\.\s*newInstance\s*\(\s*\)\s*\.\s*|[a-z_]\w*\s*\.\s*)(?:newDocumentBuilder|newSAXParser)\s*\(\s*\)\s*\.\s*parse\s*\([^;\n]*(?:request|req)\b\s*\.\s*(?:getInputStream|getReader|getParameter|getPart|getHeader)\s*\("
        r"|(?:[A-Z]\w*\s*\.\s*newInstance\s*\(\s*\)\s*\.\s*|[a-z_]\w*\s*\.\s*)(?:newDocumentBuilder|newSAXParser)\s*\(\s*\)\s*\.\s*parse\s*\([^;\n]*(?:fileItem|part|upload|multipartFile)\w*\s*\.\s*getInputStream\s*\("
        r"|\b(?:builder|docBuilder|documentBuilder|parser|saxParser|reader|xmlReader|saxReader)\w*\s*\.\s*(?:parse|read)\s*\([^;\n]*(?:request|req)\b\s*\.\s*(?:getInputStream|getReader|getParameter|getPart|getHeader)\s*\("
        r"|\b(?:builder|docBuilder|documentBuilder|parser|saxParser|reader|xmlReader|saxReader)\w*\s*\.\s*(?:parse|read)\s*\([^;\n]*(?:fileItem|part|upload|multipartFile)\w*\s*\.\s*getInputStream\s*\("
        r"|\bnew\s+SAXReader\s*\(\s*\)\s*\.\s*read\s*\([^;\n]*(?:request|req)\b\s*\.\s*(?:getInputStream|getReader|getParameter|getPart|getHeader)\s*\("
        r"|\bnew\s+SAXReader\s*\(\s*\)\s*\.\s*read\s*\([^;\n]*(?:fileItem|part|upload|multipartFile)\w*\s*\.\s*getInputStream\s*\("
        r"|\b(?:builder|docBuilder|documentBuilder|parser|saxParser|reader|xmlReader|saxReader)\w*\s*\.\s*(?:parse|read)\s*\([^;\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*"
        r"|\b(?:builder|docBuilder|documentBuilder|parser|saxParser|reader|xmlReader|saxReader)\w*\s*\.\s*(?:parse|read)\s*\([^;\n]*[a-z_]\w*\s*\.\s*(?:append|build|toString)\s*\("
        r"|\b(?:builder|docBuilder|documentBuilder|parser|saxParser|reader|xmlReader|saxReader)\w*\s*\.\s*(?:parse|read)\s*\(\s*(?!['\"])(?=[\w.]*[a-z])(?:[\w.]*?)?(?-i:xml)[\w.\[\]]*(?:\s*,|\s*\))"
        r"|(?:[A-Z]\w*\s*\.\s*newInstance\s*\(\s*\)\s*\.\s*|[a-z_]\w*\s*\.\s*)(?:newDocumentBuilder|newSAXParser)\s*\(\s*\)\s*\.\s*parse\s*\([^;\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*"
        r"|\bnew\s+SAXReader\s*\(\s*\)\s*\.\s*read\s*\([^;\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*"
        r"|(?:[A-Z]\w*\s*\.\s*newInstance\s*\(\s*\)\s*\.\s*|[a-z_]\w*\s*\.\s*)(?:newDocumentBuilder|newSAXParser)\s*\(\s*\)\s*\.\s*parse\s*\([^;\n]*[a-z_]\w*\s*\.\s*(?:append|build|toString)\s*\("
        r"|\bnew\s+SAXReader\s*\(\s*\)\s*\.\s*read\s*\([^;\n]*[a-z_]\w*\s*\.\s*(?:append|build|toString)\s*\("
        r")",
        "A Java XML parser fed client-controlled input without entity-expansion hardening — CWE-611 XXE. JAXP DocumentBuilderFactory/SAXParserFactory newInstance chains (.parse) and DOM4J SAXReader (.read), plus builder/documentBuilder/saxParser/reader/xmlReader receivers, parse a document assembled from a request accessor (getInputStream/getReader/getParameter/getPart/getHeader), an upload file stream, a '+' concatenation, a builder/.toString() chain or an xml-named variable: a crafted DOCTYPE with an external entity SYSTEM reference makes the parser read files (/etc/passwd) or hit internal URLs, and billion-laughs nested entities exhaust memory. Harden the factory (disallow-doctype-decl, external DTD/entity features off), validate the source against a whitelist or a schema-less in-memory safe parser, and refuse non-well-formed client documents",
    ),
    (
        "R063-javapath",
        "security",
        "high",
        "Java file-path sink (new File / Files / upload write) fed client-controlled or concatenated input (path traversal)",
        # CWE-22 (Improper Limitation of a Pathname to a Restricted
        # Directory): java.io.File-family constructors
        # (File/FileInputStream/FileOutputStream/FileReader/FileWriter/
        # RandomAccessFile), the java.nio Files.* helpers fed a
        # Paths.get(...) argument (readAllBytes/readAllLines/readString/
        # write/copy/newInputStream/newBufferedReader/newBufferedWriter/
        # lines/delete/move/createDirectories/createFile) and upload
        # write sinks (fileItem.write/part.write/multipartFile.transferTo)
        # compute the target path from a request accessor
        # (getParameter/getHeader/getQueryString/getRequestURI), a '+'
        # concatenation of a lowercase identifier, or a filename-named bare
        # variable (fileName/filename/originalFilename/fname).  A
        # '..'-crafted or absolute attacker-supplied path then reaches files
        # outside the intended sandbox: arbitrary file read/overwrite,
        # config or keystore disclosure and code execution via write-into-
        # deploy-location.  Literal/SCREAMING_SNAKE constant paths, ALL_CAPS
        # concat operands, parent + literal second-arg File ctor calls,
        # classpath getResourceAsStream lookups, UUID/timestamp generation
        # and getter-only expressions (part.getSubmittedFileName(),
        # fileItem.getName()) stay quiet.  Java sources are case-sensitive
        # CamelCase, so no inline flag (same convention as R053-R062).
        # Single-line contract.
        r"(?:"
        r"\bnew\s+(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile)\s*\([^)\n]*(?:request|req)\b\s*\.\s*(?:getParameter|getHeader|getQueryString|getRequestURI)\s*\("
        r"|\bnew\s+(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile)\s*\([^)\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*"
        r"|\b(?:part|fileItem|multipartFile|upload)\w*\s*\.\s*(?:write|transferTo)\s*\([^)\n]*(?:request|req)\b\s*\.\s*(?:getParameter|getHeader|getQueryString)\s*\("
        r"|\b(?:part|fileItem|multipartFile|upload)\w*\s*\.\s*(?:write|transferTo)\s*\([^)\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*"
        r"|\b(?:part|fileItem|multipartFile|upload)\w*\s*\.\s*(?:write|transferTo)\s*\([^)\n]*\b(?:fileName|filename|originalFilename|fname)\w*\s*\)"
        r"|\bnew\s+File\s*\([^,)\n]*,\s*(?!['\"])(?:fileName|filename|originalFilename|fname|name|input|key|id)\w*\s*\)"
        r"|\bnew\s+(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile)\s*\(\s*(?!['\"]|\d)(?=[A-Za-z_]\w*[a-z])(?:savePath|uploadPath|filePath|fileName|filename|originalFilename|tmpFile|saveFile|targetPath|destPath|outputPath|pathname|target|dest|output|path)\w*\s*\)"
        r"|\bFiles\s*\.\s*(?:readAllBytes|readAllLines|readString|write|copy|newInputStream|newBufferedReader|newBufferedWriter|lines|delete|move|createDirectories|createFile)\s*\(\s*Paths\s*\.\s*get\s*\([^)\n]*(?:request|req)\b\s*\.\s*(?:getParameter|getHeader|getQueryString|getRequestURI)\s*\("
        r"|\bFiles\s*\.\s*(?:readAllBytes|readAllLines|readString|write|copy|newInputStream|newBufferedReader|newBufferedWriter)\s*\(\s*Paths\s*\.\s*get\s*\([^)\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*"
        r")",
        "A Java file-path sink built from client-controlled input — CWE-22 path traversal. new File-family constructors (File/FileInputStream/FileOutputStream/FileReader/FileWriter/RandomAccessFile), Files.* helpers over Paths.get(...) (readAllBytes/readAllLines/readString/write/copy/newInputStream/newBufferedReader/newBufferedWriter/lines/delete/move/createDirectories/createFile) and upload writes (fileItem.write/part.write/multipartFile.transferTo) resolve the target from a request accessor (getParameter/getHeader/getQueryString/getRequestURI), a '+' concatenation or a filename-named variable: a '..'-laden or absolute value selects files outside the sandbox, so an attacker can read secrets, overwrite configs or write a file into a deployable location. Validate and normalize the path, canonicalize it with File.getCanonicalPath()/Paths.toRealPath() and reject values escaping the allowed base directory; derive upload names on the server side instead of trusting client filename",
    ),
    (
        "R064-javareflect",
        "security",
        "high",
        "Java reflection sink (Class.forName / ClassLoader loadClass / method or constructor lookup) fed client-controlled or concatenated input (unsafe reflection)",
        # CWE-470 (Use of Externally-Controlled Input to Select Classes or
        # Code): the reflection entry points — Class.forName(name),
        # ClassLoader-family loadClass/defineClass, and method/constructor
        # lookup via getMethod/getDeclaredMethod/getConstructor/
        # getDeclaredConstructor on any lowercase receiver (including
        # obj.getClass() chains) — resolve a class/member selected from a
        # request accessor (getParameter/getHeader/getQueryString/
        # getRequestURI), a '+' concatenation of a lowercase identifier, or
        # a bare lowercase variable holding the name.  Only the
        # Class.forName-over-a-lowercase-variable and loadClass-over-a-lowercase-variable
        # forms accept a bare variable (request.getParameter(...) results
        # only reach these via a wide [^)]* scan); the method/constructor
        # lookups require an explicit request accessor or '+' concat
        # (their arg travels through a [^;\n]* span where a bare name could
        # be a fixed member name like "execute", which stays quiet).
        # Attacker-controlled names can instantiate arbitrary reachable
        # classes, invoke unexpected methods/constructors or (with a
        # defineClass/bytecode path) load injected bytecode — gadget-driven
        # RCE, auth-bypass state switches or internal component abuse.
        # Literal "com.example.MyClass" names, SCREAMING_SNAKE constants,
        # Class.forName(Object.class.getName()) class-literal names,
        # receiver acquisition (new URLClassLoader(...),
        # Thread.currentThread().getContextClassLoader(),
        # getClass().getClassLoader()), `(Type) clazz.newInstance()`
        # instance creation, `clazz.getDeclaredMethods()[0]` array access
        # and `mapper.getMethod("toString")`-style custom receivers (non
        # .class/obj.getClass() chains not selecting a reflection member by
        # client-controlled name) stay quiet.  Java sources are
        # case-sensitive CamelCase, so no inline flag (same convention as
        # R053-R063).  Single-line contract.
        r"(?:"
        r"\bClass\s*\.\s*forName\s*\([^)\n]*(?:request|req)\b\s*\.\s*(?:getParameter|getHeader|getQueryString|getRequestURI)\s*\("
        r"|\bClass\s*\.\s*forName\s*\([^)\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*"
        r"|\bClass\s*\.\s*forName\s*\(\s*(?!['\"]|\d|[A-Z])(?=[a-z_]\w*[a-z])(?:[a-z_]\w*)"
        r"|\b[a-z_]\w*(?:\s*\.\s*[a-z_]\w*\s*\(\s*\))*\s*\.\s*(?:getMethod|getDeclaredMethod|getConstructor|getDeclaredConstructor)\s*\([^;\n]*(?:request|req)\b\s*\.\s*(?:getParameter|getHeader|getQueryString|getRequestURI)\s*\("
        r"|\b[a-z_]\w*(?:\s*\.\s*[a-z_]\w*\s*\(\s*\))*\s*\.\s*(?:getMethod|getDeclaredMethod|getConstructor|getDeclaredConstructor)\s*\([^;\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*"
        r"|\b[a-z_]\w*(?:\s*\.\s*[a-z_]\w*\s*\(\s*\))*\s*\.\s*(?:loadClass|defineClass)\s*\([^)\n]*(?:request|req)\b\s*\.\s*(?:getParameter|getHeader|getQueryString|getRequestURI)\s*\("
        r"|\b[a-z_]\w*(?:\s*\.\s*[a-z_]\w*\s*\(\s*\))*\s*\.\s*(?:loadClass|defineClass)\s*\([^)\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*"
        r"|\b[a-z_]\w*(?:\s*\.\s*[a-z_]\w*\s*\(\s*\))*\s*\.\s*(?:loadClass|defineClass)\s*\(\s*(?!['\"\d])(?=[a-z_]\w*[a-z])(?:[a-z_]\w*)"
        r")",
        "A Java reflection entry point selecting a class or member from client-controlled input — CWE-470 unsafe reflection. Class.forName, ClassLoader-family loadClass/defineClass and getMethod/getDeclaredMethod/getConstructor/getDeclaredConstructor lookups on a receiver chain (obj.getClass().getDeclaredMethod(...) included) resolve the target from a request accessor, a '+' concatenation or a bare variable: an attacker who controls the class/member name can instantiate arbitrary classes, reach internal components or invoke methods that were never meant to be client-selectable, and a bytecode-fed defineClass can load injected classes — gadget-driven RCE or privilege escalation. Keep a fixed allowlist of class/member names (never request-derived), validate input against it before any reflection call, and avoid dynamic invocations of untrusted classes; prefer switch-based dispatch over reflective lookup",
    ),
    (
        "R065-java4xx",
        "security",
        "high",
        "Java HTTP response header injected from client-controlled input: response.setHeader / addHeader / setIntHeader / setDateHeader fed a request accessor, concatenated string or bare variable (CWE-113)",
        # CWE-113 (Improper Neutralization of CRLF Sequences in HTTP Headers):
        # HttpServletResponse-family header sinks — response.setHeader /
        # addHeader / setIntHeader / setDateHeader on the response/resp/res/
        # httpResponse/httpServletResponse receivers — write user-controlled
        # bytes into an outgoing HTTP header.  When the header NAME is a
        # request accessor result (getParameter/getHeader/getQueryString/
        # getRequestURI — an attacker who picks the header name can override
        # security-relevant headers like Set-Cookie, Content-Security-Policy
        # or Location) or the VALUE is request-derived, concatenated
        # ('prefix' + lowercaseIdentifier) or a bare lowercase variable, a
        # CR/LF sequence in it splits the response and lets the attacker
        # inject arbitrary headers, poison caching or, in classic variants,
        # splice a body (response splitting).  setIntHeader/setDateHeader
        # only fire on a request-derived NAME (their values are int/long —
        # not CRLF-injectable).  The "Location" header name is excluded
        # everywhere: R060-openredir owns Location for the open-redirect
        # case, and both rules must not fire on the same line.  Literal
        # header name+value pairs ("Content-Type", "application/json"),
        # constant values (serverName, APP_VERSION, "bar" + SUFFIX),
        # static status/error/size calls (setStatus, sendError,
        # setContentType, setIntHeader("X-Limit", 100),
        # setDateHeader with a constant), header READS (getHeader) and
        # non-response receivers (wrapper/session setHeader) stay quiet.
        # Java sources are case-sensitive CamelCase, so no inline flag
        # (same convention as R053-R064).  Single-line contract.
        r"(?:"
        r"\b(?:response|resp|res|httpResponse|httpServletResponse)\s*\.\s*(?:setHeader|addHeader|setIntHeader|setDateHeader)\s*\(\s*(?:request|req)\b\s*\.\s*(?:getParameter|getHeader|getQueryString|getRequestURI)\s*\("
        r"|\b(?:response|resp|res|httpResponse|httpServletResponse)\s*\.\s*(?:setHeader|addHeader)\s*\(\s*(?![^,\n]*['\"]Location['\"])[^,\n]*,\s*(?:request|req)\b\s*\.\s*(?:getParameter|getHeader|getQueryString|getRequestURI)\s*\("
        r"|\b(?:response|resp|res|httpResponse|httpServletResponse)\s*\.\s*(?:setHeader|addHeader)\s*\(\s*(?![^,\n]*['\"]Location['\"])[^,\n]*,\s*[^,\n]*['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*"
        r"|\b(?:response|resp|res|httpResponse|httpServletResponse)\s*\.\s*(?:setHeader|addHeader)\s*\(\s*(?![^,\n]*['\"]Location['\"])[^,\n]*,\s*(?!['\"\d])(?=[a-z_]\w*[a-z])(?:[a-z_]\w*)\s*\)"
        r")",
        "A Java HTTP response header is written from client-controlled input — CWE-113 CRLF injection / response splitting. response.setHeader / addHeader / setIntHeader / setDateHeader on the HttpServletResponse with a request accessor as the header NAME (the attacker picks security-critical headers like Set-Cookie or CSP to override) or a request-derived, concatenated or bare-variable VALUE: an embedded CR/LF terminates the header early and the attacker can inject additional headers, set cookies or split the response body, undoing transport/security controls the app expects to set. Sanitize or validate any value before writing it (strip CR/LF, allowlist characters), never let the client select the header name, and set integrity headers (CSP, X-Content-Type-Options, HSTS) from server config only; treat 'Location' (redirect target — R060) separately",
    ),
    (
        "R066-javacrypto",
        "security",
        "high",
        "Java JCA getInstance literal selecting a weak or legacy algorithm (MD5, SHA-1, DES, DESede, RC4, SHA1PRNG, ECB mode): MessageDigest / Cipher / SecretKeyFactory / KeyGenerator / Mac / Signature / SecureRandom (CWE-327)",
        # CWE-327 (Use of a Broken or Risky Cryptographic Algorithm):
        # JCA algorithm selection through the FIRST quoted argument of
        # Class.getInstance("...") on a cryptographic receiver —
        # MessageDigest, Cipher, SecretKeyFactory, KeyGenerator, Mac,
        # AlgorithmParameterGenerator, Signature or SecureRandom.  A literal
        # naming a weak/legacy algorithm is flagged:
        #   MD5 (any case) — MessageDigest, "MD5withRSA" signatures,
        #     "HmacMD5" MACs, PBEWith*DES combos, PBKDF2WithHmacSHA1,
        #     the SecureRandom "MD5" self-seeding variants; deprecated/CFRG
        #     years in the recommendation track.
        #   SHA-1 / SHA1 / SHA_1 — broken since SHAttered (2017) for
        #     collision resistance; HmacSHA1 / SHA1withRSA / SHA1PRNG /
        #     PBKDF2WithHmacSHA1 all flagged.
        #   DES / DESede / 3DES / TripleDES — 56-bit key space (DES),
        #     meet-in-the-middle on EDE (3DES); only cipher-suite context.
        #   RC4 / ARC4 / ARCFOUR — broken keystream biases.
        #   SHA1PRNG — SecureRandom algorithm whose seed strength is
        #     implementation-dependent and historically weak.
        #   /ECB/ mode (ECB surrounded by '/' or ',') — leaks block
        #     structure (EBC penguin) for any cipher.
        #   PBEWith* whose inner cipher/hash is one of the weak set.
        # JCA names are case-sensitive; the common names are accepted in
        # both cases via char classes, no inline flag (R053-R065
        # convention).  The scan is anchored to the opening quote, so a
        # non-literal first argument (getInstance(variable)) and a
        # variable-derived literal stay quiet; a literal algorithm name
        # must contain the weak token to fire.  Safe algorithms stay quiet:
        # SHA-256/384/512, SHA3-*, AES/GCM or any AES mode without ECM,
        # PBKDF2WithHmacSHA256, PBEWithHmacSHA256AndAES_256, HmacSHA256,
        # SHA256withRSA / SHA384withRSA, RSA PKCS1.  Single-line contract.
        r"\b(?:MessageDigest|Cipher|SecretKeyFactory|KeyGenerator|Mac|"
        r"AlgorithmParameterGenerator|Signature|SecureRandom)\s*\.\s*"
        r"getInstance\s*\(\s*['\"]"
        r"(?=[^'\"]*?(?:"
        r"[mM][dD]5"
        r"|[sS][hH][aA][-_]?1"
        r"|DESede"
        r"|DES(?!\w)"
        r"|RC4|ARC4|ARCFOUR"
        r"|SHA1PRNG"
        r"|[/,]ECB[/,]"
        r"|PBEWith[^'\"]*?(?:[mM][dD]5|DESede|DES(?!\w)|3DES|TripleDES|RC4|ARC4|ECB)"
        r"))"
        r"[^'\"]*['\"]",
        "A Java JCA getInstance call picks a broken or legacy algorithm from a literal — CWE-327. MD5 and SHA-1 (also as HmacMD5/HmacSHA1, MD5withRSA/SHA1withRSA, PBKDF2WithHmacSHA1, SHA1PRNG) are cryptographically broken, DES/DESede/3DES and RC4/ARC4/ARCFOUR are legacy ciphers with known weaknesses, and ECB mode leaks plaintext block structure: an attacker observing ciphertext can strip/reorder blocks or exploit collision or keystream biases to forge MACs or signatures. Require an actual security review of any MD5/SHA-1/RC4/DES/3DES/ECB usage; for hashing reference integrity primitives like SHA-256 or HMAC-SHA-256, AEAD schemes like AES/GCM for encryption, PBKDF2WithHmacSHA256 / Argon2 for key derivation, and SHA256withRSA / Ed25519 for signatures — and keep algorithm names in server-side configuration, never in unattended code",
    ),
    (
        "R067-javaxss",
        "security",
        "high",
        "Java reflected/stored XSS: response body writer (response.getWriter().print/println/write/append/format/printf, bare response-writer receiver out/pw/writer/printWriter/responseWriter/outWriter .print/println/write, JSP <%= request* %> expression) fed client-controlled input (CWE-79)",
        # CWE-79 (Improper Neutralization of Input During Web Page Generation):
        # Java reflected/stored XSS.  Sinks write request-derived, concatenated
        # or bare-variable input into the HTTP response BODY:
        #   response.getWriter().print/println/write/append/format/printf(...)
        #   bare response-writer receivers — out/pw/writer/printWriter/
        #     responseWriter/outWriter .print/println/write(...)  with a
        #     (?<!System\.) guard so System.out/System.err console printing
        #     stays quiet (R036-loginj owns console log injection, and
        #     console output never reaches the HTTP client).
        #   JSP expressions <%= request|req.(getParameter|getHeader|
        #     getQueryString|getRequestURI|getAttribute)(...) %>.
        # Non-literal sources (single-line contract): a request accessor
        # (getParameter/getHeader/getQueryString/getRequestURI), a
        # 'literal' + lowercaseIdentifier concatenation, or a bare lowercase
        # variable (the (?=[a-z_]\w*[a-z]) guard keeps literals/constants out).
        # Literal output ("Hello"), constants (PAGE_CACHE, COLUMN), numeric
        # operands, non-writer receivers (helper.print), header writes
        # (setContentType/setHeader/setStatus/sendError/sendRedirect) and
        # getWriter() acquisition with no write call stay quiet.  printf/
        # format sink branches match the request-accessor or variable-arg
        # forms but not 'literal' + var (the format string is the sink).
        # Java sources are case-sensitive CamelCase, so no inline flag
        # (R053-R066 convention).  Single-line contract.
        r"(?:"
        r"\bresponse\s*\.\s*getWriter\s*\(\s*\)\s*\.\s*(?:print|println|write|append)\s*\(\s*(?:request|req)\b\s*\.\s*(?:getParameter|getHeader|getQueryString|getRequestURI)\s*\("
        r"|\bresponse\s*\.\s*getWriter\s*\(\s*\)\s*\.\s*(?:format|printf)\s*\([^)\n]*\b(?:request|req)\b\s*\.\s*(?:getParameter|getHeader|getQueryString|getRequestURI)\s*\("
        r"|\bresponse\s*\.\s*getWriter\s*\(\s*\)\s*\.\s*(?:print|println|write)\s*\([^\n]*?['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*"
        r"|\bresponse\s*\.\s*getWriter\s*\(\s*\)\s*\.\s*(?:print|println|write)\s*\(\s*(?!['\"\d])(?=[a-z_]\w*[a-z])(?:[a-z_]\w*)\s*\)"
        r"|(?<!System\.)\b(?:out|pw|writer|printWriter|responseWriter|outWriter)\s*\.\s*(?:print|println|write)\s*\(\s*(?:request|req)\b\s*\.\s*(?:getParameter|getHeader|getQueryString|getRequestURI)\s*\("
        r"|(?<!System\.)\b(?:out|pw|writer|printWriter|responseWriter|outWriter)\s*\.\s*(?:print|println|write)\s*\([^\n]*?['\"]\s*\+\s*(?!['\"\d])[a-z_]\w*"
        r"|(?<!System\.)\b(?:out|pw|writer|printWriter|responseWriter|outWriter)\s*\.\s*(?:print|println|write)\s*\(\s*(?!['\"\d])(?=[a-z_]\w*[a-z])(?:[a-z_]\w*)\s*\)"
        r"|<%=\s*(?:request|req)\b\s*\.\s*(?:getParameter|getHeader|getQueryString|getRequestURI|getAttribute)\s*\([^%]*?%>"
        r")",
        "A Java response body writer emits client-controlled bytes back to the HTTP client — CWE-79 cross-site scripting. response.getWriter().print/println/write/append/format/printf, bare response-writer receivers (out/pw/writer/printWriter/responseWriter/outWriter .print/println/write) or a JSP <%= request.* %> expression is fed a request accessor (getParameter/getHeader/getQueryString/getRequestURI), a 'prefix' + variable concatenation or a bare variable: the browser treats the echoed input as live markup/script, so a crafted parameter or header runs arbitrary JavaScript in the victim's origin (reflected or, when stored first, stored XSS) and can steal cookies/CSRF tokens or drive actions as the user. HTML-encode all dynamic output (context-aware encoding for the element/attribute/script/URL context, e.g. OWASP Java Encoder), or better render with a template engine that auto-escapes and never write request input into the body unencoded; keep data on the server side and use Content-Security-Policy to blunt the blast radius",
    ),
    (
        "R068-javarandom",
        "security",
        "high",
        "Java insecure random for a security value: java.util.Random-family PRNG (new Random(), ThreadLocalRandom, Apache Commons lang3 RandomUtils/RandomStringUtils) used to mint a password/token/secret/nonce/salt/CSRF/OTP/API key or session id (CWE-330)",
        # CWE-330 (Use of Insufficiently Random Values): a security secret
        # derived from java.util.Random / ThreadLocalRandom / Apache Commons
        # lang3 RandomUtils or RandomStringUtils is predictable.  The seeded
        # LCG (incl. the fixed-seed new Random(42) form) and the shared
        # ThreadLocalRandom PRNG recover their internal state from a few
        # observations, so an attacker replays the sequence or brute-forces
        # the sample space — forged reset/auth tokens, guessed CSRF tokens or
        # OTPs, session fixation or API-key theft.  Core Java's SecureRandom
        # (new SecureRandom(), SecureRandom.getInstanceStrong(), sr.nextBytes)
        # and UUID.randomUUID() are the SAFE alternatives and stay quiet.
        # Single-line contract: fires only when a SECURITY keyword on the
        # added line stands BEFORE a Random-family sink anywhere later on
        # that line — new (java.util.)?Random(...)  (incl. fixed seed),
        # ThreadLocalRandom (current().nextX), RandomUtils.nextToken-method,
        # RandomStringUtils.random* — the keyword names the security value
        # the PRNG result is assigned to.  Keyword matching allows simple
        # CamelCase/lowercase composite identifiers (sessionId, csrfToken,
        # authToken, apiKey, refreshToken, verifCode, passCode, nonceStr) via
        # a trailing (?:\b|(?=[a-z]*[A-Z])|(?=[a-z]+\b)) boundary.  Quiet:
        # keyword-free Random uses (rolls, sample indices, display ids,
        # logger.debug("roll="+new Random().nextInt(6))), Math.random()
        # (R043-math-random owns it in every language), staged receivers
        # (Random rnd = new Random() then rnd.nextLong() on separate added
        # lines — out of single-line scope), SecureRandom/UUID alternatives
        # and any security value that comes from a non-Random source
        # (getSecretFromVault(), saltStore.getSalt(), request input).
        # Case-sensitive CamelCase, no inline flag (R053-R067 convention).
        # Single-line contract.
        r"(?:\b(?:password|passwd|pw|token|secret|otp|nonce|salt|verif|session|csrf|jwt|pin|"
        r"api(?:[_-]?key|Key)|auth(?:[_-]?token|Token)|access(?:[_-]?token|Token)|"
        r"reset(?:[_-]?token|Token)|refresh(?:[_-]?token|Token)|pass(?:[_-]?code|Code))"
        r"(?:\b|(?=[a-z]*[A-Z])|(?=[a-z]+\b))"
        r"[^\n]*?)"
        r"(?:new\s+(?:java\.util\.)?Random\s*\(|ThreadLocalRandom\b|"
        r"RandomUtils\s*\.\s*(?:nextInt|nextLong|nextBytes|nextDouble|nextFloat)\s*\(|"
        r"RandomStringUtils\s*\.\s*random)",
        "A Java security value (password, token, secret, nonce, salt, CSRF token, OTP, API key or session id) is minted from an insecure, predictable PRNG — CWE-330. java.util.Random is a seeded LCG and ThreadLocalRandom / Apache Commons lang3 RandomUtils / RandomStringUtils recover their state from a handful of outputs, so a reset-password or access token, session id, CSRF token or OTP derived from them can be replayed, guessed or brute-forced by an attacker; even the fixed-seed form new Random(42) produces a fully predictable sequence. Replace the call with a cryptographically secure generator: new SecureRandom(), SecureRandom.getInstanceStrong() for key material, sr.nextBytes()/sr.nextInt() for nonces/salts, or UUID.randomUUID() for opaque ids; inversely, treat any security value an insecure PRNG produced as compromised and rotate it",
    ),
    (
        "R069-javacsrf",
        "security",
        "high",
        "Spring Security CSRF protection disabled: http.csrf().disable() or http.csrf(AbstractHttpConfigurer::disable / HttpSecurity::disable / csrf -> csrf.disable()) on an HttpSecurity-family receiver (http, httpSecurity, httpBuilder, httpHttp, httpConfig, httpConf, configure, security, registry, builder, config) (CWE-352)",
        # CWE-352 (Cross-Site Request Forgery): turning Spring Security's CSRF
        # token protection OFF on an HttpSecurity receiver removes the
        # synchronizer-token defense against forged state-changing requests —
        # a logged-in user's browser can be driven (auto-submitted form,
        # img/script tag, fetch with credentials, prober link) into POST/PUT/
        # DELETE mutations carrying only that user's session cookie, and the
        # app executes them as if user-intended.  Fires on the classic
        # http.csrf().disable() (deprecated but ubiquitous), the method-passed
        # http.csrf(AbstractHttpConfigurer::disable) /
        # http.csrf(HttpSecurity::disable) forms, and the lambda forms
        # http.csrf(csrf -> csrf.disable()) (incl. the block
        # http.csrf(csrf -> { csrf.disable(); })).  The receiver match is
        # prefixed by a multi-part boundary (?<![/\w'"*])(?<!/ )(?<!\* )
        # (?<!//)(?!/\*) so a string literal ("http.csrf().disable()") or
        # comment reproduction (// http.csrf().disable(), /* ... */, javadoc
        # * ...) stays quiet; getHttp().csrf().disable() is quiet (receiver
        # not a raw keyword).  Quiet forms — CSRF protection STAYS ON:
        # http.csrf().csrfTokenRepository(...) (only the token store changes),
        # http.csrf(csrf -> csrf.csrfTokenRepository(repo)) ,
        # http.csrf().ignoringAntMatchers/ignoringRequestMatchers(...)
        # (scoped exemptions), http.csrf().enable(), bare http.csrf(),
        # http.csrfTokenRepository(repo), @EnableWebSecurity (enables,
        # not disables), and unrelated .disable() calls (cors, formLogin,
        # httpBasic).  Case-sensitive CamelCase, no inline flag (R053-R068
        # convention).  Single-line contract.
        r'(?<![/\w\'"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)(?:http|httpSecurity|httpBuilder|httpHttp|httpConfig|httpConf|configure|security|registry|builder|config)\s*\.\s*csrf\s*\(\s*\)\s*\.\s*disable\s*\(\s*\)'
        r"|(?<![/\w\"'*])(?<!/ )(?<!\* )(?<!//)(?!/\*)(?:http|httpSecurity|httpBuilder|httpHttp|httpConfig|httpConf|configure|security|registry|builder|config)\s*\.\s*csrf\s*\(\s*"
        r"(?:(?:AbstractHttpConfigurer|HttpSecurity)\s*::\s*disable"
        r"|([A-Za-z_]\w*)\s*->\s*\{?\s*\1\s*\.\s*disable\s*\(\s*\)\s*[;}]?\s*\}?)"
        r"\s*\)",
        "Spring Security's CSRF filter has been switched OFF on an HttpSecurity receiver — CWE-352. Without the synchronizer-token check, Spring performs no cross-origin request forgery defense, so a victim's browser (auto-submitted form, script/img, fetch with credentials, or a pinned link) can silently replay state-changing POST/PUT/DELETE calls authenticated only by the session cookie. Remove the .disable() to keep HttpSecurity.requestMatchers(...).and().csrf() protection (Spring Boot's default) and re-train the app to emit/validate the per-session token; if a stateless API needs no 'session-fixation-style' cookie, authorize anonymous + token-authenticated access only through Spring Security's CORS, or set the exemption as narrowly as possible via http.csrf(csrf -> csrf.ignoringRequestMatchers(...)) rather than switching the whole filter off",
    ),
    (
        "R070-javacook",
        "security",
        "high",
        "Java servlet Cookie holding/linked to a session or security value created without Secure/HttpOnly protection, or those flags explicitly disabled (CWE-614 / CWE-1004)",
        # CWE-614/CWE-1004 (sensitive cookie without 'Secure' / 'HttpOnly'
        # attribute): a Servlet Cookie carrying a session id, token, secret,
        # credential or similar security value whose flags are left at
        # defaults is sent over cleartext HTTP (Cookie: JSESSIONID=...) and is
        # readable by document.cookie cross-site script — cookie links
        # the browser to the account without channel or DOM protection.
        # Fires three ways:
        #   (1) new Cookie(...) whose FIRST string argument names a security
        #       value (JSESSIONID, session/sessionid/sess/sid, token, auth,
        #       jwt, csrf/xsrf, api_key/api-key, access/refresh/id_token,
        #       secret, credential, rememberMe, principal, identity, ticket,
        #       nonce, state, userid/user_id; name literal matched
        #       case-insensitively via a scoped (?i:...) group),
        #   (2) new Cookie(...) with a generic name whose VALUE argument is a
        #       bare security-named identifier (sessionId, accessToken,
        #       csrfToken, idToken, apiKey, jwt, secret, ticket, sid...
        #       CamelCase-aware boundary; quoted literals and method-call
        #       values stay quiet),
        #   (3) an explicit flag disable on a Java identifier receiver —
        #       *Cookie*.setSecure(false) / .setHttpOnly(false) (short
        #       receivers c/ca/ck included) — protection turned OFF.
        # Each constructor form carries the name+value hardening exclusions
        # (?!(?:.*setSecure|.*setHttpOnly)\b) so a line that ALSO sends
        # Secure(true)/HttpOnly(true) on the same added line (or conversely
        # disables one flag, which Branch 3 then flags once) does not
        # double-fire.  Multi-part boundary (?<![/\w'"*])(?<!/ )(?<!\* )(?<!//)
        # keeps string-literal and comment reproductions quiet.  Quiet at the
        # call site: non-security cookies (theme/lang/track/prefs/color/page/
        # note/username), value assignment from quoted literals or method
        # calls (new Cookie("num", Integer.toString(count))), passing an
        # already-staged Cookie to response.addCookie(cookie), setMaxAge /
        # setPath / setDomain / setComment / setValue, response header writes
        # (setHeader("Set-Cookie", ...), R048-cookieset Python territory),
        # request.getCookies()[i].setSecure(true) hardening, and a variable
        # merely named cookie/String "cookie" declarations.  Case-sensitive
        # CamelCase except the scoped (?i:...) name group; no inline flag
        # (R053-R069 convention).  Single-line contract.
        r'(?:(?<![/\w\'"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)(?!(?:.*set(?:Secure|HttpOnly)\b))'
        r'\bnew\s+(?:javax\.servlet\.http\.)?Cookie\s*\('
        r'(?P<q1>["\'])\b(?i:jsessionid|session|sess|sid|token|auth|jwt|csrf|xsrf|api[_-]?key|'
        r'access[_-]?token|refresh[_-]?token|id[_-]?token|secret|credential|'
        r'rememberme|remember[_-]?me|principal|identity|ticket|nonce|state|userid|user[_-]?id)'
        r'(?:[A-Za-z0-9_-]*)?(?P=q1)'  # name-only: no value required
        r'|(?<![/\w\'"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)(?!(?:.*set(?:Secure|HttpOnly)\b))'
        r'new\s+(?:javax\.servlet\.http\.)?Cookie\s*\('
        r'(?P<q2>["\'])(?:(?:jsessionid|session|sess|sid|token|auth|jwt|csrf|xsrf|api[_-]?key|'
        r'access[_-]?token|refresh[_-]?token|id[_-]?token|secret|credential|'
        r'rememberme|remember[_-]?me|principal|identity|ticket|nonce|state|userid|user[_-]?id)(?![\w-])'
        r'|(?!jsessionid|session|sess|sid|token|auth|jwt|csrf|xsrf|api[_-]?key|'
        r'access[_-]?token|refresh[_-]?token|id[_-]?token|secret|credential|'
        r'rememberme|remember[_-]?me|principal|identity|ticket|nonce|state|userid|user[_-]?id)[^\s"/\\]){1,24}(?P=q2)'
        r'\s*,\s*(?:session(?:id)?|sess|sid|token|jwt|csrf|xsrf|auth|secret|credential|'
        r'principal|ticket|nonce|identity|user(?:[_-]?id|Id)|'
        r'api(?:[_-]?key|Key)|access(?:[_-]?token|Token)|refresh(?:[_-]?token|Token)|'
        r'id(?:[_-]?token|Token))'
        r'|(?<![A-Za-z0-9_/\'"*])(?<!/ )(?<!\* )(?<!//)'
        r'[A-Za-z_]\w*\s*\.\s*set(?:Secure|HttpOnly)\s*\(\s*false\s*\))',
        "Servlet Cookie carrying or receiving a session/security value is created without c.setSecure(true) / c.setHttpOnly(true), or the flags are explicitly disabled — CWE-614/CWE-1004. Without Secure the cookie travels in cleartext (sniffable from HttpOnly distance on the wire / MITM LAN), and without HttpOnly a successful XSS can read it via document.cookie and replay the session or token. When creating a per-session or security cookie, always set Cookie.setSecure(true) (serve it only over HTTPS) and Cookie.setHttpOnly(true) (hide it from script) on the SAME statement or immediately on the staged cookie before response.addCookie(cookie); keep setMaxAge(0)/setMaxAge(-1) for expiry, never setSecure(false)/setHttpOnly(false), and prefer short-lived, signed/opaque values (a random SessionId with secure+httponly over embedding JWTs in cookies). The flags themselves do not fix an exfiltrated token at rest — also rotate the value on logout and scope cookies by path/domain",
    ),
    (
        "R071-javatls",
        "security",
        "high",
        "Java code that disables TLS certificate or hostname verification: trust-all X509TrustManager (empty checkServerTrusted/checkClientTrusted or getAcceptedIssuers returning null/empty), HostnameVerifier.verify returning true unconditionally, setDefaultHostnameVerifier/setHostnameVerifier with a permissive verifier, HttpClientBuilder.disableHostnameVerification(), or SSLContext.init with an empty/trustAll trust anchor (CWE-295)",
        # CWE-295 (Improper Certificate Validation): TLS security decisions
        # delegated to trust-all or identity-blank code that accepts any
        # certificate and any host name, breaking the server-authentication
        # guarantee of HTTPS/TLS.  Fires on the added line, across these
        # forms:
        #   BR1  empty-body X509TrustManager overrides checkServerTrusted /
        #        checkClientTrusted (the manager accepts every chain; the
        #        body is closed immediately with nothing validated);
        #   BR2  getAcceptedIssuers returns null / new X509Certificate[0] /
        #        new X509Certificate[] {} — no trust anchor for the chain
        #        (a leading public/protected/private/final modifier is
        #        required: real TrustManager implementations are public, and
        #        the modifier puts the boundary at the '// ' prefix so
        #        comment/string-literal reproductions die on the multi-part
        #        boundary);
        #   BR3  HostnameVerifier.verify(String, SSLSession) returning true
        #        unconditionally (public/protected/private form — the bare
        #        `boolean verify(String, SSLSession)` without a modifier is
        #        left quiet so comment reproductions die on the boundary);
        #   BR4a HttpsURLConnection.setDefaultHostnameVerifier(bareIdent)
        #        (the permissive verifier becomes the JVM-wide default —
        #        null / new SecureHostnameVerifier() / a method-call arg
        #        stay quiet);
        #   BR4b anyReceiver.setHostnameVerifier(lambda -> true /
        #        { return true; } or a trust/TrustAll-named verifier
        #        variable) — getDefaultHostnameVerifier() rewiring is the
        #        safe restore and stays quiet (excluded by lookahead);
        #   BR4c anyReceiver.disableHostnameVerification() (Apache
        #        HttpClientBuilder and similar builder flavouring);
        #   BR4d okhttp builder chain .hostnameVerifier(lambda-true) on an
        #        ident chain (client.newBuilder()) or a new Constructor()
        #        receiver;
        #   BR5  sslContext-family .init(firstArg, <trust-anchor param>, ...)
        #        where the SECOND argument is empty/off: new TrustManager[0],
        #        new TrustManager[] {} or a trustAll-named array or variable,
        #        so the trust manager list carries no real anchor.
        # Real implementations stay quiet: checkServerTrusted/checkClientTrusted /
        # verify with a real body, getAcceptedIssuers with a real collection,
        # verifier.verify(...) call sites, verify(String, String) (non-SSL)
        # signatures, null / new SecureHostnameVerifier() /
        # getDefaultHostnameVerifier() wiring and lambdas comparing
        # hostname.equals(session.getPeerHost()), disableHostnameVerification()
        # call sites without the call, TrustManager[] tm / trustStoreManagers /
        # non-trustAll arrays in init, SSLContext.getInstance() /
        # System.setProperty trustStore staging, and string-literal or comment
        # reproductions (every branch carries the multi-part comment/literal
        # boundary).  No inline flag (R053-R070 convention); single-line
        # contract.
        r'(?:(?<![/\w\'"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)'
        r'(?:public|protected|private|final)\s+void\s+'
        r'check(?:Server|Client)Trusted\s*\([^)]*\)\s*'
        r'(?:throws\s+[\w.]+(?:\s*,\s*[\w.]+)*\s*)?\{\s*\})'
        r'|(?:(?<![/\w\'"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)'
        r'(?:public|protected|private|final)\s+'
        r'X509Certificate\s*\[\s*\]\s*getAcceptedIssuers\s*\([^)]*\)\s*'
        r'\{\s*return\s+(?:null|new\s+X509Certificate\s*'
        r'(?:\[\s*0\s*\]|\[\s*\]\s*\{\s*\}))\s*;)'
        r'|(?:(?<![/\w\'"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)'
        r'(?:public|protected|private)\s+boolean\s+verify\s*\('
        r'\s*String\s+\w+\s*,\s*SSLSession\s+\w+\s*\)\s*\{\s*return\s+true\s*;?\s*\})'
        r'|(?:(?<![/\w\'"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)'
        r'[A-Za-z_]\w*\s*\.\s*setDefaultHostnameVerifier\s*\('
        r'\s*(?!null\b)(?!new\s+)[A-Za-z_]\w*\s*\))'
        r'|(?:(?<![/\w\'"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)'
        r'[A-Za-z_]\w*\s*\.\s*setHostnameVerifier\s*\('
        r'(?!(?:.*get\w*DefaultHostnameVerifier\b))'
        r'(?:[^;\n]*?->\s*(?:true\b|\{\s*return\s+true\s*;?\s*\})'
        r'|trust(?:[_]?all|All)[A-Za-z0-9_]*))'
        r'|(?:(?<![/\w\'"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)'
        r'[A-Za-z_]\w*\s*\.\s*disableHostnameVerification\s*\(\))'
        r'|(?:(?<![/\w\'"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)'
        r'(?:[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*(?:\s*\(\s*\))?)*'
        r'|new\s+[\w.$]+(?:\.[A-Za-z_]\w*)*\s*\(\s*\))'
        r'\s*\.\s*hostnameVerifier\s*\('
        r'(?!(?:.*get\w*DefaultHostnameVerifier\b))'
        r'[^;\n]*?->\s*(?:true\b|\{\s*return\s+true\s*;?\s*\}))'
        r'|(?:(?<![/\w\'"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)'
        r'(?:sslContext|sslCtx|SSLContext|tlsContext)\s*\.\s*init\s*\('
        r'(?:[^,;()]*?)\s*,\s*(?:new\s+TrustManager\s*\[\s*0\s*\]'
        r'|new\s+TrustManager\s*\[\s*\]\s*\{\s*'
        r'(?:trust(?:[_]?all|All)[A-Za-z0-9_]*\s*)?\}\s*'
        r'|[^,;()]*trust(?:[_]?all|All)[A-Za-z0-9_]*(?:\s*[,}])))',
        "TLS is disabled at a layer where the app silently accepts any certificate or any host: a trust-all X509TrustManager (empty checkServerTrusted/checkClientTrusted, getAcceptedIssuers returning null/empty), a HostnameVerifier.verify that always returns true, a permissive verifier set on HttpsURLConnection (setDefaultHostnameVerifier makes it the JVM-wide default), Apache HttpClientBuilder.disableHostnameVerification(), an OkHttp hostnameVerifier(lambda -> true), or SSLContext.init with an empty TrustManager[]/trustAll anchor. An active MITM attacker can then present any certificate and any hostname and read or rewrite all traffic (logins, tokens, PII), defeating the entire purpose of TLS. Fix: use the platform trust store through the default TrustManagerFactory / KeyManagerFactory and never disable hostname verification in production connections; if a private CA must be trusted, pin its certificate or use a lean audited custom TrustManager whose checkServerTrusted actually validates chain, subject, expiry, signature and revocations and whose checkClientTrusted/verify perform real checks; prefer java.net.http.HttpClient or Apache HttpClient 5, which verify hostnames by default. Never ship a blanket trust-all manager or always-true hostname verifier; if a test/diagnostic endpoint genuinely needs one, gate it behind a non-default flag with a loud comment and CVE reference"
    ),
    (
        "R072-javaeval",
        "security",
        "high",
        "Java script engine / dynamic code evaluation fed a request-derived or otherwise non-literal code string: ScriptEngineManager engine .eval, GroovyShell/GroovyClassLoader, JShell.eval, Beanshell Interpreter, or Nashorn ScriptEngine — attacker-controlled script runs with the server JVM's privileges (CWE-94)",
        # CWE-94 (Improper Control of Generation of Code / Code Injection):
        # Java script-/code-engine sinks below compile and run the given
        # character sequence inside the server JVM, so a non-literal source
        # (request accessor, 'prefix' + lowercaseIdentifier concatenation, or
        # a bare identifier) gives the attacker arbitrary code execution with
        # the application's privileges — no sandbox by default:
        #   BR1  new GroovyShell(...).evaluate/parse
        #   BR2  new GroovyClassLoader([...]).parseClass
        #   BR3  groovy-family staged receivers (.evaluate / .parse /
        #        .parseClass)
        #   BR4  JShell.create().eval / jshell.eval
        #   BR5  new ScriptEngineManager().getEngineBy(Name|Extension|
        #        MimeType)(...)  inline  then .eval
        #   BR6  named engine receivers (scriptEngine/engine/jsEngine/
        #        nashorn/rhino/nashornEngine/groovyEngine/pythonEngine).eval
        #   BR7  new Interpreter().eval (Beanshell)
        #   BR8  interpreter.eval
        #   BR9  new NashornScriptEngineFactory().getScriptEngine().eval
        #   BR10 'literal' + var concatenation source on the engine receivers
        #        (same receiver set as BR6)
        #   BR11 conventional short staged receivers cl/gs/js/interp with
        #        eval/evaluate/parseClass/parse
        # The first argument must be non-literal: no opening quote, no
        # new/null/number, no SCREAMING_SNAKE constant, and not a
        # java.io.Reader/stream source (a wire Authorizer would never eval a
        # stream).  Every branch carries the multi-part comment/literal
        # boundary, so code-only constructions, manager acquisition,
        # getEngineBy* without .eval, setBinding/compile("") staging, string
        # literals and comment reproductions stay quiet.  Java sources are
        # case-sensitive CamelCase, so no inline flag (R053-R071
        # convention); single-line contract.
        r"(?:"
        r"(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r'(?:new\s+)GroovyShell\s*\([^)\n]*\)\s*\.\s*'
        r'(?:evaluate|parse)\s*\('
        r"(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)\s*[A-Za-z_]\w*[^)\n]*\))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r'(?:new\s+)GroovyClassLoader\s*\(\s*\)\s*\.\s*parseClass\s*\('
        r"(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)\s*[A-Za-z_]\w*[^)\n]*\))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r'\b(?:groovyShell|groovyClassLoader|gShell|grShell|groovy|sh)\b'
        r'\s*\.\s*(?:evaluate|parse(?:Class)?)\s*\('
        r"(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)\s*[A-Za-z_]\w*[^)\n]*\))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r'(?:JShell\s*\.\s*create\s*\(\s*\)|\bjshell\b)\s*\.\s*eval\s*\('
        r"(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)\s*[A-Za-z_]\w*[^)\n]*\))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r'new\s+ScriptEngineManager\s*\(\s*\)\s*\.\s*'
        r'getEngineBy(?:Name|Extension|MimeType)\s*\([^)\n]*\)\s*\.\s*eval\s*\('
        r"(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)\s*[A-Za-z_]\w*[^)\n]*\))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r'\b(?:scriptEngine|engine|jsEngine|nashorn|rhino|nashornEngine|'
        r'groovyEngine|pythonEngine)\b\s*\.\s*eval\s*\('
        r"(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)\s*[A-Za-z_]\w*[^)\n]*\))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r'(?:new\s+)Interpreter\s*\(\s*\)\s*\.\s*eval\s*\('
        r"(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)\s*[A-Za-z_]\w*[^)\n]*\))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r'\binterpreter\b\s*\.\s*eval\s*\('
        r"(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)\s*[A-Za-z_]\w*[^)\n]*\))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r'new\s+NashornScriptEngineFactory\s*\(\s*\)\s*\.\s*'
        r'getScriptEngine\s*\(\s*\)\s*\.\s*eval\s*\('
        r"(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)\s*[A-Za-z_]\w*[^)\n]*\))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r'\b(?:scriptEngine|engine|jsEngine|jshell|interpreter|groovyShell|'
        r'nashorn|nashornEngine|rhino|groovyEngine|pythonEngine|groovy)\b'
        r'\s*\.\s*(?:eval|evaluate)\s*\('
        r"[^)\n]*['\"]\s*\+\s*"
        r"(?!['\" ]|\d|[A-Z][A-Z0-9_]{2,}\b)[A-Za-z_]\w*)"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r'\b(?:cl|gs|js|interp)\b\s*\.\s*'
        r'(?:eval|evaluate|parseClass|parse)\s*\('
        r"(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)\s*[A-Za-z_]\w*[^)\n]*\))"
        r")",
        "A Java expression/script engine evaluates a non-literal code string — CWE-94 code injection. ScriptEngineManager .eval, GroovyShell/GroovyClassLoader, JShell.eval, Beanshell Interpreter and Nashorn all run the source with the server JVM's privileges (no sandbox by default), so request-derived or concatenated code gives the attacker remote code execution; fix by compiling only fixed server-side scripts (never concatenating request data), keeping engines off request paths, and if an engine is unavoidable, evaluate inside the most restrictive sandbox the engine offers with no filesystem/network permission and a minimal classloader",
    ),
    (
        "R073-javaformat",
        "security",
        "high",
        "Java format-string / printf sink fed a request-derived or otherwise non-literal format string: String.format, Formatter.format, System.out/err.printf, PrintWriter/PrintStream.printf/format, MessageFormat.format, or a 'literal prefix' + variable concatenation — attacker-controlled %-specifiers leak argument data and crash the JVM via IllegalFormatException (CWE-134)",
        # CWE-134 (Use of Externally-Controlled Format String): the format
        # argument to a printf-family sink is interpreted for %-specifiers.
        # Java keeps argument type-safety, so there is no direct %n pointer
        # walk like C, but an externally-controlled format string still
        # leaks information (%s/%h/%x print whatever objects the caller
        # passes as subsequent arguments — including credentials, tokens
        # and heap-derived values) and yields a denial of service when a
        # specifier mismatches the argument's type (IllegalFormatException).
        # The injection form is a format string that itself derives from the
        # request or is built by concatenation; a literal format string with
        # non-literal ARGUMENTS is safe and stays quiet:
        #   BR1  String.format(nonLiteralFmt, ...) / Formatter.format(nonLiteralFmt, ...)
        #   BR2  System.out/err.printf(nonLiteralFmt, ...)
        #   BR3  MessageFormat.format(nonLiteralFmt, ...)
        #   BR4  staged PrintWriter/PrintStream writers .printf/.format(nonLiteralFmt, ...)
        #   BR5  out/writer/printWriter/printStream/printer .printf/.format(nonLiteralFmt, ...)
        #   BR6  String.format("prefix " + variable, ...) — concatenated
        #        format string (literal-prefix concat source)
        # Every branch carries the multi-part comment/literal boundary and the
        # non-literal marker (no opening quote, no new/null/number, no
        # SCREAMING_SNAKE constant). The Locale-overload form
        # (printf(Locale.US, fmt, args)) puts the format string second, so a
        # Locale qualifier is consumed first and the literal check is applied
        # to the actual format argument — a literal format after Locale stays
        # quiet, and a locale-looking token cannot be misread as a format.
        # Java sources are case-sensitive CamelCase, so no inline flag
        # (R053-R072 convention); single-line contract.
        r"(?:"
        r"(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\bString\s*\.\s*format\s*\("
        r"(?:Locale\s*\.\s*[A-Za-z_][\w]*\s*(?:\([^)\n]*\))?\s*,\s*"
        r"(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)\s*[A-Za-z_]\w*"
        r"|(?!Locale\b)(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)"
        r"\s*[A-Za-z_]\w*)[^)\n]*\))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\bFormatter\s*\.\s*format\s*\("
        r"(?:Locale\s*\.\s*[A-Za-z_][\w]*\s*(?:\([^)\n]*\))?\s*,\s*"
        r"(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)\s*[A-Za-z_]\w*"
        r"|(?!Locale\b)(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)"
        r"\s*[A-Za-z_]\w*)[^)\n]*\))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\bSystem\s*\.\s*(?:out|err)\s*\.\s*printf\s*\("
        r"(?:Locale\s*\.\s*[A-Za-z_][\w]*\s*(?:\([^)\n]*\))?\s*,\s*"
        r"(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)\s*[A-Za-z_]\w*"
        r"|(?!Locale\b)(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)"
        r"\s*[A-Za-z_]\w*)[^)\n]*\))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\bMessageFormat\s*\.\s*format\s*\("
        r"(?:Locale\s*\.\s*[A-Za-z_][\w]*\s*(?:\([^)\n]*\))?\s*,\s*"
        r"(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)\s*[A-Za-z_]\w*"
        r"|(?!Locale\b)(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)"
        r"\s*[A-Za-z_]\w*)[^)\n]*\))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\b(?:out|pw|writer|printWriter|printStream|printer)\b\s*\.\s*"
        r"(?:printf|format)\s*\("
        r"(?:Locale\s*\.\s*[A-Za-z_][\w]*\s*(?:\([^)\n]*\))?\s*,\s*"
        r"(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)\s*[A-Za-z_]\w*"
        r"|(?!Locale\b)(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)"
        r"\s*[A-Za-z_]\w*)[^)\n]*\))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\bString\s*\.\s*format\s*\("
        r"[^)\n]*['\"]\s*\+\s*"
        r"(?!['\" ]|\d|[A-Z][A-Z0-9_]{2,}\b)[A-Za-z_]\w*)"
        r")",
        "A format string built from request data lets an attacker control the %-specifiers interpreted by String.format/printf: %s/%h/%x read whatever objects the code passes as arguments and a mismatched specifier kills the request with IllegalFormatException, so a format injected via request.getParameter/headers leaks argument data (credentials, tokens, PII) and denies service — CWE-134 externally-controlled format string. Fix: keep the format string a fixed compile-time literal (a \"...\" constant) and pass only runtime VALUES as arguments so input never reaches the format grammar; if a dynamic layout is truly unavoidable, parse the input against a fixed whitelist of specifiers before formatting and never let %-marking characters from the request reach the format position. Literal formats with variable arguments (String.format(\"%s\", name)) are unaffected and stay quiet",
    ),
    (
        "R074-javakeysz",
        "security",
        "high",
        "Java key/crypto parameters sized below the minimum secure threshold (RSA/DSA/DH keygen < 2048 bits, symmetric keygen < 128 bits, EC curve from the < 192-bit legacy set, small DH prime): KeyPairGenerator.initialize(n), KeyGenerator.init(n), ECGenParameterSpec / DHParameterSpec (CWE-326)",
        # CWE-326 (Inadequate Encryption Strength): JCA key/parameter sizes
        # chosen below the minimum that provides meaningful security.  The
        # scan is over a key/spec configuration verb, not an algorithm name
        # (R066-javacrypto owns weak algorithm selection): a numeric size
        # argument or explicit weak EC curve name is flagged:
        #   BR1  KeyPairGenerator.getInstance("RSA").initialize(1024) —
        #        inline chain with a < 2048-bit size (512/640/768/896/1024/
        #        1280/1536); RSA below 2048 is factorable with modern
        #        resources and 1024/512 are officially deprecated.
        #   BR2  staged keypair-generator receivers (kpg/keyPairGenerator/
        #        keyPairGen/keypairGenerator/pairGen/kpGen/rsaKeyGen/
        #        dsaKeyGen) .initialize(< 2048) — the common
        #        KeyPairGenerator kpg = ...; kpg.initialize(1024); split.
        #   BR3  KeyGenerator.getInstance("AES").init(56) — inline chain
        #        with a < 128-bit symmetric key size (56/64/80/96/112:
        #        DES-era 56, RC4-era 64-128, 80-bit WEP).
        #   BR4  staged key-generator receivers (kg/keyGenerator/keygen/
        #        symKeyGen) .init(< 128).
        #   BR5  new ECGenParameterSpec("secp160r1"/"secp192r1"/.../12X)
        #        — the standard curves below 192 bits (secp160r1/k1,
        #        secp192r1/k1, prime192v1/v2/v3, sect163r1/k1/r2); the
        #        constructor is the configuration form (a bare class-name
        #        token without `new` cannot be a config, and making `new`
        #        mandatory anchors the match on `n` so the multi-part
        #        boundary kills comment/string-literal reproductions);
        #        secp224r1 and secp256r1/384r1/521r1 are adequate and quiet.
        #   BR6  new DHParameterSpec(512, 2) — Diffie-Hellman prime smaller
        #        than 2048 bits is vulnerable to the Logjam attack's 512-bit
        #        precomputation tier (1024-bit needs only nation-state
        #        effort and is deprecated).
        # Every branch carries the multi-part comment/literal boundary and a
        # literal-size/name contract: a non-literal size argument
        # (kpg.initialize(variable)), an adequate size (2048/3072/4096,
        # 128/192/256), a non-config receiver hit on init/initialize
        # (config.init, registry.initialize) and bare declarations stay
        # quiet. Java sources are case-sensitive CamelCase, so no inline
        # flag (R053-R073 convention); single-line contract.
        r"(?:"
        r"(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\bKeyPairGenerator\s*\.\s*getInstance\s*\([^)\n]*\)\s*\.\s*"
        r"initialize\s*\(\s*(?:512|640|768|896|1024|1280|1536)\s*(?:,|\)))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\b(?:kpg|keyPairGenerator|keyPairGen|keypairGenerator|"
        r"pairGen|kpGen|rsaKeyGen|dsaKeyGen)\b\s*\.\s*initialize\s*\(\s*"
        r"(?:512|640|768|896|1024|1280|1536)\s*(?:,|\)))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\bKeyGenerator\s*\.\s*getInstance\s*\([^)\n]*\)\s*\.\s*"
        r"init\s*\(\s*(?:56|64|80|96|112)\s*(?:,|\)))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\b(?:kg|keyGenerator|keygen|symKeyGen)\b\s*\.\s*init\s*\(\s*"
        r"(?:56|64|80|96|112)\s*(?:,|\)))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\bnew\s+ECGenParameterSpec\s*\(\s*['\"]"
        r"(?:secp160r1|secp160k1|secp192r1|secp192k1|prime192v1|prime192v2|"
        r"prime192v3|sect163r1|sect163k1|sect163r2)['\"]\s*\))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\bnew\s+DHParameterSpec\s*\(\s*(?:512|640|768|896|1024|1280|1536)"
        r"\s*(?:,|\)))"
        r")",
        "A Java key/crypto size picked below the secure minimum — CWE-326 inadequate encryption strength: RSA/DSA/DH key pairs smaller than 2048 bits (KeyPairGenerator .initialize(512/1024/1536)), symmetric keys smaller than 128 bits (KeyGenerator .init(56/64/80/96/112)), EC curves from the obsolete < 192-bit standard family (new ECGenParameterSpec(\"secp160r1\"/\"secp192r1\"/...) — 160/192-bit ECDLP is solvable with commodity hardware) and Diffie-Hellman primes under 2048 bits (new DHParameterSpec(512, 2): the Logjam attack precomputed the 512-bit tier and 1024-bit needs only large state actor effort) give an attacker a practical factoring/ECDLP/relogging break, so key material or TLS/DH handshakes built on them can be decrypted or forged. Fix: use >= 2048-bit RSA/DSA/DH (or 3072 for higher assurance), >= 128-bit symmetric keys (AES-128/192/256), and current standard curves (secp256r1/384r1/521r1) — or better, let the TLS/library defaults choose parameters; sizes below these bounds should be rejected at configuration review. Adequate sizes and non-literal size variables stay quiet",
    ),
    (
        "R075-jvachttp",
        "security",
        "medium",
        "Java network/HTTP client or JNDI configuration built on a cleartext scheme literal (http:///ws:///ftp:// in URL/URI construction or request verbs, ldap:// in provider URLs): new URL/URI.create, RestTemplate/WebClient/HttpClient verbs, OkHttp/HttpUrl builders (CWE-319)",
        # CWE-319 (Cleartext Transmission of Sensitive Information): a URL
        # literal that starts with a cleartext scheme at a Java network/
        # HTTP-client sink hands credentials, cookies or body data to a
        # passive eavesdropper. R057-ssrf owns request-derived (non-literal)
        # URL targets; R071-javatls owns TLS-verification-disabled calls; this
        # rule scans only literal cleartext scheme strings at these sinks:
        #   BR1  new URL(\"http://...\") / new URI(\"http://...\") /
        #        URI.create(\"http://...\") with a literal cleartext scheme
        #        (http, ws, ftp — case-insensitive scheme token, scoped so
        #        the Java CamelCase receiver stays case-sensitive).
        #   BR2  Spring RestTemplate-family receivers
        #        (restTemplate/rest/webClient/httpClient/client) calling
        #        getForObject/getForEntity/postForEntity/patchForObject/put/
        #        delete/exchange/execute with a cleartext literal URL; the
        #        exchange/execute verbs on a bare `client` receiver also
        #        match JDBC/persistence hands like client.execute(sql) by
        #        design — those stay quiet because their first argument is
        #        not a scheme:// literal (\"SELECT \"/sql variable).
        #   BR3  WebClient fluent chains .get()/.post()/...() .uri(\"http://\")
        #        — the request-level uri() overload with a cleartext literal.
        #   BR4  OkHttp/HttpUrl builders: new Request.Builder().url(\"http://\"),
        #        receiver.url(...) on request builders/connections,
        #        HttpUrl.parse(\"http://...\").
        #   BR5  JNDI cleartext LDAP: env.put(Context.PROVIDER_URL ...) /
        #        env.put(\"java.naming.provider.url\", \"ldap://...\") /
        #        env.put(\"java.naming.security.authentication\", \"ldap://...\")
        #        and new InitialDirContext(new InitialContext(...)) ctors
        #        with a literal ldap:// value — LDAP binds/greets in clear.
        # Every branch carries the multi-part comment/literal boundary and a
        # literal-scheme contract: https/wss/ftps/ldaps (TLS) stay quiet,
        # non-literal targets (variables, concatenations, request headers —
        # R057/R060's domain) and unrelated receivers stay quiet, and
        # comment/string-literal reproductions die on the boundary. Java
        # sources are case-sensitive CamelCase, so the (?i:...) translation
        # is scoped to the scheme token only (R053-R074 convention);
        # single-line contract.
        r"(?:"
        r"(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\b(?:new\s+(?:URL|URI)|URI\s*\.\s*create)\s*\(\s*['\"]"
        r"(?i:http|ws|ftp)://)"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\b(?:restTemplate|rest|webClient|httpClient|client)\s*\.\s*"
        r"(?:getForObject|getForEntity|postForObject|postForEntity|"
        r"patchForObject|put|delete|exchange|execute)\s*\(\s*['\"]"
        r"(?i:http|ws|ftp)://)"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\bwebClient\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*\)"
        r"\s*\.\s*uri\s*\(\s*['\"]"
        r"(?i:http|ws|ftp)://)"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\b(?:new\s+Request\s*\.\s*Builder\s*\([^\n]*?\.url|"
        r"\b(?:reqBuilder|requestBuilder|okHttpRequest|httpConn|connection)"
        r"\s*\.\s*url|HttpUrl\s*\.\s*parse)\s*\(\s*['\"]"
        r"(?i:http|ws|ftp)://)"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\b\w+\.put\s*\(\s*(?:Context\.PROVIDER_URL|['\"](?:"
        r"java\.naming\.provider\.url|java\.naming\.security\.authentication)"
        r"['\"])\s*,\s*['\"]"
        r"(?i:ldap)://)"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\bnew\s+(?:InitialDirContext|InitialContext)\s*\([^\n]*?['\"]"
        r"(?i:ldap)://)"
        r")",
        "A Java network/HTTP call or JNDI binding pinned to a cleartext scheme literal — CWE-319 cleartext transmission: new URL/URI or URI.create with \"http://\" (or ws:///ftp://), a RestTemplate/WebClient/HttpClient request verb handed a cleartext literal URL, an OkHttp/HttpUrl builder .url(\"http://\")/HttpUrl.parse, or an LDAP provider configured with \"ldap://\" (Context.PROVIDER_URL / java.naming.provider.url / InitialDirContext ctor) sends the payload, cookies or LDAP bind credentials in the clear, so any attacker on the path can read or tamper with it. Fix: use the TLS variants — https:// / wss:// / ftps:// and ldaps:// (or STARTTLS for LDAP), and load URLs from config/request only through vetted channels (a request-derived target is R057's domain); cleartext schemes should be rejected at configuration review. TLS-scheme or non-literal targets and unrelated receivers stay quiet",
    ),
    (
        "R076-javaredos",
        "security",
        "high",
        "Java regex-compilation sink (Pattern.compile / Pattern.matches / String.matches / split / replaceAll / replaceFirst) fed a non-literal pattern variable or concatenation — a request-derived pattern in a Java regex sink is catastrophic/ReDoS and regex-injection (CWE-1333)",
        # CWE-1333 (Inefficient Regular Expression Complexity): Java regex
        # sinks take the pattern as their FIRST argument, and a non-literal
        # pattern fed from a variable, concatenation or request parameter is
        # attacker-tunable: a crafted pattern like "(a+)+$" makes
        # backtracking machines on such input take exponential time (ReDoS)
        # and a malicious pattern can match/`split`/replace far more than the
        # caller intended (regex injection). R034-redos owns Python re.* and
        # JS RegExp sinks; this is the Java gap. Branches:
        #   BR1  Pattern.compile(non-literal) — the static compile sink.
        #   BR2  Pattern.matches(non-literal, input) — static matcher.
        #   BR3  Pattern.compile(\"literal\" + nonLiteral + ...) — a literal
        #        prefix/regex concatenated with a variable (only this sink
        #        form: R051-R074 convention finds the same shape in
        #        String.format / SQL); a quote preceded by \\Q is Java's
        #        manual literal-quoting opener (Pattern.quote is the
        #        API-form, handled by NLARG) and stays quiet.
        #   BR4  String.matches(non-literal) on any receiver chain
        #        (email.matches(badPattern), input.matches(param)) — the
        #        `(?!Pattern\\b)` guard keeps Pattern.matches static calls
        #        owned by BR2.
        #   BR5  String.split(non-literal[, limit]) — delimiter from a
        #        variable/parameter is an injection + ReDoS vector.
        #   BR6  String.replaceAll / replaceFirst(non-literal, repl) —
        #        same pattern-source risk.
        # NLARG (the non-literal argument marker shared with the R072/R073
        # Java series) rejects quoted literals, `new`-expressions, null,
        # numbers and SCREAMING_SNAKE constants, and the safe
        # Pattern.quote(userInput) / replaceAll(Pattern.quote(tok))
        # literal-escape idiom stays quiet. Every branch carries the
        # multi-part comment/literal boundary so comment/string-literal
        # reproductions die on it; literal patterns in every sink form,
        # constant delimiters, argless non-sink calls (matcher.matches(),
        # object.split(), Path.of, indexOf), and unrelated receivers stay
        # quiet. Java sources are case-sensitive (no inline flag);
        # single-line contract.
        r"(?:"
        r"(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\bPattern\s*\.\s*compile\s*\(\s*"
        r"(?!Pattern\s*\.\s*quote\b)(?!['\" ]|new\b|null\b|\d|"
        r"[A-Z][A-Z0-9_]{2,}\b)\s*[A-Za-z_]\w*)"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\bPattern\s*\.\s*matches\s*\(\s*"
        r"(?!Pattern\s*\.\s*quote\b)(?!['\" ]|new\b|null\b|\d|"
        r"[A-Z][A-Z0-9_]{2,}\b)\s*[A-Za-z_]\w*)"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\bPattern\s*\.\s*compile\s*\([^)\n]*(?<![\\]Q)['\"]\s*\+\s*"
        r"(?!['\" ]|\d|[A-Z][A-Z0-9_]{2,}\b)\s*[A-Za-z_]\w*)"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\b(?!Pattern\b)(?:[A-Za-z_]\w*(?:\s*\([^)\n]*\))?\s*\.\s*)+"
        r"matches\s*\(\s*"
        r"(?!Pattern\s*\.\s*quote\b)(?!['\" ]|new\b|null\b|\d|"
        r"[A-Z][A-Z0-9_]{2,}\b)\s*[A-Za-z_]\w*)"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\b(?:[A-Za-z_]\w*(?:\s*\([^)\n]*\))?\s*\.\s*)+"
        r"split\s*\(\s*"
        r"(?!Pattern\s*\.\s*quote\b)(?!['\" ]|new\b|null\b|\d|"
        r"[A-Z][A-Z0-9_]{2,}\b)\s*[A-Za-z_]\w*)"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\b(?:[A-Za-z_]\w*(?:\s*\([^)\n]*\))?\s*\.\s*)+"
        r"(?:replaceAll|replaceFirst)\s*\(\s*"
        r"(?!Pattern\s*\.\s*quote\b)(?!['\" ]|new\b|null\b|\d|"
        r"[A-Z][A-Z0-9_]{2,}\b)\s*[A-Za-z_]\w*)"
        r")",
        "A Java regex-compilation sink is fed a non-literal pattern — CWE-1333 ReDoS / regex injection: Pattern.compile / Pattern.matches / String.matches / split / replaceAll / replaceFirst whose pattern argument is a variable, request parameter, builder or concatenation, so the caller's data shapes the regex. An attacker-controllable pattern like \"(a+)+$\" against adversarial input makes Java's backtracking regex engine take exponential time (ReDoS, a CPU-exhaustion DoS) and can match/split/replace far beyond the intended literal, so untrusted data must never reach a regex engine as a pattern. Fix: compile only fixed, reviewed pattern literals (or constants), and when a user-supplied string must be matched literally escape it with Pattern.quote(...) so it is treated as text, not syntax. Literal patterns, SCREAMING_SNAKE constants, the Pattern.quote escape idiom, argless non-regex sink calls and comment/string-literal reproductions stay quiet",
    ),
    (
        "R077-javajson",
        "security",
        "high",
        "Java JSON-lib deserialization sink (fastjson parseObject / Jackson readValue polymorphic) fed a non-literal payload",
        # CWE-502 (Deserialization of Untrusted Data): the JSON deserializer
        # gap left by R054-javadeser, which owns only ObjectInputStream /
        # XMLDecoder sinks. fastjson's JSON.parseObject with no explicit class
        # (or a generic/Object target) applies polymorphic autoType and can
        # instantiate arbitrary gadget classes straight from the "@type"
        # property a request can set — fastjson's autoType has been bypassed
        # repeatedly even with an explicit Class argument, so the official
        # guidance is to never parse untrusted data with parseObject at all.
        # Jackson's ObjectMapper is safe by default, but a single-argument
        # readValue (requires enableDefaultTyping to be meaningful, which is
        # configured elsewhere) and readValue(payload, Object.class) /
        # readValue(payload, new TypeReference<...>() {}) deserialize into an
        # attacker-influenced/polymorphic type and are the classic Jackson
        # gadget-chain line (CVE-2017-17485 & friends). Branches:
        #   BR1  JSON(.Object).parseObject(non-literal[, class]) — fastjson
        #        autoType: any non-literal first argument (variable, request
        #        accessor, builder concat) is flagged, explicit-Class calls
        #        included per the fastjson advisory (bypass history).
        #   BR2  parseObject("literal..." + nonLiteral + ...) — a literal
        #        JSON prefix concatenated with a variable; same shape as
        #        R076 BR3's Pattern.compile concat sink.
        #   BR3  readValue(non-literal) — Jackson single-arg deserialization
        #        into a runtime type; a bare variable or factory call.
        #   BR4  readValue(non-literal, Object.class) — polymorphic target.
        #   BR5  readValue(non-literal, (new )?TypeReference) — a raw/bare
        #        TypeReference target (TypeReference.INSTANCE, a raw
        #        `new TypeReference() {}` gradle, a bare constant): the
        #        target type is unknown/runtime. The typed-safe concrete
        #        idiom readValue(json, new TypeReference<List<User>>() {})
        #        stays quiet, as do readValue(json, User.class) reads
        #        (no default typing), JSON.parse / JSON.parseArray (JS JSON
        #        collision / list-only), JSON.toJSONString serialization,
        #        readTree, enableDefaultTyping config lines, declarations,
        #        and comment / string-literal reproductions (multi-part
        #        boundary). Java sources are case-sensitive CamelCase, so no
        #        inline flag; single-line contract.
        r"(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\bJSON(?:Object)?\s*\.\s*parseObject\s*\(\s*"
        r"(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)[a-z]\w*)"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\bJSON(?:Object)?\s*\.\s*parseObject\s*\([^)\n]*"
        r"(?<![\\]Q)['\"]\s*\+\s*"
        r"(?!['\" ]|\d|[A-Z][A-Z0-9_]{2,}\b)\s*[A-Za-z_]\w*)"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\b(?:[A-Za-z_]\w*(?:\s*\([^)\n]*\))?\s*\.\s*)+"
        r"readValue\s*\(\s*"
        r"(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)[a-z]\w*"
        r"(?:\(\s*[^)\n]*\)\s*)?\))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\b(?:[A-Za-z_]\w*(?:\s*\([^)\n]*\))?\s*\.\s*)+"
        r"readValue\s*\(\s*"
        r"(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)[a-z]\w*"
        r"\s*,\s*Object\s*\.\s*class\b)"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\b(?:[A-Za-z_]\w*(?:\s*\([^)\n]*\))?\s*\.\s*)+"
        r"readValue\s*\(\s*"
        r"(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)[a-z]\w*"
        r"\s*,\s*(?:new\s+)?TypeReference\b(?!\s*<))",
        "A Java JSON deserializer is fed a non-literal payload — CWE-502 unsafe deserialization: fastjson JSON.parseObject (autoType honors the request-set '@type' property and instantiates attacker-chosen gadget classes, RCE-prone and repeatedly bypassed even with an explicit class) and Jackson ObjectMapper single-argument readValue / readValue(payload, Object.class) / readValue(payload, raw TypeReference), which deserialize into a polymorphic or runtime target type and are the classic Jackson gadget lines (CVE-2017-17485 et al). Untrusted JSON must be rejected at the boundary or parsed with a fixed, safe schema/format; fastjson should never parse request data, and Jackson should parse into a concrete allow-listed type with default typing disabled. Typed-safe Jackson reads (readValue(json, User.class), readValue(json, new TypeReference<List<User>>() {})), JSON.toJSONString, readTree, declarations and comment/string-literal reproductions stay quiet",
    ),
    (
        "R078-javatpl",
        "security",
        "high",
        "Java server-side template engine fed a non-literal template source/name (Velocity / Freemarker / Thymeleaf)",
        # CWE-1336 (Improper Neutralization of Special Elements used in a
        # Template Engine): the Java sibling of R022-ssti (which owns the
        # Python render_template_string / jinja2 Template sinks).  A
        # template's markup string is code: when a request-derived value is
        # concatenated into (or used as) the template text, the user can
        # inject Velocity directives (#set/$class.inspect()), Freemarker
        # interpolations (${...} with T()/new()/exec()) or even trigger the
        # template engine itself (Thymeleaf's __${...}__::.x preprocessing)
        # for RCE.  Branches (single-line; Java sources case-sensitive, no
        # inline flag):
        #   BR1  Velocity/velocityEngine .evaluate(ctx, out, logTag, src)
        #        — the template is the FOURTH argument, after the context /
        #        writer / log-tag, so (?:[^,\n]*? ,){3} skips the first three.
        #   BR2  BR1's literal-prefix + variable concat template.
        #   BR3  Freemarker new Template(name, src, cfg) — the 2nd argument
        #        is the markup: a non-literal source directly, or wrapped in
        #        new StringReader(...) (StreamReader idiom).  Reader/file
        #        loading stays with other idioms.
        #   BR4  BR3's concat.  BR5  cfg/configuration/freemarkerConfig
        #        .getTemplate(non-literal) — a user-derived template NAME
        #        (Freemarker resolves ${...} in loaded templates; a name an
        #        attacker can steer is the Thymeleaf-style name vector).
        #   BR6  TemplateEngine / templateEngine / thymeleafEngine /
        #        templateParser .process(non-literal[, context]) — Thymeleaf
        #        and friends render the first argument as markup
        #        (__${...}__::.x preprocessing RCE).
        # NLARG (the shared non-literal marker) rejects quoted literals,
        # new-expressions, null, numbers and SCREAMING_SNAKE constants, and
        # every branch carries the multi-part comment/literal boundary.  All-
        # literal templates in every sink form (Velocity.evaluate("Hello
        # $name"), new Template("index", "Hi ${user}", cfg),
        # cfg.getTemplate("index.ftl"), templateEngine.process("index",
        # ctx)), constant names/sources, the safe render step on an existing
        # Template variable (template.process(model, out)), unrelated
        # receivers (engine.process, setTemplate(...)), an ANTLR
        # StringTemplate construction, and comment/string-literal
        # reproductions stay quiet.
        r"(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\b(?:Velocity|velocityEngine)\s*\.\s*evaluate\s*\((?:[^,\n]*?\s*,\s*){3}"
        r"(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)[A-Za-z_]\w*[^)\n]*\))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\b(?:Velocity|velocityEngine)\s*\.\s*evaluate\s*\((?:[^,\n]*?\s*,\s*){3}"
        r"['\"][^)\n]*?['\"]\s*\+\s*"
        r"(?!['\" ]|\d|[A-Z][A-Z0-9_]{2,}\b)[A-Za-z_]\w*[^)\n]*\))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\bnew\s+Template\s*\(\s*[^,\n]*?\s*,\s*"
        r"(?:(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)[A-Za-z_]\w*[^)\n]*"
        r"|new\s+StringReader\s*\(\s*(?!['\" ]|new\b|null\b|\d|"
        r"[A-Z][A-Z0-9_]{2,}\b)[A-Za-z_]\w*[^)\n]*\)\s*))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\bnew\s+Template\s*\(\s*[^,\n]*?\s*,\s*['\"][^)\n]*?['\"]\s*\+\s*"
        r"(?!['\" ]|\d|[A-Z][A-Z0-9_]{2,}\b)[A-Za-z_]\w*[^)\n]*\))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\b(?:cfg|configuration|freemarkerConfig)\s*\.\s*getTemplate\s*\(\s*"
        r"(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)[A-Za-z_]\w*[^)\n]*\))"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"(?:(?:new\s+TemplateEngine\s*\([^)\n]*\)\s*\.\s*)|"
        r"\b(?:templateEngine|thymeleafEngine|templateParser)\b\s*\.\s*)"
        r"process\s*\(\s*"
        r"(?:(?!['\" ]|new\b|null\b|\d|[A-Z][A-Z0-9_]{2,}\b)[A-Za-z_]\w*[^)\n]*"
        r"|['\"][^)\n]*?['\"]\s*\+\s*"
        r"(?!['\" ]|\d|[A-Z][A-Z0-9_]{2,}\b)[A-Za-z_]\w*[^)\n]*)"
        r"\))",
        "A Java server-side template engine is fed a non-literal template source or name — CWE-1336 server-side template injection: Velocity.evaluate (4th arg), Freemarker new Template(name, src, cfg) / new StringReader(src) / configuration.getTemplate(name), and TemplateEngine.process(template, context) treat the markup string as code, so a request-influenced template can run Velocity directives, Freemarker ${...} interpolations or Thymeleaf __${...}__::.x preprocessing for remote code execution. Keep template markup in reviewed server-side files/constants only, never build it from request data; if user content must appear in a rendered page, pass it as a data-model value (Freemarker ${user!} / Velocity $user output-escaping) so it is data, not syntax. Literal templates, SCREAMING_SNAKE sources/names, the safe template.process(data, out) render step, unrelated receivers and comment/string-literal reproductions stay quiet",
    ),
    (
        "R079-javacors",
        "security",
        "high",
        "Java CORS configuration or header set to the '*' wildcard origin (Spring @CrossOrigin / CorsRegistry / CorsConfiguration / Jetty CorsFilter) — CWE-942",
        # CWE-942 (Permissive Cross-domain Policy with Untrusted Domains): the
        # Access-Control-Allow-Origin wildcard lets ANY origin read the
        # response, so authenticated data is exposed to a script running on
        # an attacker page (and breaks cookies entirely when combined with
        # allowCredentials).  The generic R007-cors only notices the
        # Access-Control-Allow-Origin token in any context; this rule
        # pinpoints the actual permissive Java sinks.  Branches (Java
        # sources, case-sensitive, single-line):
        #   BR1  Spring @CrossOrigin annotation (keyword/value/array form)
        #        with a "*" origin/pattern.
        #   BR2  CorsRegistry chain: registry.addMapping("/**").
        #        allowedOrigins("*") / allowedOriginPatterns("*").
        #   BR3  CorsConfiguration: config.setAllowedOrigins(...) /
        #        setAllowedOriginPatterns(...) fed a "*" through
        #        singleton/singletonList/asList/List.of/Set.of.
        #   BR4  addAllowedOrigin("*") (Jetty CorsFilter configuration
        #        store, org.apache.catalina quirks).
        #   BR5  response.set/addHeader("Access-Control-Allow-Origin", "*").
        # Every branch wears the multi-part comment/literal boundary.  An
        # explicit origin allow-list ("https://app.example.com", a
        # SCREAMING_SNAKE constant), the getter getCorsOrigins()/others,
        # unrelated setHeader calls, and comment/string-literal
        # reproductions stay quiet.
        r"(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"@CrossOrigin\s*\([^)\n]*[\"']\*[\"'])"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\b[a-z_]\w*\s*\.\s*(?:addMapping\s*\([^)\n]*\)\s*\.\s*)?"
        r"(?:allowedOrigins|allowedOriginPatterns)\s*\(\s*[\"']\*[\"'])"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\b[a-z_]\w*\s*\.\s*(?:setAllowedOrigins|setAllowedOriginPatterns)"
        r"\s*\(\s*(?:(?:Collections|Arrays)\s*\.\s*|(?:List|Set)\s*\.\s*)?"
        r"(?:singletonList|asList|of|singleton)\s*\(\s*[\"']\*[\"'])"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\b[a-z_]\w*\s*\.\s*addAllowedOrigin\s*\(\s*[\"']\*[\"'])"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\b(?:response|resp)\w*\s*\.\s*(?:set|add)Header\s*\(\s*"
        r"[\"']Access-Control-Allow-Origin[\"']\s*,\s*[\"']\*[\"'])",
        "A Java CORS policy or header allows any origin — CWE-942 permissive cross-domain policy: @CrossOrigin(origins = \"*\"), registry.addMapping(\"/**\").allowedOrigins(\"*\"), config.setAllowedOrigins(Collections.singletonList(\"*\")), Jetty addAllowedOrigin(\"*\") or response.setHeader(\"Access-Control-Allow-Origin\", \"*\") let an attacker-hosted page fetch authenticated responses, turning the API into a cross-origin CSRF/exfiltration channel (and a wildcard alongside allowCredentials is silently invalid). Configure an explicit allow-list of trusted origins instead, echo the request's Origin only after verification, and never combine permissive origins with credentials. Explicit-origin allow-lists, constant origins, getters, unrelated header writes and comment/string-literal reproductions stay quiet",
    ),
    (
        "R080-javajwt",
        "security",
        "high",
        "Java JWT parser accepts unsigned/alg=none tokens or verifies with an impossible key (jjwt/Nimbus/Spring) — CWE-347",
        # CWE-347 (Improper Verification of Cryptographic Signature): a JWT is
        # only as strong as the parser's signature verification, so sinks that
        # disable or weaken it let an attacker forge admin/session tokens.
        # R024-jwt already covers the Python jwt library; this rule pins the
        # common Java stacks (jjwt, Nimbus JOSE, Spring Security).  Branches
        # (Java sources, case-sensitive, single-line):
        #   BR1  jjwt 0.12+ explicit unsecured parsing:
        #        Jwts.parser().parseUnsecuredContent(...) and the
        #        UnsecuredJwtParser escape hatch .unsecured().allowUnsecured(...)
        #        skip signature verification entirely.
        #   BR2  Legacy jjwt parsers told to verify with a key that cannot
        #        work: setSigningKey(null | "" | new byte[0]).
        #   BR3  The "none" algorithm constant, the crux of alg-confusion /
        #        unsigned tokens: SignatureAlgorithm.NONE (jjwt) and
        #        JWSAlgorithm.NONE (Nimbus) inside signWith/selectors/configs.
        #   BR4  Spring Security's decoder for unsigned tokens: JwtDecoders.none().
        # Every branch wears the multi-part comment/literal boundary.  Verified
        # chains (verifyWith(...).build().parseSignedClaims, setSigningKey with a
        # runtime key), issuer decoders (fromIssuerLocation/fromOidcIssuerLocation),
        # strong-algorithm constants (HS256/RS256), signing-only code, and
        # comment/string-literal reproductions stay quiet.
        r"(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"(?:parseUnsecuredContent|allowUnsecured)\s*\()"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"\.setSigningKey\s*\(\s*(?:null\b|[\"'][\"']|(?:new\s+)?byte\s*\[\s*0\s*\]))"

        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"(?:JWSAlgorithm|SignatureAlgorithm)\s*[.]\s*NONE\b)"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"JwtDecoders\s*[.]\s*none\s*\()",
        "A Java JWT parser accepts unsigned or attacker-chosen tokens — CWE-347 improper verification of cryptographic signature: jjwt's Jwts.parser().parseUnsecuredContent(...) / .unsecured().allowUnsecured(...) skip verification entirely, a legacy Jwts.parser().setSigningKey(null | \"\" | new byte[0]) asks a key-based parser to verify with a key that cannot exist, SignatureAlgorithm.NONE / JWSAlgorithm.NONE admit the 'none'/unsigned algorithm (alg-confusion), and JwtDecoders.none() decodes unsigned tokens. A forged admin token for any of these is then trusted as genuine. Always verify with a strong key from a secret store (jjwt 0.12+ .verifyWith(SecretKey).build().parseSignedClaims, legacy setSigningKey(runtimeKey)), reject the 'none' algorithm (jjwt 0.12 Configuration rejects it by default; keep a strict algorithm allow-list for Nimbus JWSVerificationKeySelector), and decode only issuer-verified signed tokens (JwtDecoders.fromIssuerLocation(...)). Verified chains with runtime keys, issuer-based decoders, strong-algorithm constants, signing-only code and comment/string-literal reproductions stay quiet",
    ),
    (
        "R081-javapw",
        "security",
        "high",
        "Java password store uses a plaintext/no-op or weak non-adaptive hashing scheme (Spring NoOpPasswordEncoder / {noop} / MessageDigestPasswordEncoder / LdapShaPasswordEncoder) — CWE-916",
        r"(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"NoOpPasswordEncoder\s*[.]\s*getInstance\s*\()"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"[\"']\{noop\}[^\"'\n]*[\"']\s*\+)"
        r"|(?:(?<![/\w'\"*])(?<!/ )(?<!\* )(?<!//)(?!/\*)"
        r"new\s+(?:MessageDigestPasswordEncoder|LdapShaPasswordEncoder|StandardPasswordEncoder)\s*\()",
        "A Java password store is coupled to a plaintext/no-op or weak non-adaptive hashing scheme — CWE-916 insufficient computational effort in password hashing: Spring Security's NoOpPasswordEncoder.getInstance() performs no hashing at all (the credential is kept verbatim), a stored value carrying the {noop} delegating prefix is treated as plaintext (DelegatingPasswordEncoder migration markers must never reach a live store), and the deprecated MessageDigestPasswordEncoder / LdapShaPasswordEncoder / StandardPasswordEncoder stretch nothing — they apply fast MD5/SHA digests a GPU can race through. A database leak then exposes every account credential verbatim or near-verbatim. Always store via an adaptive KDF with heavy work factors — BCryptPasswordEncoder (strength >= 10) or Argon2PasswordEncoder / Pbkdf2PasswordEncoder / SCryptPasswordEncoder, all from spring-security-crypto — and migrate legacy {noop}/{md5} hashes to a real scheme before shipping. Adaptive encoders, the delegating factory, digest-utility calls, and comment/string-literal reproductions of the weak marker names stay quiet",
    ),
    # ---- data -----------------------------------------------------
    (
        "D001",
        "data",
        "low",
        "New PII field added to model/schema",
        r"(?i)\b(?:email|phone|ssn|passport|address|credit_card|card_number|birth[_-]?date|health[_-]?data)\b|"
        # snake_case suffix form: user_email / customer_phone / shipping_address …
        # must be followed by a field-context assignment, colon or EOL so function
        # names like send_email(...) stay quiet.
        r"_(?:email|phone|ssn|passport|address|credit_card|card_number|birth[_-]?date|health[_-]?data)"
        r"\b(?=\s*(?:=|:)|$)",
    ),
    (
        "D002-db",
        "data",
        "medium",
        "Database schema / migration change",
        r"(?i)\b(?:create_table|add_column|migration|ALTER\s+TABLE|DROP\s+TABLE|add_foreign_key)\b|"
        # SQL DDL keyword form:  CREATE TABLE users ( … )  /  CREATE TABLE IF NOT EXISTS …
        # Indexes stay quiet — additive and non-destructive.
        r"\bCREATE\s+TABLE\b",
    ),
    (
        "D003",
        "data",
        "medium",
        "Sensitive data logged / printed",
        r"(?i)\b(?:logger|log|logging?\.)?\.?(?:debug|info|warning|error)\(\s*(?:f[\'\"])?[^\n]*?(?:password|token|secret|api_key|credit_card)\w*|"
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
        r"(?i)\bexcept\s+[^\n:]*?:\s*(?:pass|return\s+None)\b|"
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
        r"\b(?:return|raise).{0,40}\b(?:404|403|500|502)\b|"
        # HTTPError-style exception names (raise Http404 / raise errors.NotFound? no:
        # must carry the numeric code so generic exceptions stay quiet) and Flask
        # abort(404) shortcuts.
        r"\braise\s+[\w.]*(?:404|403|500|502)\b|"
        r"\babort\s*\(\s*(?:404|403|500|502)\s*\)",
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
