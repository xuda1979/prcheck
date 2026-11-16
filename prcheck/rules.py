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
        r"(?i)\b(?:eval|exec|compile)\s*\(|"
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
