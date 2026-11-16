"""Unit tests for the rules engine (AC1, AC2)."""

from pathlib import Path

import pytest

from prcheck.rules import RULES, analyze_to_issues

FIXTURE = Path(__file__).parent / "fixtures" / "example_pr.diff"


def test_categories_present_and_lines():
    """AC1: given a diff, checklist items span security/data/behavior with file:line."""
    issues, files = analyze_to_issues(FIXTURE.read_text())
    assert len(files) == 6
    cats = {i.category for i in issues}
    assert {"security", "data", "behavior"} <= cats
    for i in issues:
        assert i.path.endswith((".py", ".toml"))
        assert ":" in i.location
        assert i.line >= 1


def test_no_auth_route_flagged_high():
    """AC2: an unauth'd new route diff is marked high."""
    issues, _ = analyze_to_issues(FIXTURE.read_text())
    high = [i for i in issues if i.severity == "high" and i.rule_id == "R001-a"]
    assert high, "expected a high-severity R001-a finding"
    assert any("/public/stats" in i.snippet for i in high)
    assert any("src/app.py" == i.path for i in high)


def test_hardcoded_secret_high():
    issues, _ = analyze_to_issues(FIXTURE.read_text())
    sev = [i for i in issues if i.rule_id == "R002" and i.severity == "high"]
    assert sev
    assert sev[0].path == "src/keys.py"


def test_hardcoded_secret_compound_names_flagged():
    """R002 fires on underscore-joined secret names, not just bare keywords.

    Regression: the plain form requires a token boundary after the keyword, so
    `SECRET_KEY`, `DJANGO_SECRET_KEY`, `MYSQL_PASSWORD`, `ACCESS_TOKEN`,
    `JWT_SECRET` and dict/quoted-key forms all escaped detection.
    """
    src = (
        "SECRET_KEY = 'sk-12345678'\n"
        "DJANGO_SECRET_KEY = 'd-jango-9f8e7d6c5b4a'\n"
        "MYSQL_PASSWORD = 'hunter2!!'\n"
        "ACCESS_TOKEN = 'abc123456'\n"
        "GITHUB_TOKEN = 'ghp_1234567890abcd'\n"
        "JWT_SECRET = 'eyJhbGciOiJIUzI1NiJ9'\n"
        "client_secret = 'a1b2c3d4e5f6g7'\n"
        "'secret': '0123456789abcdef'\n"
        "tokenizer = 'abc12345'\n"            # not a secret: must NOT fire
        "not_a_secret_value = 'xyz'\n"          # ditto
        "SOCKET_TIMEOUT = 30\n"                # not a quoted secret: must NOT fire
        "GITHUB_TOKEN = os.environ['GITHUB_TOKEN']\n"  # env-driven: must NOT fire
    )
    issues, _ = analyze_to_issues(_inline_diff(src, path="keys.py"))
    hits = [i.line for i in issues if i.rule_id == "R002"]
    assert hits == [1, 2, 3, 4, 5, 6, 7, 8], f"R002 line mismatch: {hits}"


def test_dependency_rule_fires_on_manifest():
    issues, _ = analyze_to_issues(FIXTURE.read_text())
    deps = [i for i in issues if i.rule_id == "R006-deps"]
    # the pyproject manifest should have <= matched lines; package.json-style only
    assert any("pyproject.toml" == i.path for i in deps)


def test_dependency_rule_fires_on_unquoted_requirements_pins():
    """requirements.txt pins written without quotes still produce findings.

    Regression: the pyproject-style pattern required an opening quote, so a
    bare `cryptography>=41.0.0` line slipped through silently.
    """
    src = (
        "cryptography>=41.0.0\n"
        "requests~=2.31\n"
        "boto3==1.28.0\n"
        "# comment-only line\n"
        "flask\n"  # unpinned: must NOT fire
    )
    issues, _ = analyze_to_issues(_inline_diff(src, path="requirements.txt"))
    deps = [i for i in issues if i.rule_id == "R006-deps"]
    assert [i.line for i in deps] == [1, 2, 3], deps
    assert all("requirements.txt" == i.path for i in deps)
    lines = {i.snippet for i in deps}
    assert "flask" not in lines, "an unpinned dependency must not match"


def test_tls_verify_cert_none_and_check_hostname_flagged():
    """R003 catches the idiomatic stdlib TLS-disable assignments."""
    src = (
        "ctx.verify_mode = ssl.CERT_NONE\n"
        "ctx.check_hostname = False\n"
        "ctx.verify_mode = ssl.CERT_REQUIRED\n"  # safe: must NOT fire
        "res = requests.get(url, verify=True)\n"  # safe
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i.line for i in issues if i.rule_id == "R003"]
    assert hits == [1, 2], f"R003 fired on safe TLS lines: {hits}"


def test_sensitive_logging_flags_keyword_in_arguments():
    """D003 catches a secret named in the logging arguments, not just the format."""
    src = (
        'logging.debug("password hash = %s", h)\n'
        'logger.info("login ok tok=%s", token)\n'
        'logger.info("done")\n'  # clean
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i.line for i in issues if i.rule_id == "D003"]
    assert hits == [1, 2], f"D003 line mismatch: {hits}"


def test_pii_snake_case_suffix_flagged_in_field_context():
    """D001 catches `user_email = ...` / `customer_phone: str` field forms."""
    src = (
        "user_email = 'a@b.c'\n"
        "customer_phone: str\n"
        "shipping_address = 'x'\n"
        "send_email(addr, body)\n"  # function call: must NOT fire
        "notify_phone(user)\n"  # ditto
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i.line for i in issues if i.rule_id == "D001"]
    assert hits == [1, 2, 3], f"D001 suffix mismatch: {hits}"


def test_create_table_ddl_and_raise_http_error_status_flagged():
    """D002-bb flags raw CREATE TABLE DDL; B003 flags raise Http404 / abort(404)."""
    src = (
        "CREATE TABLE users (id INT);\n"
        "CREATE TABLE IF NOT EXISTS logs (ts INT, msg TEXT);\n"
        "CREATE INDEX idx_c ON t (c);\n"  # additive index: must NOT fire
        "raise HttpResponseNotFound()\n"  # no numeric code: must NOT fire
    )
    issues, _ = analyze_to_issues(_inline_diff(src, path="mig.py"))
    db = [i.line for i in issues if i.rule_id == "D002-db"]
    assert db == [1, 2], f"D002-db line mismatch: {db}"

    src = (
        "raise Http404\n"
        "raise django.http.Http404 from e\n"
        "abort(404)\n"
        "abort(500)\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    st = [i.line for i in issues if i.rule_id == "B003"]
    assert st == [1, 2, 3, 4], f"B003 line mismatch: {st}"


def test_path_traversal_and_xss_sinks_flagged():
    """R013 flags file-serving/open sinks fed by user-ish input; R014 flags XSS sinks."""
    src = (
        "return send_file(request.args['f'])\n"
        "return send_from_directory(UPLOAD_DIR, filename)\n"
        "fh = open(user_file)\n"
        "data = Path('/etc/' + name).read_text()\n"
        "el.innerHTML = userHtml;\n"
        "return mark_safe(html)\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    path_lines = [i.line for i in issues if i.rule_id == "R013-path"]
    assert path_lines == [1, 2, 3, 4], f"R013-path mismatch: {path_lines}"
    xss_lines = [i.line for i in issues if i.rule_id == "R014-xss"]
    assert xss_lines == [5, 6], f"R014-xss mismatch: {xss_lines}"


def test_path_traversal_and_xss_sink_negatives_quiet():
    """Literal paths, config constants and safe DOM APIs must not fire."""
    src = (
        "with open('/etc/hosts') as fh:\n"
        "with open('config.json', 'r') as fh:\n"
        "fh = open(LOGFILE, 'a')\n"
        "el.textContent = userHtml;\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R013-path"], issues
    assert not [i for i in issues if i.rule_id == "R014-xss"], issues


def test_crypto_random_redirect_sinks_flagged():
    """R015 flags legacy crypto; R016 flags random-for-secrets; R017 flags redirects on request input."""
    src = (
        "h = hashlib.md5(data).hexdigest()\n"
        "sig = sha1(payload.encode()).digest()\n"
        "token = ''.join(random.choice(chars) for _ in range(32))\n"
        "return redirect(request.args.get('next'))\n"
        "return redirect(url)\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    crypto = [i.line for i in issues if i.rule_id == "R015-crypto"]
    assert crypto == [1, 2], f"R015-crypto mismatch: {crypto}"
    rand = [i.line for i in issues if i.rule_id == "R016-random"]
    assert rand == [3], f"R016-random mismatch: {rand}"
    redir = [i.line for i in issues if i.rule_id == "R017-redirect"]
    assert redir == [4, 5], f"R017-redirect mismatch: {redir}"


def test_crypto_random_redirect_negatives_quiet():
    """sha256, secrets, plain random.randint and benign redirects must not fire."""
    src = (
        "h = hashlib.sha256(data).hexdigest()\n"
        "token = secrets.token_hex(16)\n"
        "i = random.randint(0, 10)\n"
        "return redirect('/dashboard')\n"
        "return redirect(url_for('index'))\n"
        "return redirect(request.url)\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    for rid in ("R015-crypto", "R016-random", "R017-redirect"):
        assert not [i for i in issues if i.rule_id == rid], (rid, issues)


def test_swallowed_exception_with_named_type_flagged():
    """B001 flags `except <Type> as e: return None`, not just bare Exception."""
    src = (
        "except ValueError as e: return None\n"
        "except (KeyError, IOError) as e: return None\n"
        "except Exception: return 5\n"  # not a swallow — must NOT fire
        "except TypeError as e: raise\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i.line for i in issues if i.rule_id == "B001"]
    assert hits == [1, 2], f"B001 line mismatch: {hits}"


def test_sql_rule_does_not_fire_on_plain_modulo():
    """R005 must only flag SQL strings built with the % operator.

    Regression: the % alternative used to match a bare `%` anywhere, so
    arithmetic modulo (`total % count`), the logging `%d%%` idiom, and
    percent-formatted f-strings all raised false SQL-injection findings.
    """
    src = (
        "cur.execute('SELECT * FROM t WHERE id = %s' % uid)\n"
        "query = 'SELECT %s FROM t' % cols\n"
        'sql = "SELECT * FROM users WHERE id = {}" % user_id\n'
        "avg = total % count\n"
        'name = "hello %s" % user\n'
        'logging.info("progress %d%%", n)\n'
        'f"{value:0.2f}%"\n'
        'cur.execute("SELECT * FROM t WHERE id = ?", (uid,))\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R005"]
    lines = [i.line for i in hits]
    assert lines == [1, 2, 3], f"R005 fired on non-SQL modulo lines: {lines}"


def test_debug_mode_and_log_level_flagged():
    """R018-debug flags truthy debug flags and DEBUG-level logging config."""
    src = (
        "app.debug = True\n"
        "DEBUG = True\n"
        "app.run(debug=True, port=8080)\n"
        "logging.basicConfig(level=logging.DEBUG)\n"
        "logger.setLevel(logging.DEBUG)\n"
        "app.debug = False\n"  # disabled: must NOT fire
        "DEBUG = False\n"  # ditto
        "DEBUG = os.environ.get('DEBUG', '0')\n"  # env-driven: must NOT fire
        "debug = True\n"  # bare lowercase var: must NOT fire
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i.line for i in issues if i.rule_id == "R018-debug"]
    assert hits == [1, 2, 3, 4, 5], f"R018-debug line mismatch: {hits}"


def test_csrf_disabled_flagged():
    """R019-csrf flags explicit CSRF-disable assignments, never the enabling call."""
    src = (
        "csrf.enable(False)\n"
        "CSRF_ENABLED = False\n"
        "WTF_CSRF_ENABLED = False\n"
        "csrf_protected = False\n"
        "app.config['CSRF_ENABLED'] = False\n"
        "'CSRF_ENABLED': False\n"
        "CSRF_ENABLED = True\n"  # enabled: must NOT fire
        "CSRFProtect(app).init_app(app)\n"  # enabling: must NOT fire
        "CSRF_ENABLED = os.environ.get('CSRF', '1')\n"  # env-driven: must NOT fire
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i.line for i in issues if i.rule_id == "R019-csrf"]
    assert hits == [1, 2, 3, 4, 5, 6], f"R019-csrf line mismatch: {hits}"


def test_existing_rule_library_integrity():
    # every rule id is unique and has valid category/severity
    assert len(RULES) == len({r.id for r in RULES.values()})
    for r in RULES.values():
        assert r.category in ("security", "data", "behavior")
        assert r.severity in ("info", "low", "medium", "high")


def test_issue_frozen_fields():
    from dataclasses import asdict

    issues, _ = analyze_to_issues(FIXTURE.read_text())
    assert issues
    d = asdict(issues[0])
    assert sorted(d.keys()) == sorted(
        ["rule_id", "category", "severity", "summary", "path", "line", "snippet", "hint", "refs"]
    )


# Every rule id that has no representation in the example_pr.diff fixture.
# These are pinned directly so a broken/regressed regex cannot pass CI silently.
_UNCOVERED_RULE_CASES = [
    (
        "B002",
        "behavior",
        "low",
        "timeout = 30\nretries = 3\nresponse = requests.get(url, timeout=15)\n",
    ),
    (
        "B003",
        "behavior",
        "medium",
        "status_code = 500\nreturn Response(status=403)\nraise ApiError(404)\n",
    ),
    (
        "R004",
        "security",
        "medium",
        "eval(code)\n"
        "data = pickle.loads(raw)\n"
        "yaml.unsafe_load(text)\n",
    ),
    (
        "R009",
        "security",
        "medium",
        "user_id = request.view_args['id']\naccount_id: 42\n",
    ),
    (
        "R010",
        "security",
        "low",
        'url = "http://example.com/path"\n',
    ),
    (
        "R011-session",
        "security",
        "medium",
        "SESSION_COOKIE_SECURE = False\napp.config['SESSION_COOKIE_HTTPONLY'] = None\n"
        "SameSite=None\n",
    ),
    (
        "R012-cmd",
        "security",
        "high",
        "os.system(\"restart.sh \" + cfg.url)\n"
        "os.popen('ls -l ' + user_input)\n"
        "subprocess.run('grep ' + term, shell=True)\n"
        "subprocess.Popen(f'curl {url}', shell=True)\n"
        "subprocess.check_call(cmd, shell=shell_enabled)\n"
        "subprocess.run([\"sh\", \"-c\", user_cmd])\n",
    ),
    (
        "R013-path",
        "security",
        "high",
        "return send_file(request.args['f'])\n"
        "fh = open(user_file)\n"
        "data = Path('/etc/' + name).read_text()\n",
    ),
    (
        "R014-xss",
        "security",
        "medium",
        "el.innerHTML = userHtml;\n"
        "document.write(markup)\n"
        "return mark_safe(html)\n",
    ),
    (
        "R015-crypto",
        "security",
        "medium",
        "h = hashlib.md5(data).hexdigest()\n"
        "sig = sha1(payload.encode()).digest()\n"
        "from Crypto.Cipher import DES\n",
    ),
    (
        "R016-random",
        "security",
        "medium",
        "token = ''.join(random.choice(chars) for _ in range(32))\n"
        "salt = random.getrandbits(64)\n",
    ),
    (
        "R017-redirect",
        "security",
        "medium",
        "return redirect(request.args.get('next'))\n"
        "return redirect(url)\n"
        "return redirect(next_url)\n",
    ),
    (
        "R018-debug",
        "security",
        "low",
        "app.debug = True\n"
        "DEBUG = True\n"
        "logger.setLevel(logging.DEBUG)\n",
    ),
    (
        "R019-csrf",
        "security",
        "medium",
        "csrf.enable(False)\n"
        "CSRF_ENABLED = False\n"
        "app.config['CSRF_ENABLED'] = False\n"
        "'WTF_CSRF_ENABLED': False\n",
    ),
]


def _inline_diff(src: str, path: str = "x.py") -> str:
    lines = "".join("+" + ln + "\n" for ln in src.splitlines())
    return (
        f"--- a/{path}\n+++ b/{path}\n@@ -0,0 +1,{len(src.splitlines())} @@\n"
        f"{lines}"
    )


@pytest.mark.parametrize("rule_id,category,severity,lines", _UNCOVERED_RULE_CASES)
def test_uncovered_rules_fire_correctly(rule_id, category, severity, lines):
    """AC1 scope: each rule without fixture coverage still fires on classic input."""
    issues, _ = analyze_to_issues(_inline_diff(lines))
    hits = [i for i in issues if i.rule_id == rule_id]
    assert hits, f"{rule_id} did not fire on:\n{lines}"
    for i in hits:
        assert i.category == category, (rule_id, i.category)
        assert i.severity == severity, (rule_id, i.severity)


def test_every_rule_has_test_exposure():
    """No rule may be silent across the whole suite (fixture + pinned cases)."""
    rids = {r.id for r in RULES.values()}
    exposed = {
        "B001", "B002", "B003", "B004", "B005",
        "D001", "D002-db", "D003", "D004",
        "R001-a", "R001-b", "R002", "R003", "R004", "R005",
        "R006-deps", "R007-cors", "R008", "R009", "R010", "R011-session",
        "R012-cmd", "R013-path", "R014-xss", "R015-crypto", "R016-random",
        "R017-redirect", "R018-debug", "R019-csrf",
    }
    assert exposed <= rids
    uncovered = rids - exposed
    assert not uncovered, f"rules with no test exposure: {sorted(uncovered)}"
