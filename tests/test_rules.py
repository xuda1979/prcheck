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


def test_hardcoded_secret_cloud_credential_names_flagged():
    """R002 catches AWS/OAuth credential names, not just key/password atoms.

    aws_access_key_id / AWS_SECRET_ACCESS_KEY have the credential keyword
    embedded with a suffix (`access_key_id`), and OAuth CONSUMER_KEY is an
    underscore-joined key name — neither can form at the plain keyword atom.
    """
    src = (
        "aws_access_key_id = 'AKIAIOSFODNN7EXAMPLE'\n"
        "AWS_ACCESS_KEY_ID = 'AKIAI44QH8DHBEXAMPLE'\n"
        "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n"
        "AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENGCAFEEXAMPLEKEY'\n"
        "CONSUMER_KEY = '2q1v7k0a9xVb3mZ8'\n"
        "consumer_secret = 'j6f3p0s9d2h7n1'\n"
        "access_key_id = 12345\n"                 # numeric, not a literal: must NOT fire
        "public_key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...'\n"  # public, not secret
        "callback = 'https://example.com/cb'\n"    # not a credential: must NOT fire
    )
    issues, _ = analyze_to_issues(_inline_diff(src, path="keys.py"))
    hits = [i.line for i in issues if i.rule_id == "R002"]
    assert hits == [1, 2, 3, 4, 5, 6], f"R002 cloud mismatch: {hits}"


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
        "res = requests.get(url, verify=False)\n"  # fetch TLS disable: fires
        "ctx.verify_mode = ssl.CERT_REQUIRED\n"  # safe: must NOT fire
        "res = requests.get(url, verify=True)\n"  # safe
        "claims = jwt.decode(token, SECRET, verify=False)\n"  # JWT sig: R024, NOT R003
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i.line for i in issues if i.rule_id == "R003"]
    assert hits == [1, 2, 3], f"R003 fired on safe TLS lines: {hits}"


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


def test_insecure_deserialization_sinks_flagged():
    """R004 flags the CWE-502 sink family; safe loaders / plain loads stay quiet."""
    src = (
        "obj = pickle.Unpickler(buf)\n"
        "data = pickle.load(f)\n"
        "cfg = yaml.load(text)\n"
        "arr = np.load(path, allow_pickle=True)\n"
        "model = torch.load('ckpt.pt')\n"
        "df = pd.read_pickle('data.pkl')\n"
        "store = shelve.open('db.store')\n"
        "safe = yaml.load(stream, Loader=yaml.SafeLoader)\n"  # safe loader
        "data = json.loads(raw)\n"  # not despatch/pickle
        "pickle.dumps(obj)\n"  # serialization, not deserialization
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i.line for i in issues if i.rule_id == "R004"]
    assert hits == [1, 2, 3, 4, 5, 6, 7], f"R004 line mismatch: {hits}"


def test_bare_eval_exec_compile_flagged_but_method_calls_quiet():
    """R004's first alternative must only fire on bare eval/exec/compile calls —
    not re.compile, obj.eval / foo.exec / self.compile method forms or
    identifiers sharing the same prefix."""
    src = (
        "eval(user_input)\n"
        "x = eval(buf)\n"
        "exec(code)\n"
        "compile(src, 'f.py', 'exec')\n"
        "pattern = re.compile(request.form['x'])\n"
        "re.compile(f'^{user}$', re.IGNORECASE)\n"
        "re.compile(EMAIL_PATTERN)\n"
        "foo.eval(codebuf)\n"
        "obj.exec(cmd)\n"
        "self.compile(src)\n"
        "code.eval(source)\n"
        "node.evaluate(x)\n"
        "if eval_result:\n"
        "executable = True\n"
        "compiled = bytecode\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i.line for i in issues if i.rule_id == "R004"]
    assert hits == [1, 2, 3, 4], f"R004 bare-call mismatch: {hits}"


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


def test_react_and_jquery_xss_sinks_flagged():
    """R014 flags React dangerouslySetInnerHTML and jQuery .html(v) setter sinks."""
    src = (
        "<div dangerouslySetInnerHTML={{__html: note}} />\n"
        "node.dangerouslySetInnerHTML = payload\n"
        "$('#list').html(data)\n"
        "jQuery('#box').html(await fetchText())\n"
        "value = el.innerHTML += more\n"
        "safe = el.textContent = user\n"  # safe DOM prop
        "s = df.to_html()\n"  # pandas, not a jQuery receiver
        "$('#panel').html()\n"  # jQuery getter, no argument
        "template = string.Template('Hello $name')\n"  # $ not a receiver
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i.line for i in issues if i.rule_id == "R014-xss"]
    assert hits == [1, 2, 3, 4, 5], f"R014-xss mismatch: {hits}"


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


def test_committed_private_key_material_flagged():
    """R020-pem flags PEM private-key block headers, never public keys/certs."""
    src = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "key = '-----BEGIN EC PRIVATE KEY-----'\n"
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
        "-----BEGIN PUBLIC KEY-----\n"          # public: must NOT fire
        "-----BEGIN CERTIFICATE-----\n"          # ditto
        "-----END RSA PRIVATE KEY-----\n"        # end marker: must NOT fire
    )
    issues, _ = analyze_to_issues(_inline_diff(src, path="keys.pem"))
    hits = [i for i in issues if i.rule_id == "R020-pem"]
    assert [i.line for i in hits] == [1, 2, 3, 4], f"R020-pem line mismatch: {hits}"
    assert all(i.severity == "high" for i in hits)


def test_ssrf_fetches_of_request_derived_urls_flagged():
    """R021-ssrf flags HTTP fetches of request input or url-ish variables,
    including session/client-object receivers and aiohttp.request()."""
    src = (
        "resp = requests.get(request.args['url'])\n"
        "r = requests.post(request.form['callback'], data=body)\n"
        "out = httpx.get(request.json['target'])\n"
        "data = urllib.request.urlopen(request.args.get('u')).read()\n"
        "fetch = requests.get(url)\n"
        "page = requests.get(callback_url)\n"
        "stream = urlopen(user_url)\n"
        "resp = await session.get(request.args['url'])\n"
        "r = await client.post(request.form['url'], json=payload)\n"
        "resp = await aiohttp.ClientSession().get(request.args['u'])\n"
        "html = await http_client.request('GET', webhook_endpoint)\n"
        "fetch = await httpx.AsyncClient().get(callback)\n"
        "foo = aiohttp.request('GET', request.args['u'])\n"
        "bar = aiohttp.request('POST', request.form['go'], data=body)\n"
        "page = await session.get(user_url)\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R021-ssrf"]
    assert [i.line for i in hits] == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], f"R021-ssrf mismatch: {hits}"
    assert all(i.severity == "high" for i in hits)


def test_ssrf_static_and_constant_urls_quiet():
    """R021-ssrf must not fire on literals, SCREAMING_CASE constants, url_for,
    non-HTTP receivers or plain setup lines."""
    src = (
        "resp = requests.get('https://api.example.com/v1')\n"
        "data = requests.get(API_URL)\n"
        "r = requests.get(BASE_URL + '/users')\n"
        "stream = urlopen('https://pypi.org/simple/')\n"
        "page = requests.get(url_for('index'))\n"
        "harness = requests.get(HARNESS_URL)\n"  # SCREAMING_CASE constant
        "url = request.args.get('next')\n"  # assignment alone, no client call
        "h = hashlib.sha256(url.encode()).hexdigest()\n"
        "resp = await session.get('https://api.example.com/v1')\n"
        "r = await client.get(API_URL)\n"
        "foo = aiohttp.request('GET', 'https://ex.com/x')\n"
        "k = session_data.get(request.args['key'])\n"  # mid-word receiver
        "v = client_id.get(request.args['id'])\n"
        "user.get(request.args['name'])\n"
        "s = requests.Session()\n"
        "async with aiohttp.ClientSession() as client:\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R021-ssrf"], issues


def test_ssti_templates_from_request_or_variable_flagged():
    """R022-ssti flags render_template_string/Template fed request input or
    template-named variables."""
    src = (
        "return render_template_string(request.args['tpl'], name=name)\n"
        "out = render_template_string(user_template)\n"
        "rendered = Template(request.form['tmpl']).render()\n"
        "html = jinja2.Template(request.json['tpl']).render()\n"
        "body = render_template_string(tmpl_var, **ctx)\n"
        "response = Template(stored_markup).render(data)\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R022-ssti"]
    assert [i.line for i in hits] == [1, 2, 3, 4, 5, 6], f"R022-ssti mismatch: {hits}"
    assert all(i.severity == "high" for i in hits)


def test_ssti_literals_and_string_template_quiet():
    """R022-ssti must not fire on inline/static templates, string.Template,
    render_template or assignment-only lines."""
    src = (
        "return render_template_string('<h1>Hello {{ name }}</h1>', name=name)\n"
        "return render_template_string(STATIC_TPL, user=user)\n"  # SCREAMING_CASE constant
        "s = string.Template('$who')\n"
        "s = string.Template(user_var)\n"
        "return render_template('index.html', user=user)\n"
        "t = Template('Hello {{ who }}')\n"
        "msg = render_template_string(f'Hello {name}')\n"
        "cfg.admin_template = 'x'\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R022-ssti"], issues


def test_xxe_xml_parsers_of_request_or_named_data_flagged():
    """R023-xxe flags stdlib/lxml/xmltodict XML parsing of request input or
    xml-named variables."""
    src = (
        "tree = xml.etree.ElementTree.fromstring(request.data)\n"
        "root = xml.etree.ElementTree.fromstring(request.data)\n"
        "parsed = xmltodict.parse(request.files['xml'])\n"
        "root = etree.fromstring(xml_body)\n"
        "events = sax.parseString(xml_payload)\n"
        "t = pulldom.parseString(xml_content)\n"
        "doc = lxml.etree.fromstring(user_xml)\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R023-xxe"]
    assert [i.line for i in hits] == [1, 2, 3, 4, 5, 6, 7], f"R023-xxe mismatch: {hits}"
    assert all(i.severity == "medium" for i in hits)


def test_xxe_static_and_defusedxml_quiet():
    """R023-xxe must not fire on literals, defusedxml, non-XML docs or
    SCREAMING_CASE constants."""
    src = (
        "tree = ET.fromstring('<root><a/></root>')\n"
        "safe = defusedxml.etree.fromstring(xml_payload)\n"
        "cfg = xml.etree.ElementTree.parse('config.xml')\n"
        "data = xmltodict.parse(json_payload)\n"
        "out = urlparse(request.args.get('u'))\n"
        "root = etree.fromstring(STATIC_XML)\n"  # SCREAMING_CASE constant
        "s = sax.parseString('<a/>')\n"
        "h = hashlib.sha256(xml.encode()).hexdigest()\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R023-xxe"], issues


def test_jwt_verification_disabled_or_none_alg_flagged():
    """R024-jwt flags verify=False, options verify_signature False and
    alg=none acceptance."""
    src = (
        "claims = jwt.decode(token, SECRET, verify=False)\n"
        "data = jwt.decode(request.args['t'], verify=False)\n"
        "claims = jwt.decode(t, key, options={'verify_signature': False})\n"
        "ok = jwt.verify(tok, KEY, options={'verify_signature': False})\n"
        "claims = jwt.decode(tok, key, algorithms=['none'])\n"
        "data = jwt.decode(request.json['t'], algorithms=['none'])\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R024-jwt"]
    assert [i.line for i in hits] == [1, 2, 3, 4, 5, 6], f"R024-jwt mismatch: {hits}"
    assert all(i.severity == "medium" for i in hits)


def test_jwt_verification_kwargs_quiet():
    """R024-jwt must not fire on safe verify=True, pinned algorithms, encode,
    header inspection or non-bool flags."""
    src = (
        "claims = jwt.decode(token, SECRET, algorithms=['HS256'])\n"
        "data = jwt.decode(tok, key, verify=True)\n"
        "claims = jwt.decode(token, SECRET)\n"
        "jwt.encode(payload, KEY, algorithm='HS256')\n"
        "cfg = jwt.get_unverified_header(token)\n"
        "opts = {'verify_signature': True}\n"
        "token = jwt.decode(t, key, verify=VERIFY_FLAG)\n"
        "algorithms = ['HS256', 'RS256']\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R024-jwt"], issues


def test_password_field_assigned_raw_input_or_variable_flagged():
    """R025-pw flags password/passwd/pwd fields assigned request-derived input
    or a bare variable (plaintext credential storage, CWE-256/261)."""
    src = (
        "user.password = request.form['password']\n"
        "account['password'] = request.args.get('pass')\n"
        "user.password = new_password\n"
        "obj.passwd = creds['passwd']\n"
        "k['password'] = cleaned['password']\n"
        'db.execute("UPDATE users SET password = raw_pw WHERE id = ?")\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R025-pw"]
    assert [i.line for i in hits] == [1, 2, 3, 4, 5, 6], f"R025-pw mismatch: {hits}"
    assert all(i.severity == "high" for i in hits)


def test_password_assignment_hashing_env_literals_quiet():
    """R025-pw must not fire on hashed assignments, env/config sources,
    SCREAMING_CASE constants, literals, type annotations or non-field uses."""
    src = (
        "user.password = bcrypt.hashpw(pw.encode(), salt).decode()\n"
        "user.password = generate_password_hash(pw)\n"
        "password = db.Column(db.String(60))\n"
        "user.set_password(new_password)\n"
        "password = os.environ.get('DB_PASS', '')\n"
        "password = DEFAULT_PASSWORD\n"
        "user.password = pw_hash\n"
        "user.password = hashed_password\n"
        "password: str\n"
        "user.password = str(request.form['pw'])\n"
        "user.password = ''\n"
        "confirm_password = form['password']\n"
        "pw = 'static-value'\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R025-pw"], issues


def test_unrestricted_file_upload_save_flagged():
    """R026-upload flags request.files saves and .save() targets fed a
    filename attribute, os.path.join with a filename, or request data."""
    src = (
        "request.files['image'].save(dest)\n"
        "request.FILES['doc'].save('/tmp/' + f.name)\n"
        "uploaded.save('/srv/uploads/' + uploaded.filename)\n"
        "handler.save('/www/' + request.args['path'])\n"
        "doc.save(os.path.join(BASE, file.filename))\n"
        "avatar.save(upload_dir + part.filename)\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R026-upload"]
    assert [i.line for i in hits] == [1, 2, 3, 4, 5, 6], f"R026-upload mismatch: {hits}"
    assert all(i.severity == "high" for i in hits)


def test_filestore_save_literal_and_orm_quiet():
    """R026-upload must not fire on ORM no-arg save, literal-path saves
    (Pillow/PDF), request.files access without .save, or unrelated saves."""
    src = (
        "instance.save()\n"
        "user.save(update_fields=['name'])\n"
        "img.save('/static/logo.png')\n"
        "pdf.save('/tmp/report.pdf')\n"
        "file = request.files['f']\n"
        "name = request.files['f'].filename\n"
        "logger.save_config('/etc/app.conf')\n"
        "cache.save(key, value)\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R026-upload"], issues


def test_mass_assignment_request_dict_flagged():
    """R027-massassig flags request dicts fed wholesale (not field-by-field)
    into ORM create/update family, .update* receivers, or capital constructors
    (mass assignment, CWE-915)."""
    src = (
        "User.objects.create(**request.POST)\n"
        "Account.objects.create(**request.json)\n"
        "User.objects.filter(pk=uid).update(**request.form)\n"
        "Entry.objects.update_or_create(pk=pk, defaults=request.POST.dict())\n"
        "obj.update_from_dict(request.form)\n"
        "instance.update_from_request(request.json)\n"
        "account.update(**request.json)\n"
        "User(**request.form.to_dict())\n"
        "Ticket(**request.get_json())\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R027-massassig"]
    assert [i.line for i in hits] == [1, 2, 3, 4, 5, 6, 7, 8, 9], f"R027-massassig mismatch: {hits}"
    assert all(i.severity == "medium" for i in hits)


def test_mass_assignment_fieldwise_and_unrelated_quiet():
    """R027-massassig must not fire on explicit field assignments, literal
    dicts, indexed request reads (not wholesale), request accessors as
    receivers, form/serializer whitelists, or unrelated sinks."""
    src = (
        "User.objects.create(name=name, email=email)\n"
        "instance.update(name='x')\n"
        "d.update({'a': 1})\n"
        "User.objects.filter(name=request.form['name']).delete()\n"
        "obj.update(request.form['key'])\n"
        "request.form.update(name='x')\n"
        "request.args.setdefault('page', 1)\n"
        "requests.post(url, json=request.json)\n"
        "aiohttp.request('POST', url, json=request.form)\n"
        "data = request.form.to_dict()\n"
        "User(**data)\n"
        "UserForm(request.form)\n"
        "LoginForm(**request.json)\n"
        "UserSerializer(request.json)\n"
        "User.objects.create_user(**request.form)\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R027-massassig"], issues


def test_nosql_request_dict_query_flagged():
    """R028-nosql flags Mongo-family query calls fed a wholesale request dict
    or a $where built from request-derived fragments (NoSQL injection/CWE-943)."""
    src = (
        "db.users.find(request.json)\n"
        "collection.find_one(request.form)\n"
        "db.orders.find(request.get_json())\n"
        "users.find_one_and_update({'_id': oid}, request.json)\n"
        "db['accounts'].find(request.args)\n"
        "db.events.count_documents(request.json)\n"
        "db.users.distinct('role', request.form)\n"
        "db.users.find({'$where': \"this.role == '\" + request.args['role'] + \"'\"})\n"
        "coll.find({'$where': request.form['js']})\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R028-nosql"]
    assert [i.line for i in hits] == [1, 2, 3, 4, 5, 6, 7, 8, 9], f"R028-nosql mismatch: {hits}"
    assert all(i.severity == "medium" for i in hits)


def test_nosql_literals_and_non_mongo_quiet():
    """R028-nosql must not fire on literal queries, framework-bound find/
    aggregate receivers (ElementTree, jQuery, Django ORM), write ops,
    request accessors as receivers, or field-wise request reads."""
    src = (
        "db.users.find({'name': 'admin'})\n"
        "db.users.find_one({'_id': ObjectId(oid)})\n"
        "db.users.find(sort=[('x', 1)])\n"
        "root.find('tag')\n"
        "$('ul').find('li')\n"
        "qs.aggregate(Count('id'))\n"
        "coll.insert_one(request.json)\n"
        "db.users.update_one({'_id': i}, {'$set': request.json})\n"
        "request.json.find('key')\n"
        "db.users.find_one(request.args.get('query'))\n"
        "payload = json.loads(request.form['data'])\n"
        "User.objects.filter(name=request.form['name'])\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R028-nosql"], issues


def test_ldap_injection_search_flagged():
    """R029-ldap flags LDAP search calls fed request-derived input as
    filter/dn arguments (CWE-90): python-ldap search_s/search_st/search_ext
    family on any receiver, plus ldap3-style bare .search on ldap/conn-named
    receivers. Indexed reads and .get() ARE payloads here."""
    src = (
        "conn.search_s(base, SCOPE_SUBTREE, '(&(uid=' + request.form['uid'] + '))')\n"
        "ldap_conn.search_s(base, scope, request.args.get('filter'))\n"
        "con.search_st(base, scope, request.form['user'] + ')*')\n"
        "admin_conn.search_ext_s(base, scope, request.get_json()['flt'])\n"
        "connection.search_ext(base, scope, request.data)\n"
        "server_conn.search_s(base, SCOPE_BASE, request.headers.get('X-Filter'))\n"
        "conn.search(base, '(uid=' + request.form['uid'] + ')')\n"
        "ldap3.search(base, request.form['q'])\n"
        "server.ldap.search(base, request.args.get('user'))\n"
        "ldap_handle.search(base, request.json)\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R029-ldap"]
    assert [i.line for i in hits] == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], f"R029-ldap mismatch: {hits}"
    assert all(i.severity == "medium" for i in hits)


def test_ldap_injection_literals_and_generic_search_quiet():
    """R029-ldap must not fire on literal filters, non-search LDAP methods,
    same-line escape_filter_chars/escape_dn_chars sanitization, or generic
    search-engine receivers (es/client/index/results/arr/db/page)."""
    src = (
        "conn.search_s(base, scope, '(uid=jdoe)')\n"
        "conn.search_s(base, scope, '(uid=%s)' % uid)\n"
        "conn.search_s(base, scope, user_filter)\n"
        "ldap_conn.delete_s(dn)\n"
        "conn.search_s(base, scope, ldap.filter.escape_filter_chars(request.form['uid']))\n"
        "conn.search(base, scope, ldap.dn.escape_dn_chars(request.form['uid']))\n"
        "es.search(index='idx', body=request.json)\n"
        "client.search(request.args['q'])\n"
        "index.search('users', '*:*')\n"
        "results.search(request.form['q'])\n"
        "arr.search(u => u.id === request.form['id'])\n"
        "db.search(request.form['x'])\n"
        "page.search(request.args['q'])\n"
        "conn.search('static filter')\n"
        "ldap_conn.search_s(base, scope, fixed_filter)\n"
        "request.form.get('q')\n"
        "filter = request.args.get('filter')\n"
        "logger.info('uid=%s', request.form['uid'])\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R029-ldap"], issues


def test_xpath_injection_query_flagged():
    """R030-xpath flags XPath query calls fed request-derived input (CWE-643):
    lxml element .xpath() on any receiver and compiled XPath/E/etree.XPath
    constructors. Indexed reads and .get() ARE payloads here."""
    src = (
        "root.xpath(request.form['query'])\n"
        "tree.xpath(\"//user[name='\" + request.args.get('name') + \"']\")\n"
        "doc.xpath(request.data)\n"
        "parser.parse(f).xpath(request.get_json()['q'])\n"
        "resume.xpath(request.headers.get('X-Query'))\n"
        "conn.xpath(request.json)\n"
        "XPath(request.form['expr'])\n"
        "etree.XPath(request.args.get('q'))\n"
        "lxml.etree.XPath(request.get_json()['path'])\n"
        "etree.XPathEvaluator(request.data)\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R030-xpath"]
    assert [i.line for i in hits] == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], f"R030-xpath mismatch: {hits}"
    assert all(i.severity == "medium" for i in hits)


def test_xpath_literals_and_unrelated_quiet():
    """R030-xpath must not fire on literal/non-request queries, SCREAMING
    constants or bare variables, ElementTree find/findall, browser $x/Selenium
    By.XPATH, or standalone request reads."""
    src = (
        "root.xpath('//book/title')\n"
        "tree.xpath(\"//user[name='jdoe']\")\n"
        "root.xpath(QUERY)\n"
        "root.xpath(user_query)\n"
        "XPath('//user')\n"
        "etree.XPath('/titles')\n"
        "el.find('tag')\n"
        "el.findall('.//item')\n"
        "el.iter()\n"
        "request.form.get('q')\n"
        "q = request.args.get('q')\n"
        "logger.info('xpath=%s', request.form['q'])\n"
        "$x('//div')\n"
        "wait.until(EC.presence_of_element_located((By.XPATH, '//div')))\n"
        "result = XPathEvaluator(expr_literal)\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R030-xpath"], issues


def test_ssrf_js_fetch_sinks_flagged():
    """R031-ssrf-js flags JS client-side fetch sinks fed request-derived URLs or
    url-named variables (CWE-918): fetch/axios/got/Node http(s)/request and
    XMLHttpRequest-family .open(method, url)."""
    src = (
        "fetch(req.query.url)\n"
        "const r = await axios.get(request.body.redirect)\n"
        "const resp = await got(targetUrl)\n"
        "await fetch(userWebhook)\n"
        "const res = await fetch(req['url'])\n"
        "http.request(ctx.request.url, cb)\n"
        "https.get(event.headers.referer, cb)\n"
        "request(raw_url, cb)\n"
        "const t = await got(`base/${req.query.u}`)\n"
        "xhr.open('GET', request.query.url)\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R031-ssrf-js"]
    assert [i.line for i in hits] == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], f"R031-ssrf-js mismatch: {hits}"
    assert all(i.severity == "high" for i in hits)


def test_ssrf_js_literals_and_nonjs_receivers_quiet():
    """R031-ssrf-js must not fire on literal quoted URLs, SCREAMING_CASE
    constants, or non-JS receivers (db.fetch, router.get, api.get,
    window.open, socket.connect)."""
    src = (
        "fetch('/api/users')\n"
        "axios.post('/api/submit', { url: formUrl })\n"
        "const res = await got(BASE_URL)\n"
        "http.get('http://localhost:8000/health')\n"
        "router.get('/users', listUsers)\n"
        "app.use(requestHandler)\n"
        "xhr.open('GET', '/static/app.js')\n"
        "const data = await api.get(path)\n"
        "window.open(url, '_blank')\n"
        "db.fetch('id_123')\n"
        "socket.connect(targetUrl)\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R031-ssrf-js"], issues


def test_cmd_node_child_process_sinks_flagged():
    """R032-cmd-node flags Node child_process exec/spawn calls building a shell
    command from a variable / request input / interpolation (CWE-78): non-literal
    exec/execSync args, `${}` backtick templates, concatenated command strings,
    shell:true enabled execs and sh -c arrays."""
    src = (
        "child_process.exec(req.query.cmd)\n"
        "const out = execSync(`rm -rf /tmp/${req.body.path}`)\n"
        "cp.exec('ls -la ' + request.query.dir)\n"
        "execFileSync(userCmd, { shell: true })\n"
        "child_process.execSync(command, { stdio: 'inherit' })\n"
        "spawn('/bin/sh', ['-c', userInput])\n"
        "exec(`git clone ${targetUrl}`)\n"
        "cp.execFile('run.sh', [req.query.arg], { shell: true })\n"
        "process.execSync('git status ' + branchName)\n"
        "cp.spawnSync('/bin/sh', ['-c', req.params.cmd])\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R032-cmd-node"]
    assert [i.line for i in hits] == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], f"R032-cmd-node mismatch: {hits}"
    assert all(i.severity == "high" for i in hits)


def test_cmd_node_child_process_literals_and_safe_spawns_quiet():
    """R032-cmd-node must not fire on literal quoted commands, SCREAMING_CASE
    constants, argument-list spawns without an enabled shell, Python exec() /
    subprocess forms, or non-child_process receivers."""
    src = (
        "child_process.exec('ls -la')\n"
        "execSync('git rev-parse HEAD')\n"
        "spawn('ls', ['-la'])\n"
        "execFile('git', ['status', '--short'])\n"
        "cp.execFileSync('node', ['--version'])\n"
        "const { exec } = require('child_process'); exec('clean', ['start'])\n"
        "exec(code)\n"
        "process.execPath\n"
        "cp.execSync(BASE_CMD)\n"
        "spawn('python', ['-c', code])\n"
        "git.exec('pull')\n"
        "subprocess.run(['ls'], shell=True)\n"
        "exec(`ls -la`)\n"
        "child_process.exec(`echo done`)\n"
        "spawn('git', ['-c', 'core.pager=cat', 'log'])\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R032-cmd-node"], issues


def test_prototype_pollution_request_merges_flagged():
    """R033-protopoll flags JS merge/extend sinks fed request-derived objects
    (Object.assign / lodash merge family / jQuery extend) and direct __proto__
    assignment from request input (CWE-1321)."""
    src = (
        "Object.assign({}, req.query)\n"
        "_.merge(config, req.body)\n"
        "const merged = _.defaultsDeep({}, request.json)\n"
        "$.extend(true, {}, request.body)\n"
        "jQuery.extend({}, ctx.request.query)\n"
        "const merged = _.mergeWith(target, req.body, customizer)\n"
        "Object.assign({}, ...req.body)\n"
        "const merged = _.merge(baseOpts, sanitize(req.query))\n"
        "obj['__proto__'] = req.body\n"
        "item.__proto__ = JSON.parse(request.body)\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R033-protopoll"]
    assert [i.line for i in hits] == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], f"R033-protopoll mismatch: {hits}"
    assert all(i.severity == "high" for i in hits)


def test_prototype_pollution_literals_and_safe_merges_quiet():
    """R033-protopoll must not fire on literal objects, SCREAMING_CASE constants,
    pandas/git merges, __proto__ reads / null resets, safe deep-clones, or plain
    spread-into-literal."""
    src = (
        "Object.assign({}, DEFAULTS)\n"
        "const cfg = _.merge(baseConf, BASE_CONFIG)\n"
        "df.merge(request.body, on='id', how='inner')\n"
        "git merge(requestedBranch)\n"
        "obj['__proto__']\n"
        "obj['__proto__'] = null\n"
        "Object.setPrototypeOf(thing, proto)\n"
        "_.cloneDeep(request.body)\n"
        "const copia = structuredClone(payload)\n"
        "Object.assign({}, { name: 'x', role: 'admin' })\n"
        "user.profile = { role: 'admin' }\n"
        "const merged = { ...request.body }\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R033-protopoll"], issues


def test_regex_injection_request_patterns_flagged():
    """R034-redos flags Python re-module sinks fed a request-derived pattern as
    the first argument, and JS RegExp constructors built from request input
    (CWE-1333)."""
    src = (
        "re.compile(request.form['pattern'])\n"
        "result = re.search(req.query.re, text)\n"
        "if re.match(request.json['rx'], line):\n"
        "ok = re.fullmatch(request.args.get('pat'), s)\n"
        "hits = re.findall(request.data.re, buf)\n"
        "html = re.sub(request.get_json().get('re'), 'x', html)\n"
        "pattern = re.compile(ctx.request.query.regex)\n"
        "new RegExp(req.query.re)\n"
        "const rx = new RegExp(request.body.pattern, 'i')\n"
        "if (RegExp(request.json.pattern).test(name))\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R034-redos"]
    assert [i.line for i in hits] == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], f"R034-redos mismatch: {hits}"
    assert all(i.severity == "high" for i in hits)


def test_regex_injection_literal_and_safe_patterns_quiet():
    """R034-redos must not fire on literal/constant/bare-variable patterns, a
    request-derived SUBJECT as second argument, string .match(), regex literals,
    or non-sink calls."""
    src = (
        "re.search(r'\\d+', request.body.text)\n"
        "re.match('^[a-z]+$', username)\n"
        "re.compile(EMAIL_PATTERN)\n"
        "rx = re.compile(SAFE_RE_48)\n"
        "re.findall(term, request.body.text)\n"
        "m = re.match(user_filter, text)\n"
        "page = re.search(pattern_var, html)\n"
        "re.sub(LITERAL_RE, '', request.form['html'])\n"
        "re.compile(f'^{user}$', re.IGNORECASE)\n"
        "reversed(items)\n"
        "related_url.match(rex)\n"
        "new RegExp('^admin$')\n"
        "const re = new RegExp(USER_INPUT_PATTERN)\n"
        "cleaned = body.replace(/bad/g, '')\n"
        "const m = data.match(/^\\d+$/)\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R034-redos"], issues


def test_response_header_injection_request_values_flagged():
    """R035-hdrinj flags request-derived values written into response headers via
    Python subscript-assign, Python set_header/add_header/set_cookie calls, and
    Node/JS res.setHeader/header/append/set/cookie/writeHead and
    xhr.setRequestHeader sinks (CWE-113)."""
    src = (
        "response.headers['X-Request-ID'] = request.headers.get('X-Request-ID')\n"
        "resp['X-Trace'] = req.query.trace\n"
        "res.headers['Content-Disposition'] = request.args.get('download')\n"
        "response.set_header('X-Custom', request.headers.get('origin'))\n"
        "resp.add_header(request.json['name'], 'x')\n"
        "set_cookie('session', request.cookies.get('next'))\n"
        "res.setHeader('X-Powered-By', request.query.name)\n"
        "res.append('Set-Cookie', req.query.val)\n"
        "res.cookie('auth', request.body.token)\n"
        "res.writeHead(200, { 'X-Custom': request.query.v })\n"
        "xhr.setRequestHeader('Authorization', request.body.tok)\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R035-hdrinj"]
    assert [i.line for i in hits] == list(range(1, 12)), f"R035-hdrinj mismatch: {hits}"
    assert all(i.severity == "high" for i in hits)


def test_response_header_injection_literal_and_generic_quiet():
    """R035-hdrinj must not fire on literal headers/static values, generic dict
    writes, .headers reads, helper receivers, or non-header setters."""
    src = (
        "response.headers['Content-Type'] = 'application/json'\n"
        "res.setHeader('Content-Type', 'application/json')\n"
        "response.set_header('X', 'static')\n"
        "response.headers['X'] = API_KEY\n"
        "self.headers['X'] = request.headers.get('Y')\n"
        "cache['X'] = request.query.v\n"
        "session['user'] = request.body.user\n"
        "os.environ['PATH'] = request.body.path\n"
        "headers['X'] = request.query.v\n"
        "res.headers.get('X-Rate-Limit')\n"
        "res.send(request.query.msg)\n"
        "auth.set_cookie(request.body.uid)\n"
        "res2.setHeader('X', request.query.v)\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R035-hdrinj"], issues


def test_log_injection_request_values_flagged():
    """R036-loginj flags request-derived values written to logging/console sinks
    across Python logger/log/logging (.debug/.info/.warning/.error/.exception/
    .critical), logging.getLogger(name).method chains, print(), Node console.*,
    and Java System.out/err.println/printf (CWE-117)."""
    src = (
        "logger.error(\"login failed for \" + request.headers.get('user'))\n"
        "log.info(f\"user {ctx.request.remote_addr} arrived\")\n"
        "logging.warning(\"invalid input: %s\" % req.query.v)\n"
        "logging.exception(\"failed to parse \" + request.body.payload)\n"
        "console.log(\"req: \" + request.body.data)\n"
        "console.error(\"[auth]\", request.query.token)\n"
        "print(request.args.get('debug'))\n"
        "System.out.println(\"user: \" + request.getParameter(\"u\"))\n"
        "System.err.println(\"failed \" + ctx.request.method)\n"
        "self.logger.error(\"bad txn \" + request.json['amount'])\n"
        "logging.getLogger(__name__).error(\"boom \" + request.query.v)\n"
        "app.logger.warning(\"rate \" + req.query.rate)\n"
        "log.debug(request.headers.get(\"trace\"))\n"
        "logger.critical(\"db from \" + request.host)\n"
        "console.log(req?.query?.tag)\n"
        "print(f\"cache-bust {request.args.get('v')}\")\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R036-loginj"]
    assert [i.line for i in hits] == list(range(1, 17)), f"R036-loginj mismatch: {hits}"
    assert all(i.severity == "high" for i in hits)


def test_log_injection_static_and_non_sink_quiet():
    """R036-loginj must not fire on static log literals, config/factory calls,
    log of a bare variable, other receivers, accessors outside the sink's argument
    list (ternary condition / later call), or non-sink assignments."""
    src = (
        "logger.info(\"service started\")\n"
        "logging.basicConfig(level=logging.DEBUG)\n"
        "logger = logging.getLogger(__name__)\n"
        "logger.setLevel(logging.DEBUG)\n"
        "console.log(\"connected\")\n"
        "System.out.println(\"ready\")\n"
        "print(\"wrote %d items\" % items_written)\n"
        "log.info(user.name)\n"
        "backend.info(request.query.backend)\n"
        "report = audit.replace(req.query.tag, request.body.id)\n"
        "log.info('ok') if request.query.ok else log.error('bad')\n"
        "parser.error('usage: %s' % request.query.v)\n"
        "pprint.pprint(request.query.v)\n"
        "logging.shutdown()\n"
        "console.error = request.query.v\n"
        "res.writeHead(200, {'X': request.query.v})\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R036-loginj"], issues


def test_cred_in_url_userinfo_flagged():
    """R037-credurl flags literals that embed real credentials: URI userinfo with a
    non-empty password (postgres/redis/mysql/mongodb/amqps/…://user:pass@host) and
    a credential query param in a URL (jdbc:…?user=x&password=y, ?token=…)
    (CWE-798)."""
    src = (
        'DATABASE_URL = "postgres://admin:Secret123@db.example.com:5432/app"\n'
        'redis_url = "redis://:passw0rd@localhost:6379/0"\n'
        'conn = psycopg2.connect("postgres://myuser:mypass@10.0.0.1/db")\n'
        'mongodb_url = "mongodb://user:secret@cluster0.example.com:27017/db"\n'
        'amqp_url = "amqps://guest:guest@rabbit.example.com:5671//"\n'
        'String url = "jdbc:mysql://localhost:3306/db?user=admin&password=hunter2";\n'
        'auth_url = "https://api.example.com/v1?token=AbCdEf1234"\n'
        'db_dsn = "mysql://root:rootpw@localhost/mydb"\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R037-credurl"]
    assert [i.line for i in hits] == list(range(1, 9)), f"R037-credurl mismatch: {hits}"
    assert all(i.severity == "high" for i in hits)


def test_cred_in_url_legit_and_dynamic_quiet():
    """R037-credurl must not fire on env-var reads, host:port URLs, bare user@host
    (no password), dynamic f-string/% /template placeholders, non-credential query
    params, data: URIs, or empty credential values."""
    src = (
        'DATABASE_URL = os.environ["DATABASE_URL"]\n'
        'url = "postgres://localhost:5432/app"\n'
        'base = "https://example.com/api/v1"\n'
        'api = "http://user@example.com/profile"\n'
        'f = f"postgres://{user}:{passwd}@{host}/db"\n'
        's = "mysql://user:%s@host/db" % (pwd,)\n'
        'target = "https://example.org/login?next=%2Fdashboard"\n'
        'img = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAE=="\n'
        'host = "db.internal:5432"\n'
        'url2 = "https://example.com:8080/healthz"\n'
        'const s = `postgres://${user}:${p}@host/db`\n'
        'cb = "http://example.com/callback?code=1234"\n'
        'empty = "https://example.com/path?password="\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R037-credurl"], issues


def test_insecure_permissions_world_writable_flagged():
    """R038-perm flags world-writable file permissions / disabled umask (CWE-732):
    os.chmod/os.open/fs.chmod(ync)/fs.open(ync)/fs.writeFile(ync)/Path().chmod with
    a 0o777/0o666/0o1777 (incl. setuid/setgid 0o4777) or legacy 0777 literal,
    os.makedirs/os.mkdir with mode=0o777/0o666/0o1777, umask(0)/(0o0) masking
    disabled, and argv-array ['chmod', '777'|'0777', …] invocations."""
    src = (
        'os.chmod("app/key.pem", 0o777)\n'
        "os.chmod(KEY_PATH, 0o666)\n"
        "fs.chmodSync('/tmp/upload', 0o777)\n"
        'Path("/srv/www").chmod(0o1777)\n'
        "fs.openSync(cache_path, 'w', 0o666)\n"
        "fs.writeFileSync('logs/app.log', data, { mode: 0o666 })\n"
        'os.makedirs("/srv/uploads", mode=0o777, exist_ok=True)\n'
        "os.mkdir(tmp, mode=0o666)\n"
        "os.makedirs('/srv', mode=0o1777)\n"
        "os.umask(0)\n"
        "umask(0)  # disable masking before mkdtemp\n"
        "process.umask(0)\n"
        "os.chmod(f, 0777)   # legacy leading-zero octal\n"
        "os.chmod(f, 0o4777) # setuid + world-writable\n"
        'subprocess.run(["chmod", "-R", "777", upload_dir])\n'
        'open("/tmp/key", "w").chmod(0o666)\n'
        "os.open(pidfile, os.O_CREAT | os.O_WRONLY, 0o666)\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R038-perm"]
    assert [i.line for i in hits] == list(range(1, 18)), f"R038-perm mismatch: {hits}"
    assert all(i.severity == "high" for i in hits)


def test_insecure_permissions_safe_and_dynamic_quiet():
    """R038-perm must not fire on restrictive modes (0o600/0o644/0o700/0o755),
    variable or symbolic-constant modes, proper umasks (0o022/0o077, and the
    over-restrictive 0o777), decimal 777 (not octal), bare shell `chmod 777 /tmp/x`,
    non-world-writable modes on the same call, or 0o777 appearing after the call
    closes."""
    src = (
        'os.chmod("app/key.pem", 0o600)\n'
        "os.chmod('x', 0o644)\n"
        "os.chmod(x, 0o700)\n"
        "os.chmod(path, perm)  # variable mode\n"
        "os.chmod(path, S_IRUSR | S_IWUSR)\n"
        "fs.chmodSync('/tmp/f', 0o644)\n"
        "os.makedirs(out, exist_ok=True)\n"
        "os.umask(0o022)\n"
        "os.umask(0o077)\n"
        "os.umask(0o777)  # over-restrictive, not a disable\n"
        "chmod 777 /tmp/x\n"
        "os.chmod(f, 777)  # decimal, not octal\n"
        'os.open(pidfile, os.O_CREAT | os.O_WRONLY, 0o644)\n'
        "os.chmod(f, 0o600)  # 0o777 mentioned later on the line\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R038-perm"], issues


def test_navigation_dynamic_and_executable_urls_flagged():
    """R039-nav flags client-side navigation to an unsafe URL (CWE-79/CWE-601):
    (A) javascript:/html-capable data: literals into window.open /
    location.assign|replace / location(.href)= / document.location / jQuery
    .attr('href', …) / element .href =; (B) request/URL-search-derived URLs
    (req.*/request.*/ctx.*/event.* accessors, searchParams.get(…),
    location.search-derived) into those sinks; (C) url-named variables
    (url/uri/link/endpoint/target/callback/webhook, case-insensitive like R031
    so returnUrl fires)."""
    src = (
        'location.href = "javascript:alert(1)";\n'
        'window.location = "javascript:" + payload;\n'
        "window.location.href = 'javascript:void(0)';\n"
        'document.location = "javascript:document.cookie";\n'
        'window.open("javascript:alert(document.cookie)");\n'
        'location.replace("javascript:alert(1)");\n'
        '$("#btn").attr("href", "javascript:alert(1)");\n'
        'a.href = "javascript:evil()";\n'
        'window.open("data:text/html,<script>alert(1)</script>");\n'
        'document.location = "data:text/html;base64,PHNjcmlwdD4=";\n'
        "window.open(req.query.returnUrl);\n"
        "window.location = request.query.next;\n"
        "location.href = req.params.link;\n"
        "location.assign(searchParams.get('url'));\n"
        "document.location.href = new URLSearchParams(window.location.search).get('redirect');\n"
        "if (req.query.next) location.href = req.query.next;\n"
        "location.replace(url);\n"
        "window.open(url, '_blank', 'noopener');\n"
        "location.href = returnUrl;\n"
        "window.open(deployedUrl);\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R039-nav"]
    assert [i.line for i in hits] == list(range(1, 21)), f"R039-nav mismatch: {hits}"
    assert all(i.severity == "high" for i in hits)


def test_navigation_static_literals_and_neutral_vars_quiet():
    """R039-nav must not fire on static URL literals (/login, https://…),
    non-URL element assignments (img.src / iframe.src), neutral variables
    (nextStep / iframeSrc / userSelectedItem / deployedUrl handled via R031
    convention), SCREAMING_CASE constants (BASE_URL / DEPLOYED_URL), the
    two-statement `const next = req.query.next; location.href = next;` shape,
    location.reload() / history.replaceState / location.hash = assignment,
    or a bare window.open() with no navigation argument."""
    src = (
        'location.href = "/login";\n'
        'window.location = "/home";\n'
        'window.open("https://example.com/docs");\n'
        'location.assign("/success?ref=" + orderId);\n'
        'a.href = "/profile";\n'
        'img.src = "/img/logo.png";\n'
        'iframe.src = "about:blank";\n'
        "location.href = nextStep;\n"
        "window.location = window.location.origin + pathname;\n"
        "window.location.reload();\n"
        "window.open(userSelectedItem);\n"
        "location.href = iframeSrc;\n"
        "const next = req.query.next; location.href = next;\n"
        "location.href = BASE_URL + '/docs';\n"
        "window.open(DEPLOYED_URL);\n"
        'history.replaceState(null, "", "/new");\n'
        "action.href = response.url;\n"
        "popup = window.open();\n"
        'location.hash = "tab-id";\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R039-nav"], issues


def test_tabnabbing_target_blank_without_noopener_flagged():
    """R040-tabnab flags (A) inline HTML/JSX anchors whose opening tag uses
    target="_blank" (case-insensitive, attribute order irrelevant) with no
    rel= value containing noopener/noreferrer, and (B) window.open(url,
    "_blank") with no features string or a features string lacking
    noopener/noreferrer — reverse tabnabbing (CWE-1021)."""
    src = (
        '<a href="https://example.com" target="_blank">Docs</a>\n'
        '<a href={docsUrl} target="_blank">Docs</a>\n'
        "'<a href=\"' + url + '\" target=\"_blank\">click</a>'\n"
        '<a target="_blank" href="/docs">Go</a>\n'
        '<a href="/x" TARGET="_BLANK" class="btn">Go</a>\n'
        '<a href="https://x.io" target="_blank" rel="external">\n'
        '<a href={u} target="_blank" rel="">\n'
        '<a href="./report.pdf" target="_blank">Report</a>\n'
        '<a href={{ \'/a/\' + id }} target="_blank">\n'
        '<a href={url} data-x="1" target="_blank" onClick={f}>\n'
        "<a href=\"https://x.com\" target='_blank'>\n"
        'window.open(url, "_blank");\n'
        "window.open(docsUrl, '_blank');\n"
        'window.open(link, "_blank", "width=600,height=400");\n'
        'window.open(link, "_blank", "toolbar=yes");\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R040-tabnab"]
    assert [i.line for i in hits] == list(range(1, 16)), f"R040-tabnab mismatch: {hits}"
    assert all(i.severity == "medium" for i in hits)


def test_tabnabbing_rel_noopener_or_safe_target_quiet():
    """R040-tabnab stays quiet when the anchor carries rel=noopener/noreferrer
    (any position/case/spacing), window.open passes noopener/noreferrer in the
    features string or targets _self, and for non-anchor / non-navigating code:
    plain links, img/form/name/_blank attributes, element.target assignment, a
    bare `const target = "_blank"` string, and id="blank" elements."""
    src = (
        '<a href="https://example.com" target="_blank" rel="noopener">Docs</a>\n'
        '<a href={url} target="_blank" rel="noopener noreferrer">Go</a>\n'
        '<a target="_blank" rel="noreferrer" href="/logout">Logout</a>\n'
        '<a rel="noopener" target="_blank" href="/x">\n'
        'window.open(url, "_blank", "noopener");\n'
        "window.open(url, '_blank', 'noopener,width=600');\n"
        'window.open(url, "_blank", "noopener", "extra");\n'
        'window.open(url, "_blank", "width=600,noopener");\n'
        "return window.open(url, '_blank', 'location=yes,noopener');\n"
        'window.open(url, "_self");\n'
        '<a href="/docs">Plain link</a>\n'
        '<img src="pic.jpg" alt="blank page">\n'
        '<form action="/submit" method="post" target="_blank">\n'
        'element.target = "_blank";\n'
        '<a name="_blank" href="#toc">Top</a>\n'
        'const target = "_blank";\n'
        '<a id="blank" href="/x">\n'
        "if (a && b) { link(target) }\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R040-tabnab"], issues


def test_postmsg_wildcard_or_dynamic_targetorigin_flagged():
    """R041-postmsg flags (A) postMessage with a wildcard '*' targetOrigin and
    (B) a dynamic targetOrigin derived from request/req/ctx/event, URL search
    params, or a url-named variable — the message payload is disclosed to or
    injectable by any/attacker-controlled origin (CWE-940 / CWE-345)."""
    src = (
        'window.postMessage(payload, "*");\n'
        "parent.postMessage(msg, '*');\n"
        'targetWindow.postMessage(JSON.stringify(x), "*");\n'
        'opener.postMessage(data, "*");\n'
        'iframe.contentWindow.postMessage(userData, "*");\n'
        "window.postMessage(data, request.query.origin);\n"
        "target.postMessage(msg, req.query.targetUrl);\n"
        "win.postMessage(x, returnUrl);\n"
        "frame.postMessage(d, searchParams.get('target'));\n"
        "window.postMessage(JSON.stringify(msg), new URLSearchParams(location.search).get('target'));\n"
        "parent.postMessage(cb, ctx.request.target);\n"
        "window.opener.postMessage(userData, userOrigin);\n"
        "postMessage(text, callbackUrl + '/api');\n"
        "postMessage(data, endpoint)\n"
        "window.postMessage(x, origin)\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R041-postmsg"]
    assert [i.line for i in hits] == list(range(1, 16)), f"R041-postmsg mismatch: {hits}"
    assert all(i.severity == "medium" for i in hits)


def test_postmsg_specific_or_same_origin_target_quiet():
    """R041-postmsg stays quiet for a literal specific-origin targetOrigin, the
    sender's own origin (window/document/location.origin), a Web Worker /
    service-worker transfer list array, an e./event.origin echo-back, a
    SCREAMING_CASE origin constant, single-argument/single-arg-object forms,
    and frames/messages unrelated to sending (addEventListener, guards without
    a postMessage call)."""
    src = (
        'window.postMessage(data, "https://app.example.com");\n'
        "content.postMessage(data, 'https://trusted.example.com/callback');\n"
        "parent.postMessage(data, window.location.origin);\n"
        "window.postMessage(data, document.location.origin);\n"
        "postMessage(data, location.origin);\n"
        'postMessage(data, "/");\n'
        'postMessage(data, "https://app.example.com" + path);\n'
        "postMessage(data);\n"
        "this.postMessage(result);\n"
        "worker.postMessage(data, [buf]);\n"
        "runner.postMessage(payload, [transfer]);\n"
        "this.postMessage({ type: 'ready' });\n"
        "target.postMessage(data, e.origin);\n"
        "if (e.origin === 'https://app.example.com') postMessage(reply, event.origin);\n"
        "postMessage(data, APP_ORIGIN);\n"
        "addEventListener('message', (e) => handle(e.data));\n"
        "parent.postMessage('hello');\n"
        "if (a && b) { worker.postMessage() }\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R041-postmsg"], issues


def test_websocket_cleartext_or_dynamic_endpoint_flagged():
    """R042-websock flags (A) a cleartext 'ws://…' WebSocket literal — the
    connection is sent unencrypted (CWE-319) — and (B) a WebSocket opened
    against a request/req/ctx/query/params/payload/event-derived or
    URL-search-derived URL, or a url-named variable / expression, which lets an
    attacker redirect the socket endpoint (CWE-918/939)."""
    src = (
        "const ws = new WebSocket('ws://localhost:8080/data');\n"
        'ws = new WebSocket("ws://chat.example.com");\n'
        "const sock = new WebSocket(request.query.url);\n"
        "ws = new WebSocket(req.params.socket);\n"
        "const ws = new WebSocket(ctx.request.body.url);\n"
        "conn = new WebSocket(searchParams.get('target'));\n"
        "conn = new WebSocket(new URLSearchParams(location.search).get('host'));\n"
        "ws = new WebSocket(location.search.split('?')[1]);\n"
        "ws = new WebSocket(endpoint);\n"
        "new WebSocket(wsUrl);\n"
        "new WebSocket(origin + '/ws');\n"
        "new WebSocket(callbackUrl);\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R042-websock"]
    assert [i.line for i in hits] == list(range(1, 13)), f"R042-websock mismatch: {hits}"
    assert all(i.severity == "medium" for i in hits)


def test_websocket_wss_literal_or_safe_origin_quiet():
    """R042-websock stays quiet for an encrypted 'wss://…' literal, a
    SCREAMING_CASE endpoint constant, a template fed from process.env, host-only
    location reads (window.location.host / protocol-based scheme derivation),
    a generic/await-derived variable, null/empty/one-arg forms, and global
    WebSocket.prototype usage (R039/R040 SCREAMING + location.* convention)."""
    src = (
        "const ws = new WebSocket('wss://api.example.com/socket');\n"
        'new WebSocket("wss://secure.example.com");\n'
        "new WebSocket(WS_ENDPOINT);\n"
        "new WebSocket(DEFAULT_SOCKET_URL);\n"
        "new WebSocket(`wss://${process.env.WS_URL}/socket`);\n"
        "new WebSocket(`wss://${host}/ws`);\n"
        "new WebSocket();\n"
        "const chat = io('wss://chat.example.com');\n"
        "new WebSocket(window.location.host + '/ws');\n"
        "new WebSocket((window.location.protocol === 'https:' ? 'wss://' : 'ws://') + window.location.host);\n"
        "ws = new WebSocket(connection);\n"
        "new WebSocket(null);\n"
        "const ws = new WebSocket('wss://' + window.location.host + '/ws');\n"
        "WebSocket.prototype.send(data);\n"
        "var WS = new WebSocket('wss://news.example.com/live');\n"
        "const ws = new WebSocket('');\n"
        "const ws = new WebSocket(await getConn());\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R042-websock"], issues


def test_math_random_security_value_flagged():
    """R043-math-random flags Math.random() used to build a security value — a
    token, OTP/pin, nonce, salt, session id, JWT/CSRF token or api key, whether
    the keyword precedes or follows the call (CWE-338)."""
    src = (
        "const token = Math.random().toString(36).slice(2);\n"
        "let otp = Math.floor(Math.random() * 1000000);\n"
        "const pin = String(Math.floor(Math.random() * 1e6)).padStart(6, '0');\n"
        "const nonce = String(Math.random());\n"
        "var apiKey = Math.random().toString(36).slice(2, 10);\n"
        "const resetToken = Math.random().toString(16);\n"
        "const secret = Math.random();\n"
        "const salt = Math.floor(Math.random() * 999999);\n"
        "const sessionId = Math.random().toString(36);\n"
        "const csrfToken = Math.random().toString(36);\n"
        "const passcode = Math.random().toString(36).slice(2);\n"
        "const digits = [0,1,2,3,4,5,6,7,8,9]; const otp = digits.sort(() => Math.random() - 0.5).join('');\n"
        "const unc = Math.random().toString(36); const accessToken = unc + suffix;\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R043-math-random"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), (
        f"R043-math-random mismatch: {hits}"
    )
    assert all(i.severity == "medium" for i in hits)


def test_math_random_plain_or_crypto_quiet():
    """R043-math-random stays quiet for Math.random() used as a plain PRNG
    (gaming dice, animations, shuffle utilities, delays) and for
    cryptographically secure substitutes (crypto.randomBytes / randomInt /
    randomUUID / getRandomValues / subtle.digest), plus SCRAMBLED-out
    keyword variables that hold the value off the same line."""
    src = (
        "const x = Math.random() * 10;\n"
        "const point = Math.random();\n"
        "Math.random() < 0.5 ? 'a' : 'b';\n"
        "const frame = Math.floor(Math.random() * frames.length);\n"
        "const token = crypto.randomBytes(32).toString('hex');\n"
        "const otp = crypto.randomInt(100000, 999999);\n"
        "const nonce = crypto.getRandomValues(new Uint32Array(1))[0];\n"
        "const token = await crypto.subtle.digest('SHA-256', data);\n"
        "function shuffle(a) { return a.sort(() => Math.random() - 0.5); }\n"
        "const seed = Math.round(Math.random() * 100);\n"
        "const url = '/roll?n=' + Math.floor(Math.random() * 6 + 1);\n"
        "setTimeout(() => Math.random(), 100);\n"
        "const randomToken = crypto.getRandomValues(new Uint8Array(32));\n"
        "const delay = Math.random() * 1000;\n"
        "const id = String(Math.random());\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R043-math-random"], issues


def test_storage_security_key_or_value_flagged():
    """R044-storage flags writes of security-named keys or values to
    localStorage / sessionStorage — setItem, bracket-key and dot-key
    assignment forms (CWE-922)."""
    src = (
        "localStorage.setItem('token', res.data.token);\n"
        'localStorage.setItem("accessToken", auth.token);\n'
        "sessionStorage.setItem('jwt', payload);\n"
        "localStorage.setItem('refresh_token', getToken());\n"
        "localStorage.setItem('csrf_token', csrf);\n"
        "localStorage.setItem('user_token', v);\n"
        "localStorage.setItem('secret_key', v);\n"
        "localStorage['session_id'] = sid;\n"
        "sessionStorage['user_token'] = token;\n"
        "localStorage.jwt = res.accessToken;\n"
        "localStorage.access_token = x;\n"
        "localStorage.setItem('userData', accessToken);\n"
        "localStorage.setItem('k', apiKey);\n"
        "localStorage.setItem(`auth_token`, v);\n"
        "localStorage.password = pwd;\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R044-storage"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), (
        f"R044-storage mismatch: {hits}"
    )
    assert all(i.severity == "medium" for i in hits)


def test_storage_generic_or_read_stays_quiet():
    """R044-storage stays quiet for generic keys (theme/cart/last_page/visited),
    key-management reads (getItem/removeItem/clear), non-write comparisons,
    word-substring keys like 'tokenizer', and values re-read from the same
    storage (a move, not a new sink)."""
    src = (
        "localStorage.setItem('theme', 'dark');\n"
        "localStorage.setItem('tokenizer', v);\n"
        "localStorage.setItem('cart', JSON.stringify(items));\n"
        "localStorage.removeItem('token');\n"
        "localStorage.clear();\n"
        "const t = localStorage.getItem('token');\n"
        "x = localStorage.token;\n"
        "localStorage.token == saved;\n"
        "const ok = localStorage.token != null;\n"
        "localStorage.setItem('count', n + 1);\n"
        "sessionStorage.setItem('visited', '1');\n"
        "localStorage.setItem('last_page', '/home');\n"
        "localStorage.setItem('k', localStorage.getItem('token'));\n"
        "localStorage.authHeader();\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R044-storage"], issues


def test_cookie_security_key_or_value_flagged():
    """R045-cookie flags client-side *writes* of security-named keys or
    values to document.cookie — plain '=', '+=' with snake_case keys and
    camelCase values (tokens/sessions/credentials can never be httpOnly,
    so XSS reads them straight off the cookie object, CWE-922)."""
    src = (
        "document.cookie = 'token=' + res.token;\n"
        "document.cookie = `session=${sess}`;\n"
        'document.cookie = "jwt=" + tok;\n'
        "document.cookie += 'csrf_token=' + c;\n"
        "document.cookie = 'access_token=' + at;\n"
        "document.cookie = 'sid=' + sess;\n"
        'document.cookie = "user_token=" + u;\n'
        "document.cookie = 'credential=' + cred;\n"
        "document.cookie = 'api_key=' + k;\n"
        "document.cookie = 'secret=' + s;\n"
        "document.cookie = 'password=' + p;\n"
        "document.cookie = 'sessionid=' + s;\n"
        "document.cookie = 'SESSION_ID=' + s;\n"
        "document.cookie = 'sid=' + sessionId;\n"
        "document.cookie = tokenStr + '; path=/';\n"
        "document.cookie = 'x=' + userToken;\n"
        "document.cookie = 'k=' + getToken();\n"
        "document.cookie = 'auth=' + jwt;\n"
        "document.cookie = 'data=' + accessToken;\n"
        "document.cookie = 'a=' + authToken;\n"
        "document.cookie = 'a=' + apiKey;\n"
        "document.cookie = 'a=' + sessionId;\n"
        "document.cookie = sessionStorage.getItem('token');\n"
        "document.cookie = 'k=' + session;\n"
        "document.cookie = 'auth=' + auth;\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R045-cookie"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), (
        f"R045-cookie mismatch: {hits}"
    )
    assert all(i.severity == "medium" for i in hits)


def test_cookie_generic_compare_or_read_stays_quiet():
    """R045-cookie stays quiet for generic keys (theme/lang/foo), reads,
    equality comparisons, other storage sinks (localStorage/sessionStorage),
    a security keyword in a *later* statement on the same line, and
    plural/suffix identifier forms (tokenizer/tokens/aTokens/tokenize)."""
    src = (
        "document.cookie = 'theme=dark';\n"
        "document.cookie = 'lang=en';\n"
        "document.cookie = 'foo=1; bar=2';\n"
        "x = document.cookie;\n"
        "document.cookie;\n"
        "localStorage.setItem('token', t);\n"
        "sessionStorage.jwt = x;\n"
        "document.cookie = '';\n"
        'document.cookie = "module=\'foo\'";\n'
        "document.cookie = 'foo=1'; login(token);\n"
        "document.cookie = 'v=' + tokenizer(name);\n"
        "document.cookie = 'v=' + tokens;\n"
        "document.cookie = 'v=' + aTokens;\n"
        "document.cookie = 'v=' + tokenize(x);\n"
        "if (document.cookie == saved) return;\n"
        "gh_token = 'x'; document.cookie = 'theme=dark';\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R045-cookie"], issues


def test_evaljs_dynamic_code_flagged():
    """R046-evaljs flags JS dynamic code execution from strings — new
    Function / Function() constructors (incl. window/globalThis/global
    dotted forms) and setTimeout/setInterval with a string first
    argument (CWE-95)."""
    src = (
        "new Function('return this')();\n"
        "const fn = Function('return config.secret');\n"
        "window.Function('alert(1)')();\n"
        "globalThis.Function(payload)();\n"
        "setTimeout('tick(' + n + ')', 100);\n"
        'setInterval("check();", 1000);\n'
        "const t = setTimeout(`poll(${q})`, 0);\n"
        "fn = new Function(a, b, body);\n"
        "window.setTimeout('boom()', 50);\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R046-evaljs"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), (
        f"R046-evaljs mismatch: {hits}"
    )
    assert all(i.severity == "medium" for i in hits)


def test_evaljs_callbacks_and_lowercase_functions_stay_quiet():
    """R046-evaljs stays quiet for callback/closure forms, lowercase
    `function` keywords, and non-sink identifiers (FunctionString,
    myFunction, foo.Function, Function.prototype, parser.setFunction,
    window.setTimeout with a callback)."""
    src = (
        "new FunctionString(code);\n"
        "myFunction(callback);\n"
        "setTimeout(callback, 100);\n"
        "setTimeout(() => cleanup(), 0);\n"
        "setInterval(() => {}, 1000);\n"
        "(function() { seed(); })();\n"
        "function helper() { return 1; }\n"
        "x = foo.Function;\n"
        "const res = Function.prototype.bind(x);\n"
        "eval(request_data);\n"
        "obj.Eval(data);\n"
        "parser.setFunction(d);\n"
        "const t = window.setTimeout(done, 200);\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R046-evaljs"], issues


def test_postmsg_recv_payload_consumed_without_sender_check_flagged():
    """R047-postmsg-recv fires when a window message handler consumes the
    payload (e.data / event['data']) without referencing event.origin /
    event.source / originalEvent on the same line (CWE-346)."""
    src = (
        "window.addEventListener('message', (e) => applySettings(e.data));\n"
        "window.onmessage = (e) => update(e.data);\n"
        "addEventListener('message', function(e) { render(e.data); });\n"
        'window.addEventListener("message", (event) => frame.do(event["data"]));\n'
        "document.addEventListener('message', evt => log(evt.data));\n"
        "self.addEventListener('message', e => { store(e.data); });\n"
        "onmessage = e => handle(e.data);\n"
        "window.addEventListener('message', e => { token = e.data; });\n"
        "parent.addEventListener('message', m => ingest(m.data));\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R047-postmsg-recv"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "medium" for i in hits)


def test_postmsg_recv_sender_validated_or_non_listener_stays_quiet():
    """R047-postmsg-recv stays quiet when the handler validates the sender
    (event.origin / event.source on the line), doesn't consume a payload, or
    isn't a window message listener at all (socket('message') events, Worker /
    MessagePort onmessage handles, own-property reads)."""
    src = (
        "window.addEventListener('message', (e) => { if (e.origin !== 'https://app.example') return; use(e.data); });\n"
        "window.addEventListener('message', handler);\n"
        "window.onmessage = null;\n"
        "socket.on('message', handle);\n"
        "window.addEventListener('data', fn);\n"
        "port.onmessage = (e) => { if (e.source === parent) send(e.data); };\n"
        "port.onmessage = e => log(e.data);\n"
        "worker.onmessage = (e) => apply(e.data);\n"
        "navigator.serviceWorker.onmessage = e => respond(e.data);\n"
        "window.addEventListener('message', e => this.frames.forEach(f => f.postMessage('hi', '*')));\n"
        "e['data'];\n"
        "const update = (data) => render(data);\n"
        "window.addEventListener('message', (e) => { if (!allowed(e.origin)) return; });\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R047-postmsg-recv"], issues


def test_cookieset_sensitive_key_without_flag_flagged():
    """R048-cookieset fires when a response set_cookie / res.cookie call names
    a security-sensitive key (session/token/credential) with none of
    Secure/HttpOnly/SameSite on the line (CWE-614/CWE-1004)."""
    src = (
        "response.set_cookie('session', token)\n"
        "resp.set_cookie('jwt', token.encode())\n"
        "response.set_cookie('csrf_token', csrf_value)\n"
        "r.set_cookie('sid', xsrf)\n"
        "res.cookie('auth_token', value);\n"
        "res.cookie('session', sid.value)\n"
        "response.set_cookie('api_key', k)\n"
        "res.cookie('token', t)\n"
        "response.set_cookie('secret', 's3cr3t')\n"
        "Response.set_cookie('SessionID', v)\n"
        "reply.set_cookie('id_token', tok)\n"
        "response.set_cookie('access-token', token)\n"
        "res.cookie('csrfToken', t, {});\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R048-cookieset"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "medium" for i in hits)


def test_cookieset_flagged_or_other_sinks_stay_quiet():
    """R048-cookieset stays quiet when any hardening flag appears on the line,
    the cookie name is generic, or the sink is client-side document.cookie /
    jar/$.cookie / a bare set_cookie (not response-scoped)."""
    src = (
        "response.set_cookie('session', token, httponly=True, secure=True, samesite='Lax')\n"
        "response.set_cookie('session', token, httponly=True)\n"
        "res.cookie('token', t, { httpOnly: true, secure: true })\n"
        "res.cookie('token', t, { secure: true })\n"
        "response.set_cookie('theme', 'dark')\n"
        "document.cookie = 'session=' + token;\n"
        "jar.set_cookie(cookie)\n"
        "$.cookie('session', v)\n"
        "res.setTimeout(fn, 100)\n"
        "response.cookies['session'] = token\n"
        "set_cookie('session', x)\n"
        "response.set_cookie('uid', uid, max_age=3600)\n"
        "res.cookie('csrf_token', csrf, { httpOnly: true })\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R048-cookieset"], issues


def test_fixatn_session_id_assigned_request_input_flagged():
    """R049-fixatn fires when a session container indexed by a sid-ish key or
    a session-object id property is assigned request-derived input (CWE-384)."""
    src = (
        "session['session_id'] = request.args.get('sid')\n"
        "request.session['sid'] = request.form['sid']\n"
        "req.session.id = req.query.sid\n"
        "flask.session['session-id'] = request.values.get('session')\n"
        "session['sid'] = request.json.get('sid')\n"
        "req.session.sessionID = req.cookies.sid\n"
        "session['id_token'] = request.GET.get('id_token')\n"
        "req.session.sid = req.params.sid\n"
        "session['sid'] = sanitize(request.args.get('sid'))\n"
        "flask.session['sid'] = flask.request.values.get('sid')\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R049-fixatn"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_fixatn_generic_key_server_value_or_readops_stay_quiet():
    """R049-fixatn stays quiet for generic session keys, server-generated
    session ids, reads/pops/comparisons, method-call update paths, and
    non-session receivers like client./db.session (client may legitimately
    adopt a provider session id)."""
    src = (
        "session['theme'] = request.args.get('theme')\n"
        "session['sid'] = secrets.token_hex(16)\n"
        "session['sid'] = uuid4().hex\n"
        "session.pop('sid')\n"
        "payload = session['sid']\n"
        "session['sid'] == prev\n"
        "request.session['sid'] == request.args.get('sid')\n"
        "request.session.update(locale=request.args.get('locale'))\n"
        "client.session['sid'] = req.args.get('x')\n"
        "db.session['sid'] = raw\n"
        "req.session.destroy()\n"
        "sessionvalidate('sid', request.args.get('sid'))\n"
        "request.session['token'] = request.headers.get('X-Session')\n"
        "request.session['session_id'] = uuid4().hex\n"
        "if request.session['sid'] == stored:\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R049-fixatn"], issues


def test_dynimp_request_derived_module_flagged():
    """R050-dynimp fires when a dynamic import primitive (Python __import__/
    importlib.import_module, Node require()/import()) is given a
    request-derived module/package name (CWE-470)."""
    src = (
        "__import__(request.args.get('mod'))\n"
        "importlib.import_module(request.form.get('module'))\n"
        "mod = import_module(request.values.get('pkg'))\n"
        "importlib.import_module('views.' + request.GET.get('view'))\n"
        "const mod = require(req.params.controller);\n"
        "require(request.query.module);\n"
        "await import(req.query.screen);\n"
        "require(`./services/${req.baseUrl}/handler`)\n"
        "const lib = require(request.headers.get('x-module'));\n"
        "require(req.body.pkg + '.js')\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R050-dynimp"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_dynimp_static_or_request_outside_call_stays_quiet():
    """R050-dynimp stays quiet for static literals (require('express')),
    plain/config variables, request data consumed after a static load
    (require('fs').readFileSync(req...)), non-call uses, and guarded
    receivers (app.require / myRequire / require.resolve)."""
    src = (
        "require('express')\n"
        "__import__('os')\n"
        "importlib.import_module('config.defaults')\n"
        "const mod = require(moduleName);\n"
        "await import(COMPONENT_BASE);\n"
        "import_module(CONFIG.module)\n"
        "require('fs').readFileSync(request.args.get('path'))\n"
        "importlib.import_module('os').system(request.args.get('x'))\n"
        "app.require('path')\n"
        "myRequire('x')\n"
        "require.cache['m']\n"
        "require(request)\n"
        "import_module()\n"
        "handler(require('fs'), vars)\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R050-dynimp"], issues


def test_hostpois_redirect_or_url_from_host_header_flagged():
    """R051-hostpois fires when a redirect target, absolute URL or
    reset/callback link is built from the client-supplied Host header —
    request.host / request.host_url or request|req.headers['Host'] / .Host /
    headers.get('Host') (CWE-644)."""
    src = (
        "return redirect(request.host_url)\n"
        "redirect(f\"https://{request.host}/login\")\n"
        "return redirect('https://' + request.host + '/auth')\n"
        "redirect(request.headers.get('Host'))\n"
        "redirect('http://' + req.headers.host)\n"
        "reset_url = f\"https://{request.headers.get('Host')}/reset?token={token}\"\n"
        "callback = 'https://' + req.headers.host + '/cb'\n"
        "verify_link = f'https://{request.host}/confirm/{uid}'\n"
        "url = request.host_url + '/verify'\n"
        "invite_url = request.headers['Host'] + '/invite?t=' + token\n"
        "return_url = 'https://' + request.host + '/done'\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R051-hostpois"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_hostpois_guards_reads_or_static_targets_stay_quiet():
    """R051-hostpois stays quiet for allowed-host guards, comparisons, log
    lines, plain reads of the host, static http(s) literals, non-Host
    headers, and redirects fed config constants or other request fields —
    no host source or no in-line construction signal."""
    src = (
        "if request.host not in ALLOWED_HOSTS: raise SuspiciousOperation\n"
        "if request.host != settings.HOST: abort(400)\n"
        "logger.warning('bad host %s', request.headers.get('Host'))\n"
        "expected = request.host == CONFIG.expected_host\n"
        "base_host = request.host_url  # used downstream\n"
        "ALLOWED_HOSTS = ['example.com', 'api.internal']\n"
        "return redirect(url_for('login', next=request.form.get('next')))\n"
        "return redirect(settings.LOGIN_URL)\n"
        "app.config['SERVER_NAME'] = 'example.com'\n"
        "verify_host = request.host == expected\n"
        "url = 'https://example.com/api'\n"
        "link = f\"https://{CONFIG.BASE_URL}/reset?t={token}\"\n"
        "redirect('https://accounts.oursite.com/login')\n"
        "host = request.headers.get('Host', 'default')  # for logging\n"
        "download_url = 'https://static.example.com/' + file\n"
        "if url == request.host: pass\n"
        "xh = request.headers.get('x-forwarded-host')\n"
        "remote = request.headers['X-Forwarded-For']\n"
        "csrf_origin = request.headers.get('Host')\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R051-hostpois"], issues


def test_hdritrust_spoofable_header_security_decision_flagged():
    """R052-hdritrust fires when a client-spoofable proxy/forwarded header
    (X-Forwarded-For / X-Real-IP / CF-Connecting-IP / X-Forwarded-Proto /
    X-Original-URL / Forwarded) feeds an in-line identity, scheme or URL
    decision — IP allowlist, rate limit, auth, https check, redirect (CWE-807)."""
    src = (
        "ip = request.headers.get('X-Forwarded-For')\n"
        "client_ip = request.headers.get('X-Real-IP')\n"
        "user_ip = req.headers['x-forwarded-for'].split(',')[0].strip()\n"
        "addr = request.headers.get('CF-Connecting-IP')\n"
        "remote = req.headers.get('Forwarded')\n"
        "if request.headers.get('X-Forwarded-For') not in ALLOWED_IPS: abort(403)\n"
        "if req.headers.get('x-forwarded-for') in INTERNAL_NETS: grant_admin()\n"
        "if request.headers.get('X-Forwarded-For') in BLOCKED_NETS: deny()\n"
        "rate_limit(request.headers.get('X-Forwarded-For'))\n"
        "request.environ['REMOTE_ADDR'] = request.headers.get('X-Forwarded-For')\n"
        "scheme = request.headers.get('X-Forwarded-Proto')\n"
        "is_secure = request.headers.get('X-Forwarded-Proto') == 'https'\n"
        "if request.headers.get('x-forwarded-proto') == 'https': secure_cookie(...)\n"
        "if request.headers.get('X-Forwarded-Proto') != 'https': return redirect('http://...')\n"
        "path = request.headers.get('X-Original-URL') or request.headers.get('X-Rewrite-URL')\n"
        "return redirect('https://' + request.headers.get('X-Forwarded-Host'))\n"
        "target = 'https://' + request.headers.get('X-Forwarded-Host') + '/cb'\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R052-hdritrust"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_hdritrust_logs_plain_reads_and_non_header_sources_stay_quiet():
    """R052-hdritrust stays quiet for log lines, analytics reads, display-only
    uses, generic variable buffering, non-spoofable peer sources, and headers
    that are not in the trusted-proxy set — no in-line decision signal."""
    src = (
        "logger.info('xff %s', request.headers.get('X-Forwarded-For'))\n"
        "xff = request.headers.get('X-Forwarded-For')  # analytics\n"
        "return render_template('x.html', ip=request.headers.get('X-Forwarded-For'))\n"
        "return render_template('x.html', client=request.headers.get('X-Forwarded-For'))\n"
        "proxy = request.headers.get('X-Forwarded-For', request.remote_addr)\n"
        "headers = request.headers.get('X-Forwarded-Proto') or 'http'\n"
        "app.run(host='0.0.0.0')\n"
        "trusted_proxies = ['127.0.0.1']\n"
        "ip = request.remote_addr\n"
        "user = request.args.get('u')\n"
        "scheme = 'https' if request.is_secure else 'http'\n"
        "r.headers.get('User-Agent')\n"
        "host = request.headers.get('Host') or request.host\n"
        "cookie = request.cookies.get('session')\n"
        "csrf_origin = request.headers.get('Host')\n"
        "if \"https\" == scheme: pass\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R052-hdritrust"], issues


def test_javaexec_os_command_from_request_or_variable_flagged():
    """R053-javaexec fires when Runtime.getRuntime().exec(...) or a
    ProcessBuilder construction is fed a non-literal argument — a request
    parameter, request header, @RequestBody-derived variable, argv, env lookup
    or string concatenation with a variable (Java always runs exec through the
    shell — CWE-78)."""
    src = (
        'Runtime.getRuntime().exec(request.getParameter("cmd"));\n'
        "Runtime.getRuntime().exec(cmd);\n"
        'Runtime.getRuntime().exec("ping " + request.getHeader("Host"));\n'
        'Runtime.getRuntime().exec("cmd /c " + command);\n'
        'Runtime.getRuntime().exec(new String[]{"sh", "-c", command});\n'
        'ProcessBuilder pb = new ProcessBuilder(request.getParameter("cmd"));\n'
        "ProcessBuilder pb = new ProcessBuilder(cmd);\n"
        'new ProcessBuilder("sh", "-c", cmd).start();\n'
        'new ProcessBuilder("/bin/sh", "-c", userInput).start();\n'
        'new ProcessBuilder(cmd).directory(new File("/tmp")).start();\n'
        'new ProcessBuilder("ls", "-la", "\"" + file + "\"").start();\n'
        "Runtime.getRuntime().exec(args[0]);\n"
        'Runtime.getRuntime().exec(env.get("SHELL_CMD"));\n'
        'Runtime.getRuntime().exec("sh -c " + req.getParameter("x"));\n'
        "new ProcessBuilder(Arrays.asList(command));\n"
        "ProcessBuilder pb = new ProcessBuilder(userCmd); pb.start();\n"
        "Runtime.getRuntime().exec(payload);\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R053-javaexec"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_javaexec_static_literals_other_sinks_stay_quiet():
    """R053-javaexec stays quiet for all-literal commands, ProcessBuilder
    config-only calls, regex .exec(), and shells owned by other rules — no
    non-literal argument feeds the Java exec sink."""
    src = (
        'Runtime.getRuntime().exec("ls -la /tmp");\n'
        'Runtime.getRuntime().exec("echo hello");\n'
        'new ProcessBuilder("ls", "-la").start();\n'
        'new ProcessBuilder("java", "-version");\n'
        "pb.redirectErrorStream(true);\n"
        'ProcessBuilder pb = new ProcessBuilder("python", "script.py");\n'
        "String m = pattern.exec(input).group(1);\n"
        "executor.execute(command);\n"
        "Runtime rt = Runtime.getRuntime();\n"
        'new ProcessBuilder(new String[]{"sh", "-c", "echo hi"}).start();\n'
        'new ProcessBuilder("sh", "-c", "/bin/echo hi").start();\n'
        'if (cmd != null) { Runtime.getRuntime().exec("ls"); }\n'
        "child_process.exec(command);\n"
        'subprocess.run(["ls", "-la"])\n'
        'logger.info("running " + cmd);\n'
        "void exec(String cmd) { return; }\n"
        "ProcessBuilder pb; pb = new ProcessBuilder();\n"
        'pb.command("ls", "-la");\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R053-javaexec"], issues


def test_javadeser_non_literal_stream_flagged():
    """R054-javadeser fires when ObjectInputStream or XMLDecoder is
    constructed from a non-literal stream — a request accessor, uploaded
    file, socket, byte buffer or any bare variable (CWE-502: readObject /
    XMLDecoder turn attacker-controlled bytes into live objects)."""
    src = (
        "ObjectInputStream ois = new ObjectInputStream(request.getInputStream());\n"
        "new XMLDecoder(request.getInputStream()).readObject();\n"
        "ObjectInputStream in = new ObjectInputStream(is);\n"
        "ObjectInputStream in = new ObjectInputStream(inputStream);\n"
        "new ObjectInputStream(new FileInputStream(uploadedFile))\n"
        "new ObjectInputStream(new ByteArrayInputStream(body.getBytes()))\n"
        "new XMLDecoder(new BufferedInputStream(new FileInputStream(userFile)))\n"
        "new ObjectInputStream(socket.getInputStream()).readObject();\n"
        "new ObjectInputStream(conn.getInputStream());\n"
        'new ObjectInputStream(new FileInputStream(env.get("UPLOAD_DIR") + "/" + name));\n'
        'Object o = new ObjectInputStream(req.getPart("file").getInputStream()).readObject();\n'
        "XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(xmlBytes));\n"
        "ObjectInputStream ois = new ObjectInputStream(cache.loadStreamByKey(userKey));\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R054-javadeser"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_javadeser_literal_classpath_or_plain_reference_stays_quiet():
    """R054-javadeser stays quiet for all-literal stream chains, classpath /
    this.getClass() resource loads (developer-bundled), readObject() follow-up
    calls, declarations, class.forName/import and any non-construction use —
    no attacker-touchable stream reaches the deserialization sink."""
    src = (
        'new ObjectInputStream(new FileInputStream("data.bin"));\n'
        'new ObjectInputStream(new BufferedInputStream(new FileInputStream("data.dat")));\n'
        "ois.readObject();\n"
        "import java.io.ObjectInputStream;\n"
        'Class<?> c = Class.forName("ObjectInputStream");\n'
        'new ObjectInputStream(ClassLoader.getSystemResourceAsStream("conf.ser"))\n'
        "new XMLDecoder(new ByteArrayInputStream(XML_TEMPLATE.getBytes()));\n"
        "Object sig = new ObjectInputStream(new ByteArrayInputStream(HARDCODED_BYTES));\n"
        'new ObjectInputStream(this.getClass().getResourceAsStream("data.ser"))\n'
        'new ObjectInputStream(this.getClass().getClassLoader().getResourceAsStream("x.ser"))\n'
        "ObjectInputStream ois = null;\n"
        "public ObjectInputStream create(InputStream in) { return in; }\n"
        'String s = "ObjectInputStream(" + x + ")";\n'
        'new ObjectInputStream(new FileInputStream("config" + File.separator + "data.bin"));\n'
        'ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream("payload".getBytes()));\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R054-javadeser"], issues


def test_spelinj_non_literal_expression_flagged():
    """R055-spelinj fires when a SpEL / MVEL / OGNL / EL sink evaluates a
    non-literal expression — a request-derived variable, method chain,
    concatenated-with-'+' string, or a config lookup (CWE-917: expression
    languages compile the string in the JVM, so request input can reach
    static-method invocation for RCE)."""
    src = (
        'Expression exp = new SpelExpressionParser().parseExpression(request.getParameter("expr"));\n'
        "Expression exp = new TemplateAwareExpressionParser().parseExpression(header);\n"
        "Expression exp = parser.parseExpression(userInput);\n"
        "Expression exp = spelParser.parseExpression(body);\n"
        "Object v = expressionParser.parseExpression(payload);\n"
        "Expression e = parser.parseExpression(SPEL_TEMPLATE_PREFIX + userToken);\n"
        'Object r = MVEL.eval(request.getParameter("formula"));\n'
        "Serializable compiled = MVEL.compileExpression(ruleSource);\n"
        "Object r = MVEL.executeExpression(compiled, ctx);\n"
        'Object r = MVEL.eval("sum:" + total + ":" + input);\n'
        "Object v = Ognl.getValue(ognlExpr, ctx, root);\n"
        "Object v = OgnlUtil.getValue(config.get(\"expr\"), context, null);\n"
        "Object v = Ognl.parseExpression(userFormula);\n"
        'Object v = Ognl.getValue("id:" + rawId, ctx);\n'
        "new ELProcessor().eval(expr);\n"
        "elProcessor.eval(input);\n"
        "Object r = ExpressionFactory.newInstance().createValueExpression(elContext, expr, String.class);\n"
        "Object r = ExpressionFactory.newInstance().createMethodExpression(elCtx, userExpr, String.class, null);\n"
        "Object v = elp.setValue(propName, val);\n"
        "Object v = factory.createValueExpression(context, userExpr, Object.class);\n"
        'Object v = exprFactory.createValueExpression(ctx, request.getParameter("e"), String.class);\n'
        'Object v = elProcessor.eval("#{bean." + prop + "}");\n'
        'Object v = spelParser.parseExpression("user.name" + suffix);\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R055-spelinj"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_spelinj_literal_or_no_sink_stays_quiet():
    """R055-spelinj stays quiet for literal expression strings, declarations,
    imports, custom-receiver parser names, SCREAMING_SNAKE expression
    constants, null args, and MVEL / OGNL value writes — no non-literal
    expression reaches an EL sink."""
    src = (
        'Expression exp = new SpelExpressionParser().parseExpression("ROLE_USER");\n'
        'Expression exp = parser.parseExpression("user.id");\n'
        'Expression exp = parser.parseExpression("Hello " + "world");\n'
        "SpelExpressionParser parser = new SpelExpressionParser();\n"
        "private final ExpressionParser parser = new SpelExpressionParser();\n"
        "import org.springframework.expression.spel.standard.SpelExpressionParser;\n"
        "Query query = QueryParser.parseExpression(sql);\n"
        "XmlNode n = new XmlParser().parseExpression(doc);\n"
        "ASTNode node = sqlParser.parseExpression(rawSql);\n"
        'Object r = MVEL.eval("2 + 2");\n'
        "Object r = MVEL.eval(null);\n"
        'Ognl.setValue("root", ctx, value);\n'
        'Object r = ExpressionFactory.newInstance().createValueExpression(elContext, "value", String.class);\n'
        "elProcessor.eval(null);\n"
        'String sql = "SELECT " + userCol + " FROM t";\n'
        "exprHandler.eval(userInput);\n"
        "parser.parseExpression(DEFAULT_EXPR);\n"
        "MVEL.eval(BOOT_EXPR);\n"
        "Ognl.getValue(DEFAULT_OGNL, root);\n"
        "elp.setValue(DEFAULT_NAME, value);\n"
        "Object r = Ognl.getValue(null, root);\n"
        "Integer n = MVEL.eval(42);\n"
        'Object v = factory.createValueExpression(context, "#{bean.prop}", Object.class);\n'
        'Object v = factory.createValueExpression(context, "#{bean." + prop + "}", Object.class);\n'
        'Object v = elp.setValue("name", value);\n'
        'engine.eval(request.getParameter("x"));\n'
        "groovyShell.evaluate(code);\n"
        "interpreter.eval(userCode);\n"
        "jshell.eval(script);\n"
        'config.getExpression("x");\n'
        "mvel.eval(code);\n"
        'request.getParameter("expr");\n'
        "sqlParser.parseExpression();\n"
        "Comparator c = parser.parseExpr(token);\n"
        '// spelParser.parseExpression(request.getParameter("expr"));\n'
        "// elProcessor.eval(userExpr);\n"
        "// Ognl.getValue(ognlExpr, root);\n"
        'String s = "parser.parseExpression(expr);";\n'
        'String t = "MVEL.eval(code);";\n'
        'String u = "elProcessor.eval(\\"#{a.b}\\");";\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R055-spelinj"], issues


def test_jpaqli_string_built_query_flagged():
    """R056-jpaqli fires when a JPQL / HQL / native SQL query is assembled by
    string concatenation or a builder and fed to a JPA EntityManager or
    Hibernate session query sink — '+' literal-concat of a lowercase
    identifier, a builder/.toString() chain, a request accessor, or an
    unquoted 'var + lower' expression (CWE-943: the query string crosses
    into the DB, so request input can smuggle OR/UNION fragments)."""
    src = (
        'TypedQuery<User> q = em.createQuery("SELECT u FROM User u WHERE u.name = " + name);\n'
        'Query q = entityManager.createQuery("FROM Product WHERE price > " + price);\n'
        'List<User> r = em.createQuery("SELECT u FROM User u WHERE u.id = " + request.getParameter("id")).getResultList();\n'
        'Query q = em.createNativeQuery("SELECT * FROM " + tableName);\n'
        'Query q = entityManager.createNativeQuery("SELECT * FROM " + user.getTable() + " WHERE id = " + id);\n'
        'Query q = manager.createNamedQuery("User.findBy" + suffix);\n'
        'Query q = em.createStoredProcedureQuery("find_" + procName);\n'
        "Query q = em.createQuery(queryBuilder.toString());\n"
        'Query q = em.createQuery(sb.append("FROM User WHERE name = ").append(userInput).toString());\n'
        "Query q = em.createQuery(\"FROM User WHERE name = '\" + userInput + \"'\");\n"
        'Query q = session.createQuery("FROM User WHERE id = " + userId);\n'
        'Query q = currentSession.createNativeQuery("SELECT * FROM " + dynamicTable);\n'
        'SQLQuery q = session.createSQLQuery("DELETE FROM " + table + " WHERE id=" + id);\n'
        'TypedQuery<Item> tq = em.createQuery("SELECT i FROM Item i WHERE i.code = " + code, Item.class);\n'
        'Query q = em.createQuery("FROM Order o WHERE o.state = " + state + " ORDER BY o.id");\n'
        'Query q = em.createQuery(JPQL_SELECT + whereClause);\n'
        'Query q = sessionFactory.getCurrentSession().createQuery("FROM " + tableName + " WHERE id = " + id);\n'
        'TypedQuery<User> q = entityManager.createQuery(qb.toString(), User.class);\n'
        'Query q = em.createQuery(request.getParameter("query"));\n'
        'Query q = em.createQuery("FROM " + entity.getClass().getSimpleName() + " WHERE id = " + id);\n'
        'Query q = em.createQuery(HEADER_PREFIX + req.getHeader("filter"));\n'
        'Query q = entityManager.createQuery(queryText + dynamicSuffix);\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R056-jpaqli"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_jpaqli_literal_bare_identifier_or_other_sinks_stay_quiet():
    """R056-jpaqli stays quiet for parameterized (:param / ?) queries, the
    Criteria API builder / TypedQuery<CriteriaQuery>, bare-identifier query
    objects / UPPER_CASE constants, all-literal queries, arithmetic inside a
    literal string, and non-query string building — no concatenated lowercase
    input reaches a JPA / Hibernate query sink."""
    src = (
        'TypedQuery<User> q = em.createQuery("SELECT u FROM User u WHERE u.name = :name");\n'
        'Query q = em.createQuery("FROM User WHERE id = :id").setParameter("id", id);\n'
        'List<User> r = em.createQuery("SELECT u FROM User u WHERE u.active = true").getResultList();\n'
        'TypedQuery<Item> tq = em.createQuery("SELECT i FROM Item i WHERE i.id = :id", Item.class);\n'
        'Query q = em.createNativeQuery("SELECT * FROM users WHERE id = ?");\n'
        "CriteriaBuilder cb = em.getCriteriaBuilder();\n"
        "CriteriaQuery<User> cq = cb.createQuery(User.class);\n"
        "TypedQuery<User> q = em.createQuery(cq);\n"
        "Query q = em.createQuery(criteriaQuery);\n"
        "Query q = em.createQuery(queryObject);\n"
        'Query q = em.createQuery(cq.where(cb.equal(u.get("name"), "x")));\n'
        "Query query = em.createQuery(QUERY_NAME);\n"
        "em.createQuery(EMPTY);\n"
        'Query q = em.createNamedQuery("User.findByEmail");\n'
        'Query q = em.createStoredProcedureQuery("find_orders");\n'
        'Query q = session.createQuery("FROM User WHERE name = :name");\n'
        'Query q = session.createNativeQuery("SELECT * FROM users WHERE id = ?");\n'
        'em.createQuery("SELECT u FROM User u WHERE u.id=" + "1");\n'
        'em.createNativeQuery("SELECT * FROM log");\n'
        "import javax.persistence.EntityManager;\n"
        'Query q = em.createQuery("FROM User WHERE name = " + NAME_CONST);\n'
        'em.createQuery("SELECT u.a+b FROM User u").getResultList();\n'
        'Query q = em.createQuery("FROM User WHERE total > x + y");\n'
        'session.createQuery("FROM User WHERE id = :id").setParameter("id", id).list();\n'
        'String sql = "FROM User WHERE name = " + NAME_CONST;\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R056-jpaqli"], issues


def test_ssrf_java_request_derived_or_non_literal_url_flagged():
    """R057-ssrf fires when a Java URL / HTTP-client sink receives a
    non-literal, request-derived or concatenated URL — new URL() on request
    input, URL.openConnection/openStream on a bare lowercase or builder-chain
    argument, \"literal\" + lower-concat URL strings, HttpClient.send with
    URI.create(request...), RestTemplate/WebClient/OkHttpClient concat URLs,
    Apache HttpGet/HttpPost on request input, and url/u-named variables
    opened (CWE-918: the server fetches an attacker-chosen target such as
    cloud metadata or internal services)."""
    src = (
        'URL url = new URL(request.getParameter("url"));\n'
        'URL u = new URL(req.getParameter("target"));\n'
        "HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();\n"
        "URLConnection c = new URL(userInput).openConnection();\n"
        "URLConnection conn = new URL(sb.toString()).openConnection();\n"
        'URLConnection conn = new URL("https://api.example.com/report?dest=" + request.getParameter("url")).openConnection();\n'
        'String html = new URL(baseUrl + "/" + request.getParameter("doc")).openStream();\n'
        'HttpClient client = HttpClient.newHttpClient(); client.send(HttpRequest.newBuilder().uri(URI.create(request.getParameter("url"))).build(), HttpResponse.BodyHandlers.ofString());\n'
        'RestTemplate rest = new RestTemplate(); String r = rest.getForObject("https://internal/" + request.getParameter("path"), String.class);\n'
        'WebClient.create().get().uri("http://meta.internal/" + userInput).retrieve();\n'
        'OkHttpClient client = new OkHttpClient(); Request r = new Request.Builder().url("http://169.254.169.254/" + path).build();\n'
        "HttpURLConnection conn = (HttpURLConnection) url.openConnection();\n"
        'String json = new RestTemplate().getForObject("http://" + backend + "/status", String.class);\n'
        'CloseableHttpResponse resp = httpclient.execute(new HttpGet(request.getParameter("url")));\n'
        "HttpPost post = new HttpPost(req.getParameter(\"target\"));\n"
        'URI target = URI.create(request.getParameter("dest"));\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R057-ssrf"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_ssrf_java_literal_const_or_other_targets_stay_quiet():
    """R057-ssrf stays quiet for literal https:// URLs, ALL_CAPS URL
    constants, bare HttpRequest objects passed to send(), non-URL variables,
    imports, getResource()/classloader lookups, literal-path WebClient calls
    and plain string building — no fused URL sink receives non-literal
    input."""
    src = (
        'URL url = new URL("https://example.com/api");\n'
        'URL u = new URL("https://example.com");\n'
        'HttpURLConnection conn = (HttpURLConnection) new URL("https://example.com").openConnection();\n'
        'URLConnection conn = new URL("https://example.com/report").openConnection();\n'
        'String html = new URL("https://example.com").openStream();\n'
        "URLConnection conn = conn2.openConnection();\n"
        'URI uri = URI.create("https://example.com");\n'
        "HttpClient client = HttpClient.newHttpClient(); client.send(request, handler);\n"
        'client.send(HttpRequest.newBuilder().uri(URI.create(BASE_URL)).build(), handler);\n'
        'HttpURLConnection hc = (HttpURLConnection) new URL("https://" + HOST).openConnection();\n'
        'String r = restTemplate.getForObject("https://api.example.com/users", String.class);\n'
        'webClient.get().uri("/api/users").retrieve();\n'
        "import java.net.URL;\n"
        'URLConnection conn = this.getClass().getResource("x").openConnection();\n'
        'String connector = url + "/connect";\n'
        'URLConnection conn = new URL(config.get("url")).openConnection();\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R057-ssrf"], issues


def test_jdbcsqli_concat_or_request_derived_sql_flagged():
    """R058-jdbcsqli fires when a JDBC Statement/PreparedStatement or Spring
    JdbcTemplate sink receives a concatenated, request-derived or builder-
    chain SQL string — '"...' + lowercase identifier, a bare request accessor
    / builder .toString() argument, a createStatement().execute* chain, or a
    template query/update/execute (CWE-89: the SQL text crosses into the JDBC
    driver, so request input can inject OR/UNION or stack statements)."""
    src = (
        'stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);\n'
        'st.executeUpdate("DELETE FROM orders WHERE id = " + orderId);\n'
        'ps.executeUpdate("UPDATE accounts SET balance = " + amount);\n'
        'pstmt.execute("DROP TABLE " + tbl);\n'
        'statement.executeLargeUpdate("INSERT INTO log VALUES(" + msg + ")");\n'
        'stmt.executeQuery(request.getParameter("query"));\n'
        'ps.executeUpdate(req.getParameter("sql"));\n'
        "stmt.executeQuery(queryBuilder.toString());\n"
        'statement.executeUpdate(sb.append("UPDATE t SET x=").append(val).toString());\n'
        'conn.prepareStatement("SELECT * FROM products WHERE id = " + productId);\n'
        'connection.prepareStatement("SELECT " + cols + " FROM t WHERE pk = " + key);\n'
        'PreparedStatement ps = conn.prepareStatement(request.getParameter("sqlStr"));\n'
        "conn.prepareStatement(builder.toString());\n"
        'conn.createStatement().executeQuery("SELECT * FROM users WHERE name = " + name);\n'
        'connection.createStatement().executeUpdate("DELETE FROM t" + suffix);\n'
        'conn.createStatement().executeQuery(request.getParameter("id"));\n'
        'jdbcTemplate.query("SELECT * FROM users WHERE id = " + id, mapper);\n'
        "jdbcTemplate.update(\"UPDATE users SET role = '\" + role + \"'\");\n"
        'namedParameterJdbcTemplate.queryForObject("SELECT " + col + " FROM t", map, String.class);\n'
        'jdbcTemplate.queryForList("SELECT * FROM " + tableName);\n'
        'jt.execute("TRUNCATE " + targetTable);\n'
        'jdbcTemplate.queryForObject("SELECT count(*) FROM t WHERE c = " + code, Integer.class);\n'
        'jdbcTemplate.update(request.getParameter("sqlDml"));\n'
        "conn.createStatement().execute(builder.toString());\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R058-jdbcsqli"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_jdbcsqli_literal_parameterized_or_other_targets_stay_quiet():
    """R058-jdbcsqli stays quiet for parameterized (? / :name) queries, fully
    literal SQL, UPPER_CASE SQL constants, ALL_CAPS concat operands, bare
    Statement objects or no-arg execute(), setString binding, in-string
    arithmetic, non-query string building, JdbcTemplate lambda receivers and
    custom receivers — no fused JDBC sink receives concatenated input."""
    src = (
        'stmt.executeQuery("SELECT * FROM users WHERE id = 5");\n'
        'ps.executeUpdate("UPDATE t SET x = 1");\n'
        'pstmt.executeQuery("SELECT * FROM users WHERE id = ?");\n'
        'conn.prepareStatement("SELECT * FROM users WHERE id = ?");\n'
        'connection.prepareStatement("INSERT INTO t VALUES (?, ?)");\n'
        "conn.prepareStatement(QUERY_BY_ID);\n"
        "ps.executeQuery();\n"
        "stmt.execute();\n"
        "int n = stmt.executeUpdate();\n"
        'jdbcTemplate.query("SELECT * FROM users", mapper);\n'
        'jdbcTemplate.update("UPDATE users SET n = ? WHERE id = ?", name, id);\n'
        'jdbcTemplate.queryForObject("SELECT count(*) FROM users", Integer.class);\n'
        "import java.sql.Statement;\n"
        "Statement stmt = connection.createStatement();\n"
        "ps.setString(1, userInput);\n"
        'namedParameterJdbcTemplate.update("UPDATE t SET n = :n", params);\n'
        "jdbcTemplate.execute(connection -> connection.createStatement());\n"
        'ResultSet rs = stmt.executeQuery(BASE_QUERY + " ORDER BY id");\n'
        'stmt.executeQuery("SELECT * FROM t WHERE a+b = 2");\n'
        'String sql = "SELECT * FROM users WHERE id = " + userId;\n'
        "jdbcTemplate.query(sql, new RowMapper<U>() {});\n"
        'ex.executeQuery("SELECT * FROM t");\n'
        "statement.executeQuery(SQL_CONST);\n"
        'conn.prepareStatement("SELECT " + COLUMNS);\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R058-jdbcsqli"], issues


def test_xpathjava_concat_or_request_derived_expression_flagged():
    """R059-xpathjava fires when a Java XPath sink — javax.xml.xpath
    XPathFactory.newInstance().newXPath().evaluate/compile/evaluateExpression,
    an xpath/xp-named receiver, or DOM4J document.selectNodes/
    selectSingleNode — is fed a concatenated, request-derived or builder-chain
    expression (CWE-643: the predicate crosses into the XPath engine, so
    request input can inject boolean tautologies or read sibling nodes)."""
    src = (
        'XPathExpression expr = XPathFactory.newInstance().newXPath().compile("/users/user[name=\'" + name + "\']");\n'
        'XPathExpression expr = xpath.compile("/orders/order[id=" + orderId + "]");\n'
        'String value = xpath.evaluate("/users/user[name=\'" + creds + "\']", doc);\n'
        'String value = xpath.evaluate(request.getParameter("q"), doc);\n'
        'String r = XPathFactory.newInstance().newXPath().evaluate("//item[price>" + price + "]", doc);\n'
        'String r = xpath.evaluate(qb.toString(), doc);\n'
        'String r = xp.evaluate("/root[@n=\'" + attr + "\']", source);\n'
        'String r = xpath.evaluate("/users/" + req.getParameter("u"), doc);\n'
        'XPathExpression ex = xpath.compile("/x[@v=\'" + user + "\']");\n'
        'String r = xpathEvaluator.evaluate("//node[@" + key + "=" + val + "]", input);\n'
        'String v = XPathFactory.newInstance().newXPath().evaluate("/r/" + path, doc);\n'
        'NodeList list = document.selectNodes("/users/user[name=\'" + login + "\']");\n'
        'Node n = doc.selectSingleNode("//item[id=" + itemId + "]");\n'
        'Object v = xpath.compile("string(//user[" + cond + "])");\n'
        'String o = xp.evaluate(bb.toString(), src);\n'
        'String v = root.selectNodes("/users/user[name=\'" + getUserInput() + "\']").size() > 0 ? "y" : "n";\n'
        'String v = xpath.evaluate(req.getQueryString(), doc);\n'
        'String v = XPathFactory.newInstance().newXPath().evaluate(sb.toString(), doc);\n'
        'String v = document.selectNodes("/x[@y=\'" + request.getParameter("y") + "\']").get(0).getText();\n'
        'String o = xpath.evaluate("/users/" + request.getUserPrincipal().getName(), doc);\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R059-xpathjava"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_xpathjava_literal_constant_or_non_sink_targets_stay_quiet():
    """R059-xpathjava stays quiet for fully literal expressions,
    SCREAMING_SNAKE constants, bare String variables, ALL_CAPS concat
    operands, in-string arithmetic, XPath construction / variable-resolution
    without a sink call, DOM traversal, Selenium By.xpath staging and
    non-XPath receivers — no fused Java XPath sink receives string-built
    input."""
    src = (
        "String value = xpath.evaluate(\"/users/user[name='admin']\", doc);\n"
        "String value = xpath.evaluate(USER_XPATH, doc);\n"
        "String value = xpath.evaluate(query, doc);\n"
        "XPathFactory.newInstance().newXPath();\n"
        "xpath.setXPathVariableResolver(v);\n"
        'String r = xpath.evaluate("/users" + PATH_SUFFIX, doc);\n'
        "String r = xpath.evaluate(\"/users/user[name='\" + NAME + \"']\", doc);\n"
        'String r = doc.getElementsByTagName("item").item(0).getTextContent();\n'
        "SAXBuilder sb = new SAXBuilder();\n"
        'Node node = driver.findElement(By.xpath("//div").getNode());\n'
        "String r = xpath.evaluate(doc);\n"
        'String r = xpath.evaluate("/a" + "/b", doc);\n'
        "String value = xpath.compile(QUERY_CONST).evaluate(doc);\n"
        "Document doc = dbFactory.newDocumentBuilder().parse(xmlFile);\n"
        'String r = xpath.evaluate("/x[@v=\'" + (String) input + "\']", source);\n'
        'String r = xp.evaluateExpression("/users/user[@id=1]");\n'
        'String r = xpath.evaluate("/n" + (a + b), doc);\n'
        'String v = xpath.evaluate("/users", null);\n'
        "String r = query.evaluate(doc);\n"
        "String r = expression.evaluate(doc);\n"
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R059-xpathjava"], issues


def test_openredir_concat_or_request_derived_redirect_flagged():
    """R060-openredir fires when a Java redirect sink — HttpServletResponse
    .sendRedirect, response.setHeader("Location", ...), Spring RedirectView /
    redirectView.setUrl, or ModelAndView "redirect:" views — is fed a
    concatenated, request-derived, unbounded bare-identifier or builder-chain
    URL (CWE-601: the response 3xx's to an attacker-chosen host)."""
    src = (
        'response.sendRedirect("/login?to=" + returnTo);\n'
        'response.sendRedirect(request.getParameter("next"));\n'
        'resp.sendRedirect(req.getHeader("Referer"));\n'
        'response.sendRedirect("/next?u=" + userId);\n'
        'response.sendRedirect(sb.toString());\n'
        'response.setHeader("Location", request.getParameter("goto"));\n'
        'response.setHeader("Location", "/next?u=" + userId);\n'
        'RedirectView view = new RedirectView("http://go/?r=" + ref);\n'
        'RedirectView v = new RedirectView(request.getParameter("dest"));\n'
        'redirectView.setUrl(request.getParameter("to"));\n'
        'response.sendRedirect(request.getRequestURL().toString());\n'
        'redirectView.setUrl("/go/?t=" + token);\n'
        'return new ModelAndView("redirect:" + dest);\n'
        'return new ModelAndView("redirect:/" + path);\n'
        'response.sendRedirect(nextUrl);\n'
        'res.sendRedirect(target);\n'
        'httpResponse.sendRedirect("/login?cb=" + callbackUrl);\n'
        'response.sendRedirect(request.getRequestURI());\n'
        'resp.sendRedirect(builder.build());\n'
        'return new ModelAndView("redirect:https://go/?u=" + encoded);\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R060-openredir"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_openredir_literal_constant_or_non_redirect_targets_stay_quiet():
    """R060-openredir stays quiet for fully literal redirect URLs,
    SCREAMING_SNAKE constants, bare String variables, ALL_CAPS concat
    operands, status-only responses, dispatcher forwards, non-redirect
    headers and attribute plumbing — no fused redirect sink receives
    string-built input."""
    src = (
        'response.sendRedirect("/home");\n'
        'response.sendRedirect(HOME_URL);\n'
        'response.setHeader("Location", "/login");\n'
        'RedirectView view = new RedirectView("/done");\n'
        'return new ModelAndView("redirect:/home");\n'
        'response.setStatus(302);\n'
        'String s = request.getParameter("u");\n'
        'request.getRequestDispatcher("/home").forward(request, response);\n'
        'response.sendError(404);\n'
        'response.sendRedirect("/go" + SUFFIX);\n'
        'response.sendRedirect(request.getContextPath() + "/home");\n'
        'RedirectView v = new RedirectView(url);\n'
        'return new ModelAndView("user/" + uid + ".jsp");\n'
        'response.setHeader("Cache-Control", "no-cache");\n'
        'model.addAttribute("url", request.getParameter("u"));\n'
        'response.sendRedirect(null);\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R060-openredir"], issues


def test_ldapjndi_concat_or_request_derived_search_flagged():
    """R061-ldapjndi fires when a Java LDAP / Spring LDAP search sink —
    JNDI InitialDirContext/DirContext/LdapContext-family receiver .search
    or Spring LdapTemplate.search / searchForObject / searchForContext — is
    fed a concatenated, request-derived or builder-chain filter/base
    (CWE-90: LDAP ANDs attacker terms like ')(objectClass=*)' into the filter,
    bypassing auth or reading sibling entries)."""
    src = (
        'ctx.search("ou=people", "(uid=" + username + ")");\n'
        'dirContext.search(BASE, "(cn=" + cn + ")");\n'
        'initialDirContext.search(b, "(mail=" + email + ")");\n'
        'ldapContext.search(base, "(uid=" + login + ")");\n'
        'ldapTemplate.search("", "(uid=" + uid + ")", LdapNameMapper.class);\n'
        'ctx.search("ou=people", request.getParameter("filter"));\n'
        'ldapTemplate.search(base, req.getHeader("filter"));\n'
        'ctx.search(req.getParameter("base"), "(uid=*)");\n'
        'dirContext.search(base, sb.toString());\n'
        'ldapTemplate.searchForObject(base, "(uid=" + user + ")", User.class);\n'
        'ctx.search(base, bf.append("(").append("uid=").toString());\n'
        'ldapTemplate.search("", "(uid=" + request.getParameter("u") + ")", mapper);\n'
        'ctx.search("dc=x", "(cn=" + displayName + ")");\n'
        'dirContext.search(BASE, builder.build());\n'
        'ldapTemplate.searchForContext(base, "(cn=" + q + ")");\n'
        'ldapContext.search(base, sb2.append("(uid=").append(user).append(")").toString());\n'
        'ldapTemplate.search(b, request.getHeader("X-Filter"));\n'
        'ctx.search(base, stringBuilder.append("(uid=").append(uid).append(")").toString());\n'
        'dirContext.search(BASE, "(mail=" + getEmail() + ")");\n'
        'ldapTemplate.search("", "(uid=" + login + ")", new UserMapper());\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R061-ldapjndi"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_ldapjndi_literal_constant_or_non_search_targets_stay_quiet():
    """R061-ldapjndi stays quiet for fully literal filters, SCREAMING_SNAKE
    constants, bare String variables, ALL_CAPS concat operands, in-string
    arithmetic, non-search LDAP operations and non-LDAP receivers — no fused
    LDAP search sink receives string-built input."""
    src = (
        'ctx.search("ou=people", "(uid=admin)");\n'
        'dirContext.search(BASE, USER_FILTER);\n'
        'ctx.search(base, filter);\n'
        'Context ctx = new InitialDirContext(env);\n'
        'ctx.search(BASE, BASE + FILTER);\n'
        'ctx.search(base, "(uid=" + USER_ID + ")");\n'
        'attrs.put("memberOf", "cn=admin");\n'
        'ctx.createSubcontext("ou=managers");\n'
        'ctx.close();\n'
        'String filter = request.getParameter("u");\n'
        'ldapTemplate.authenticate(DN, "(uid=" + creds + ")");\n'
        're.search("(uid=.*)", s);\n'
        'table.search(criteria.getFilter());\n'
        'ldapTemplate.search(DN, SQL_FILTER, mapper);\n'
        'ctx.search(base, "(uid=" + (a + b) + ")");\n'
        'query.search("(uid=" + uk + ")");\n'
        'ctx.lookup("cn=admin");\n'
        'ldapTemplate.lookup("ou=people");\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R061-ldapjndi"], issues


def test_javaxxe_request_derived_or_string_built_parse_flagged():
    """R062-javaxxe fires when a Java XML parser — JAXP
    DocumentBuilderFactory/SAXParserFactory chains, builder/documentBuilder/
    saxParser/reader/xmlReader receivers or DOM4J `new SAXReader().read(...)` —
    is fed request input, an upload stream, a concatenated string, a
    builder/.toString() chain or an xml-named variable without entity-
    expansion hardening (CWE-611: crafted DOCTYPE external entities read
    local files / hit internal URLs)."""
    src = (
        'DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(request.getInputStream());\n'
        'SAXParserFactory.newInstance().newSAXParser().parse(request.getInputStream(), handler);\n'
        'builder.parse(request.getInputStream());\n'
        'documentBuilder.parse(req.getReader());\n'
        'saxParser.parse(part.getInputStream());\n'
        'xmlReader.parse(new InputSource(request.getReader()));\n'
        'saxReader.read(part.getInputStream());\n'
        'new SAXReader().read(request.getInputStream());\n'
        'new SAXReader().read(fileItem.getInputStream());\n'
        'builder.parse("<?xml version=\\"1.0\\"?>" + payload);\n'
        'parser.parse("<root>" + userXml);\n'
        'reader.parse(sb.toString());\n'
        'builder.parse(stringBuilder.append("<doc>").append(content).toString());\n'
        'documentBuilder.parse(request.getParameter("docUrl"));\n'
        'saxReader.read(xmlBody);\n'
        'new SAXReader().read("<resp>" + data);\n'
        'DocumentBuilderFactory.newInstance().newDocumentBuilder().parse("<a>" + content);\n'
        'parser.parse(new InputSource(req.getInputStream()));\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R062-javaxxe"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_javaxxe_hardened_literal_or_non_parse_targets_stay_quiet():
    """R062-javaxxe stays quiet for factory construction / hardening
    (setFeature/setProperty, disallow-doctype-decl), literal or constant
    sources, ALL_CAPS concat operands, node-model building, validation,
    transformers/serializers, streaming char reads and non-parse streams —
    no unhardened XML sink parses client-controlled input."""
    src = (
        'DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n'
        'DocumentBuilderFactory.newInstance().newDocumentBuilder();\n'
        'builder.parse("config.xml");\n'
        'builder.parse(XML_PATH);\n'
        'builder.parse(is);\n'
        'saxParser.parse(entity.getInputStream());\n'
        'SAXReader reader = new SAXReader();\n'
        'factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n'
        'builder.setExpandEntityReferences(false);\n'
        'saxParser.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");\n'
        'xmlReader.setFeature("http://xml.org/sax/features/external-general-entities", false);\n'
        'reader.read(new InputSource(new FileInputStream(f)));\n'
        'builder.parse(new InputSource(XML_PATH));\n'
        'transformer.transform(xmlSource, result);\n'
        'Document doc = builder.newDocument();\n'
        'schema.newValidator().validate(new StreamSource(xmlContent));\n'
        'builder.parse(STATIC_DOC + SUFFIX);\n'
        'saxReader.read(new CharArrayReader(chars));\n'
        'BufferedReader reader = new BufferedReader(in); reader.read(buffer, 0, len);\n'
        'parser.parse(attachments.getInputStream());\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R062-javaxxe"], issues


def test_javapath_request_derived_or_string_built_target_flagged():
    """R063-javapath fires when a Java file-path sink — new File-family
    constructors, Files.* helpers over Paths.get(...) or upload writes —
    resolves its target from a request accessor, a concatenated string or a
    filename-named variable (CWE-22: '..' or absolute input escapes the
    intended directory)."""
    src = (
        'File f = new File(request.getParameter("path"));\n'
        'File target = new File(req.getParameter("fileName"));\n'
        'new FileInputStream(request.getParameter("file"));\n'
        'FileOutputStream out = new FileOutputStream(req.getParameter("out"));\n'
        'new FileReader(request.getHeader("file"));\n'
        'new FileWriter(req.getParameter("report"));\n'
        'RandomAccessFile raf = new RandomAccessFile(request.getParameter("path"), "r");\n'
        'Files.readAllBytes(Paths.get(request.getParameter("path")));\n'
        'String s = Files.readString(Paths.get(req.getParameter("data")));\n'
        'Files.write(Paths.get(request.getParameter("out")), data);\n'
        'new File("uploads/" + userName);\n'
        'FileOutputStream fos = new FileOutputStream("/srv/" + request.getParameter("name"));\n'
        'fileItem.write(new File(directory, fileName));\n'
        'new File(savePath);\n'
        'part.write("uploads/" + request.getParameter("name"));\n'
        'multipartFile.transferTo(new File(uploadDir, request.getParameter("fileName")));\n'
        'File out = new File(uploadDirectory, originalFilename);\n'
        'fileItem.write(saveDirectory + fileName);\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R063-javapath"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_javapath_literal_constant_or_classpath_targets_stay_quiet():
    """R063-javapath stays quiet for literal paths, SCREAMING_SNAKE
    constants, ALL_CAPS concat operands, parent + literal second-arg File
    constructor calls, classpath getResourceAsStream lookups, UUID/timestamp
    generation and getter-only filename expressions — no path sink is fed
    traversable input."""
    src = (
        'File f = new File("/etc/hostname");\n'
        'File f = new File(XML_PATH);\n'
        'File f = new File(ROOT_DIR, "webapp/index.html");\n'
        'new FileInputStream(STATIC_FILE);\n'
        'Paths.get("data", "users.csv");\n'
        'Paths.get(System.getProperty("java.io.tmpdir"), "app.log");\n'
        'Files.readAllLines(Paths.get(getClass().getResource("/config.properties").toURI()));\n'
        'new FileInputStream("/etc/passwd");\n'
        'InputStream in = this.getClass().getResourceAsStream("/templates/home.html");\n'
        'new ByteArrayInputStream(data);\n'
        'String path = "uploads/" + UUID.randomUUID();\n'
        'part.write("uploads/stable.txt");\n'
        'fileItem.write(new File("uploads", "fixed.csv"));\n'
        'Files.newInputStream(Paths.get(XML_PATH));\n'
        'new File(f.getParent(), "child.xml");\n'
        'File dir = new File("/app/data"); dir.mkdirs();\n'
        'String fileName = part.getSubmittedFileName();\n'
        'File out = new File(cacheDir, "result.txt");\n'
        'Files.copy(inputStream, Paths.get("/var/lib/app/data.bin"));\n'
        'new PrintWriter(new FileWriter("/var/log/app.log", true));\n'
        'File tmp = new File(tempDir);\n'
        'new File(dataDir, "index.html");\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R063-javapath"], issues


def test_javareflect_request_derived_or_string_built_selection_flagged():
    """R064-javareflect fires when a Java reflection entry point —
    Class.forName, ClassLoader-family loadClass/defineClass or method /
    constructor lookup — resolves its class or member selection from a
    request accessor, a concatenated string or a lowercase variable
    (CWE-470: attacker chooses which class/member is loaded or invoked)."""
    src = (
        'Object o = Class.forName(request.getParameter("class")).newInstance();\n'
        'Class<?> c = Class.forName(req.getHeader("type"));\n'
        'Object obj = Class.forName("com.example." + className).newInstance();\n'
        'Class.forName(className);\n'
        'Object x = Class.forName("plugins." + pluginName).getDeclaredConstructor().newInstance();\n'
        'cl.loadClass(pluginClass);\n'
        'classLoader.loadClass(request.getParameter("name"));\n'
        'Class<?> c = loader.defineClass(request.getParameter("name"), bytes, 0, len);\n'
        'ucl.loadClass("evil." + clz);\n'
        'cl.loadClass("com." + request.getParameter("jndi"));\n'
        'Method m = obj.getClass().getDeclaredMethod(request.getParameter("method"));\n'
        'Method m = clazz.getMethod(req.getParameter("name"));\n'
        'Constructor<?> c = cls.getConstructor(request.getHeader("sig"));\n'
        'Method m = clazz.getMethod("execute" + actionName);\n'
        'Object inst = clazz.getDeclaredConstructor(request.getParameter("argTypes")).newInstance();\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R064-javareflect"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_javareflect_literal_constant_or_acquisition_expressions_stay_quiet():
    """R064-javareflect stays quiet for literal class names,
    SCREAMING_SNAKE constants, class-literal names, ClassLoader acquisition,
    plain instance creation and fixed member-name lookups — the reflection
    target is never client-controlled."""
    src = (
        'Class<?> c = Class.forName("java.lang.String");\n'
        'Class<?> c = Class.forName(APP_CLASS);\n'
        'Class<?> c = Class.forName(SomeClass.class.getName());\n'
        'Class<?> c = Class.forName("com.example.MyClass");\n'
        'runner.loadClass("com.example.plugins.ExtRunner");\n'
        'cl.loadClass(DEFAULT_PLUGIN_CLASS);\n'
        'Method m = obj.getClass().getDeclaredMethod("execute", String.class);\n'
        'Method m = target.getClass().getMethod("run", int.class);\n'
        'Constructor<?> ctor = Date.class.getConstructor(long.class);\n'
        'Object m = mapper.getMethod("toString");\n'
        'URLClassLoader ucl = new URLClassLoader(new URL[]{repo});\n'
        'ClassLoader cl = Thread.currentThread().getContextClassLoader();\n'
        'clazz.newInstance();\n'
        'String name = request.getParameter("className");\n'
        'Class.forName(Object.class.getName());\n'
        'Object obj = factory.getConstructor(String.class).newInstance("x");\n'
        'Method m = clazz.getDeclaredMethods()[0];\n'
        'customMapper.getMethod("map", input);\n'
        'ClassLoader cl = getClass().getClassLoader();\n'
        'loader.getResourceAsStream("plugins/run.jar");\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R064-javareflect"], issues


def test_java4xx_request_derived_or_string_built_header_flagged():
    """R065-java4xx fires when a Java HttpServletResponse header sink —
    setHeader / addHeader / setIntHeader / setDateHeader — writes a
    request accessor result (as NAME or VALUE), a '+' concatenation or a
    bare lowercase variable into the header (CWE-113: CRLF injection /
    response splitting).  Location is excluded — R060-openredir owns it."""
    src = (
        'response.setHeader("X-Request-ID", request.getParameter("rid"));\n'
        'response.setHeader("ETag", req.getHeader("If-None-Match"));\n'
        'resp.addHeader("X-Trace-Id", request.getHeader("traceId"));\n'
        'response.addHeader("Cache-Control", "max-age=" + maxAge);\n'
        'response.setHeader("X-Backend", "svc" + backendName);\n'
        'response.setHeader("X-User", userName);\n'
        'resp.addHeader("X-Frame-Options", frameMode);\n'
        'response.setHeader(request.getParameter("hname"), "deny");\n'
        'httpResponse.setHeader("X-Custom", request.getQueryString());\n'
        'response.setIntHeader(request.getHeader("hdrName"), 2048);\n'
        'response.setHeader("X-Ops", "op" + opCode);\n'
        'res.setHeader("X-Node", nodeId);\n'
        'response.addHeader("Set-Cookie", sessionCookie);\n'
        'response.setHeader("X-Stats", "total=" + hits);\n'
        'httpServletResponse.setHeader("X-Req-URI", request.getRequestURI());\n'
        'response.addHeader("X-Id", req.getParameter("extra"));\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R065-java4xx"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_java4xx_literal_constant_or_non_header_sinks_stay_quiet():
    """R065-java4xx stays quiet for literal header name+value pairs,
    constant values, Location headers (owned by R060-openredir),
    status/error/size calls, header READS and non-response receivers —
    nothing client-controlled reaches an outgoing header."""
    src = (
        'response.setHeader("Content-Type", "application/json");\n'
        'response.addHeader("Cache-Control", "no-store");\n'
        'response.setHeader("Location", "/login");\n'
        'response.setHeader("Location", nextUrl);\n'
        'response.setHeader("Location", request.getHeader("host"));\n'
        'response.sendRedirect("/auth/login");\n'
        'response.setStatus(302);\n'
        'response.sendError(500);\n'
        'response.setContentType("text/html");\n'
        'response.setIntHeader("X-Limit", 100);\n'
        'String rid = request.getParameter("rid");\n'
        'response.setHeader("X-Id", config.getHeader("X-Id"));\n'
        'response.setDateHeader("Expires", System.currentTimeMillis() + 3600000);\n'
        'response.setHeader("X-Powered-By", SERVER_NAME);\n'
        'response.setHeader("X-Version", "1.0.3");\n'
        'response.addHeader("Vary", "Accept-Encoding");\n'
        'wrapper.setHeader("X-A", "b");\n'
        'String val = response.getHeader("X-Id");\n'
        'response.setHeader("X-Foo", "bar" + SUFFIX);\n'
        'response.setHeader("X-Static", STATIC_VALUE);\n'
        'HttpHeaders headers = new HttpHeaders();\n'
        'response.addHeader("Expires", "0");\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R065-java4xx"], issues


def test_javacrypto_weak_algorithm_getinstance_flagged():
    """R066-javacrypto fires when a JCA getInstance call on a cryptographic
    receiver picks a weak/legacy algorithm from a literal — MD5, SHA-1,
    DES, DESede, RC4/ARC4/ARCFOUR, SHA1PRNG, ECB mode or a PBEWith*
    combination built on one of them (CWE-327)."""
    src = (
        'MessageDigest md = MessageDigest.getInstance("MD5");\n'
        'MessageDigest md = MessageDigest.getInstance("SHA-1");\n'
        'MessageDigest msg = MessageDigest.getInstance("SHA1");\n'
        'Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");\n'
        'Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");\n'
        'Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");\n'
        'SecretKeyFactory f = SecretKeyFactory.getInstance("PBEWithMD5AndDES");\n'
        'KeyGenerator kg = KeyGenerator.getInstance("RC4");\n'
        'Mac mac = Mac.getInstance("HmacMD5");\n'
        'Signature sig = Signature.getInstance("MD5withRSA");\n'
        'Signature sig = Signature.getInstance("SHA1withRSA");\n'
        'SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");\n'
        'Mac mac = Mac.getInstance("HmacSHA1");\n'
        'SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");\n'
        'Cipher cipher = Cipher.getInstance("DES");\n'
        'KeyGenerator kg = KeyGenerator.getInstance("ARCFOUR");\n'
        'MessageDigest.getInstance("md5");\n'
        'MessageDigest md = MessageDigest.getInstance("MD5");\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R066-javacrypto"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_javacrypto_safe_algorithm_or_nonliteral_getinstance_stays_quiet():
    """R066-javacrypto stays quiet for modern algorithms (SHA-256/384/512,
    SHA3-*, AES non-ECB modes, PBKDF2WithHmacSHA256, PBEWithHmacSHA256AndAES_256,
    HmacSHA256, SHA256withRSA / SHA384withRSA), non-literal first arguments
    and non-getInstance contexts — no weak algorithm is selected."""
    src = (
        'MessageDigest md = MessageDigest.getInstance("SHA-256");\n'
        'MessageDigest md = MessageDigest.getInstance("SHA-384");\n'
        'MessageDigest md = MessageDigest.getInstance("SHA-512");\n'
        'MessageDigest md = MessageDigest.getInstance("SHA3-256");\n'
        'Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");\n'
        'Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");\n'
        'Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding");\n'
        'SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");\n'
        'SecretKeyFactory f = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_256");\n'
        'Mac mac = Mac.getInstance("HmacSHA256");\n'
        'Signature sig = Signature.getInstance("SHA256withRSA");\n'
        'Signature sig = Signature.getInstance("SHA384withRSA");\n'
        'MessageDigest md = MessageDigest.getInstance(algorithmName);\n'
        'Cipher cipher = Cipher.getInstance(configuredAlgo);\n'
        'SecureRandom sr = SecureRandom.getInstanceStrong();\n'
        'byte[] buf = Cipher.getInstance("AES").doFinal(data);\n'
        'MessageDigest sha256 = MessageDigest.getInstance("SHA-256");\n'
        'String algo = "MD5";\n'
        'BigInteger two = BigInteger.valueOf(2);\n'
        'MessageDigest md = MessageDigest.getInstance("SHA-512", "BC");\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R066-javacrypto"], issues


def test_javaxss_response_writer_request_input_flagged():
    """R067-javaxss fires when a Java HTTP response body writer feeds
    client-controlled input back to the browser — request accessor,
    'literal' + variable concatenation or bare variable, plus JSP <%= %>
    expressions (CWE-79)."""
    src = (
        'response.getWriter().println(request.getParameter("q"));\n'
        'response.getWriter().write(request.getParameter("name"));\n'
        'response.getWriter().append(req.getHeader("X-Data"));\n'
        'response.getWriter().printf("id=%s", request.getParameter("id"));\n'
        'out.println(request.getParameter("user"));\n'
        'pw.print(req.getParameter("id"));\n'
        'writer.println(request.getHeader("traceId"));\n'
        'out.print("<h1>" + title + "</h1>");\n'
        'pw.write("<option value=" + optionId + ">");\n'
        'response.getWriter().print("Welcome, " + displayName);\n'
        'response.getWriter().println(userName);\n'
        'out.print(comment);\n'
        'pw.println(address);\n'
        'printWriter.println(request.getQueryString());\n'
        '<%= request.getParameter("page") %>\n'
        '<%= request.getParameter("user") %>\n'
        '<%= req.getHeader("X-Custom") %>\n'
        'outWriter.write(request.getRequestURI());\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R067-javaxss"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_javaxss_literal_or_console_or_nonwriter_stays_quiet():
    """R067-javaxss stays quiet for literal output, constants, numeric
    operands, System.out/System.err console printing (R036-loginj owns log
    injection), non-writer receivers and non-body-write calls — no XSS
    sink on the HTTP response body."""
    src = (
        'System.out.println(request.getParameter("u"));\n'
        'System.out.println("user=" + user);\n'
        'System.err.println("warn: " + request.getParameter("x"));\n'
        'logger.error("bad input: " + input);\n'
        'log.info("user " + username + " logged in");\n'
        'out.println();\n'
        'out.print(100);\n'
        'pw.close();\n'
        'out.flush();\n'
        'response.setContentType("text/html");\n'
        '<%= pageContext.getAttribute("name") %>\n'
        '<%= fullName %>\n'
        '<% if (session.isNew()) { %>\n'
        'response.getWriter();\n'
        'out.println("Hello, world!");\n'
        'pw.print(PAGE_CACHE);\n'
        'writer.println("<td>" + COLUMN + "</td>");\n'
        'helper.print(request.getParameter("u"));\n'
        'response.sendRedirect("/home");\n'
        'String out = "x";\n'
        'out.trim();\n'
        'console.log(request.getParameter("u"));\n'
        'writer.print("");\n'
        '<%= pageContext.findAttribute("user") %>\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R067-javaxss"], issues


def test_javarandom_security_value_from_insecure_prng_flagged():
    """R068-javarandom fires when a security keyword stands before a
    java.util.Random-family PRNG on the same line — new Random() (incl.
    fixed-seed form), ThreadLocalRandom, Commons lang3 RandomUtils and
    RandomStringUtils minting a password/token/nonce/salt/CSRF/OTP/API key
    or session id (CWE-330)."""
    src = (
        'String password = String.valueOf(new Random().nextLong());\n'
        'String sessionId = String.valueOf(new Random().nextInt());\n'
        'byte[] salt = new byte[16]; new Random().nextBytes(salt);\n'
        'BigInteger nonce = new BigInteger(128, new Random());\n'
        'String otp = String.format("%06d", new Random().nextInt(1000000));\n'
        'String csrfToken = Integer.toString(new Random().nextInt());\n'
        'String resetToken = new BigInteger(130, new Random()).toString(32);\n'
        'String verifCode = String.valueOf(new Random().nextLong());\n'
        'String csrf = Integer.toString(new Random().nextInt());\n'
        'String authToken = String.valueOf(new Random(42).nextLong());\n'
        'String apiKey = Long.toString(ThreadLocalRandom.current().nextLong());\n'
        'String secret = String.valueOf(new Random().nextInt());\n'
        'String jwt = Long.toString(new Random().nextLong()) + "";\n'
        'String refreshToken = "" + new java.util.Random().nextInt();\n'
        'String pin = String.format("%04d", RandomUtils.nextInt(0, 10000));\n'
        'String passCode = RandomStringUtils.randomAlphanumeric(16);\n'
        'char[] pw = randomPassword(new Random());\n'
        'String nonceStr = String.valueOf(new Random().nextLong());\n'
        'String pwd = String.valueOf(new Random().nextInt());\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R068-javarandom"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_javarandom_secure_or_keywordfree_random_stays_quiet():
    """R068-javarandom stays quiet for SecureRandom/UUID alternatives,
    Math.random() (R043 owns it), keyword-free Random uses (rolls, indices),
    staged receivers (Random rnd = new Random() then a separate nextX line)
    and security values from non-Random sources."""
    src = (
        'Random rand = new Random();\n'
        'int n = new Random().nextInt(100);\n'
        'double d = Math.random();\n'
        'int guess = ThreadLocalRandom.current().nextInt(1, 7);\n'
        'String id = UUID.randomUUID().toString();\n'
        'SecureRandom sr = new SecureRandom();\n'
        'byte[] b = new byte[16]; new SecureRandom().nextBytes(b);\n'
        'sr.nextBytes(salt);\n'
        'String token = request.getParameter("token");\n'
        'String nonce = nonceProvider.get();\n'
        'Collections.shuffle(list);\n'
        'String password = "correct horse battery staple";\n'
        'long stamp = System.nanoTime();\n'
        'Random rnd = new Random(42);\n'
        'int row = rowRandom.nextInt();\n'
        'String salt = saltStore.getSalt();\n'
        'logger.debug("roll=" + new Random().nextInt(6));\n'
        'double ratio = Math.random() * 2 - 1;\n'
        'char c = alphabet.charAt(new Random().nextInt(alphabet.length()));\n'
        'new Random().setSeed(System.nanoTime());\n'
        'String seed = new BigInteger(130, new Random()).toString(32);\n'
        'String sessionid = sessionManager.next();\n'
        'Set<String> tokenStore = new HashSet<>();\n'
        'String pwd = derivePassword();\n'
        'String secret = getSecretFromVault();\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R068-javarandom"], issues


def test_javacsrf_spring_csrf_disable_flagged():
    """R069-javacsrf fires when an HttpSecurity-family receiver turns CSRF
    protection OFF: the classic http.csrf().disable() (deprecated), the
    method-passed http.csrf(AbstractHttpConfigurer::disable) /
    http.csrf(HttpSecurity::disable) forms, the lambda forms
    csrf -> csrf.disable() (incl. the block form), on http, httpSecurity,
    httpBuilder, httpHttp, httpConfig, httpConf, configure, security,
    registry, builder or config (CWE-352)."""
    src = (
        'http.csrf().disable();\n'
        'httpSecurity.csrf().disable();\n'
        'http.csrf(AbstractHttpConfigurer::disable);\n'
        'http.csrf(csrf -> csrf.disable());\n'
        'http.csrf(c -> c.disable()).and().authorizeRequests();\n'
        'registry.csrf().disable();\n'
        'http.csrf().disable().and().formLogin();\n'
        'builder.csrf(csrf -> csrf.disable());\n'
        'config.csrf(AbstractHttpConfigurer::disable).and().build();\n'
        'httpBuilder.csrf().disable();\n'
        'httpConfig.csrf().disable();\n'
        'security.csrf().disable();\n'
        'configure.csrf().disable();\n'
        'http.csrf(HttpSecurity::disable);\n'
        'http.csrf(hsc -> hsc.disable());\n'
        'return http.csrf().disable();\n'
        'http.httpConf.csrf().disable();\n'
        'http.csrf(csrf -> { csrf.disable(); });\n'
        'if (http.csrf(c -> { c.disable(); }).and().authorizeRequests() != null) {}\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R069-javacsrf"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_javacsrf_spring_csrf_kept_on_or_unrelated_stays_quiet():
    """R069-javacsrf stays quiet when CSRF protection stays ON (token
    repository swaps, scoped ignoringXxx exemptions, enable()), the call is
    unrelated (cors/formLogin/httpBasic .disable(), bare http.csrf(),
    http.csrfTokenRepository(repo)), the receiver is not a raw keyword
    (getHttp().csrf().disable(), @EnableWebSecurity), or the text is a
    string-literal/comment reproduction."""
    src = (
        'http.cors().disable();\n'
        'http.formLogin().disable();\n'
        'http.httpBasic().disable();\n'
        'http.csrf().csrfTokenRepository(new CookieCsrfTokenRepository());\n'
        'http.csrf().ignoringAntMatchers("/webhook/**");\n'
        'http.csrf();\n'
        'CookieCsrfTokenRepository repo = CookieCsrfTokenRepository.withHttpOnlyFalse();\n'
        'String s = "http.csrf().disable()";\n'
        'String s = "// http.csrf().disable()";\n'
        'http.csrf().csrfTokenRepository(cookieCsrfTokenRepository);\n'
        'http.authorizeRequests().antMatchers("/api/**").permitAll();\n'
        '@EnableWebSecurity\n'
        'csrfTokenRepository.saveToken(token);\n'
        'http.csrf().enable();\n'
        'http.csrfTokenRepository(repo);\n'
        'http.csrf(csrf -> csrf.enable());\n'
        'public SecurityFilterChain filterChain(HttpSecurity http) {\n'
        'http.csrf(csrf -> csrf.csrfTokenRepository(repo));\n'
        'server.csrf().disable();\n'
        'http.csrf(csrf -> csrf.ignoringRequestMatchers("/h2"));\n'
        '// http.csrf().disable()\n'
        '/* http.csrf().disable() */\n'
        '* http.csrf().disable() */\n'
        'getHttp().csrf().disable();\n'
        'http.csrf(csrf -> { csrf.csrfTokenRepository(repo); });\n'
        'public void configure(AuthenticationManagerBuilder auth) {\n'
        'http.csrf(c -> c.ignoringRequestMatchers("/actuator"));\n'
        'MockMvc mockMvc = webAppContextSetup(http.csrf());\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R069-javacsrf"], issues


def test_javacook_cookie_for_security_value_without_flags_flagged():
    """R070-javacook fires when a Servlet Cookie holds or is linked to a
    session/security value with no Secure/HttpOnly on the added line: a
    security-named cookie created bare and added (JSESSIONID, sessionid, jwt,
    auth_token, XSRF-TOKEN, api_key, secret, rememberMe, id_token, session_id,
    userid, state, SID, sid), a generic-named cookie whose VALUE is a bare
    security identifier (sessionId, csrfToken, accessToken, sid, oauthState,
    freshSecret, uid...), or an explicit setSecure(false)/setHttpOnly(false)
    on a cookie-named receiver (c, ca, cookie) (CWE-614/CWE-1004)."""
    src = (
        'httpResponse.addCookie(new Cookie("JSESSIONID", sessionId));\n'
        'Cookie c = new Cookie("sessionid", req.getSession().getId());\n'
        'Cookie csrfCookie = new Cookie("XSRF-TOKEN", csrfToken);\n'
        'response.addCookie(new Cookie("auth_token", authToken));\n'
        'Cookie c = new Cookie("jwt", accessToken);\n'
        'cookie.setSecure(false);\n'
        'ca.setHttpOnly(false);\n'
        'new Cookie("session", sessionId); c.setSecure(false);\n'
        'Cookie c = new Cookie("token", request.getParameter("st"));\n'
        'new Cookie("api_key", getUserToken());\n'
        'Cookie c = new Cookie("ref", accessToken);\n'
        'Cookie c = new Cookie("returnUrl", sessionId);\n'
        'new Cookie("secret", freshSecret);\n'
        'Cookie c = new Cookie("SID", sid);\n'
        'response.addCookie(new Cookie("id_token", idToken));\n'
        'new Cookie("rememberMe", rememberToken);\n'
        'Cookie c = new javax.servlet.http.Cookie("session_id", getSessionId());\n'
        'Cookie c = new Cookie("userid", uid);\n'
        'c.setSecure(false);\n'
        'new Cookie("state", oauthState);\n'
        'Cookie cookie = new Cookie("sessionid", sid); cookie.setHttpOnly(false);\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R070-javacook"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_javacook_hardened_or_unrelated_cookie_stays_quiet():
    """R070-javacook stays quiet when the cookie is non-security (theme, lang,
    track, prefs, color, page, note, username, num), the same added line
    hardens it (setSecure(true)/setHttpOnly(true), incl. alongside a stale
    bare cookie), the value is a quoted literal or method call
    (Integer.toString(count), getJwt() with flags set), the code only stages
    a cookie for response.addCookie(cookie) or mutates non-flag attributes
    (setMaxAge/setPath/setDomain/setComment), the Set-Cookie goes through a
    response header, hardening reads request.getCookies()[i].setSecure(true),
    or the text is a string-literal/comment reproduction."""
    src = (
        'new Cookie("theme", "dark");\n'
        'new Cookie("lang", "en");\n'
        'Cookie c = new Cookie("JSESSIONID", sid); c.setSecure(true); c.setHttpOnly(true);\n'
        'cookie.setSecure(true);\n'
        'ck.setHttpOnly(true);\n'
        'response.addCookie(cookie);\n'
        'String s = "new Cookie(\\"token\\", t)";\n'
        '// new Cookie("JSESSIONID", sid)\n'
        'c.setMaxAge(3600);\n'
        'c.setPath("/");\n'
        'new Cookie("track", request.getParameter("t"));\n'
        'new Cookie("prefs", "tokenValue");\n'
        'Cookie c = new Cookie("color", "blue"); c.setSecure(true);\n'
        'cookie.setDomain("example.com");\n'
        'var c = new Cookie("page", "1");\n'
        'new Cookie("num", Integer.toString(count));\n'
        'sessionCookie.setMaxAge(-1);\n'
        'String token = buildToken();\n'
        'new Cookie("username", userName);\n'
        'new Cookie("note", "hi");\n'
        'httpResponse.setHeader("Set-Cookie", "sid=" + sid + "; HttpOnly");\n'
        'request.getCookies()[0].setSecure(true);\n'
        'String cookie = "http-only";\n'
        'cookie.setComment("session cookie");\n'
        'new Cookie("jwt", getJwt()); c.setHttpOnly(true); c.setSecure(true);\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R070-javacook"], issues


def test_javatls_trust_all_or_unverified_tls_flagged():
    """R071-javatls fires when Java code disables TLS certificate or
    hostname verification on the added line (CWE-295): an empty-body
    X509TrustManager checkServerTrusted/checkClientTrusted, getAcceptedIssuers
    returning null or an empty X509Certificate array, a HostnameVerifier.verify
    returning true unconditionally, permissive wiring of
    setDefaultHostnameVerifier(bareIdent) /
    setHostnameVerifier(lambda-true|trustAllVerifier),
    disableHostnameVerification(), an OkHttp builder
    .hostnameVerifier(lambda-true) chain, or SSLContext.init with an
    empty/trustAll trust anchor."""
    src = (
        'public void checkServerTrusted(X509Certificate[] chain, String authType) { }\n'
        'public void checkClientTrusted(X509Certificate[] chain, String authType) {}\n'
        'public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {}\n'
        'public X509Certificate[] getAcceptedIssuers() { return null; }\n'
        'public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }\n'
        'public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[] { }; }\n'
        'public boolean verify(String hostname, SSLSession session) { return true; }\n'
        'protected boolean verify(String hostname, SSLSession session) { return true; }\n'
        'HttpsURLConnection.setDefaultHostnameVerifier(hv);\n'
        'HttpsURLConnection.setDefaultHostnameVerifier(permissiveVerifier);\n'
        'conn.setHostnameVerifier((hostname, session) -> true);\n'
        'connection.setHostnameVerifier((h, s) -> { return true; });\n'
        'conn.setHostnameVerifier(trustAllVerifier);\n'
        'builder.disableHostnameVerification();\n'
        'httpClientBuilder.disableHostnameVerification();\n'
        'client.newBuilder().hostnameVerifier((hostname, session) -> true);\n'
        'new OkHttpClient.Builder().hostnameVerifier((h, s) -> { return true; });\n'
        'sslContext.init(keyManagers, trustAllCerts, new SecureRandom());\n'
        'sslContext.init(null, new TrustManager[] { trustAll }, new SecureRandom());\n'
        'sslContext.init(null, new TrustManager[0], null);\n'
        'sslContext.init(null, new TrustManager[] { }, null);\n'
        'sslCtx.init(kms, new TrustManager[] { trustAllCerts }, random);\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R071-javatls"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_javatls_real_verification_or_unrelated_stays_quiet():
    """R071-javatls stays quiet when trust evaluation is real or the text is
    unrelated: checkServerTrusted/checkClientTrusted/verify with a real body,
    verifier call sites or non-SSL signatures, getAcceptedIssuers returning a
    real collection, safe default verifier wiring (null, new Secure...,
    getDefaultHostnameVerifier(), hostname.equals(session.getPeerHost())
    lambdas), disableHostnameVerification call sites or an off-wiring call,
    non-trustAll trust-anchor staging (SSLContext.getInstance,
    System.setProperty trustStore, sslContext.init(null, null, ..) / with
    trustStoreManagers / a plain tm array), TrustManager array declarations,
    and string-literal/comment reproductions."""
    src = (
        'public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException { validateChain(chain); }\n'
        'tm.checkServerTrusted(chain, authType);\n'
        'sc.checkClientTrusted(chain, authType);\n'
        'public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException;\n'
        'public X509Certificate[] getAcceptedIssuers() { return trustedCerts; }\n'
        'public X509Certificate[] getAcceptedIssuers() { return cacerts.toArray(new X509Certificate[0]); }\n'
        'public boolean verify(String hostname, SSLSession session) { return hostname.equals(session.getPeerHost()); }\n'
        'public boolean verify(String hostname, SSLSession session) { return HttpsURLConnection.getDefaultHostnameVerifier().verify(hostname, session); }\n'
        'verifier.verify(hostname, session);\n'
        'public boolean verify(String hostname, String authType) { return true; }\n'
        'HttpsURLConnection.setDefaultHostnameVerifier(new SecureHostnameVerifier());\n'
        'HttpsURLConnection.setDefaultHostnameVerifier(null);\n'
        'HttpsURLConnection.setDefaultHostnameVerifier(getDefaultHostnameVerifier());\n'
        'conn.setHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier());\n'
        'conn.setHostnameVerifier(verifier);\n'
        'conn.setHostnameVerifier((hostname, session) -> hostname.equals(session.getPeerHost()));\n'
        'connection.setHostnameVerifier(null);\n'
        'new OkHttpClient.Builder().hostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier());\n'
        'client.hostnameVerifier();\n'
        'String s = "public void checkServerTrusted(X509Certificate[] chain, String authType) { }";\n'
        'String s = "HttpsURLConnection.setDefaultHostnameVerifier(hv);";\n'
        '// public boolean verify(String hostname, SSLSession session) { return true; }\n'
        '// public X509Certificate[] getAcceptedIssuers() { return null; }\n'
        'String s = "public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }";\n'
        'String s = "conn.setHostnameVerifier((hostname, session) -> true);";\n'
        '// builder.disableHostnameVerification();\n'
        '// sslContext.init(null, trustAllCerts, new SecureRandom());\n'
        'X509TrustManager tmx = new X509TrustManager() {\n'
        'TrustManager[] trustAllCerts = new TrustManager[] { tm };\n'
        'SSLContext.getInstance("TLS");\n'
        'System.setProperty("javax.net.ssl.trustStore", "cacerts");\n'
        'sslContext.init(keyManagers, trustStoreManagers, new SecureRandom());\n'
        'sslContext.init(null, null, new SecureRandom());\n'
        'sslContext.init(kms, new TrustManager[] { tm }, random);\n'
        'httpClientBuilder.disableHostnameVerification(false);\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R071-javatls"], issues


def test_javaeval_script_engine_fed_injectable_code_flagged():
    """R072-javaeval fires when the added line evaluates a non-literal code
    string through a Java script/dynamic-code engine (CWE-94): ScriptEngineManager
    getEngineBy*().eval, scriptEngine/engine/nashorn/rhino/groovyEngine/
    pythonEngine receivers .eval, new GroovyShell().evaluate/parse,
    GroovyClassLoader().parseClass, GroovyShell/GroovyClassLoader variable
    receivers evaluate/parse/parseClass, JShell.create().eval / jshell.eval,
    Beanshell Interpreter eval, NashornScriptEngineFactory().getScriptEngine()
    .eval, string-concatenated eval sources, and conventional short staged
    receivers (cl/gs/js/interp) eval-evaluate-parseClass-parse."""
    src = (
        'new ScriptEngineManager().getEngineByName("javascript").eval(request.getParameter("script"));\n'
        'new ScriptEngineManager().getEngineByExtension("js").eval(req.getHeader("code"));\n'
        'new ScriptEngineManager().getEngineByMimeType("text/javascript").eval(request.getQueryString());\n'
        'engine.eval(userScript);\n'
        'scriptEngine.eval(payload);\n'
        'jsEngine.eval(request.getParameter("eval"));\n'
        'nashorn.eval(code);\n'
        'rhino.eval(script);\n'
        'groovyEngine.eval(input);\n'
        'pythonEngine.eval(scriptSource);\n'
        'new GroovyShell().evaluate(request.getParameter("groovy"));\n'
        'new GroovyShell(binding).evaluate(userCode);\n'
        'groovyShell.evaluate(code);\n'
        'groovy.evaluate(userCode);\n'
        'new GroovyShell().parse(code);\n'
        'new GroovyClassLoader().parseClass(request.getParameter("src"));\n'
        'groovyShell.parseClass(sourceCode);\n'
        'JShell.create().eval(request.getParameter("jshell"));\n'
        'jshell.eval(script);\n'
        'new Interpreter().eval(code);\n'
        'interpreter.eval(request.getHeader("x-eval"));\n'
        'new NashornScriptEngineFactory().getScriptEngine().eval(payload);\n'
        'engine.eval("var x = " + request.getParameter("n"));\n'
        'jsEngine.eval("var x = " + request.getParameter("n"));\n'
        'jshell.eval("var r = " + userInput);\n'
        'groovyShell.evaluate("def x = " + input);\n'
        'new ScriptEngineManager().getEngineByName("groovy").eval(rule);\n'
        'ScriptEngine js = manager.getEngineByName("js"); js.eval(code);\n'
        'GroovyClassLoader cl = new GroovyClassLoader(); cl.parseClass(src);\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R072-javaeval"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_javaeval_real_or_literal_engine_usage_stays_quiet():
    """R072-javaeval stays quiet when the engine code is literal, staged
    without an eval, using a non-injectable receiver or source, or is a
    comment/string-literal reproduction: manager acquisition, eval with a
    literal/null/numeric/constant/Reader source, setVariable/setBinding/
    getLanguageName wiring, non-engine receiver evals (context/models/
    metrics/evaluator), Compilable.compile, Interpreter constructor staging,
    static-helper logs like logger.info("eval result = " + result), and
    comment/string-literal reproductions of the firing forms."""
    src = (
        'new ScriptEngineManager().getEngineByName("js");\n'
        'ScriptEngineManager manager = new ScriptEngineManager();\n'
        'engine.eval(null);\n'
        'engine.eval("1 + 1");\n'
        'jshell.eval("System.out.println(1)");\n'
        'new GroovyShell().evaluate("1 + 1");\n'
        'new GroovyShell(binding).evaluate(new InputStreamReader(System.in));\n'
        'binding.setVariable("name", userInput);\n'
        'manager.getEngineByExtension("groovy");\n'
        'groovyShell.setBinding(binding);\n'
        'engine.getFactory().getLanguageName();\n'
        'engine.eval(5);\n'
        'interpreter.set("x", 5);\n'
        'context.eval(code);\n'
        'models.eval(query);\n'
        'metrics.eval(timeout);\n'
        '// jshell.eval(code);\n'
        '// engine.eval(script);\n'
        'String s = "jshell.eval(code)";\n'
        'String s = "engine.eval(payload)";\n'
        '// groovyShell.evaluate(userCode);\n'
        '// new GroovyShell().evaluate(request.getParameter("groovy"));\n'
        '// new ScriptEngineManager().getEngineByName("js").eval(script);\n'
        'String s = "new GroovyShell().evaluate(a)";\n'
        'ScriptEngine e = mgr.getEngineByName("js"); e.eval("1+1");\n'
        'js.eval("1+1");\n'
        'cl.parseClass("class A {}");\n'
        'gs.evaluate("1+1");\n'
        'interp.eval("2+2");\n'
        '// js.eval(code);\n'
        'ScriptEngine engine = manager.getEngine("groovy");\n'
        '((Compilable) engine).compile("1+1");\n'
        'new Interpreter("x = 9;");\n'
        'logger.info("eval result = " + result);\n'
        'StringBuffer sb = new StringBuffer();\n'
        'groovy.evaluate(null);\n'
        'result = evaluator.process(code);\n'
        'engine.eval(SCRIPT_CONSTANT);\n'
        'engine.eval(new FileReader("script.groovy"));\n'
        'jshell.analyzeSource("var x = 1");\n'
        'GroovyShell groovyShell = new GroovyShell();\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R072-javaeval"], issues


def test_javaformat_injected_format_string_flagged():
    """R073-javaformat fires when the added line feeds a non-literal format
    string into a Java printf-family sink (CWE-134): String.format /
    java.util.Formatter.format, System.out/err.printf, MessageFormat.format,
    staged PrintWriter/PrintStream/printer/writer/out receivers
    .printf/.format, the Locale-overload form with a non-literal format, and
    a 'literal prefix' + variable concatenated format string."""
    src = (
        'String.format(request.getParameter("fmt"), a, b);\n'
        'String.format(userInput, x);\n'
        'Formatter.format(req.getParameter("f"), v);\n'
        'System.out.printf(userFormat, x);\n'
        'System.err.printf(request.getParameter("p"), val);\n'
        'MessageFormat.format(request.getHeader("x-fmt"), obj);\n'
        'out.printf(userPrompt, arg);\n'
        'writer.format(request.getParameter("f"), v);\n'
        'printWriter.format(input, a);\n'
        'printStream.printf(reqFormat, v);\n'
        'String.format("%d " + request.getParameter("n"), a);\n'
        'String.format("val=" + userInput, b);\n'
        'System.out.printf(Locale.US, userFormat, x);\n'
        'String.format(Locale.US, request.getParameter("f"), a);\n'
        'sb.append(String.format(request.getParameter("f"), a));\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R073-javaformat"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_javaformat_literal_format_string_stays_quiet():
    """R073-javaformat stays quiet when the format string is a fixed literal
    (with non-literal ARGUMENTS only — the safe idiom), the Locale overload
    carries a literal format, the text is staging/declaration/non-call, the
    receiver is unrelated, or it is a comment/string-literal reproduction."""
    src = (
        'String.format("Hello %s", name);\n'
        'String.format("%d %s", count, label);\n'
        'System.out.printf("%d", count);\n'
        'System.out.printf("Hello %s%n", user);\n'
        'out.printf("%s", result);\n'
        'MessageFormat.format("You said {0}", input);\n'
        'String.format("%s=%s", key, val);\n'
        'System.out.printf(Locale.US, "%d", count);\n'
        'String.format(Locale.US, "%d %s", a, b);\n'
        'String fmt = request.getParameter("fmt");\n'
        'String userInput = getParam("q");\n'
        'PrintWriter out = new PrintWriter(resp.getWriter());\n'
        'String.format = getString();\n'
        'System.out.println("format string is here");\n'
        'logger.info(String.format("total=%d", total));\n'
        'formatter.append("x");\n'
        'DecimalFormat df = new DecimalFormat("#.##");\n'
        'System.out.printf(ANNUAL_REPORT_FMT, data);\n'
        '// String.format(request.getParameter("fmt"), a, b);\n'
        'String literal = "String.format(request.getParameter(\\"fmt\\"), a, b);";\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R073-javaformat"], issues


def test_javakeysz_weak_sizes_flagged():
    """R074-javakeysz fires when the added line configures a Java key/crypto
    parameter below the secure minimum (CWE-326): KeyPairGenerator inline
    chain and staged receivers .initialize(< 2048), KeyGenerator inline
    chain and staged receivers .init(< 128), the obsolete < 192-bit EC
    curve family (new ECGenParameterSpec(...)), and a small DH prime
    (new DHParameterSpec(...))."""
    src = (
        'KeyPairGenerator.getInstance("RSA").initialize(1024);\n'
        'KeyPairGenerator.getInstance("DSA").initialize(512);\n'
        'kpg.initialize(512);\n'
        'keyPairGenerator.initialize(1024);\n'
        'pairGen.initialize(768, new SecureRandom());\n'
        'rsaKeyGen.initialize(1536);\n'
        'KeyGenerator.getInstance("AES").init(56);\n'
        'KeyGenerator.getInstance("AES").init(112);\n'
        'kg.init(64);\n'
        'keyGenerator.init(96);\n'
        'symKeyGen.init(80);\n'
        'new ECGenParameterSpec("secp160r1");\n'
        'ECGenParameterSpec curve = new ECGenParameterSpec("secp192r1");\n'
        'new ECGenParameterSpec("prime192v1");\n'
        'new DHParameterSpec(1024, 2);\n'
        'new DHParameterSpec(512, 2);\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R074-javakeysz"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_javakeysz_adequate_sizes_stay_quiet():
    """R074-javakeysz stays quiet when the size is adequate (>= 2048-bit
    keygen, >= 128-bit symmetric, current EC curves, 2048-bit DH), the size
    is a non-literal variable, the text is staging/declaration/non-config,
    the receiver is unrelated, or it is a comment/string-literal
    reproduction."""
    src = (
        'KeyPairGenerator.getInstance("RSA").initialize(2048);\n'
        'KeyPairGenerator.getInstance("RSA").initialize(4096);\n'
        'kpg.initialize(2048);\n'
        'kpg.initialize(2048, new SecureRandom());\n'
        'keyPairGenerator.initialize(3072);\n'
        'KeyGenerator.getInstance("AES").init(128);\n'
        'KeyGenerator.getInstance("AES").init(256);\n'
        'kg.init(192);\n'
        'new ECGenParameterSpec("secp256r1");\n'
        'new ECGenParameterSpec("secp384r1");\n'
        'new ECGenParameterSpec("secp521r1");\n'
        'new ECGenParameterSpec("secp224r1");\n'
        'new DHParameterSpec(2048, 2);\n'
        'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");\n'
        'KeyGenerator kg = KeyGenerator.getInstance("HmacSHA256");\n'
        'kpg.initialize(new SecureRandom());\n'
        'kpg.initialize(sizeVariable);\n'
        'kpg.initialize(fixedKeySize);\n'
        'Integer.parseInt("1024");\n'
        'kg.mass = 56;\n'
        'config.init(1512, mode);\n'
        'registry.initialize(2024, seed);\n'
        '// KeyPairGenerator.getInstance("RSA").initialize(1024);\n'
        '// new ECGenParameterSpec("secp160r1");\n'
        'String s = "KeyPairGenerator.getInstance(\\"RSA\\").initialize(1024);";\n'
        'String t = "new ECGenParameterSpec(\\"secp160r1\\");";\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R074-javakeysz"], issues


def test_jvachttp_cleartext_sinks_flagged():
    """R075-jvachttp fires when the added line builds a Java network/HTTP
    call or JNDI binding on a literal cleartext scheme (CWE-319): new
    URL/URI/URI.create with http:// ws:// ftp://, RestTemplate-family and
    HttpClient verbs with a cleartext literal URL, WebClient fluent
    .uri(http://), OkHttp/HttpUrl builders .url(http://)/HttpUrl.parse, and
    JNDI provider-url configuration or context ctor with ldap://."""
    src = (
        'URL u = new URL("http://legacy.example.com/data");\n'
        'new URL("ws://chat.example.com/socket");\n'
        'URI u = new URI("http://internal.example.org/v1");\n'
        'URI.create("http://svc.example.net:8080");\n'
        'URI.create("ftp://files.example.com/pub");\n'
        'new URL("HTTP://case.example.com");\n'
        'restTemplate.getForObject("http://billing.example.com/accounts", String.class);\n'
        'restTemplate.exchange("http://legacy.example.com/api", HttpMethod.GET, entity, String.class);\n'
        'client.execute("http://stats.example.com/ping");\n'
        'httpClient.postForObject("http://pay.example.com/tx", req, Resp.class);\n'
        'webClient.get().uri("http://analytics.example.com/events").retrieve();\n'
        'webClient.post().uri("http://ingest.example.com/log").send();\n'
        'new Request.Builder().url("http://ok.example.com/endpoint").build();\n'
        'requestBuilder.url("http://old.example.com/v1");\n'
        'HttpUrl.parse("http://dns.example.com/resolve");\n'
        'env.put(Context.PROVIDER_URL, "ldap://ldap.example.com:389");\n'
        'env.put("java.naming.provider.url", "ldap://legacy-ldap.example.com");\n'
        'new InitialDirContext(props, "ldap://dir.example.com");\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R075-jvachttp"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "medium" for i in hits)


def test_jvachttp_cleartext_negatives_stay_quiet():
    """R075-jvachttp stays quiet for TLS-scheme URLs (https/wss/ftps/ldaps),
    URI-case variations of secure schemes, non-literal URL targets
    (variables/concatenations — R057's domain), https in HTTP-client verbs,
    unrelated receivers/statements, and comment/string-literal
    reproductions."""
    src = (
        'URL u = new URL("https://api.example.com/secure");\n'
        'URI u = new URI("https://accounts.example.com");\n'
        'URI.create("https://cdn.example.com/x");\n'
        'URI.create("wss://socket.example.com");\n'
        'new URL("ftps://secure.example.com");\n'
        'new URL("HTTPS://UPPER.example.com");\n'
        'new URL(request.getParameter("u"));\n'
        'new URL(url);\n'
        'URI.create(baseEndpoint + "/v1");\n'
        'restTemplate.getForObject(endpoint + "/users", String.class);\n'
        'HttpRequest.newBuilder(URI.create("https://req.example.com")).build();\n'
        'restTemplate.getForObject("https://internal.example.com/api", String.class);\n'
        'restTemplate.exchange("https://svc.example.com", HttpMethod.GET, e, String.class);\n'
        'client.execute("SELECT * FROM t");\n'
        'client.execute(sql, ps);\n'
        'webClient.get().uri("https://www.example.com/me").retrieve();\n'
        'new Request.Builder().url("https://ok.example.com/endpoint").build();\n'
        'requestBuilder.url("https://new.example.com/v1");\n'
        'HttpUrl.parse("https://dns.example.com/resolve");\n'
        'env.put(Context.PROVIDER_URL, "ldaps://ldap.example.com:636");\n'
        'String conn = "ldap://ldap.example.com";\n'
        'new InitialDirContext(props);\n'
        'env.put(Context.SECURITY_PRINCIPAL, "cn=admin");\n'
        'String ldapUrl = props.getProperty("ldap.url");\n'
        'builder.append("http://x.example.com");\n'
        'logger.info("http://debug.example.com");\n'
        'String s = "http://plain.example.com";\n'
        '// new URL("http://bad.example.com");\n'
        '// restTemplate.getForObject("http://x.example.com", String.class);\n'
        '// env.put(Context.PROVIDER_URL, "ldap://ldap.example.com");\n'
        'String t = "new URL(\\"http://bad.example.com\\");";\n'
        'String u = "env.put(\\"java.naming.provider.url\\", \\"ldap://x.example.com\\");";\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R075-jvachttp"], issues


def test_javaredos_java_regex_sinks_flagged():
    """R076-javaredos fires when the added line feeds a non-literal pattern
    into a Java regex-compilation sink (CWE-1333): Pattern.compile /
    Pattern.matches with a variable or request-derived argument, a literal
    prefix concatenated with a variable, and String.matches / split /
    replaceAll / replaceFirst on any receiver chain with a non-literal
    pattern."""
    src = (
        'Pattern p = Pattern.compile(request.getParameter("regex"));\n'
        'Pattern.compile(userInput);\n'
        'Pattern.compile(builder.toString());\n'
        'Pattern.compile(prefix + "|" + suffix);\n'
        'boolean m = Pattern.matches(userPattern, data);\n'
        'Pattern.matches(uuidFromClient, payload);\n'
        'Pattern.compile("^[a-z]+" + tier + "$");\n'
        'Pattern.compile("(?:" + groups + ")");\n'
        'boolean ok = email.matches(badPattern);\n'
        'if (input.matches(req.getParameter("pat"))) {\n'
        'String[] cols = row.split(delim);\n'
        'String[] parts = request.getParameter("list").split(sep);\n'
        'String clean = text.replaceAll(userPattern, "");\n'
        'text.replaceFirst(prefixRegex, "x");\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R076-javaredos"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_javaredos_java_regex_negatives_stay_quiet():
    """R076-javaredos stays quiet for literal patterns in every sink form,
    SCREAMING_SNAKE pattern constants, the Pattern.quote(userInput) literal-
    escape idiom (including a manual \\Q...\\E concat), argless non-regex
    sink calls (matcher.matches(), object.split(), Path.of, indexOf), a
    dynamic import/require-style receiver, and comment/string-literal
    reproductions."""
    src = (
        'Pattern.compile("^[a-z]+$");\n'
        'Pattern.compile("[a-z]+", Pattern.CASE_INSENSITIVE);\n'
        'boolean ok = email.matches("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\\\.[A-Z]{2,}$");\n'
        'String[] cols = row.split(",");\n'
        'String[] words = line.split("\\\\s+", -1);\n'
        'String clean = text.replaceAll("\\\\s+", " ");\n'
        'text.replaceFirst("[0-9]+", "#");\n'
        'Pattern.compile(EMAIL_REGEX);\n'
        'line.split(CSV_DELIM);\n'
        'text.replaceAll(ILLEGAL_CHARS, "");\n'
        'Pattern.compile(Pattern.quote(userLiteral));\n'
        'text.replaceAll(Pattern.quote(tok), "X");\n'
        'Pattern p = Pattern.compile("literal\\\\Q" + escaped + "\\\\E");\n'
        'matcher.matches();\n'
        'object.split();\n'
        'Path p = Path.of(filename);\n'
        'int i = text.indexOf("/");\n'
        'Stream s = data.stream();\n'
        '// Pattern.compile(request.getParameter("regex"));\n'
        '// text.replaceAll(userPattern, "");\n'
        'String t = "Pattern.compile(\\"(a+)+$\\");";\n'
        'String u = "Pattern.compile(\\"^\\" + tier);";\n'
        'String v = "row.split(delim);";\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R076-javaredos"], issues


def test_javajson_json_deserialization_sinks_flagged():
    """R077-javajson fires when the added line feeds a non-literal payload
    into a Java JSON deserializer (CWE-502): fastjson JSON.parseObject with
    any non-literal argument (autoType honors the request-set '@type' and is
    bypass-prone even with an explicit class), and Jackson ObjectMapper
    single-argument readValue / readValue(payload, Object.class) /
    readValue(payload, (new )?TypeReference<...>) polymorphic targets."""
    src = (
        'Object o = JSON.parseObject(request.getParameter("json"));\n'
        'JSON.parseObject(payload);\n'
        'JSONObject.parseObject(body, User.class);\n'
        'JSON.parseObject("{\\"@type\\":" + t + "}", Object.class);\n'
        'Map m = mapper.readValue(input);\n'
        'objectMapper.readValue(raw);\n'
        'new ObjectMapper().readValue(userBody);\n'
        'Object o = mapper.readValue(payload, Object.class);\n'
        'Object o2 = this.mapper.readValue(body, TypeReference.INSTANCE);\n'
        'Object v = objectMapper.readValue(resp, TypeReference.INSTANCE);\n'
        'Object w = mapper.readValue(data, new TypeReference());\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R077-javajson"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_javajson_json_deserialization_negatives_stay_quiet():
    """R077-javajson stays quiet for the typed-safe Jackson idiom
    readValue(json, User.class), string/serialization/inspection calls
    (JSON.parse, JSON.parseArray, JSON.toJSONString, readTree, convertValue),
    enableDefaultTyping config lines, JSON keys/values, declarations, and
    comment/string-literal reproductions."""
    src = (
        'User u = mapper.readValue(json, User.class);\n'
        'List<User> us = mapper.readValue(body, new TypeReference<List<User>>() {});\n'
        'Object m = JSON.parse(body);\n'
        'JSONArray a = JSON.parseArray(text);\n'
        'String s = JSON.toJSONString(user);\n'
        'JsonNode n = mapper.readTree(payload);\n'
        'Object v = mapper.convertValue(src, User.class);\n'
        'mapper.enableDefaultTyping(DefaultTyping.NON_FINAL);\n'
        'ObjectMapper mapper = new ObjectMapper();\n'
        'String value = json.get("name");\n'
        '// JSON.parseObject(request.getParameter("json"));\n'
        '// mapper.readValue(body, TypeReference.INSTANCE);\n'
        'String t = "JSON.parseObject(\\"{\\\\");";\n'
        'String u = "mapper.readValue(input);";\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R077-javajson"], issues


def test_javatpl_template_sinks_flagged():
    """R078-javatpl fires when the added line feeds a non-literal template
    source or name into a Java server-side template engine (CWE-1336):
    Velocity/velocityEngine.evaluate (4th-arg template), Freemarker
    new Template(name, src, cfg) with a variable source or a
    new StringReader(src) wrapper, configuration.getTemplate(variable name),
    and TemplateEngine/templateEngine/thymeleafEngine/templateParser.process
    rendering a variable or concatenated template (Thymeleaf relies on this
    first-argument signature)."""
    src = (
        'velocityEngine.evaluate(ctx, writer, "log", userTemplate);\n'
        'Velocity.evaluate(ctx, out, "log", request.getParameter("tpl"));\n'
        'Velocity.evaluate(ctx, out, "log", "Hello " + userName + "!");\n'
        'new Template("t", userSrc, cfg);\n'
        'new Template("t", new StringReader(raw), cfg);\n'
        'new Template("t", new StringReader(request.getParameter("tpl")), cfg);\n'
        'new Template("t", "hi " + userName, cfg);\n'
        'cfg.getTemplate(userName);\n'
        'configuration.getTemplate(request.getParameter("name"));\n'
        'templateEngine.process(userMarkup, ctx);\n'
        'new TemplateEngine().process(request.getParameter("tpl"), ctx);\n'
        'templateEngine.process("index " + userName, ctx);\n'
        'thymeleafEngine.process(injectedTemplate, context);\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R078-javatpl"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_javatpl_template_negatives_stay_quiet():
    """R078-javatpl stays quiet for all-literal templates in every sink form,
    SCREAMING_SNAKE template names/sources (regarded as constants), the safe
    render step on an existing Template variable (template.process(model,
    out)), unrelated receivers (engine.process, setTemplate), an ANTLR
    StringTemplate construction, and comment/string-literal reproductions."""
    src = (
        'Velocity.evaluate(ctx, out, "log", "Hello $name");\n'
        'new Template("index", "Hi ${user}", cfg);\n'
        'new Template("index", new StringReader("Hi ${user}"), cfg);\n'
        'cfg.getTemplate("index.ftl");\n'
        'configuration.getTemplate(TPL_NAME);\n'
        'templateEngine.process("index", ctx);\n'
        'template.process(model, out);\n'
        'engine.process(template, ctx);\n'
        'StringTemplate st = new StringTemplate("Hello $name$");\n'
        'setTemplate(new StringReader("x"));\n'
        '// velocityEngine.evaluate(ctx, writer, "log", userTemplate);\n'
        '// cfg.getTemplate(userName);\n'
        '// templateEngine.process(userMarkup, ctx);\n'
        'String t = "velocityEngine.evaluate(ctx, writer, \\"log\\", userTemplate);";\n'
        'String s = "Velocity.evaluate(ctx, out, \\"log\\", \\"Hello $name\\");";\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R078-javatpl"], issues


def test_javacors_wildcard_origin_sinks_flagged():
    """R079-javacors fires when the added line sets a CORS policy or
    Access-Control-Allow-Origin header to the '*' wildcard origin (CWE-942
    permissive cross-domain policy): Spring's @CrossOrigin annotation, the
    CorsRegistry addMapping(...).allowedOrigins/allowedOriginPatterns chain,
    CorsConfiguration setAllowedOrigins/setAllowedOriginPatterns fed through
    singleton/singletonList/asList/List.of/Set.of, Jetty CorsFilter's
    addAllowedOrigin, and a hand-written
    response.set/addHeader("Access-Control-Allow-Origin", "*")."""
    src = (
        '@CrossOrigin(origins = "*")\n'
        '@CrossOrigin(origins="*")\n'
        '@CrossOrigin(origins = {"*"})\n'
        'registry.addMapping("/**").allowedOrigins("*")\n'
        'registry.addMapping("/api/**").allowedOriginPatterns("*")\n'
        'config.setAllowedOrigins(Collections.singletonList("*"))\n'
        'config.setAllowedOriginPatterns(Arrays.asList("*"))\n'
        'config.setAllowedOrigins(List.of("*"))\n'
        'config.setAllowedOrigins(Set.of("*"))\n'
        'config.setAllowedOrigins(Collections.singleton("*"))\n'
        'corsConfig.addAllowedOrigin("*")\n'
        'cfgs.addAllowedOrigin("*");\n'
        'response.setHeader("Access-Control-Allow-Origin", "*")\n'
        'resp.addHeader("Access-Control-Allow-Origin", "*")\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R079-javacors"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_javacors_wildcard_origin_negatives_stay_quiet():
    """R079-javacors stays quiet for explicit-origin allow-lists in every sink
    form, constants/request-derived origins, the wildcard used for methods or
    headers (allowedMethods/allowedHeaders/addAllowedHeader/addAllowedMethod
    are not origins), getters and setAllowCredentials, unrelated header
    writes, and comment/string-literal reproductions."""
    src = (
        '@CrossOrigin(origins = "https://app.example.com")\n'
        '@CrossOrigin(origins = {"https://a.com", "https://b.com"})\n'
        'registry.addMapping("/**").allowedOrigins("https://app.example.com")\n'
        'registry.addMapping("/**").allowedMethods("*")\n'
        'registry.addMapping("/**").allowedHeaders("*")\n'
        'config.setAllowedOrigins(Collections.singletonList("https://app.example.com"))\n'
        'config.setAllowedOrigins(ALLOWED_ORIGINS)\n'
        'config.getAllowedOrigins().forEach(System.out::println)\n'
        'config.setAllowCredentials(true)\n'
        'corsConfig.addAllowedHeader("*")\n'
        'corsConfig.addAllowedMethod("*")\n'
        'response.setHeader("Content-Type", "application/json")\n'
        'response.setHeader("Access-Control-Allow-Origin", origin)\n'
        '// config.setAllowedOrigins(Collections.singletonList("*"))\n'
        'String s = "registry.addMapping(\\"/**\\").allowedOrigins(\\"*\\")";\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R079-javacors"], issues


def test_javajwt_unsecured_or_none_sinks_flagged():
    """R080-javajwt fires when the added line makes a Java JWT parser accept
    unsigned or attacker-chosen tokens (CWE-347 improper verification of
    cryptographic signature): jjwt's parseUnsecuredContent / unsecured().
    allowUnsecured() skip signature verification, a legacy
    setSigningKey(null | \"\" | new byte[0]) can never verify a real token,
    SignatureAlgorithm.NONE / JWSAlgorithm.NONE admit the 'none' algorithm,
    and Spring Security's JwtDecoders.none() decodes unsigned tokens."""
    src = (
        'Jwts.parser().parseUnsecuredContent(token)\n'
        'Jwts.parser().unsecured().allowUnsecured().build().parse(token)\n'
        'Jwts.parser().setSigningKey(null)\n'
        'Jwts.parser().setSigningKey("")\n'
        'Jwts.parser().setSigningKey(new byte[0])\n'
        'Jwts.builder().signWith(SignatureAlgorithm.NONE, insecureKey)\n'
        'new JWSVerificationKeySelector(JWSAlgorithm.NONE, jwkSource)\n'
        'return JwtDecoders.none();\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R080-javajwt"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_javajwt_unsecured_or_none_negatives_stay_quiet():
    """R080-javajwt stays quiet for parsers that actually verify: jjwt 0.12+
    verifyWith(secretKey).build().parseSignedClaims chains, legacy
    setSigningKey fed a runtime key, issuer-based decoders
    (fromIssuerLocation/fromOidcIssuerLocation), strong-algorithm constants
    (HS256/RS256), signing-only code, and comment/string-literal
    reproductions."""
    src = (
        'Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token)\n'
        'Jwts.parser().setSigningKey(signingKey).build().parseClaimsJws(token)\n'
        'parserBuilder.setSigningKey(hmacSecret.getEncoded())\n'
        'JwtDecoders.fromIssuerLocation("https://auth.example.com/issuer")\n'
        'JwtDecoders.fromOidcIssuerLocation(ISSUER_URL)\n'
        'Jwts.builder().signWith(SignatureAlgorithm.HS256, secretKey)\n'
        'new JWSVerificationKeySelector(JWSAlgorithm.RS256, jwkSource)\n'
        'Jwts.builder().signWith(jwk.toPublicJWK()).compact()\n'
        '// setSigningKey(null)\n'
        '// Jwts.parser().verifyWith(secretKey)\n'
        'String s = "parseUnsecuredContent(token)";\n'
        'String s = "setSigningKey(null)";\n'
        'String s = "JwtDecoders.none()";\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R080-javajwt"], issues


def test_javapw_plaintext_or_weak_scheme_flagged():
    """R081-javapw fires when the added line stores or derives a Java password
    with a plaintext/no-op or weak non-adaptive scheme (CWE-916 insufficient
    computational effort in password hashing): Spring Security's
    NoOpPasswordEncoder.getInstance() keeps credentials verbatim, a {noop}
    delegating prefix marks a stored value as plaintext, and the deprecated
    MessageDigestPasswordEncoder / LdapShaPasswordEncoder /
    StandardPasswordEncoder apply fast non-adaptive digests."""
    src = (
        'PasswordEncoder encoder = NoOpPasswordEncoder.getInstance();\n'
        'return NoOpPasswordEncoder.getInstance();\n'
        'encoded = "{noop}" + rawPassword;\n'
        'credentials.setValue("{noop}" + plaintext);\n'
        'new MessageDigestPasswordEncoder("MD5")\n'
        'PasswordEncoder ldap = new LdapShaPasswordEncoder();\n'
        'new StandardPasswordEncoder()\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R081-javapw"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_javapw_plaintext_or_weak_scheme_negatives_stay_quiet():
    """R081-javapw stays quiet for adaptive KDF encoders (BCrypt/Argon2/
    Pbkdf2/SCrypt), the delegating factory, digest-utility calls, and
    comment/string-literal reproductions of the weak marker names."""
    src = (
        'PasswordEncoder encoder = new BCryptPasswordEncoder(12);\n'
        'return new Argon2PasswordEncoder();\n'
        'encoded = pbkdf2Encoder.encode(rawPassword);\n'
        'PasswordEncoder scrypt = new SCryptPasswordEncoder();\n'
        'encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();\n'
        'String digest = DigestUtils.sha256Hex(rawPassword);\n'
        'encoded = "{bcrypt}" + bcryptEncoder.encode(rawPassword);\n'
        '// NoOpPasswordEncoder.getInstance()\n'
        '// new MessageDigestPasswordEncoder()\n'
        'String s = "{noop}not-a-store";\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R081-javapw"], issues


def test_javasecret_hardcoded_key_flagged():
    """R082-javasecret fires when the added line derives a Java crypto or JWT
    key directly from a hardcoded string literal (CWE-321 use of a hard-coded
    cryptographic key): new SecretKeySpec(\"...\"), jjwt Keys.hmacShaKeyFor /
    signWith(alg, \"...\"), legacy setSigningKey(\"...\"), and
    PBEKeySpec(\"...\") password-derived keys."""
    src = (
        'SecretKey key = new SecretKeySpec("0123456789abcdef", "AES");\n'
        'new SecretKeySpec("changeit", "DES")\n'
        'Keys.hmacShaKeyFor("my-statically-baked-secret".getBytes())\n'
        'Jwts.builder().signWith(SignatureAlgorithm.HS256, "maybe-token-secret-yes")\n'
        'parser.setSigningKey("legacy-literal-signing-key")\n'
        'new PBEKeySpec("pencil-and-paper-password", salt1, 1000)\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R082-javasecret"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_javasecret_hardcoded_key_negatives_stay_quiet():
    """R082-javasecret stays quiet when key material comes from variables,
    config/env, runtime input, or KDF derivation."""
    src = (
        'SecretKey key = new SecretKeySpec(keyBytes, "AES");\n'
        'new SecretKeySpec(secretEnv.getEncoded(), algorithm)\n'
        'Keys.hmacShaKeyFor(vaultSecret.getBytes(StandardCharsets.UTF_8))\n'
        'Jwts.builder().signWith(SignatureAlgorithm.RS256, privateKey)\n'
        'parser.setSigningKey(signingKey)\n'
        'new PBEKeySpec(password.toCharArray(), salt, iterations)\n'
        'PBEKeySpec spec = new PBEKeySpec(new char[0]);\n'
        'String s = "new SecretKeySpec(\\"literal\\", \\"AES\\")";\n'
        '// Keys.hmacShaKeyFor("baked-in")\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R082-javasecret"], issues


def test_javaopen_response_body_echo_flagged():
    """R083-javaopen fires when the added line writes client-controlled input
    back into the HTTP response through a sink the declared writer rule does
    not cover (CWE-116 improper encoding/escaping of output): the raw byte
    channel response.getOutputStream().write(...) and Spring @ResponseBody /
    ResponseEntity bodies built directly from request accessors."""
    src = (
        'response.getOutputStream().write(request.getParameter("q").getBytes());\n'
        'response.getOutputStream().write(req.getHeader("X-Raw").getBytes());\n'
        'response.getOutputStream().write(("id=" + paramId).getBytes());\n'
        '@ResponseBody String raw(HttpServletRequest request) { return request.getParameter("name"); }\n'
        'new ResponseEntity<byte[]>(req.getParameter("blob").getBytes(), HttpStatus.OK)\n'
        'return ResponseEntity.ok(request.getHeader("callback"));\n'
        'return ResponseEntity.badRequest(req.getParameter("error"));\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R083-javaopen"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_javaopen_response_body_echo_negatives_stay_quiet():
    """R083-javaopen stays quiet when the response body is built from
    server-side data — literals, constants, method results, files, empty
    writes, status/content-type setup — and for comment/string-literal
    reproductions: no unsanitized request echo."""
    src = (
        'response.setContentType("application/pdf");\n'
        'response.getOutputStream().write(pdfBytes);\n'
        'response.getOutputStream().write(staticContent(CONFIG_PATH));\n'
        'response.getOutputStream().write(new byte[0]);\n'
        '@ResponseBody String ok() { return "<h1>Welcome</h1>"; }\n'
        '@ResponseBody List<String> names() { return userService.allNames(); }\n'
        'return ResponseEntity.ok(assetLoader.load("logo.png"));\n'
        'new ResponseEntity<String>("created", HttpStatus.OK)\n'
        'String tpl = "response.getOutputStream().write(request.getParameter(\\"q\\"))";\n'
        '// ResponseEntity.ok(request.getParameter("cb"))\n'
        'return ResponseEntity.ok(req);\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R083-javaopen"], issues


def test_javalog_request_derived_values_flagged():
    """R084-javalog fires when a logging-framework call emits request-derived
    or session-derived values (getParameter/getHeader/getQueryString/URI or
    remote-addr/user/session-id accessors) into the log message."""
    src = (
        'logger.info(request.getParameter("user"));\n'
        'log4j.LOG.info("login=" + req.getParameter("u"));\n'
        'LOGGER.debug("raw headers: " + request.getHeader("X-Trace"));\n'
        'log.warn("q=" + req.getQueryString());\n'
        'logger.error("uri=" + request.getRequestURI());\n'
        'LOG.fine("from=" + request.getRemoteAddr());\n'
        'LOGGER.info("user=" + req.getRemoteUser());\n'
        'Logger.getLogger("audit").severe("sid=" + request.getRequestedSessionId());\n'
        'LoggerFactory.getLogger(X.class).error("err " + req.getHeader("Host"));\n'
        'LogFactory.getLog(X.class).info("body=" + request.getParameter("data"));\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    hits = [i for i in issues if i.rule_id == "R084-javalog"]
    assert [i.line for i in hits] == list(range(1, len(src.splitlines()) + 1)), hits
    assert all(i.severity == "high" for i in hits)


def test_javalog_server_side_messages_stay_quiet():
    """R084-javalog stays quiet when the logged message is built from
    server-side data only, when System.out/err is used (R036-loginj owns
    that), and for comment/string-literal reproductions."""
    src = (
        'logger.info("user " + user.getId() + " updated");\n'
        'LOGGER.debug("total=" + stats.getTotal());\n'
        'LOG.info("startup complete in " + (end - start) + "ms");\n'
        'log.error("db down", ex);\n'
        'System.out.println(request.getParameter("q"));\n'
        'System.err.println("err " + req.getHeader("X"));\n'
        'logger.info(PASSWORD);\n'
        '// LOG.info("sid=" + request.getRequestedSessionId())\n'
        'String tpl = "LOGGER.debug(\\"u=" + request.getParameter(\\"u\\") + \\"\\")";\n'
    )
    issues, _ = analyze_to_issues(_inline_diff(src))
    assert not [i for i in issues if i.rule_id == "R084-javalog"], issues


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
        "yaml.unsafe_load(text)\n"
        "yaml.load(text)\n"
        "torch.load('ckpt.pt')\n",
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
        "return mark_safe(html)\n"
        "node.dangerouslySetInnerHTML = payload\n"
        "$('#list').html(data)\n",
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
        "R017-redirect", "R018-debug", "R019-csrf", "R020-pem", "R021-ssrf",
        "R022-ssti", "R023-xxe", "R024-jwt", "R025-pw", "R026-upload",
        "R027-massassig", "R028-nosql", "R029-ldap", "R030-xpath",
        "R031-ssrf-js", "R032-cmd-node", "R033-protopoll",
        "R034-redos", "R035-hdrinj", "R036-loginj", "R037-credurl",
        "R038-perm", "R039-nav", "R040-tabnab", "R041-postmsg",
        "R042-websock", "R043-math-random", "R044-storage", "R045-cookie",
        "R046-evaljs",
        "R047-postmsg-recv",
        "R048-cookieset",
        "R049-fixatn",
        "R050-dynimp",
        "R051-hostpois",
        "R052-hdritrust",
        "R053-javaexec",
        "R054-javadeser",
        "R055-spelinj",
        "R056-jpaqli",
        "R057-ssrf",
        "R058-jdbcsqli",
        "R059-xpathjava",
        "R060-openredir",
        "R061-ldapjndi",
        "R062-javaxxe",
        "R063-javapath",
        "R064-javareflect",
        "R065-java4xx",
        "R066-javacrypto",
        "R067-javaxss",
        "R068-javarandom",
        "R069-javacsrf",
        "R070-javacook",
        "R071-javatls",
        "R072-javaeval",
        "R073-javaformat",
        "R074-javakeysz",
        "R075-jvachttp",
        "R076-javaredos",
        "R077-javajson",
        "R078-javatpl",
        "R079-javacors",
        "R080-javajwt",
        "R081-javapw",
        "R082-javasecret",
        "R083-javaopen",
        "R084-javalog",
    }
    assert exposed <= rids
    uncovered = rids - exposed
    assert not uncovered, f"rules with no test exposure: {sorted(uncovered)}"
