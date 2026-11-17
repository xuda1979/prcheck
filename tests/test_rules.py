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
    }
    assert exposed <= rids
    uncovered = rids - exposed
    assert not uncovered, f"rules with no test exposure: {sorted(uncovered)}"
