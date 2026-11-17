# prcheck — PR Security Checklist + OpenAPI Changelog

Automatic PR **code review checklist + security triage** for GitHub pull
requests, plus a **breaking-change changelog** for OpenAPI specs. Runs as a
local CLI or as a GitHub Action, and emits Markdown (comments) and SARIF (CI /
code scanning) reports.

This is the MVP of the "04-github-prcheck" slice. The analysis engine is
**purely local** — regex/token rules over the diff, plus a deterministic
OpenAPI semantic diff. There is no training data, no network, and no LLM in
the default path (an off-by-default mock summarizer exists).

---

## Features

- **PR diff → checklist** across Security / Data / Behavior categories, every
  item cited with `file:line`.
- **OpenAPI changelog** — semantic diff between two specs (v2 `swagger` or
  v3 `openapi`): endpoints, parameters, schemas, with breaking/non-breaking
  classification and a suggested semver bump.
- **Outputs**: GitHub-flavored Markdown (PR-comment ready) and SARIF 2.1.0.
- **CLI filters**: `--security-only`, `--behavior-only`, `--data-only`, `--min-severity`.
- **Merge gate**: `--require-high-ok` fails the build when High findings are
  unresolved.
- **GitHub Action** for CI + optional `gh` PR comment posting, plus
  **inline review comments** anchoring high/medium findings to the changed
  lines (idempotent on re-runs).
- Fixture-driven tests; no `gh` CLI needed at test time.

## Install

Python 3.10+.

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/prcheck --version
```

## Usage

### 1. Diff → checklist (local file)

```bash
git diff origin/main...HEAD > /tmp/pr.diff
prcheck -d /tmp/pr.diff                # Markdown on stdout
prcheck -d /tmp/pr.diff -o report.md   # write Markdown
prcheck -d /tmp/pr.diff --sarif report.sarif
prcheck -d /tmp/pr.diff --json         # structured JSON
```

Or fetch the PR directly via the `gh` CLI (requires the GitHub CLI, auth'd):

```bash
prcheck --repo owner/repo --pr 123           # fetches `gh pr diff`
prcheck --repo owner/repo --pr 123 --security-only
```

### 2. OpenAPI changelog

```bash
prcheck -d /tmp/pr.diff \
  --openapi-old openapi_v1.yaml \
  --openapi-new openapi_v2.yaml
# OpenAPI section is merged into the same report.
```

### 3. Filters and gate

```bash
prcheck -d /tmp/pr.diff --security-only --min-severity medium
prcheck -d /tmp/pr.diff --require-high-ok   # exit 1 if any unres. High
prcheck -d /tmp/pr.diff --llm-summary       # optional mock summary (off by default)
```

### 4. Cache / incremental

Same base input isn't analyzed twice: findings are keyed on a SHA-256 of the
diff + OpenAPI specs + filter options in `--cache-dir` (default
`.prcheck-cache`). Cache-busting is automatic — an engine-version salt is part
of the key, so a rules change silently misses old entries.

```bash
prcheck -d /tmp/pr.diff --cache-dir .prcheck-cache   # populates
prcheck -d /tmp/pr.diff --cache-dir .prcheck-cache   # cached; replay
prcheck -d /tmp/pr.diff --no-cache                   # bypass
```

### 5. PR comment + local "gh simulation" (AC6)

Real posting (needs a token): the CLI itself doesn't post; the GitHub Action
does it, or you can run the comment helper directly:

```bash
python action/gh_comment.py --repo owner/repo --pr 12 --body-file report.md \
    --gh-cli            # via the `gh` CLI, or without --gh-cli via REST API(needs GH_TOKEN)
```

The full report is **updated in place, not stacked**: on a re-run the Action
looks for the previous report comment (tagged with a `<!-- prcheck-report -->`
marker) and PATCHes it with the fresh body, so every push refreshes a single
comment instead of accumulating duplicates.

Offline simulation (no network, no token) — writes the would-be comment body
into `tests/ghmock/posted_comment.md`:

```bash
python action/gh_comment.py --repo owner/repo --pr 12 --body-file report.md --mock
```

Inline review comments: with `--post-inline-comment=true` the Action turns
high/medium findings into GitHub review comments anchored to the added lines
(`path` + `line`). Findings at the same location are merged into one comment;
a `<!-- prcheck-inline -->` marker makes re-runs idempotent (already-posted
comments are skipped, so the PR doesn't accumulate duplicates).

### 6. As a GitHub Action

See `.github/workflows/prcheck.yml`. The workflow:

1. checks out the repo and base ref,
2. generates the diff with `git diff origin/main...HEAD`,
3. compares `BASE_SPEC` vs `HEAD_SPEC`,
4. runs `prcheck`, posts the Markdown as a PR comment with `gh`, and exits 1
   on `--require-high-ok` gate.

Action inputs include `post-comment` (post the Markdown report as a PR
comment) and `post-inline-comment` (also anchor per-finding review comments to
the added lines). Set `permissions: { pull-requests: write }` in the workflow
so the ephemeral `GITHUB_TOKEN` can post both.

### 7. Webhook bridge (phase P3, bonus)

`action/webhook.py` exposes the **same** analysis engine over a minimal WSGI
endpoint. Useful as the seed of a hosted GitHub App: a handler receives the
diff + specs, returns the checklist JSON, and can post the Markdown as a PR
comment (reusing the REST client).

```bash
# analyze a payload file directly (no server)
python action/webhook.py payload.json > report.json

# or mount as WSGI:  gunicorn action.webhook:wsgi_app
```

Payload: `{"diff": "...", "repo": "owner/repo", "pr": "7",
"base_spec": "<inline or path>", "head_spec": "<inline or path>"}`. Gate /
comment behavior honors the same `INPUT_*` env vars as the action.

The bridge also accepts **raw GitHub `pull_request` webhook events** directly
(the shape GitHub sends a hosted App): `repository.full_name`,
`pull_request.diff_url` and the PR number are extracted automatically, so a
hosted App can forward the unmodified event body.

Set `WEBHOOK_SECRET` to verify every request against GitHub's
`X-Hub-Signature-256` header before analysis (HMAC-SHA256). Forged or
unauthenticated events get a clean `401` instead of being analyzed or posting
comments.

The bridge can also fetch a PR's diff itself: pass `"diff_url"` (a GitHub PR
URL such as `https://api.github.com/repos/owner/repo/pulls/7`) instead of an
inline `diff`. The diff is fetched with the GitHub API's unified-diff media
type, using `GH_TOKEN`/`GITHUB_TOKEN` when present (private repos). An inline
`diff` always takes precedence.

## Rules

The rule library lives in `prcheck/rules.py` and is a plain list of
(id, category, severity, summary, regex, hint). Categories:

- **Security** — no-auth routes, hardcoded secrets (incl. credentials embedded in
  URL / connection-string literals such as `postgres://user:pass@host` or
  `jdbc:…?user=x&password=y`), TLS disable, eval/exec,
  SQL injection, insecure deserialization (pickle/cPickle/marshal/joblib,
  `yaml.load`/`full_load`/`unsafe_load`, `np.load(allow_pickle=True)`,
  `torch.load`, `read_pickle`, `shelve`), dependency changes, CORS, privilege
  checks, IDOR, insecure HTTP, OS command injection via shell (Python) or Node child_process exec/spawn, path
  traversal, XSS sinks (innerHTML/outerHTML/document.write, React
  `dangerouslySetInnerHTML`, jQuery `.html()` setters), session cookie flags,
  weak/legacy crypto, insecure
  `random` for security values, insecure JS `Math.random()` for security
  values (tokens/OTPs/nonces vs. `crypto.getRandomValues`/`randomUUID`/
  `randomBytes`), open redirects, client-side navigation to
  dynamic/executable-scheme URLs (window.open / location.href / location.assign|replace /
  document.location fed javascript:/html-data: literals, request-derived URLs, or url-named
  variables — DOM XSS / open redirect), reverse tabnabbing (target=_blank
  anchors / window.open lacking rel=noopener/noreferrer), cross-origin message
  disclosure (postMessage with a wildcard `'*'` or a request/URL-derived
  targetOrigin), SSRF (outbound fetches of
  request-derived URLs via requests/httpx/urllib/aiohttp, including
  session/client-object receivers and `aiohttp.request(method, url)`), debug mode / DEBUG-level logging, CSRF protection
  disabled, committed private key material (PEM key blocks), server-side
  template injection (SSTI), XXE (XML parsers fed request-derived data), JWT
  verification disabled / alg=none accepted, plaintext password storage
  (password fields assigned raw request input or bare variables), unrestricted
  file upload (request.files saved directly or .save() targets fed a filename
  attribute / request data / os.path.join with a filename), mass assignment
  (request dicts fed wholesale into ORM create/update or constructors), NoSQL
  injection (Mongo-family queries fed request dicts wholesale or `$where`
  built from request fragments), LDAP injection (python-ldap `search_s`/
  `search_st`/`search_ext` family or ldap3/conn-named `.search` receivers fed
  request-derived filters), XPath injection (lxml `.xpath()` calls or
  `etree.XPath`/`XPathEvaluator` compilations fed request-derived queries),
  client-side SSRF (JS `fetch`/`axios`/`got`/Node `http(s)`/`request` and
  `XMLHttpRequest().open(method, url)` sinks fed request-derived URLs),
  WebSocket endpoint from cleartext `ws://` literal or request/URL-derived URL
  (`new WebSocket(…)` against request/ctx/query/search-derived input or a
  url-named variable, vs. trusted `wss://` literals and location/scheme-derived
  hosts),
  prototype pollution (JS `Object.assign`/lodash `merge` family/jQuery
  `extend` fed request-derived objects, or direct `__proto__` assignment of
  request input), regex injection / ReDoS (Python `re.*` sinks
  compile a request-derived pattern as their first argument, or a JS
  `RegExp` constructor is built from request input), HTTP response header
  injection (request-derived values written via Python
  `response.headers[]`/`resp[]` subscript-assign or
  `set_header`/`add_header`/`set_cookie`, or Node `res.setHeader`/`header`/
  `append`/`set`/`cookie`/`writeHead` and XHR `setRequestHeader`), log
  injection / log forging (request-derived values written to Python
  `logger`/`log`/`logging` `.debug`/`.info`/`.warning`/`.error`/`.exception`/
  `.critical` or `print()`, Node/JS `console.log`/`warn`/`error`/`info`, Java
  `System.out`/`err` `.println`/`.print`/`.printf`), insecure file
  permissions (world-writable chmod 0o777/0o666/0o1777, setuid/setgid
  0o4777, makedirs/mkdir `mode=…`, quoted `['chmod', '777', …]`, and
  `umask(0)` masking disabled), browser storage of security-sensitive
  values (tokens/sessions/credentials written to `localStorage`/
  `sessionStorage` via `setItem`, bracket-key or dot-key assignment —
  readable by any injected script, vs. httpOnly cookies), client-side
  `document.cookie` writes of security values (tokens/sessions/credentials
  written via `=`/`+=` — such cookies can never be httpOnly, so XSS reads the
  bearer material straight off the cookie object, vs. server-side httpOnly
  cookies), JS dynamic code execution from strings (`new Function`/`Function()`
  constructors including `window`/`globalThis`/`global` dotted forms, and
  `setTimeout`/`setInterval` with a string — not a callback — first
  argument, the same primitive as `eval`, CWE-95), unvalidated
  cross-window message receivers (postMessage handlers consuming `event.data`
  without referencing `event.origin`/`event.source` on the same line —
  CWE-346, the receiver-side complement to the wildcard targetOrigin rule),
  server-side session/token cookies written without
  Secure/HttpOnly/SameSite flags (`response.set_cookie`/`res.cookie` calls
  naming a session/token/credential key with none of the three hardening
  flags on the line — CWE-614/CWE-1004), session containers
  (re)assigned a request-derived session identifier (a session dict/session
  object indexed by a sid/`session_id`/`id_token` key or the `req.session.id`
  property adopted from `request.*`/`req.*` input — CWE-384, adopting a
  client-supplied id pre-picks the victim's session and fixates it after
  login; server-generated ids and generic keys like `session['theme']` stay
  quiet), dynamic imports of a request-derived module path (Python
  `__import__`/`importlib.import_module` or Node `require()`/dynamic
  `import()` fed by `request.*`/`req.*` — CWE-470, letting the caller pick
  which module/package loads, arbitrary code in Node; static literals like
  `require('express')` and config variables stay quiet), redirects and
  absolute URLs built from the client-supplied Host header (request.host / 
  request.host_url or request|req.headers['Host'] / .Host / headers.get('Host')
  fed to a redirect(...) call, an http/https literal build, or a
  URL/reset/callback-link assignment — CWE-644 Host Header Attack: open
  redirect, poisoned emailed-reset links, and Vary-less cache poisoning;
  allowed-host guards, comparisons, log lines and plain reads stay quiet),
  security decisions built on a client-spoofable proxy/forwarded header
  (X-Forwarded-For / X-Real-IP / X-Client-IP / CF-Connecting-IP /
  True-Client-IP / X-Forwarded-Host / X-Forwarded-Proto(-col) / X-Scheme /
  X-Forwarded-Url / X-Original-URL / X-Rewrite-URL / Forwarded fed to an IP
  allowlist, rate limit, auth, scheme or URL decision — CWE-807 / CWE-348:
  clients forge the value to bypass IP-based access control, downgrade HTTPS
  checks, or poison generated URLs; log lines, plain reads into generic
  variables and display-only uses stay quiet), Java OS command execution
  (`Runtime.getRuntime().exec(...)` / `ProcessBuilder(...)` constructions fed
  a non-literal command — a request parameter, `@RequestBody`-derived
  variable, argv, env lookup or a `+`-concatenated string: Java always forwards
  the exec argument to the shell (`/bin/sh -c`), so command separators execute
  attacker code — CWE-78; all-literal commands, ProcessBuilder config-only
  calls and regex `.exec(...)` stay quiet, and Node `child_process.exec` /
  Python `subprocess` remain owned by R032/R012).
- **Data** — PII fields, migrations, sensitive logging, destructive DML.
- **Behavior** — swallowed exceptions, retries/timeouts, status codes,
  imports, system calls.

Rules fire only on **added** lines of the diff, so closed-but-unchanged code
isn't re-flagged.

## OpenAPI diff semantics

| change                          | breaking |
|---------------------------------|----------|
| endpoint added                  | no       |
| endpoint removed                | yes      |
| parameter added                 | no       |
| parameter now required          | yes      |
| parameter removed               | yes      |
| parameter schema type changed   | yes      |
| schema added / new property     | no       |
| schema removed / property removed  | yes       |
| required flag changed           | yes      |
| summary / description changed   | no       |

Suggested bump: `major` if any breaking change, `minor` if only non-breaking
additions, `patch` otherwise.

## Development

```bash
.venv/bin/pip install pytest
.venv/bin/python -m pytest -q
```

Fixtures live in `tests/fixtures/`:

- `example_pr.diff` — a realistic PR touching routes, secrets, DB, CORS,
  deps, and migrations (hits AC1/AC2/AC5).
- `openapi_v1.yaml` / `openapi_v2.yaml` — a spec pair with additive **and**
  breaking changes (hits AC3/AC4/AC6).

## Roadmap / non-goals

Not in this MVP: deep static analysis (module 03), a fully hosted GitHub App /
tenant dashboard (phase P3 is provided only as a minimal webhook bridge),
multi-service orchestration. Optional LLM summarizer is a stub (mock) and
stays off by default.
