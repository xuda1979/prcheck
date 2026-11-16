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

- **Security** — no-auth routes, hardcoded secrets, TLS disable, eval/exec,
  SQL injection, insecure deserialization (pickle/cPickle/marshal/joblib,
  `yaml.load`/`full_load`/`unsafe_load`, `np.load(allow_pickle=True)`,
  `torch.load`, `read_pickle`, `shelve`), dependency changes, CORS, privilege
  checks, IDOR, insecure HTTP, OS command injection via shell, path
  traversal, XSS sinks, session cookie flags, weak/legacy crypto, insecure
  `random` for security values, open redirects, SSRF (outbound fetches of
  request-derived URLs), debug mode / DEBUG-level logging, CSRF protection
  disabled, committed private key material (PEM key blocks), server-side
  template injection (SSTI), XXE (XML parsers fed request-derived data), JWT
  verification disabled / alg=none accepted.
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
