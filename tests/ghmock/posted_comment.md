<!-- gh-mock comment for owner/repo#12 (no network) -->

## 🔒 PR Security & Data Checklist

_Analyzed 6 files, +46 / -5 lines._

| Category | High | Medium | Low | Info |
|---|---|---|---|---|
| Security | 5 | 7 | 0 | 0 |
| Data | 0 | 5 | 4 | 0 |
| Behavior | 0 | 3 | 1 | 0 |

### Security checklist

12 item(s) to review:

- [ ] 🔴 [`R001-a`] **No-auth / new public route detected** — src/app.py:13
  ```text
  @app.route("/public/stats", methods=["GET"])
  ```
  _hint: New unauth'd endpoint_
- [ ] 🔴 [`R001-a`] **No-auth / new public route detected** — src/cors.py:13
  ```text
  @app.route("/admin/export")
  ```
  _hint: New unauth'd endpoint_
- [ ] 🔴 [`R008`] **Privilege / authorization logic changed** — src/cors.py:8
  ```text
  def is_admin(user):
  ```
- [ ] 🔴 [`R002`] **Hardcoded credential/key/secret in diff** — src/keys.py:1
  ```text
  API_KEY = "sk-live-1234567890abcdef"
  ```
  _hint: Possible secret committed_
- [ ] 🔴 [`R002`] **Hardcoded credential/key/secret in diff** — src/keys.py:2
  ```text
  password = "hunter2secret!"
  ```
  _hint: Possible secret committed_
- [ ] 🟠 [`R006-deps`] **Dependency added / changed** — pyproject.toml:18
  ```text
  "cryptography>=41.0.0",
  ```
- [ ] 🟠 [`R001-b`] **New route — verify authentication guard** — src/app.py:13
  ```text
  @app.route("/public/stats", methods=["GET"])
  ```
  _hint: Route decorator - check auth_
- [ ] 🟠 [`R007-cors`] **CORS policy configured / relaxed** — src/cors.py:1
  ```text
  from flask_cors import CORS
  ```
- [ ] 🟠 [`R001-b`] **New route — verify authentication guard** — src/cors.py:13
  ```text
  @app.route("/admin/export")
  ```
  _hint: Route decorator - check auth_
- [ ] 🟠 [`R007-cors`] **CORS policy configured / relaxed** — src/cors.py:5
  ```text
  CORS(app, resources={r"/*": {"origins": "*"}})
  ```
- [ ] 🟠 [`R005`] **Potential SQL injection (string-built queries)** — src/db.py:16
  ```text
  query = 'SELECT ' + cols + ' FROM users'
  ```
- [ ] 🟠 [`R003`] **TLS / certificate check disabled** — src/keys.py:5
  ```text
  cfg.verify = False
  ```

### Data checklist

9 item(s) to review:

- [ ] 🟠 [`D003`] **Sensitive data logged / printed** — src/keys.py:6
  ```text
  print("passing KEY=", API_KEY)
  ```
- [ ] 🟠 [`D004`] **Data removed / destructive change** — src/migrations.py:11
  ```text
  conn.execute("DELETE FROM users WHERE token_expired = 1")
  ```
- [ ] 🟠 [`D002-db`] **Database schema / migration change** — src/migrations.py:2
  ```text
  conn.execute("ALTER TABLE users DROP COLUMN ssn")
  ```
- [ ] 🟠 [`D004`] **Data removed / destructive change** — src/migrations.py:2
  ```text
  conn.execute("ALTER TABLE users DROP COLUMN ssn")
  ```
- [ ] 🟠 [`D002-db`] **Database schema / migration change** — src/migrations.py:4
  ```text
  conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
  ```
- [ ] 🟡 [`D001`] **New PII field added to model/schema** — src/migrations.py:2
  ```text
  conn.execute("ALTER TABLE users DROP COLUMN ssn")
  ```
- [ ] 🟡 [`D001`] **New PII field added to model/schema** — src/migrations.py:4
  ```text
  conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
  ```
- [ ] 🟡 [`D001`] **New PII field added to model/schema** — src/migrations.py:7
  ```text
  fields = ["id", "email", "phone"]
  ```
- [ ] 🟡 [`D001`] **New PII field added to model/schema** — src/migrations.py:8
  ```text
  pii = ["ssn", "passport_number"]
  ```

### Behavior checklist

4 item(s) to review:

- [ ] 🟠 [`B001`] **Exception handling changed / swallowed** — src/app.py:22
  ```text
  pass
  ```
- [ ] 🟠 [`B004`] **New library/import affecting behavior** — src/cors.py:1
  ```text
  from flask_cors import CORS
  ```
- [ ] 🟠 [`B004`] **New library/import affecting behavior** — src/keys.py:9
  ```text
  import os
  ```
- [ ] 🟡 [`B005`] **System-level call changed** — src/keys.py:10
  ```text
  os.system("restart.sh " + cfg.url)
  ```

