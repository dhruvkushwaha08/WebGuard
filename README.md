# WebGuard

WebGuard is a Flask and SQLite learning project that demonstrates request inspection, SQL injection and XSS pattern detection, secure query handling, authentication, audit events, and a database-backed dashboard. It is designed for a local college demonstration. Its pattern detector is heuristic and is not a substitute for secure coding, a WAF, or a professional security review.

## Problem and objectives

Web applications receive malicious input and can expose data through unsafe queries, rendered HTML, weak access control, or poor monitoring. WebGuard aims to demonstrate how request screening, input validation, parameterized queries, output escaping, authentication, security headers, event recording, and visible metrics work together.

## Stack and features

- Python 3.12+, Flask, Flask Blueprints, SQLite (`sqlite3`)
- Bootstrap 5 and vanilla JavaScript; Chart.js charts
- Werkzeug password hashing and signed Flask sessions
- SQLi/XSS pattern detection, request size checks, CSRF token checks, and login throttling
- User registration/login/logout; admin bootstrap script and admin user status API
- Security events page and API with attack/severity/action/date/search filters, pagination, sorting, and event details
- Database-backed dashboard and analytics KPIs, recent events, attack, severity, and activity charts
- Responsive dark navy/charcoal interface with blue/cyan accents
- Local controlled simulation lab and opt-in, in-memory before/after script

## Architecture and database

`app/__init__.py` creates the Flask app and SQLite schema. `app/security/` contains detector, validator, request inspection, headers, and rate-limit modules. `app/routes/` defines authentication, dashboard, events/simulation, and admin endpoints. Jinja templates and static assets provide the UI. All app SQL statements bind untrusted values through `?` parameters. The `users`, `security_events`, `request_counts`, and `rate_limits` tables are created automatically at startup; see [database-schema.md](docs/database-schema.md).

## Setup on Windows

Open Command Prompt in the project directory:

```bat
py -3 -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if not exist .env copy .env.example .env
```

Edit `.env`: set a random `SECRET_KEY` (generate with `python -c "import secrets; print(secrets.token_hex(32))"`) and set a strong one-time `BOOTSTRAP_ADMIN_PASSWORD`. Keep `.env` private; `.gitignore` excludes it and local database files. Then bootstrap the administrator and remove the password from `.env` after use:

```bat
python scripts\create_admin.py
```

Start on loopback only:

```bat
python run.py
```

Open `http://127.0.0.1:5000`. The actual local environment in which this project was assembled had Python 3.12.14, Flask 3.1.3, and pytest 8.4.2 available in its project virtual environment. No administrator account or database is shipped.

## Use

Register a regular account, sign in, inspect the dashboard and event list, and open **Testing Lab** to simulate a SQLi example, XSS example, safe keyword example, or custom text. Simulations are local and non-destructive; detected examples create audit records. Administrator accounts are created only by the bootstrap script. The admin users API is `GET /api/admin/users` and `PUT /api/admin/users/<id>/status`.

## APIs

The API routes and example responses are described in [api-documentation.md](docs/api-documentation.md). Authenticated JSON endpoints include `GET /api/analytics/attacks`, `GET /api/security/events`, `GET /api/security/events/<id>`, and `POST /api/security/simulate`. State-changing requests outside login/registration require the session CSRF token in `X-CSRF-Token` or `csrf_token` form field.

## Security notes

- Passwords use Werkzeug hashing. Sessions are HTTP-only and SameSite=Lax; enable HTTPS and set `SESSION_COOKIE_SECURE=1` when deployed behind TLS.
- The request detector is heuristic. It can miss obfuscated payloads and can flag benign text. It excludes password, token, cookie, and authorization values from content inspection and never stores submitted values in events.
- All database calls use parameter binding. Jinja autoescapes template output, and client-side tables use `textContent`.
- CSP allows the configured jsDelivr CDN for Bootstrap and Chart.js. For disconnected demos, vendor those assets locally and tighten the policy.
- Rate limiting and SQLite storage are intended for one local process, not distributed or high-traffic deployment. The default Flask development server is not production hosting.
- Configure `SECRET_KEY`; the built-in fallback exists for test/development and logs a warning.

## Tests

```bat
python -m pytest -v
```

The included suite covers login, hashing, protected routes, CSRF, detection and false-positive regressions, SQL parameter binding, escaping, validation, middleware, request size, headers, dashboard data, events, the lab, admin access, and throttling. Current result: **31 passed**. Run the loopback HTTP audit against a disposable SQLite database with:

```bat
python scripts\verify_http.py
```

The most recent run passed **40/40 HTTP checks**. Browser smoke checks also exercised the main navigation, forms, charts, simulator, events filters/details, and pagination against disposable SQLite data. See [testing-report.md](docs/testing-report.md) and [verification-report.md](docs/verification-report.md).

## OWASP ZAP

See [security-assessment/README.md](docs/security-assessment/README.md). A ZAP scan has not been run as part of project assembly; no findings or scan clearance are claimed.

## Documentation and screenshots

- [Architecture](docs/architecture.md)
- [Latest verification report](docs/verification-report.md)
- [API reference](docs/api-documentation.md)
- [Project report](docs/project-report.md)
- [Before/after comparison](docs/before-after-comparison.md)
- [Security assessment instructions](docs/security-assessment/README.md)
- Screenshots: capture real pages after a local run and save them in `docs/screenshots/`; none are included yet.

## Limitations and future work

No production deployment hardening, multi-factor authentication, email verification, distributed throttling, retention controls, structured SIEM integration, admin UI, configurable rule editor, report export, or completed ZAP scan is included. Detection remains heuristic. Useful follow-up work includes production WSGI hosting, broader browser/device and accessibility review, and formal threat modeling.

## Viva preparation

1. **Why use parameterized SQL?** The database treats bound values as data rather than SQL syntax, so input cannot alter query structure.
2. **Does the detector prevent SQL injection by itself?** No. It is a supplementary heuristic; parameterized queries are the primary database defense.
3. **How does XSS prevention work?** Jinja escapes template values and client scripts insert untrusted strings via `textContent`; CSP adds another layer.
4. **Why hash passwords?** A one-way password hash limits exposure if the user table is copied; passwords are not stored in plaintext.
5. **What does the dashboard count?** Request counters and incident rows from SQLite, not hardcoded demonstration values.
6. **What does CSRF protection do?** It requires a session-bound token on state-changing routes to make cross-site forged requests harder.
7. **Why is the vulnerable example isolated?** It uses opt-in execution, synthetic in-memory data, and no network listener or application database.
8. **What are the detector's limits?** Pattern rules can miss variants and produce false positives; they are not a complete WAF or proof of security.
