# Architecture

```text
Browser (Bootstrap, Jinja, vanilla JS, Chart.js)
        │ HTTP / JSON
        ▼
Flask app factory ── before_request inspection ── after_request headers
   ├── auth routes and session guards
   ├── dashboard/analytics routes
   ├── events and simulation routes
   └── admin routes
        │ sqlite3 with bound parameters
        ▼
SQLite: users · security_events · request_counts · rate_limits
```

The application factory in `app/__init__.py` initializes the schema, registers route blueprints, request inspection, response headers, and error handlers. `app/extensions.py` opens one connection per Flask request context and closes it at teardown. The detector normalizes percent/HTML encoding and evaluates heuristic patterns; the middleware blocks a matching request and stores a reason, type, severity, response, and source IP without logging submitted values. Password and token fields are excluded from input inspection. Jinja autoescaping and DOM `textContent` protect displayed content. The lab bypasses middleware scanning only for its controlled detector endpoint and records simulated findings through the detector itself.

## Trust boundaries

All browser supplied values are untrusted. Route validation constrains data size and format. Database queries bind values. Session state is signed by Flask and cookies are HTTP-only/SameSite. The event table is read-only through ordinary application routes. The opt-in comparison script uses only a disposable in-memory SQLite database and synthetic records.

## Known design limits

The application is a local educational build. The rate limiter and counters use SQLite and are not designed for distributed deployment. Flask's development server is loopback-bound but is not a production server. Detector rules need contextual tuning and are not exhaustive.
