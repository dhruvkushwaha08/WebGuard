# WebGuard: Web Application Attack Detection and Prevention System

## 1. Abstract

WebGuard is a local educational application that demonstrates request inspection, heuristic SQL injection and cross-site scripting detection, parameterized SQLite queries, escaped output, session-based authentication, event logging, and live database-backed monitoring. The implementation currently has 31 passing automated tests and a loopback HTTP audit with 40 passing checks. It has not undergone an OWASP ZAP assessment and is not a production security certification.

## 2. Introduction

Web applications accept data through URLs, forms, JSON bodies, and cookies. Unsafe handling can allow an attacker to change the meaning of database queries or inject executable browser content. Defensive programming uses validation, safe query APIs, output encoding, access control, request integrity checks, security headers, and monitoring as layers.

## 3. Problem statement

Students need a working example that demonstrates how hostile input is detected and how code-level controls reduce risk, while recording security events and presenting the results from a real database.

## 4. Objectives

- Build a modular Flask and SQLite application.
- Support registration, sign-in, sign-out, roles, and a first-admin bootstrap.
- Inspect request values for common SQLi and XSS patterns.
- Bind SQL values instead of concatenating user input.
- Escape untrusted output and set browser security headers.
- Validate account fields and constrain request size.
- Log suspicious requests and provide authenticated monitoring APIs and UI.
- Demonstrate attack-shaped inputs locally without targeting external systems.
- Verify core behavior through repeatable pytest coverage.

## 5. Existing system

Many small classroom examples either use static mock data or show vulnerable code without isolation. Such examples do not connect detection to persistence and monitoring, and may imply that input filters alone provide security.

## 6. Proposed system

WebGuard combines middleware detection with route validation and safe database/output patterns. Events are persisted in SQLite. Authenticated users can view recent totals and use a controlled detector lab; administrators can view and change account status through protected APIs.

## 7. Literature and security concepts

- **SQL injection:** prevent query structure changes by binding values through parameterized queries; detection patterns are supplementary.
- **Cross-site scripting:** encode output for the context where it is inserted; avoid unsafe HTML sinks and add a Content Security Policy as another layer.
- **CSRF:** require a session-bound token on state-changing requests.
- **Password storage:** use a password hashing function with per-password salt and an appropriate work factor rather than reversible encryption or plaintext.
- **Defense in depth:** combine validation, safe APIs, access control, headers, logging, and operational review.

## 8. Requirements

Python 3.12+, Flask, SQLite, a modern browser, and an optional ZAP installation for a local assessment. Exact install steps are in the README. The app binds to `127.0.0.1` by default.

## 9. System architecture

The Flask application factory initializes the database, registers route blueprints, attaches request inspection and response headers, and installs error handlers. The browser uses Jinja, Bootstrap, vanilla JavaScript, and Chart.js. A request-context database connection is opened and closed through Flask teardown. See [architecture.md](architecture.md).

## 10. Module descriptions

- **Authentication:** validated account creation, Werkzeug hashes, signed session, role state, login throttling, CSRF.
- **Detection:** bounded decoding and regular-expression rules for selected SQLi/XSS shapes.
- **Middleware:** request size checks, query/form/JSON inspection, block responses, and event/counter persistence.
- **Event management:** filter, search, sort, paginate, and read details; no user delete/update route.
- **Dashboard:** SQLite aggregates feed KPI cards, distribution and trend charts, and latest incidents.
- **Testing lab:** controlled local samples call the actual detector and record simulated findings.
- **Before/after:** opt-in command-line script contrasts concatenated and parameterized SQL against a temporary in-memory database.
- **Admin:** list accounts and update another account's active state.

## 11. Database design

SQLite contains `users`, `security_events`, `request_counts`, and `rate_limits`. Password hashes are stored; no password, session cookie, authorization header, or request body is copied to event records. See [database-schema.md](database-schema.md).

## 12. Implementation

All application SQL uses bound parameters. Jinja template expressions are autoescaped by default; browser tables use `textContent`. The detector decodes percent and HTML entities in a bounded loop, then applies configured patterns. Event reasons describe rule matches without storing attack strings. The middleware validates CSRF on state-changing routes, including authentication submissions.

## 13. Testing

The test suite covers accounts, hashes, roles, CSRF, request inspection, event creation, SQLi/XSS pattern samples and false-positive regressions, parameter binding, output escaping, validators, malformed JSON, oversized requests, headers, analytics structure and SQLite snapshot consistency, simulation persistence, admin status, deactivated-session rejection, counter semantics, and throttling. Result: **31 passed** on Python 3.12.14 / Flask 3.1.3 / pytest 8.4.2. A separate loopback HTTP audit passed **40/40 checks**. Browser smoke checks exercised the main flows against a disposable SQLite database. This is functional test evidence, not proof against all attacks.

## 14. Results

The application starts successfully on `http://127.0.0.1:5000`; `/health` and `/auth/login` return HTTP 200 in a local smoke check with expected security headers. The current suite reports 31 passing tests and the real HTTP audit reports 40/40. Browser smoke checks verified registration, authentication, navigation, charts, the simulator, event controls and pagination against a disposable SQLite database. The before/after script returns synthetic records for the unsafe tautology example and zero rows for the parameterized query. ZAP assessment remains unstarted by request.

## 15. Before/after comparison

Concatenated SQL in the isolated script can change the predicate and return synthetic rows. The parameterized query treats the same input as a literal username and returns no rows. Output is shown as escaped text rather than HTML. See [before-after-comparison.md](before-after-comparison.md).

## 16. Limitations

Detector patterns are incomplete and may create false positives or miss variants. Historical aggregated counters from before the current classification fix are not recalculated. The login limiter uses one SQLite table and does not coordinate across processes. There is no MFA, email verification, recovery flow, admin console UI, configurable rule editor, long-term retention policy, or distributed logging. The development server is not production hosting. ZAP assessment is not yet complete.

## 17. Future scope

Add formal threat modeling, structured rule configuration with audit history, a complete user management view, verified browser tests, production WSGI deployment guidance, secure proxy configuration, rate-limit backend suitable for multiple workers, event retention controls, and ZAP baseline plus manually reviewed active scan evidence.

## 18. Conclusion

WebGuard is a functional defensive learning application connecting request detection, secure query/output patterns, event persistence, and database-backed monitoring. Its strongest guarantees come from parameterized database operations and contextual output escaping; its detector is an educational signal, not a standalone security boundary.

## 19. References

1. OWASP, [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html).
2. OWASP, [Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).
3. OWASP, [Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).
4. Flask, [Flask documentation](https://flask.palletsprojects.com/).
5. Python, [sqlite3 documentation](https://docs.python.org/3/library/sqlite3.html).
6. OWASP ZAP, [ZAP documentation](https://www.zaproxy.org/docs/).
