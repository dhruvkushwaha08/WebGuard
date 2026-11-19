# Testing report

## Automated suite

Command: `.venv\Scripts\python.exe -m pytest -q`  
Environment: Windows, Python 3.12.14, Flask 3.1.3, pytest 8.4.2.  
Result: **31 passed** on 2026-11-05.

Coverage includes registration and password hashing, successful/failed authentication, logout and route protection, CSRF enforcement, deactivated-session rejection, SQLi/XSS detection and false-positive regression samples, parameter binding, escaped rendering, validators, malformed JSON, request-size rejection, security event logging, request-counter classification, security headers, dashboard data, event filters/details, lab event creation, administrator authorization/status updates, and login throttling.

## Real HTTP audit

Command: `.venv\Scripts\python.exe scripts\verify_http.py`  
Result: **40/40 checks passed** on 2026-11-05.

The script starts a loopback server on an ephemeral port and uses a temporary SQLite database. It exercises registration/login/logout, password-hash storage, protected pages, CSRF, SQLi and XSS block and benign-text HTTP probes, simulator behavior, event persistence/search/filtering/date range/sort/pagination/detail, dashboard counts compared with SQLite, normal 404 counter semantics, and regular/admin access. These are HTTP integration checks; they do not run ZAP.

## Browser smoke checks

The updated application was opened in a second loopback process backed by a disposable SQLite database. The browser successfully submitted registration and login, changed dashboard date range, rendered the three charts, navigated Dashboard/Analytics/Events/Testing Lab, ran SQLi and XSS simulations plus a benign keyword scenario, applied and reset events filters (type, severity, action, dates, search, sort, direction), opened and closed event details, moved Next and Previous across two pages of 23 records, and signed out. The dark theme and responsive two-column KPI layout were visually checked at the available narrow viewport.

Synthetic browser-test users and event rows were in the temporary database, not the regular application database. The browser test does not constitute a comprehensive browser compatibility or accessibility audit.

## Final live detection recheck

On 2026-11-05, the existing database was inspected before testing; its four historical `GET /health` alerts were retained. A fresh normal `/health` returned 200 and added no event. The safe simulator phrase returned allowed and added no event. A fresh SQLi and XSS HTTP probe each returned 400 and were persisted as event IDs 5 and 6. The daily blocked counter rose from 6 to 8; the dashboard displayed three SQLi and three XSS events, matching the database aggregates. See the verification report for the historical-event assessment and the dashboard snapshot timing detail.

The Pytest rerun for this pass completed: **31 passed in 32.45s**. The analytics snapshot fix is covered by a regression test; the HTTP audit confirms the KPI and current-day trend match SQLite after the request counter commits. The allowed request cases are tracked only in aggregate `request_counts`; there is no per-request audit row for benign traffic.

After restarting the main app with that fix, a fresh `/health` request returned 200 and did not create another event.

## Not tested / remaining

- OWASP ZAP scan, production WSGI/HTTPS deployment, load testing, distributed rate limiting, cross-browser/device matrix, and formal accessibility review.
- Detector behavior for every possible SQLi/XSS encoding or application context. It remains a heuristic with possible false positives and false negatives.
- The application has no admin UI, rules editor, settings page, or report export flow.
