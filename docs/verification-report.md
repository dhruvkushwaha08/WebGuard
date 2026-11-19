# WebGuard verification report

**Review date:** 2026-11-05  
**Scope:** Existing WebGuard project and its current local implementation. Phase 13 ZAP assessment was completed on localhost; detailed evidence is recorded below and in `docs/security-assessment/findings-summary.md`.

## Final detection recheck against the existing database

No historical records were deleted or altered. The existing database initially contained four `GET /health` alerts:

| ID | Type | Reason | Assessment |
|---:|---|---|---|
| 1 | XSS | `Script element` | Cannot classify definitively: the original request value is not stored. |
| 2 | SQL_INJECTION | `SQL comment marker` | Cannot classify definitively: the original request value is not stored. |
| 3 | XSS | `Script element` | Cannot classify definitively: the original request value is not stored. |
| 4 | SQL_INJECTION | `UNION followed by SELECT` | The prior verification recorded the benign `UNION SELECT` probe being blocked. This is the confirmed historical false positive. |

The event schema intentionally records rule/reason and request metadata, not submitted input. That makes ID 4 identifiable from the prior verification record, but the stored rows alone cannot establish whether IDs 1–3 were malicious or benign.

Fresh checks against the regular local app/database then produced:

| Probe | HTTP/UI result | SQLite result |
|---|---|---|
| `GET /health` | HTTP 200, `{"status":"ok"}` | `/health` event count stayed 4; daily `safe` counter increased 89→90; `blocked` stayed 6. |
| Simulator with `SELECT is a common keyword in documentation.` | UI showed `NO MATCH · ALLOWED`; the repeatable HTTP audit returned 200 for this valid safe simulation. | On the regular app, simulator event rows stayed empty; daily `safe` counter increased 94→95 for the simulator request. The HTTP audit independently confirmed the safe result only increments allowed counters. |
| SQLi `GET /health?q=' OR 1=1--` | HTTP 400 | Event **ID 5**, `SQL_INJECTION`, `Boolean tautology pattern`, `BLOCKED`, status 400. |
| XSS `GET /health?q=<script>alert(1)</script>` | HTTP 400 | Event **ID 6**, `XSS`, `Executable script element`, `BLOCKED`, status 400. |

The two attack requests increased the blocked counter from 6 to 8. No event was created for either allowed probe, as expected by the current event model. SQLite stores daily allowed/blocked totals rather than a separate row for each benign request, so the normal and safe simulator probes are represented in aggregate, not individually traceable event rows.

The dashboard initially displayed **Safe 99, Blocked 8, Total 107, SQLi 3, XSS 3**. An immediate database snapshot showed safe 100, blocked 8, total 108 because the analytics request was counted in `after_request` after the API response snapshot. That exposed a one-request lag. The analytics endpoint was updated to include its own allowed request in the response KPI and current-day trend. A new regression test and the HTTP audit now assert the returned KPI equals the SQLite counters once the response completes. Later dashboard and events navigation/polling increased the safe total further. The event aggregates (3 SQLi and 3 XSS) matched SQLite.

The events UI was verified against the six actual records. Combined SQLi/HIGH/BLOCKED/date/search/sort filters returned event 4 for the `UNION` search; combined XSS/MEDIUM/BLOCKED/date/search/sort filters returned event 6. Event details displayed the stored rule reason/status. Since the UI page size is fixed at 20 and only six rows existed, its Next button was correctly disabled; the authenticated events API returned actual stored event ID 2 for `per_page=1&page=2` (`total=6`).

Final full Pytest rerun after the dashboard snapshot fix: **31 passed in 32.45s**. The loopback HTTP audit then passed **40/40**, including a safe simulator POST (HTTP 200) that left the event table unchanged and incremented only the allowed counter.

After restarting the regular app with the snapshot fix, a final `GET /health` returned HTTP 200 with `{"status":"ok"}`. The `/health` event count stayed at six; the aggregate safe count increased 158→159 and blocked stayed at eight.

## Summary

- Automated suite: **31 passed** with `.venv\Scripts\python.exe -m pytest -q`.
- Real loopback HTTP audit: **40/40 checks passed** with `.venv\Scripts\python.exe scripts\verify_http.py`. It starts an ephemeral local HTTP server and uses a disposable SQLite database.
- Browser smoke test: completed on the updated UI using a second loopback instance and disposable SQLite database. Registration and login, navigation, date-range refresh, chart rendering, simulator scenarios, event filtering/search/reset/details, pagination in both directions, and sign-out were exercised.
- The false-positive regressions checked over actual HTTP include benign `UNION SELECT` prose and XSS documentation text containing `<script>` and `onerror=`. Both returned HTTP 200; SQLi and XSS test payloads returned HTTP 400.
- All application SQL value inputs use bound parameters. Dynamic event sort identifiers and directions are selected from allow-lists; the schema script is static.
- ZAP assessment was intentionally not run. No ZAP results or security clearance are claimed.

## Architecture inspected

`run.py` loads environment configuration and runs Flask on `127.0.0.1:5000`. `app/__init__.py` is the application factory; it initializes SQLite, registers route blueprints, request inspection, request-count updates, security headers, CSRF template context, and error handlers. `app/extensions.py` manages request-scoped SQLite connections. `app/routes/` contains authentication, dashboard and analytics, event listing and simulation, and administrator APIs. `app/security/` contains input validation, SQLi/XSS heuristics, request inspection, security headers, and login throttling. `app/templates/` and `app/static/` provide the themed pages and browser-side rendering. `scripts/` contains administrator bootstrap, the isolated demonstration, and loopback HTTP audit. `tests/` holds pytest coverage; `docs/` contains the project, API, and verification records.

## Feature-by-feature verification

| Feature | Verification evidence | Result |
|---|---|---|
| SQL injection detection | Actual HTTP requests blocked `' OR 1=1--` and `' UNION SELECT NULL--` with 400. Plain `SELECT` and `UNION SELECT` documentation text returned 200. Regression tests cover those distinctions. | Verified for tested samples; heuristic coverage is not exhaustive |
| Parameterized queries | Reviewed every application `execute()` in `app/`. User-supplied and other query values use `?` bindings. Event sort column/direction are allow-listed; `executescript` is only used for the static schema. | Verified in source |
| XSS detection and safe output | Actual HTTP script-tag query returned 400 without reflecting `<script>`. Normal documentation text mentioning `<script>`, `onerror=`, and `javascript:` returned 200. Pytest confirms Jinja escaping; event/details and dashboard rows use `textContent`. | Verified for tested samples |
| Registration and login | Browser registered a synthetic account in the disposable UI database and displayed the success notice. Browser login reached the dashboard. HTTP audit also exercised registration, hashed password storage, and login. | Verified |
| Authentication, session, logout | Protected routes redirect or return 401 while signed out; browser sign-out returned to login; HTTP audit confirmed a later API call returned 401. | Verified |
| CSRF | Real HTTP state-changing simulator request without a token returned 400; token-bearing request succeeded. Auth forms and sign-out were exercised. | Verified |
| Administrator authorization | HTTP audit confirmed regular user receives 403, admin can list users without password hashes, and admin can update another account's status. | Verified by HTTP; there is no browser-facing admin console |
| SQLite event logging | SQLi and XSS block events and simulator events were queried back from the same disposable SQLite database through the events API and event-detail route. | Verified |
| Dashboard statistics | Analytics values were compared to SQLite `request_counts` snapshots. A separate check confirms a normal application 404 increases the allowed/inspected count, not the blocked count. | Verified; counters represent the middleware security decision |
| Events filters and detail | Browser applied attack type, severity, action, from/to date, search, sort, and direction controls; result rows matched. Reset restored all events. A detail dialog opened and closed. HTTP audit tested invalid dates, search, combined filters, sort, pagination, and range exclusion against SQLite records. | Verified |
| Events pagination | With 23 seeded synthetic events in the disposable UI database, browser Next showed page 2 of 2, Previous returned to page 1 of 2, and the opposite edge button was disabled. HTTP audit also checks page 2 results. | Verified |
| Dashboard and analytics charts | Browser rendered attack distribution, request activity, and severity charts. Changing the date range refreshed KPI values; the Analytics navigation route rendered the same chart set with analytics headings. | Verified at current browser viewport; no chart drill-down behavior is implemented |
| Simulator/backend communication | Browser ran SQLi, XSS, and safe keyword scenarios. The first two displayed detected/blocked results and created SQLite-backed event rows; the safe phrase displayed no match/allowed. | Verified |
| Navigation and responsive theme | Browser navigated dashboard, analytics, events, testing lab, registration, and sign-in. Visual inspection showed the dark navy/charcoal palette, blue/cyan accents, green safe KPI, red blocked KPI, and two-column narrow-width card layout. | Verified at the available viewport; broader device matrix not run |

## Fixes made during verification

1. Tightened SQLi heuristics so plain `UNION SELECT` prose, standalone SQL vocabulary, and ordinary boolean text are not automatically classified as attacks. Quote/comment injection contexts remain detected.
2. Tightened XSS rules to require executable script contents, event-handler attributes, active-element attributes, or executable URL schemes rather than flagging explanatory prose solely for naming HTML or JavaScript terms.
3. Added regression tests and real HTTP checks for both false-positive examples and genuine malicious SQLi/XSS samples.
4. Completed the events page with attack type, severity, action, date, search, sort, pagination, reset, and event-detail controls. The browser renders untrusted event data with `textContent`.
5. Applied a responsive dark cybersecurity theme across authentication, dashboard, analytics, events, and lab pages; added the analytics page and dark chart styling.
6. Corrected request-counter semantics. Counts now follow the security inspection decision, so a normal route-level 404 is not miscounted as a detector block. Request validation, request inspection, CSRF, and rate-limit blocks are counted as blocked.
7. Expanded `scripts/verify_http.py` to test these behaviors against a disposable database and real HTTP server.

## Remaining limitations

- Detection remains heuristic. Other encodings, contexts, or payload forms may be missed, and untested benign expressions may still be flagged. Passing these probes is not proof of a low global false-positive rate.
- Request counters describe security middleware allowed/blocked decisions. They are not a count of successful business operations or a complete traffic telemetry system.
- Existing aggregate `request_counts` data from before the counter-classification fix is not recalculated. The app has no per-request history from which to reconstruct the old daily totals.
- The admin API has no browser-facing user-management console. There is no rule editor, settings page, or report-export flow.
- Browser checks used one available viewport. A full cross-browser and multi-device responsive matrix, assistive-technology review, and load test remain undone.
- Production deployment hardening remains out of scope: the default Flask development server is local-only, secret-key configuration is required, and secure cookies require HTTPS configuration. SQLite throttling is single-process and not distributed.
- ZAP Phase 13 was completed. Its scan scope and authenticated-route limitations are documented in the assessment section below.

## OWASP ZAP Phase 13 verification (2026-11-05)

### Scan execution

- OWASP ZAP **2.17.0** with Java **25.0.2**.
- Pre-fix baseline targeted only `http://127.0.0.1:5000/`. It used ZAP’s Automation Framework, a one-minute traditional spider, depth 5 and up to 25 children per node, with form processing and POST submissions disabled, followed by passive scan completion.
- After fixes, the baseline and controlled active scan targeted only the updated WebGuard source at `http://127.0.0.1:5001/`, running with an isolated temporary SQLite database. The original port-5000 process remained running but could not be restarted under this environment’s process-control policy.
- The corrected plan completed successfully with exit code **0**. It generated `zap-baseline.html/json` and `zap-active.html/json`. The active portion scanned only `/health`, with rules **40012** (Reflected XSS) and **40018** (SQL Injection), Low strength, one worker, 100 ms delay, and a two-minute maximum.
- A first baseline report from port 5000 is retained as `zap-baseline-before-fixes-5000.html/json`; that initial plan returned exit 1 because a report-job `sites` parameter was misplaced. A first active attempt is also retained with its plan warning. The final corrected plan and reports are authoritative.

### Findings and fixes

- **Medium — CSP missing `form-action` (10055):** The initial report evidenced the missing directive on `/`, `/auth/login`, `/auth/register`, `/events`, and `/lab`. Added `form-action 'self'` to the policy. The alert is absent from both post-fix reports.
- **Medium — CDN stylesheet missing SRI (90003):** The initial report showed the Bootstrap 5.3.3 stylesheet without `integrity` on the root, login, and registration pages. Added a version-specific SHA-384 integrity value and `crossorigin="anonymous"`; added SRI to the Chart.js 4.4.7 script as well. Regression tests assert both rendered integrity attributes. The alert is absent from the post-fix reports.
- **Low — Server version disclosure (10036):** Initial responses disclosed `Werkzeug/3.1.9 Python/3.12.14`. `run.py` now supplies a request handler whose header is `Server: WebGuard`. This is verified by a live HTTP response on the updated port-5001 instance; the pre-existing port-5000 process still needs a restart to load the change.
- **Informational — session management response identified (10112):** ZAP recognized Flask’s `session` cookie. This is not a vulnerability. The login response included `HttpOnly` and `SameSite=Lax`; `Secure` was absent because this was an HTTP-only local run. For HTTPS deployment, set `SESSION_COOKIE_SECURE=1`.
- No SQL injection or XSS ZAP vulnerability alert appeared in the final active report. WebGuard’s isolated test database recorded blocked ZAP probes, and separate actual HTTP verification confirmed normal input returned **200** with no malicious event, SQLi returned **400** and event **36**, and XSS returned **400** and event **37**. The SQLite scan database contained 37 blocked events after the scan/test sequence; no existing project records were deleted or altered.

### Verification after fixes

- `.venv\Scripts\python.exe -m pytest -q`: **32 passed in 35.43s**.
- Updated instance `/health`: HTTP **200**; observed response headers included `form-action 'self'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Server: WebGuard`.
- The final post-fix baseline and active reports contain one informational alert group with three session-cookie recognition instances, and no Medium or Low vulnerabilities.

### Limitations

- ZAP authentication was not configured, so protected dashboard, analytics, events, lab, and administrator routes were not crawled. Existing HTTP/browser verification of access control remains in the earlier report sections.
- The scan is limited to the listed local URLs and rules; a clean report is not a statement that the application is secure.
- ZAP startup logged Java preferences and optional JBroFuzz initialization warnings/errors. The final selected scan jobs completed, and the Automation Framework exited 0; the report JSON contains scanner log insights.
- The initial passive crawl sent only GET requests to port 5000, so its allowed-request aggregate may have increased; active attack probes used the isolated port-5001 database. No existing event rows were deleted. The application at port 5000 was kept running as requested. A final check confirmed it still returns HTTP 200 but retains the old Werkzeug/Python `Server` header and CSP without `form-action`, because its pre-existing process did not reload changed code. Since this environment rejected process-control approval and Task Manager was inaccessible at its integrity level, post-fix scan evidence was gathered from a fresh updated instance on port 5001 with a separate SQLite database. Stop the old process from its original terminal and run `python run.py` from the project directory to apply the code changes at port 5000. Until then, the source fixes are not active in the retained port-5000 process.

See `docs/security-assessment/findings-summary.md` for the severity table and the raw scan artifacts in that directory.
## Commands

From Command Prompt:

```bat
cd /d C:\Users\Asus\Projects\WebGuard
.venv\Scripts\activate
python -m pytest -q
python scripts\verify_http.py
python run.py
```

Open `http://127.0.0.1:5000`. Before a demonstration, create `.env` from `.env.example`, set a random `SECRET_KEY`, and provision an administrator once with `BOOTSTRAP_ADMIN_PASSWORD` using `python scripts\create_admin.py`.



