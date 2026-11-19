# WebGuard development progress

**Updated:** 2026-11-05

## Completed in this implementation pass

- Reduced the confirmed SQLi/XSS false positives while keeping the tested malicious payloads detectable.
- Added unit regression coverage and actual HTTP probes for benign phrases and malicious payloads.
- Completed the events page with attack-type, severity, action, date range, search, sorting, pagination, reset, and detail dialog.
- Added the analytics page and applied the dark cybersecurity theme consistently across auth, dashboard, analytics, events, and testing lab.
- Corrected request counter classification so ordinary route errors are not counted as security blocks; middleware, CSRF, malformed input, and rate-limit blocks are counted as blocked.
- Tested SQLite persistence and dashboard counts against real temporary database records.
- Exercised browser registration/login/sign-out, navigation, date range, charts, simulator safe/attack cases, event filters/details, and pagination with disposable records.
- Updated `docs/verification-report.md`, `docs/testing-report.md`, and project documentation with current results and limits.

## Verification results

- Latest Pytest after ZAP-related fixes: **32 passed in 35.43s** with `.venv\Scripts\python.exe -m pytest -q`.
- Loopback HTTP audit: **40/40 passed** with `.venv\Scripts\python.exe scripts\verify_http.py`.
- Browser smoke checks: completed against an isolated loopback instance and disposable SQLite database. See the verification report for the exercised controls.
- SQL parameterization: reviewed every application SQL execution; query values are bound, while dynamic sort identifiers are allow-listed.
- ZAP Phase 13: local baseline/passive and controlled active scans completed; see `docs/security-assessment/`.

## Final live detection verification (2026-11-05)

- Kept all historical SQLite events. Of the four older `GET /health` events, ID 4 (`UNION followed by SELECT`) is the previously confirmed `UNION SELECT` false positive; IDs 1–3 cannot be definitively classified because the submitted values are not stored.
- Fresh `GET /health`: **200**, no new security event; daily safe counter increased by one.
- After restarting the app with the dashboard snapshot fix, another `GET /health` returned **200**; `/health` event count stayed at six and aggregate safe/blocked moved 158/8→159/8.
- Safe simulator phrase: **NO MATCH · ALLOWED**, no malicious event; daily safe counter increased by one.
- Fresh SQLi and XSS requests: **400** each; SQLite event IDs **5** and **6**, respectively; daily blocked count increased from 6 to 8.
- The first dashboard snapshot lagged its post-response SQLite counter by one. The analytics response now includes its own allowed request; the updated regression test and HTTP audit assert KPI totals match SQLite after the response completes.
- Events filters and details were tested against the six real rows. The UI Next button was disabled at the fixed 20-row page size; authenticated API pagination returned event ID 2 on page 2 of 6.
- Full Pytest rerun: **31 passed in 32.45s**; loopback HTTP audit: **40/40 passed**.

## Remaining tasks / known limits

- ZAP Phase 13 has been completed. The post-fix scan is limited to localhost and does not establish that the application is secure; authenticated route coverage remains incomplete.
- Detection rules are heuristic and cannot guarantee zero false positives or full coverage of obfuscated/novel payloads.
- Allowed requests are represented by daily aggregate counters rather than one SQLite event row per benign request; stored historical security-event records omit submitted values, limiting retrospective classification.
- No admin browser console, rules editor, settings page, or report export exists.
- Production hosting, HTTPS/security-cookie setup, multi-process rate limiting, cross-browser/device QA, load testing, and a formal accessibility review remain outside this pass.

## Local run

From Command Prompt:

```bat
cd /d C:\Users\Asus\Projects\WebGuard
.venv\Scripts\activate
python -m pytest -q
python scripts\verify_http.py
python run.py
```

Open `http://127.0.0.1:5000`. Configure `.env` first for a demonstration; set a random `SECRET_KEY` and provision an administrator with a one-time `BOOTSTRAP_ADMIN_PASSWORD` via `python scripts\create_admin.py`.

## OWASP ZAP assessment (2026-11-05)

- Installed and verified OWASP ZAP 2.17.0; Java 25.0.2 was available.
- Pre-fix baseline on `http://127.0.0.1:5000/` found a missing CSP `form-action` directive (Medium), missing SRI on the Bootstrap CDN stylesheet (Medium), and a Werkzeug/Python `Server` version banner (Low). Evidence and retained pre-fix reports are in `docs/security-assessment/`.
- Fixed the CSP, added version-pinned SHA-384 SRI for Bootstrap CSS and Chart.js, and masked the development server version in `run.py`.
- The corrected post-fix ZAP baseline and controlled active scan plans completed with exit code 0 on updated source at `http://127.0.0.1:5001/`, using a separate temporary SQLite database. The reports contain only informational session-cookie recognition; no Medium/Low SQLi, XSS, or header findings were reported.
- The active scan scope was only `/health`, rules 40012 and 40018, Low strength, one worker, 100 ms delay, two-minute cap. SQLite recorded detector blocks during ZAP probes. Explicit post-scan HTTP checks returned normal input 200, SQLi 400 (event 36), and XSS 400 (event 37).
- Cookie observation: `HttpOnly` and `SameSite=Lax` were present; `Secure` is not set for this HTTP-only local run. For HTTPS deployment set `SESSION_COOKIE_SECURE=1`.
- Latest automated test suite after fixes: **32 passed in 35.43s**.
- Port 5000 remained running, but a final check confirmed it still emits the old Werkzeug/Python `Server` header and CSP without `form-action`; the existing Python process did not reload the edited source. This session could not restart it because process-control approval was rejected and Task Manager was inaccessible. Stop the old process in its original terminal and run `python run.py` to load the source changes. The post-fix retest used updated source on port 5001 and an isolated database.
- ZAP emitted Java preference and optional JBroFuzz startup log warnings/errors; the final corrected scan plan still completed with exit code 0. ZAP authentication was not configured, so protected dashboard/admin routes were not crawled.



