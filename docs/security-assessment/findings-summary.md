# OWASP ZAP findings summary

**Assessment date:** 2026-11-05 (Asia/Kolkata)  
**ZAP:** 2.17.0  
**Java:** 25.0.2  
**Scope:** Only WebGuard on loopback. The first pre-fix passive baseline targeted `http://127.0.0.1:5000/`. Post-fix baseline and active retests targeted the same updated source at `http://127.0.0.1:5001/` in an isolated temporary SQLite database because the existing port 5000 process could not be restarted under the current process-control policy. No external host was scanned.

## Outcome

The pre-fix baseline reported three actionable findings. All three were reviewed and fixed in the source tree. The corrected post-fix Automation Framework plan completed with exit code **0**. Its baseline and controlled active reports contain no medium or low vulnerability alerts; both contain one informational session-recognition alert. This is a bounded scan result, not a security clearance.

| ZAP rule | Pre-fix severity / confidence | Evidence | Assessment and action | Post-fix result |
|---|---|---|---|---|
| 10055 — CSP: Failure to Define Directive with No Fallback | Medium / High | `GET /`, `/auth/login`, `/auth/register`, `/events`, `/lab` returned a CSP without `form-action`; the alert detail says that directive has no fallback to `default-src`. | Confirmed policy gap. Added `form-action 'self'` in `app/security/headers.py`. | Absent from the post-fix baseline and active reports. Manual HTTP response on port 5001 contains `form-action 'self'`. |
| 90003 — Sub Resource Integrity Attribute Missing | Medium / High | The login, registration, and root HTML referenced Bootstrap 5.3.3 from jsDelivr without an `integrity` value. | Confirmed for the stylesheet. Added a version-specific SHA-384 SRI value and `crossorigin="anonymous"`. Added SRI to the Chart.js 4.4.7 script as well. | Absent from post-fix reports; regression test asserts both rendered SRI attributes. |
| 10036 — Server Leaks Version Information via `Server` header | Low / High | Responses included `Werkzeug/3.1.9 Python/3.12.14` on five routes. | Confirmed low-risk disclosure in the local `run.py` development server. Added a request handler that reports only `WebGuard`. Other WSGI hosts must suppress their own version header separately. | Absent from post-fix reports; port 5001 returned `Server: WebGuard`. |
| 10112 — Session Management Response Identified | Informational / Medium | ZAP recognized the Flask `session` cookie on baseline pages. | Informational fingerprint only; ZAP’s rule describes this as not a vulnerability. No change needed. | Remains as one informational alert group (three instances) in both final reports. |

## Other security checks

- **Cookie:** The login response set `HttpOnly; Path=/; SameSite=Lax`. It did not set `Secure` because this local scan used plain HTTP and the project’s local default keeps the session usable over loopback HTTP. For HTTPS deployment, enable `SESSION_COOKIE_SECURE=1` and terminate TLS correctly.
- **CSRF:** The passive reports did not raise an anti-CSRF finding on the public pages. The app has CSRF tokens in its login/registration forms and protects state-changing requests. Authenticated actions were not crawled by ZAP.
- **SQL injection and XSS:** The final active report contains no SQLi or XSS alert. During ZAP’s active request set, WebGuard logged detector blocks in the isolated SQLite database. Direct loopback probes after scanning returned: ordinary `/health?q=hello%20world` **200** with no malicious event; SQLi `/health?q=%27%20OR%201%3D1--` **400**, event **36** (`SQL_INJECTION`, HIGH, `Boolean tautology pattern`, BLOCKED); XSS `/health?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E` **400**, event **37** (`XSS`, MEDIUM, `Executable script element`, BLOCKED).
- **SQLite evidence:** The isolated scan database recorded 37 blocked security events by the end of the checks: 25 SQL_INJECTION, 7 XSS, and 5 INVALID_INPUT, all with status 400. Events 1–35 arose from ZAP request probes and events 36–37 from the explicit SQLi/XSS verification requests. The ordinary request incremented the allowed aggregate counter; it did not create a malicious event. No existing project database records were removed or modified.
- **Tests:** `.venv\Scripts\python.exe -m pytest -q` — **32 passed in 35.43s**.

## Scope and limitations

- The post-fix scan used ZAP’s native Automation Framework. Its passive baseline used a bounded traditional spider (one minute, maximum depth five and 25 children per node), did not submit HTML forms, waited for passive scanning, and generated HTML and JSON reports. ZAP documents its baseline scan as spider plus passive scanning without active attacks ([baseline scan](https://www.zaproxy.org/docs/docker/baseline-scan/); [Automation Framework](https://www.zaproxy.org/docs/desktop/addons/automation-framework/)).
- The controlled active scan was limited to `http://127.0.0.1:5001/health`, Low strength, one worker, 100 ms delay, two-minute maximum, and active rules 40012 (Reflected XSS) and 40018 (SQL Injection). No external or non-loopback targets were in either context.
- No ZAP authentication context was configured. Protected dashboard, analytics, events, testing-lab, and administrator routes were not assessed by ZAP; their access controls were previously verified separately in `docs/verification-report.md`.
- The initial passive crawl sent only GET requests to the existing app at `127.0.0.1:5000`, so its allowed-request aggregate may have increased; no active attacks were sent to that database and no existing event rows were deleted. The app remained running throughout. A final check confirmed it still returns HTTP 200 but still emits the old `Server: Werkzeug/3.1.9, Python/3.12.14` and CSP without `form-action`; its pre-existing Python process did not reload the edited source. Restarting it was blocked because process-control approval was rejected and Task Manager was inaccessible at its Windows integrity level. Post-fix HTTP/ZAP evidence is therefore from the updated source on port 5001, using a separate temporary SQLite database. Stop the old process from its original terminal and run `python run.py` from the project directory to activate the fixes on port 5000. Until then, the source fixes are not live on the retained port-5000 instance.
- ZAP emitted Java preferences and optional JBroFuzz initialization log warnings/errors at startup. The corrected Automation Framework plan nevertheless completed successfully (exit code 0), and the selected spider, passive scan, active scan, and report jobs all completed. The generated reports record low-level ZAP log insights; these are scanner-environment warnings, not WebGuard findings.
- A first pre-fix baseline report was generated with an invalid report-job `sites` parameter and returned exit code 1. It is retained as `zap-baseline-before-fixes-5000.*`; the corrected post-fix reports and successful plan are the authoritative retest artifacts.
- The scan does not establish absence of vulnerabilities, does not cover all inputs or encodings, and is not a production deployment review.

## Artifacts

- `zap-baseline.html` and `zap-baseline.json` — successful post-fix passive baseline.
- `zap-active.html` and `zap-active.json` — successful post-fix controlled active scan.
- `zap-baseline-before-fixes-5000.html` and `.json` — initial pre-fix evidence.
- `zap-active-attempt1.html` and `.json` — actual first active-scan report retained with the initial plan warning.
- `zap-retest-plan.yaml` — corrected repeatable local-only plan.


