# OWASP ZAP assessment record

**Assessment date:** 2026-11-05 (Asia/Kolkata)  
**ZAP:** 2.17.0  
**Scope:** WebGuard on loopback only. A pre-fix passive baseline used `http://127.0.0.1:5000/`. The post-fix baseline and controlled active retest used `http://127.0.0.1:5001/`, an isolated local instance of the updated source with a temporary SQLite database. No external host was scanned.

## Results

The corrected local Automation Framework plan completed with exit code 0. Before the fixes, ZAP reported three actionable findings: missing CSP `form-action` (Medium), missing SRI for the Bootstrap CDN stylesheet (Medium), and a Werkzeug/Python version header (Low). Those fixes were applied and all three findings were absent from the post-fix baseline and active reports. The only remaining alert was informational session-cookie recognition.

The login cookie included `HttpOnly` and `SameSite=Lax`; `Secure` was absent because this is an HTTP-only local demonstration. Use HTTPS and set `SESSION_COOKIE_SECURE=1` for an HTTPS deployment. ZAP did not authenticate; it did not crawl protected dashboard or administrator routes.

See [findings-summary.md](findings-summary.md) for severity, evidence, code fixes, event IDs, scan limits, and the runtime restart note. The scan reports and plans are stored in this directory.

## Scan procedure

- Passive baseline: one-minute traditional spider, maximum depth five, 25 children per node; form processing and form POST submission disabled; passive queue drained before report generation.
- Controlled active scan: exact `/health` route only; active rule 40012 (Reflected XSS) and 40018 (SQL Injection), Low strength, one thread, 100 ms delay, and two-minute maximum.
- The app stayed bound to `127.0.0.1:5000`. Because the existing process could not be restarted by this automation session, retests used the updated source on `127.0.0.1:5001` with a separate database. A final check confirmed `127.0.0.1:5000` still runs its pre-fix process: HTTP 200, old Werkzeug/Python `Server` header, and old CSP without `form-action`. Stop the old process in its original terminal and restart it with `python run.py` to load the source changes there.

The passive baseline method follows ZAP’s documented spider-plus-passive model ([ZAP Baseline Scan](https://www.zaproxy.org/docs/docker/baseline-scan/)); orchestration used the [Automation Framework](https://www.zaproxy.org/docs/desktop/addons/automation-framework/). Results cover the configured scope only and are not a security clearance.

