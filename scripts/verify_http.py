"""Run a loopback-only end-to-end verification against a disposable SQLite DB."""
import json
import re
import secrets
import sqlite3
import sys
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path

from werkzeug.serving import make_server
from werkzeug.security import generate_password_hash
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import create_app


def main():
    with tempfile.TemporaryDirectory(prefix="webguard-audit-") as temp:
        db_path = str(Path(temp) / "audit.sqlite3")
        app = create_app({"TESTING": True, "SECRET_KEY": "http-audit-only", "DATABASE_PATH": db_path})
        db=sqlite3.connect(db_path)
        db.execute("INSERT INTO users(username,email,password_hash,role) VALUES(?,?,?,'admin')",("auditadmin","auditadmin@example.test",generate_password_hash("AuditAdmin12345")))
        db.commit(); db.close()
        server = make_server("127.0.0.1", 0, app)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        cookies = urllib.request.HTTPCookieProcessor()
        opener = urllib.request.build_opener(cookies)

        def request(path, method="GET", payload=None, headers=None):
            data = None if payload is None else (payload if isinstance(payload, bytes) else json.dumps(payload).encode())
            request_headers = dict(headers or {})
            if isinstance(payload, dict):
                request_headers.setdefault("Content-Type", "application/json")
            req = urllib.request.Request(base + path, data=data, headers=request_headers, method=method)
            try:
                with opener.open(req) as response:
                    return response.status, response.read().decode("utf-8", "replace"), response.headers, response.geturl()
            except urllib.error.HTTPError as error:
                return error.code, error.read().decode("utf-8", "replace"), error.headers, error.geturl()

        checks = []

        def fetchone(sql, params=()):
            db=sqlite3.connect(db_path)
            try:
                return db.execute(sql,params).fetchone()
            finally:
                db.close()
        try:
            status, body, _, final_url = request("/dashboard")
            checks.append(("protected dashboard redirects while signed out", status == 200 and final_url.endswith("/auth/login")))

            status, body, _, _ = request("/auth/register")
            csrf = re.search(r'<meta name="csrf-token" content="([^"]*)">', body)
            checks.append(("registration form issues a CSRF token", status == 200 and csrf is not None))
            if not csrf:
                raise RuntimeError("Registration page did not expose its session CSRF token")
            token = csrf.group(1)
            nested_status, _, _, _=request("/auth/register","POST",{"profile":{"bio":"<script>alert(1)</script>"}},{"X-CSRF-Token":token})
            checks.append(("HTTP middleware inspects nested JSON values",nested_status==400))
            suffix = secrets.token_hex(4)
            username = "audit" + suffix
            password = "AuditPass12345"
            status, body, _, _ = request("/auth/register", "POST", {"username": username, "email": username + "@example.test", "password": password}, {"X-CSRF-Token": token})
            checks.append(("HTTP registration succeeds", status == 201))
            row = fetchone("SELECT password_hash FROM users WHERE username=?", (username,))
            checks.append(("registration stores a hash, not the submitted password", bool(row and row[0] != password)))

            status, body, _, _ = request("/auth/login", "POST", {"username": username, "password": password}, {"X-CSRF-Token": token})
            checks.append(("HTTP login establishes a session", status == 200))
            status, body, _, _ = request("/dashboard")
            checks.append(("authenticated dashboard page references its chart scripts", status == 200 and "dashboard.js" in body and "chart.umd.min.js" in body))
            status, lab_body, _, _ = request("/lab")
            checks.append(("simulator page exposes a CSRF token without inline script", status == 200 and '<meta name="csrf-token" content="' in lab_body and "window.webguardCsrf" not in lab_body and "simulator.js" in lab_body))
            status, analytics_page, _, _ = request("/analytics")
            checks.append(("analytics page renders its range selector and chart panels", status == 200 and 'id="days"' in analytics_page and 'id="attacks"' in analytics_page and 'id="severity"' in analytics_page))
            status, events_page, _, _ = request("/events")
            checks.append(("events page renders filters, pagination, and event details", status == 200 and all(f'id="{element}"' in events_page for element in ("filters", "attack-type", "severity", "action", "date-from", "date-to", "search", "sort", "direction", "prev", "next", "event-detail-dialog"))))
            for asset, marker, label in (("/static/js/dashboard.js", "new Chart", "dashboard chart code is served"), ("/static/js/events.js", "loadEvents", "event filter and pagination code is served"), ("/static/js/simulator.js", "api/security/simulate", "simulator client code is served")):
                status, body, _, _=request(asset)
                checks.append((label,status==200 and marker in body))
            match = re.search(r'<meta name="csrf-token" content="([^"]*)">', lab_body)
            token = match.group(1) if match else ""

            sql_status, _, _, _ = request("/health?q=%27+OR+1%3D1--")
            xss_status, xss_body, _, _ = request("/health?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
            safe_status, _, _, _ = request("/health?q=SELECT")
            benign_union_status, _, _, _=request("/health?q=UNION+SELECT")
            benign_xss_status, _, _, _=request("/health?q=The+%3Cscript%3E+tag+and+onerror%3D+are+discussed+in+the+guide")
            malicious_union_status, _, _, _=request("/health?q=%27+UNION+SELECT+NULL--")
            checks += [("HTTP SQL injection request is blocked", sql_status == 400),
                       ("HTTP XSS request is blocked", xss_status == 400),
                       ("blocked XSS response does not echo executable markup", xss_status==400 and "<script>" not in xss_body.lower()),
                       ("benign UNION SELECT phrase is allowed",benign_union_status==200),
                       ("benign XSS documentation text is allowed",benign_xss_status==200),
                       ("injection-context UNION SELECT payload is blocked",malicious_union_status==400),
                       ("ordinary SQL vocabulary is allowed", safe_status == 200)]

            csrf_status, _, _, _=request("/api/security/simulate","POST",{"category":"xss","payload":"<script>alert(1)</script>"})
            checks.append(("state-changing API rejects a missing CSRF token",csrf_status==400))
            status, body, _, _ = request("/api/security/simulate", "POST", {"category": "xss", "payload": "<script>alert(1)</script>"}, {"X-CSRF-Token": token})
            simulation = json.loads(body) if body else {}
            checks.append(("HTTP simulator calls the detector and returns a finding", status == 200 and simulation.get("detected") is True))
            checks.append(("simulator response does not echo executable payload markup", "<script>" not in body.lower()))
            simulator_events_before=fetchone("SELECT COUNT(*) FROM security_events WHERE path='/api/security/simulate'")[0]
            safe_counts_before=fetchone("SELECT COALESCE(SUM(safe),0),COALESCE(SUM(blocked),0) FROM request_counts")
            safe_sim_status,safe_sim_body,_,_=request("/api/security/simulate","POST",{"category":"safe","payload":"SELECT is a common keyword in documentation."},{"X-CSRF-Token":token})
            safe_sim=json.loads(safe_sim_body) if safe_sim_body else {}
            simulator_events_after=fetchone("SELECT COUNT(*) FROM security_events WHERE path='/api/security/simulate'")[0]
            safe_counts_after=fetchone("SELECT COALESCE(SUM(safe),0),COALESCE(SUM(blocked),0) FROM request_counts")
            checks.append(("HTTP safe simulator input is allowed and reflected only in allowed counters",safe_sim_status==200 and safe_sim.get("detected") is False and safe_sim.get("action")=="ALLOWED" and simulator_events_after==simulator_events_before and safe_counts_after[0]==safe_counts_before[0]+1 and safe_counts_after[1]==safe_counts_before[1]))

            status, body, _, _ = request("/api/security/events")
            events = json.loads(body).get("items", []) if body else []
            kinds = {event["attack_type"] for event in events}
            checks.append(("HTTP event API returns persisted SQLi and XSS records", status == 200 and {"SQL_INJECTION", "XSS"}.issubset(kinds)))
            filtered_status, filtered_body, _, _=request("/api/security/events?attack_type=SQL_INJECTION&per_page=1&page=1")
            filtered=json.loads(filtered_body) if filtered_body else {}
            checks.append(("event type filter and pagination return matching records",filtered_status==200 and filtered.get("total",0)>=1 and len(filtered.get("items",[]))==1 and filtered["items"][0]["attack_type"]=="SQL_INJECTION"))
            today = fetchone("SELECT date('now')")[0]
            yesterday = (datetime.strptime(today,"%Y-%m-%d").date()-timedelta(days=1)).isoformat()
            severity_status, severity_body, _, _=request("/api/security/events?severity=HIGH&action=BLOCKED&date_from="+today+"&date_to="+today+"&sort=attack_type&direction=asc")
            severity_data=json.loads(severity_body) if severity_body else {}
            severity_items=severity_data.get("items",[])
            checks.append(("event severity, action, date range, and sort filters use matching SQLite records",severity_status==200 and bool(severity_items) and all(e["severity"]=="HIGH" and e["action"]=="BLOCKED" and e["attack_type"]=="SQL_INJECTION" for e in severity_items)))
            page2_status, page2_body, _, _=request("/api/security/events?per_page=1&page=2&sort=timestamp&direction=asc")
            page2=json.loads(page2_body) if page2_body else {}
            checks.append(("event pagination returns the requested second page",page2_status==200 and page2.get("page")==2 and len(page2.get("items",[]))==1))
            invalid_date_status, _, _, _=request("/api/security/events?date_from=2026-02-31")
            checks.append(("event date filter rejects invalid calendar dates",invalid_date_status==400))
            empty_range_status, empty_range_body, _, _=request("/api/security/events?date_from="+yesterday+"&date_to="+yesterday)
            empty_range=json.loads(empty_range_body) if empty_range_body else {}
            checks.append(("event date range excludes records outside the selected dates",empty_range_status==200 and empty_range.get("total")==0))
            if events:
                detail_status, detail_body, _, _=request("/api/security/events/"+str(events[0]["id"]))
                checks.append(("event detail endpoint returns the stored record",detail_status==200 and json.loads(detail_body).get("id")==events[0]["id"]))
            search_status, search_body, _, _=request("/api/security/events?q=LAB%20SIMULATION")
            searched=json.loads(search_body) if search_body else {}
            checks.append(("event search finds the lab record",search_status==200 and any("LAB SIMULATION" in e["reason"] for e in searched.get("items",[]))))
            count_snapshot=fetchone("SELECT COALESCE(SUM(safe),0),COALESCE(SUM(blocked),0) FROM request_counts")
            missing_status, _, _, _=request("/missing-page")
            missing_counts=fetchone("SELECT COALESCE(SUM(safe),0),COALESCE(SUM(blocked),0) FROM request_counts")
            checks.append(("normal application 404 remains distinct from a security-blocked request",missing_status==404 and missing_counts[0]==count_snapshot[0]+1 and missing_counts[1]==count_snapshot[1]))
            # after_request updates the counter after the analytics response,
            # so compare the returned snapshot with the DB state captured first.
            counts_before = fetchone("SELECT COALESCE(SUM(safe),0),COALESCE(SUM(blocked),0) FROM request_counts")
            status, body, _, _ = request("/api/analytics/attacks")
            analytics = json.loads(body) if body else {}
            counts = fetchone("SELECT COALESCE(SUM(safe),0),COALESCE(SUM(blocked),0) FROM request_counts")
            today = fetchone("SELECT date('now')")[0]
            today_counts = fetchone("SELECT safe,blocked FROM request_counts WHERE day=?",(today,))
            today_trend = next((row for row in analytics.get("trend",[]) if row["day"]==today),None)
            stored = fetchone("SELECT COUNT(*) FROM security_events")[0]
            checks.append(("dashboard KPI and trend snapshots match SQLite after response", status == 200 and analytics["kpis"]["safe_requests"] == counts_before[0]+1 and analytics["kpis"]["blocked_requests"] == counts_before[1] and analytics["kpis"]["total_requests"] == sum(counts_before)+1 and counts[0] == counts_before[0]+1 and counts[1] == counts_before[1] and sum(counts)==analytics["kpis"]["total_requests"] and today_counts is not None and today_trend is not None and today_trend["safe"]==today_counts[0] and today_trend["blocked"]==today_counts[1]))
            checks.append(("security incidents exist in SQLite", stored >= 3))

            status, _, _, _ = request("/api/admin/users")
            checks.append(("regular user cannot access administrator API", status == 403))
            _, _, _, _ = request("/auth/logout", "POST", {}, {"X-CSRF-Token": token})
            status, _, _, _ = request("/api/analytics/attacks")
            checks.append(("logout invalidates the session", status == 401))
            _, login_body, _, _=request("/auth/login")
            admin_token_match=re.search(r'<meta name="csrf-token" content="([^"]*)">',login_body)
            admin_token=admin_token_match.group(1) if admin_token_match else ""
            status, _, _, _=request("/auth/login","POST",{"username":"auditadmin","password":"AuditAdmin12345"},{"X-CSRF-Token":admin_token})
            checks.append(("administrator can authenticate",status==200))
            status, body, _, _=request("/api/admin/users")
            users=json.loads(body).get("users",[]) if body else []
            checks.append(("administrator authorization allows user listing without password hashes",status==200 and any(u["username"]==username for u in users) and all("password_hash" not in u for u in users)))
            audit_user=next((u for u in users if u["username"]==username),None)
            _, admin_form, _, _=request("/auth/login")
            fresh_admin_token=re.search(r'<meta name="csrf-token" content="([^"]*)">',admin_form)
            admin_token=fresh_admin_token.group(1) if fresh_admin_token else ""
            status, body, _, _=request(f"/api/admin/users/{audit_user['id']}/status","PUT",{"active":False},{"X-CSRF-Token":admin_token}) if audit_user else (404,"",{},"")
            checks.append(("administrator can change another account's status",status==200))
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

        for label, ok in checks:
            print(f"{'PASS' if ok else 'FAIL'}  {label}")
        failed = [label for label, ok in checks if not ok]
        print(f"\n{len(checks)-len(failed)}/{len(checks)} checks passed")
        if failed:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
