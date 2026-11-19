from flask import Blueprint, jsonify, render_template, request
from app.routes.main import login_required
from app.extensions import get_db
bp = Blueprint("dashboard", __name__)

@bp.get("/dashboard")
@login_required
def index(): return render_template("dashboard.html")

@bp.get("/analytics")
@login_required
def analytics_page(): return render_template("analytics.html")

@bp.get("/api/analytics/attacks")
@login_required
def analytics():
    db = get_db(); days = min(max(request.args.get("days", 7, type=int), 1), 90)
    counts = db.execute("SELECT COALESCE(SUM(safe),0) safe,COALESCE(SUM(blocked),0) blocked FROM request_counts WHERE day >= date('now',?)", (f"-{days-1} days",)).fetchone()
    types = db.execute("SELECT attack_type,COUNT(*) count FROM security_events WHERE timestamp >= datetime('now',?) GROUP BY attack_type ORDER BY count DESC", (f"-{days-1} days",)).fetchall()
    severity = db.execute("SELECT severity,COUNT(*) count FROM security_events WHERE timestamp >= datetime('now',?) GROUP BY severity", (f"-{days-1} days",)).fetchall()
    trend = [dict(r) for r in db.execute("SELECT day,safe,blocked FROM request_counts WHERE day >= date('now',?) ORDER BY day", (f"-{days-1} days",)).fetchall()]
    # This authenticated analytics request passes inspection and is counted by
    # after_request. Include it in the response snapshot so displayed totals
    # agree with SQLite once the response has completed.
    today = db.execute("SELECT date('now')").fetchone()[0]
    if trend and trend[-1]["day"] == today:
        trend[-1]["safe"] += 1
    else:
        trend.append({"day":today,"safe":1,"blocked":0})
    recent = db.execute("SELECT id,timestamp,attack_type,severity,method,path,action FROM security_events WHERE timestamp >= datetime('now',?) ORDER BY id DESC LIMIT 10", (f"-{days-1} days",)).fetchall()
    attacks = {r["attack_type"]:r["count"] for r in types}
    safe_count=counts["safe"]+1
    blocked_count=counts["blocked"]
    return jsonify(kpis={"total_requests":safe_count+blocked_count, "safe_requests":safe_count, "blocked_requests":blocked_count, "sqli_attempts":attacks.get("SQL_INJECTION",0), "xss_attempts":attacks.get("XSS",0), "invalid_input_attempts":attacks.get("INVALID_INPUT",0)}, attacks=[dict(r) for r in types], severity=[dict(r) for r in severity], trend=trend, recent=[dict(r) for r in recent])
