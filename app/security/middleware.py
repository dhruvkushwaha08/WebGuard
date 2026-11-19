import secrets
from flask import request, current_app, session, jsonify, render_template, g
from app.extensions import get_db
SENSITIVE_KEYS = {"password", "confirm_password", "csrf_token", "token", "authorization", "cookie"}

def _values():
    values = [(k, v) for k, v in request.args.items() if k.lower() not in SENSITIVE_KEYS]
    if request.mimetype in {"application/x-www-form-urlencoded", "multipart/form-data"}:
        values += [(k, v) for k, v in request.form.items() if k.lower() not in SENSITIVE_KEYS]
    elif request.is_json:
        obj = request.get_json(silent=True)
        stack = [obj]
        visited = 0
        while stack and visited < 5000:
            item = stack.pop()
            visited += 1
            if isinstance(item, dict):
                stack.extend(v for k, v in item.items() if str(k).lower() not in SENSITIVE_KEYS)
            elif isinstance(item, list):
                stack.extend(item)
            elif isinstance(item, (str, int, float)):
                values.append(("json", item))
        if stack:
            values.append(("_inspection_limit_exceeded", True))
    return values

def _record(findings, action, status):
    try:
        db = get_db()
        for f in findings:
            db.execute("INSERT INTO security_events(timestamp,attack_type,severity,method,path,reason,action,response_status,source_ip) VALUES(datetime('now'),?,?,?,?,?,?,?,?)",
                       (f["attack_type"], f["severity"], request.method, request.path[:300], f["reason"][:200], action, status, (request.remote_addr or "")[:64]))
        db.commit()
    except Exception:
        current_app.logger.exception("Security event could not be persisted")

def _increment_request_counts(db,safe,blocked):
    db.execute("INSERT INTO request_counts(day,safe,blocked) VALUES(date('now'),?,?) ON CONFLICT(day) DO UPDATE SET safe=safe+excluded.safe,blocked=blocked+excluded.blocked",(safe,blocked))

def record_request_count(response):
    if not getattr(g,"webguard_count_pending",False): return response
    try:
        db=get_db()
        blocked=bool(getattr(g,"webguard_request_blocked",False))
        _increment_request_counts(db,0,1) if blocked else _increment_request_counts(db,1,0)
        db.commit()
    except Exception:
        current_app.logger.warning("Request counter could not be updated")
    return response

def inspect_request():
    g.webguard_count_pending=True
    if request.endpoint == "static" or request.path.startswith("/static/"):
        return None
    if request.content_length and request.content_length > current_app.config["MAX_CONTENT_LENGTH"]:
        g.webguard_request_blocked=True
        _record([{"attack_type":"MALFORMED_REQUEST","severity":"MEDIUM","reason":"Request body exceeds configured maximum"}], "BLOCKED", 413)
        return (jsonify(error="Request too large"), 413) if request.is_json else ("Request too large", 413)
    from app.security.detector import inspect_value
    # The lab intentionally submits detector payloads; it records its own simulated events.
    values = [] if request.endpoint == "security.simulate" else _values()
    findings = [{"attack_type":"MALFORMED_REQUEST","severity":"MEDIUM","reason":"JSON request exceeds inspection item limit"}] if any(k == "_inspection_limit_exceeded" for k, _ in values) else [finding for _, value in values for finding in inspect_value(value)]
    if findings:
        g.webguard_request_blocked=True
        _record(findings, "BLOCKED", 400)
        if request.is_json or request.path.startswith("/api/"):
            return jsonify(error="Suspicious request blocked", events=[{"type": f["attack_type"], "reason": f["reason"]} for f in findings]), 400
        return render_template("errors/blocked.html", findings=findings), 400
    session.setdefault("csrf_token", secrets.token_urlsafe(32))
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
        if not token or token != session.get("csrf_token"):
            g.webguard_request_blocked=True
            _record([{"attack_type":"INVALID_INPUT","severity":"LOW","reason":"Missing or invalid CSRF token"}], "BLOCKED", 400)
            return (jsonify(error="CSRF validation failed"), 400) if request.is_json else ("CSRF validation failed", 400)
    return None
