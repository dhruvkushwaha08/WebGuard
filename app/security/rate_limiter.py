from functools import wraps
from flask import request, jsonify, g
from app.extensions import get_db

def rate_limit(limit=8, window_seconds=300):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if request.method != "POST":
                return fn(*args, **kwargs)
            ip = (request.remote_addr or "unknown")[:64]
            db = get_db()
            db.execute("DELETE FROM rate_limits WHERE created_at < datetime('now', ?)", (f"-{window_seconds} seconds",))
            count = db.execute("SELECT COUNT(*) FROM rate_limits WHERE ip=?", (ip,)).fetchone()[0]
            if count >= limit:
                g.webguard_request_blocked=True
                db.execute("INSERT INTO security_events(timestamp,attack_type,severity,method,path,reason,action,response_status,source_ip) VALUES(datetime('now'),'RATE_LIMIT','MEDIUM',?,?,?,'BLOCKED',429,?)", (request.method, request.path, "Login rate limit exceeded", ip))
                db.commit()
                return (jsonify(error="Too many attempts"), 429) if request.is_json else ("Too many attempts", 429)
            db.execute("INSERT INTO rate_limits(ip) VALUES(?)", (ip,)); db.commit()
            return fn(*args, **kwargs)
        return wrapped
    return decorator
