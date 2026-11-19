import secrets
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import get_db
from app.security.validators import validate_username, validate_email, validate_password
from app.security.rate_limiter import rate_limit

bp = Blueprint("auth", __name__, url_prefix="/auth")

def _log_invalid(reason, attack_type="INVALID_INPUT"):
    g.webguard_request_blocked=True
    try:
        db=get_db()
        db.execute("INSERT INTO security_events(timestamp,attack_type,severity,method,path,reason,action,response_status,source_ip) VALUES(datetime('now'),?,'LOW',?,?,?,'BLOCKED',400,?)",(attack_type,request.method,request.path,reason,(request.remote_addr or "")[:64]))
        db.commit()
    except Exception:
        from flask import current_app
        current_app.logger.warning("Could not record an authentication validation event")

@bp.route("/register", methods=["GET", "POST"])
@rate_limit(10, 600)
def register():
    if request.method == "GET":
        session.setdefault("csrf_token", secrets.token_urlsafe(32))
        return render_template("register.html")
    if request.is_json:
        data=request.get_json(silent=True)
        if data is None:
            _log_invalid("Malformed JSON in registration request", "MALFORMED_REQUEST")
            return jsonify(error="Malformed JSON"),400
    else:
        data=request.form
    if not hasattr(data,"get"):
        _log_invalid("Registration JSON must be an object", "MALFORMED_REQUEST")
        return jsonify(error="Expected a JSON object"),400
    username, email, password = data.get("username", ""), data.get("email", ""), data.get("password", "")
    errors = [message for ok, message in [validate_username(username), validate_email(email), validate_password(password)] if not ok]
    if errors:
        _log_invalid("Registration fields failed validation")
        if request.is_json: return jsonify(error="Validation failed", messages=errors), 400
        for error in errors: flash(error, "error")
        return render_template("register.html"), 400
    db = get_db()
    try:
        db.execute("INSERT INTO users(username,email,password_hash,role) VALUES(?,?,?,'user')", (username, email.lower(), generate_password_hash(password)))
        db.commit()
    except Exception:
        if request.is_json: return jsonify(error="Username or email already exists"), 409
        flash("Username or email already exists.", "error")
        return render_template("register.html"), 409
    if request.is_json: return jsonify(message="Registered"), 201
    flash("Account created. Please sign in.", "success")
    return redirect(url_for("auth.login"))

@bp.route("/login", methods=["GET", "POST"])
@rate_limit(8, 300)
def login():
    if request.method == "GET":
        session.setdefault("csrf_token", secrets.token_urlsafe(32))
        return render_template("login.html")
    if request.is_json:
        data=request.get_json(silent=True)
        if data is None:
            _log_invalid("Malformed JSON in login request", "MALFORMED_REQUEST")
            return jsonify(error="Malformed JSON"),400
    else:
        data=request.form
    if not hasattr(data,"get"):
        _log_invalid("Login JSON must be an object", "MALFORMED_REQUEST")
        return jsonify(error="Expected a JSON object"),400
    username, password = data.get("username", ""), data.get("password", "")
    if not isinstance(username,str) or not isinstance(password,str) or len(username)>32 or len(password)>128:
        _log_invalid("Login fields failed validation")
        return (jsonify(error="Invalid username or password"),400) if request.is_json else ("Invalid username or password",400)
    user = get_db().execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        if request.is_json: return jsonify(error="Invalid username or password"), 401
        flash("Invalid username or password.", "error")
        return render_template("login.html"), 401
    session.clear()
    session["user_id"], session["username"], session["role"] = user["id"], user["username"], user["role"]
    session["csrf_token"] = secrets.token_urlsafe(32)
    if request.is_json: return jsonify(message="Signed in", role=user["role"])
    return redirect(url_for("dashboard.index"))

@bp.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
