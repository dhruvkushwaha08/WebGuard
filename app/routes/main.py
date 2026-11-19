from functools import wraps
from flask import Blueprint, session, redirect, url_for, request, jsonify, render_template, abort
from app.extensions import get_db
bp = Blueprint("main", __name__)

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        user_id=session.get("user_id")
        user=get_db().execute("SELECT username,role,active FROM users WHERE id=?",(user_id,)).fetchone() if user_id else None
        if not user or not user["active"]:
            session.clear()
            if request.path.startswith("/api/"): return jsonify(error="Authentication required"), 401
            return redirect(url_for("auth.login"))
        session["username"],session["role"]=user["username"],user["role"]
        return fn(*args, **kwargs)
    return wrapped

def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapped(*args, **kwargs):
        if session.get("role") != "admin": abort(403)
        return fn(*args, **kwargs)
    return wrapped

@bp.get("/health")
def health(): return {"status":"ok"}

@bp.get("/")
def home(): return redirect(url_for("dashboard.index")) if session.get("user_id") else redirect(url_for("auth.login"))

@bp.get("/lab")
@login_required
def lab(): return render_template("simulator.html")
