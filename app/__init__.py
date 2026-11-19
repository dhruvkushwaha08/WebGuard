import os
import sqlite3
from pathlib import Path
from flask import Flask, g, request, session
from config import Config
from app.extensions import close_db, get_db
from app.security.headers import add_security_headers
from app.security.middleware import inspect_request, record_request_count

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin','user')),
 active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS security_events (
 id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, attack_type TEXT NOT NULL,
 severity TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL, reason TEXT NOT NULL,
 action TEXT NOT NULL, response_status INTEGER NOT NULL, source_ip TEXT
);
CREATE TABLE IF NOT EXISTS request_counts (
 day TEXT PRIMARY KEY, safe INTEGER NOT NULL DEFAULT 0, blocked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS rate_limits (
 id INTEGER PRIMARY KEY, ip TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_type ON security_events(attack_type);
CREATE INDEX IF NOT EXISTS idx_rate_ip_time ON rate_limits(ip, created_at);
"""

def init_db(app):
    path = app.config["DATABASE_PATH"]
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    if not app.config.get("TESTING") and app.config["SECRET_KEY"] == "development-only-change-me":
        app.logger.warning("Using development secret key; set SECRET_KEY before deployment")
    os.makedirs(app.instance_path, exist_ok=True)
    init_db(app)
    app.teardown_appcontext(close_db)
    from app.routes.auth import bp as auth_bp
    from app.routes.main import bp as main_bp
    from app.routes.dashboard import bp as dashboard_bp
    from app.routes.security import bp as security_bp
    from app.routes.admin import bp as admin_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(security_bp)
    app.register_blueprint(admin_bp)
    app.before_request(inspect_request)
    app.after_request(record_request_count)
    app.after_request(add_security_headers)
    @app.context_processor
    def csrf_context():
        return {"csrf_token": session.get("csrf_token", "")}
    @app.errorhandler(413)
    def too_large(_error):
        return {"error": "Request too large"}, 413
    @app.errorhandler(404)
    def not_found(_error):
        return {"error": "Not found"}, 404
    @app.errorhandler(500)
    def server_error(_error):
        app.logger.exception("Unhandled application error")
        return {"error": "Internal server error"}, 500
    return app
