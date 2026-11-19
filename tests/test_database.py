def test_sqlite_schema_created(app):
    with app.app_context():
        from app.extensions import get_db
        tables={r[0] for r in get_db().execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"users","security_events","request_counts","rate_limits"} <= tables
