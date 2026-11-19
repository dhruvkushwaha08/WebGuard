def test_middleware_blocks_and_logs(client,app):
    response=client.get("/health?q=%27%20OR%201%3D1--")
    assert response.status_code==400
    with app.app_context():
        from app.extensions import get_db
        assert get_db().execute("SELECT COUNT(*) FROM security_events WHERE attack_type='SQL_INJECTION'").fetchone()[0]==1

def test_request_counters_follow_security_inspection_decision(client,app):
    assert client.get("/health").status_code==200
    # A normal request can end in an application-level 404 without being a
    # security block; the counters describe the inspection decision.
    assert client.get("/missing-page").status_code==404
    assert client.get("/health?q=%27%20OR%201%3D1--").status_code==400
    with app.app_context():
        from app.extensions import get_db
        row=get_db().execute("SELECT safe,blocked FROM request_counts").fetchone()
        assert row["safe"]==2 and row["blocked"]==1

def test_middleware_allows_legitimate_query(client):
    assert client.get("/health?q=please-select-an-option").status_code==200

def test_nested_json_values_are_inspected(client):
    from tests.conftest import csrf_token
    token=csrf_token(client,"/auth/register")
    response=client.post("/auth/register",json={"username":"student","email":"student@example.test","password":"StrongPass123","profile":{"bio":"<script>alert(1)</script>"}},headers={"X-CSRF-Token":token})
    assert response.status_code==400

def test_large_request_rejected(client):
    response=client.post("/auth/register",data={"username":"u","email":"a@example.test","password":"x"*1100000})
    assert response.status_code==413
