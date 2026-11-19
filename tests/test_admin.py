def test_admin_api_requires_admin(signed_in):
    assert signed_in.get("/api/admin/users").status_code==200
    with signed_in.session_transaction() as sess: token=sess["csrf_token"]
    signed_in.post("/auth/logout",data={"csrf_token":token})
    assert signed_in.get("/api/admin/users").status_code==401

def test_regular_user_cannot_access_admin(app):
    from werkzeug.security import generate_password_hash
    from tests.conftest import csrf_token
    from app.extensions import get_db
    with app.app_context():
        db=get_db(); db.execute("INSERT INTO users(username,email,password_hash) VALUES(?,?,?)",("ordinary","ordinary@example.test",generate_password_hash("Ordinary12345"))); db.commit()
    client=app.test_client(); token=csrf_token(client)
    assert client.post("/auth/login",json={"username":"ordinary","password":"Ordinary12345"},headers={"X-CSRF-Token":token}).status_code==200
    assert client.get("/api/admin/users").status_code==403

def test_admin_can_change_user_status(signed_in,app):
    with app.app_context():
        from app.extensions import get_db
        db=get_db(); db.execute("INSERT INTO users(username,email,password_hash) VALUES('student','student@example.test','hash')"); db.commit()
        user_id=db.execute("SELECT id FROM users WHERE username='student'").fetchone()[0]
    with signed_in.session_transaction() as sess: token=sess["csrf_token"]
    response=signed_in.put(f"/api/admin/users/{user_id}/status",json={"active":False},headers={"X-CSRF-Token":token})
    assert response.status_code==200

def test_deactivated_account_loses_existing_session(app):
    from werkzeug.security import generate_password_hash
    from tests.conftest import csrf_token
    from app.extensions import get_db
    with app.app_context():
        db=get_db(); db.execute("INSERT INTO users(username,email,password_hash) VALUES(?,?,?)",("member","member@example.test",generate_password_hash("MemberPass123"))); db.commit()
    client=app.test_client(); token=csrf_token(client)
    assert client.post("/auth/login",json={"username":"member","password":"MemberPass123"},headers={"X-CSRF-Token":token}).status_code==200
    with app.app_context():
        get_db().execute("UPDATE users SET active=0 WHERE username=?",("member",)); get_db().commit()
    assert client.get("/api/analytics/attacks").status_code==401
