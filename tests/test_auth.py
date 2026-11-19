from app.extensions import get_db
from tests.conftest import csrf_token
from werkzeug.security import check_password_hash

def test_registration_hashes_password(app,client):
    response=client.post("/auth/register",json={"username":"student","email":"student@example.test","password":"StrongPass123"},headers={"X-CSRF-Token":csrf_token(client,"/auth/register")})
    assert response.status_code==201
    with app.app_context():
        row=get_db().execute("SELECT password_hash FROM users WHERE username=?",("student",)).fetchone()
        assert row and row["password_hash"]!="StrongPass123" and check_password_hash(row["password_hash"],"StrongPass123")

def test_login_logout_and_protected_route(client):
    assert client.get("/dashboard").status_code==302
    token=csrf_token(client)
    assert client.post("/auth/login",json={"username":"admin","password":"Testing12345"},headers={"X-CSRF-Token":token}).status_code==200
    assert client.get("/dashboard").status_code==200
    with client.session_transaction() as sess: token=sess["csrf_token"]
    client.post("/auth/logout",data={"csrf_token":token})
    assert client.get("/api/analytics/attacks").status_code==401

def test_invalid_login(client):
    assert client.post("/auth/login",json={"username":"admin","password":"bad"},headers={"X-CSRF-Token":csrf_token(client)}).status_code==401

def test_auth_posts_require_csrf(client):
    client.get("/auth/login")
    assert client.post("/auth/login",json={"username":"admin","password":"Testing12345"}).status_code==400
