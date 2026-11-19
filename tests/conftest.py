import pytest
from werkzeug.security import generate_password_hash
from app import create_app
from app.extensions import get_db

@pytest.fixture
def app(tmp_path):
    app=create_app({"TESTING":True,"SECRET_KEY":"test-secret","DATABASE_PATH":str(tmp_path/"test.db"),"SESSION_COOKIE_SECURE":False})
    with app.app_context():
        db=get_db(); db.execute("INSERT INTO users(username,email,password_hash,role) VALUES(?,?,?,'admin')",("admin","admin@example.test",generate_password_hash("Testing12345"))); db.commit()
    yield app

@pytest.fixture
def client(app): return app.test_client()

def csrf_token(client,path="/auth/login"):
    client.get(path)
    with client.session_transaction() as sess: return sess["csrf_token"]

@pytest.fixture
def signed_in(client):
    token=csrf_token(client)
    response=client.post("/auth/login",json={"username":"admin","password":"Testing12345"},headers={"X-CSRF-Token":token})
    assert response.status_code==200
    return client
