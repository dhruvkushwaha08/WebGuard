from tests.conftest import csrf_token

def test_login_rate_limit(app):
    client=app.test_client()
    token=csrf_token(client)
    for _ in range(8): client.post("/auth/login",json={"username":"missing","password":"bad"},headers={"X-CSRF-Token":token})
    response=client.post("/auth/login",json={"username":"missing","password":"bad"},headers={"X-CSRF-Token":token})
    assert response.status_code==429

def test_login_page_views_do_not_consume_attempts(client):
    for _ in range(12):
        assert client.get("/auth/login").status_code==200
    from tests.conftest import csrf_token
    response=client.post("/auth/login",json={"username":"missing","password":"bad"},headers={"X-CSRF-Token":csrf_token(client)})
    assert response.status_code==401
