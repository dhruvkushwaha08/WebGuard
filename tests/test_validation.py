from app.security.validators import validate_username,validate_email,validate_password,validate_text
from tests.conftest import csrf_token

def test_validators():
    assert validate_username("Zoë_7")[0]
    assert not validate_username("ab")[0]
    assert validate_email("a@example.test")[0]
    assert not validate_email("bad-address")[0]
    assert validate_password("StrongPass123")[0]
    assert not validate_password("short")[0]
    assert not validate_text("x"*501)[0]

def test_registration_rejects_invalid_json(client):
    assert client.post("/auth/register",data="{bad",content_type="application/json",headers={"X-CSRF-Token":csrf_token(client,"/auth/register")}).status_code==400
