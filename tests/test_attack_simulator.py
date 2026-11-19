def test_lab_simulates_payload_and_creates_event(signed_in,app):
    with signed_in.session_transaction() as sess: token=sess["csrf_token"]
    r=signed_in.post("/api/security/simulate",json={"category":"sqli","payload":"test"},headers={"X-CSRF-Token":token})
    assert r.status_code==200 and r.get_json()["detected"]
    with app.app_context():
        from app.extensions import get_db
        row=get_db().execute("SELECT path,action,response_status FROM security_events WHERE path='/api/security/simulate'").fetchone()
        assert row and row["action"]=="FLAGGED" and row["response_status"]==200
