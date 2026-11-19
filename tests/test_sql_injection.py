from app.security.detector import inspect_value

def test_sqli_samples_detected():
    for payload in ["' OR '1'='1", "' UNION SELECT NULL--", "admin'--", "' OR 1=1--", "%27%20OR%201%3D1"]:
        assert any(f["attack_type"]=="SQL_INJECTION" for f in inspect_value(payload)), payload

def test_legitimate_sql_words_allowed():
    for text in ["Please SELECT an option", "The UPDATE section describes the release", "UNION is a set operation", "UNION SELECT is a phrase in the SQL lesson", "UNION ALL SELECT appears in the documentation example"]:
        assert not any(f["attack_type"]=="SQL_INJECTION" for f in inspect_value(text))

def test_parameterized_query_preserves_input(app):
    with app.app_context():
        from app.extensions import get_db
        db=get_db(); db.execute("INSERT INTO users(username,email,password_hash) VALUES(?,?,?)",("safeuser","safe@example.test","hash")); db.commit()
        payload="' OR 1=1--"
        row=db.execute("SELECT id FROM users WHERE username=?",(payload,)).fetchone()
        assert row is None
