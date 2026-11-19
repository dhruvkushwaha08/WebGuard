def test_security_headers(client):
    response=client.get("/health")
    assert response.headers["X-Content-Type-Options"]=="nosniff"
    assert response.headers["X-Frame-Options"]=="DENY"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert "form-action 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers.get("Referrer-Policy")

def test_external_stylesheet_and_chart_script_use_subresource_integrity(signed_in):
    login_page=signed_in.get("/auth/login")
    dashboard=signed_in.get("/dashboard")
    assert b"integrity=\"sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH\"" in login_page.data
    assert b"integrity=\"sha384-vsrfeLOOY6KuIYKDlmVH5UiBmgIdB1oEf7p01YgWHuqmOHfZr374+odEv96n9tNC\"" in dashboard.data
    assert b"crossorigin=\"anonymous\"" in login_page.data
