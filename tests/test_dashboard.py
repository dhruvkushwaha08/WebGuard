def test_dashboard_is_database_backed(signed_in):
    r=signed_in.get("/api/analytics/attacks")
    assert r.status_code==200
    data=r.get_json()
    assert set(data["kpis"])=={"total_requests","safe_requests","blocked_requests","sqli_attempts","xss_attempts","invalid_input_attempts"}
    assert data["kpis"]["total_requests"]>=1

def test_dashboard_snapshot_matches_sqlite_after_response(signed_in,app):
    with app.app_context():
        from app.extensions import get_db
        before=get_db().execute("SELECT COALESCE(SUM(safe),0) safe,COALESCE(SUM(blocked),0) blocked FROM request_counts").fetchone()
        before_safe,before_blocked=before["safe"],before["blocked"]
    response=signed_in.get("/api/analytics/attacks")
    assert response.status_code==200
    kpis=response.get_json()["kpis"]
    with app.app_context():
        from app.extensions import get_db
        after=get_db().execute("SELECT COALESCE(SUM(safe),0) safe,COALESCE(SUM(blocked),0) blocked FROM request_counts").fetchone()
        today=get_db().execute("SELECT date('now')").fetchone()[0]
        today_counts=get_db().execute("SELECT safe,blocked FROM request_counts WHERE day=?",(today,)).fetchone()
        assert kpis["safe_requests"]==after["safe"]==before_safe+1
        assert kpis["blocked_requests"]==after["blocked"]==before_blocked
        assert kpis["total_requests"]==after["safe"]+after["blocked"]
        today_trend=next((row for row in response.get_json()["trend"] if row["day"]==today),None)
        assert today_trend is not None
        assert (today_trend["safe"],today_trend["blocked"])==(today_counts["safe"],today_counts["blocked"])
