from app.extensions import get_db

def _seed_events(app):
    with app.app_context():
        db=get_db()
        rows=[
            ("2026-11-04 10:00:00","SQL_INJECTION","HIGH","GET","/health","Boolean tautology pattern","BLOCKED",400,"127.0.0.1"),
            ("2026-11-03 10:00:00","XSS","MEDIUM","POST","/search","Script element detected","BLOCKED",400,"127.0.0.1"),
            ("2026-11-02 10:00:00","SQL_INJECTION","LOW","GET","/docs","SQL comment marker","FLAGGED",200,"127.0.0.1"),
        ]
        db.executemany("INSERT INTO security_events(timestamp,attack_type,severity,method,path,reason,action,response_status,source_ip) VALUES(?,?,?,?,?,?,?,?,?)",rows)
        db.commit()

def test_event_filters_date_search_and_pagination(app,signed_in):
    _seed_events(app)
    response=signed_in.get("/api/security/events?attack_type=SQL_INJECTION&severity=HIGH&action=BLOCKED&date_from=2026-11-04&date_to=2026-11-04")
    data=response.get_json()
    assert response.status_code==200 and data["total"]==1
    assert data["items"][0]["path"]=="/health"
    response=signed_in.get("/api/security/events?q=Script%20element")
    assert response.status_code==200 and response.get_json()["total"]==1
    response=signed_in.get("/api/security/events?per_page=1&page=1&sort=timestamp&direction=asc")
    data=response.get_json()
    assert response.status_code==200 and data["total"]==3 and len(data["items"])==1
    assert data["items"][0]["timestamp"]=="2026-11-02 10:00:00"
    assert signed_in.get("/api/security/events?date_from=not-a-date").status_code==400

def test_event_detail_returns_sqlite_record(app,signed_in):
    _seed_events(app)
    with app.app_context(): event_id=get_db().execute("SELECT id FROM security_events WHERE path='/health'").fetchone()[0]
    response=signed_in.get(f"/api/security/events/{event_id}")
    assert response.status_code==200
    assert response.get_json()["reason"]=="Boolean tautology pattern"

def test_events_page_has_all_filter_and_detail_controls(signed_in):
    response=signed_in.get("/events")
    body=response.get_data(as_text=True)
    assert response.status_code==200
    for control in ('name="attack_type"','name="severity"','name="action"','name="date_from"','name="date_to"','name="q"','name="sort"','name="direction"','id="next"','id="prev"','event-detail-dialog'):
        assert control in body
