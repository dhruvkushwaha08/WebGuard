from flask import Blueprint, request, jsonify, render_template, abort
from datetime import datetime
from app.extensions import get_db
from app.routes.main import login_required
from app.security.detector import inspect_value
from app.security.validators import validate_text
bp = Blueprint("security", __name__)

@bp.get("/events")
@login_required
def events_page(): return render_template("events.html")

@bp.get("/api/security/events")
@login_required
def list_events():
    page=max(request.args.get("page",1,type=int),1); per_page=min(max(request.args.get("per_page",20,type=int),1),100)
    clauses=[]; params=[]
    for key in ("attack_type","severity","action"):
        value=request.args.get(key)
        if value: clauses.append(f"{key}=?"); params.append(value.upper())
    for key, operator in (("date_from",">="),("date_to","<=")):
        value=request.args.get(key)
        if value:
            try: datetime.strptime(value,"%Y-%m-%d")
            except ValueError: return jsonify(error=f"{key} must use YYYY-MM-DD"),400
            clauses.append(f"date(timestamp) {operator} date(?)"); params.append(value)
    if request.args.get("date_from") and request.args.get("date_to") and request.args["date_from"]>request.args["date_to"]:
        return jsonify(error="date_from must be on or before date_to"),400
    search=request.args.get("q","")
    if search:
        valid,_=validate_text(search,100)
        if not valid: return jsonify(error="Search is too long"),400
        clauses.append("(path LIKE ? OR reason LIKE ?)"); params += [f"%{search}%",f"%{search}%"]
    where=(" WHERE "+" AND ".join(clauses)) if clauses else ""
    db=get_db(); total=db.execute("SELECT COUNT(*) FROM security_events"+where,params).fetchone()[0]
    sort=request.args.get("sort","timestamp"); direction=request.args.get("direction","desc").lower()
    allowed_sort={"timestamp":"timestamp","attack_type":"attack_type","severity":"severity","path":"path"}
    order=allowed_sort.get(sort,"timestamp"); direction="ASC" if direction=="asc" else "DESC"
    rows=db.execute("SELECT * FROM security_events"+where+f" ORDER BY {order} {direction} LIMIT ? OFFSET ?",params+[per_page,(page-1)*per_page]).fetchall()
    return jsonify(items=[dict(r) for r in rows],page=page,per_page=per_page,total=total)

@bp.get("/api/security/events/<int:event_id>")
@login_required
def event_detail(event_id):
    row=get_db().execute("SELECT * FROM security_events WHERE id=?",(event_id,)).fetchone()
    if not row: abort(404)
    return jsonify(dict(row))

@bp.post("/api/security/simulate")
@login_required
def simulate():
    data=request.get_json(silent=True)
    if not isinstance(data,dict): return jsonify(error="Expected a JSON object"),400
    category=data.get("category","custom"); value=data.get("payload","")
    valid,message=validate_text(value,1000)
    if not valid: return jsonify(error=message),400
    predefined={"sqli":"' OR '1'='1", "xss":"<script>alert(1)</script>", "safe":"SELECT is a common keyword in documentation."}
    findings=inspect_value(predefined.get(category,value))
    db=get_db()
    for finding in findings:
        db.execute("INSERT INTO security_events(timestamp,attack_type,severity,method,path,reason,action,response_status,source_ip) VALUES(datetime('now'),?,?,?,?,?,?,?,?)",(finding["attack_type"],finding["severity"],request.method,request.path,"LAB SIMULATION: "+finding["reason"],"FLAGGED",200,request.remote_addr))
    if findings: db.commit()
    return jsonify(category=category,detected=bool(findings),findings=findings,action="BLOCKED" if findings else "ALLOWED",message="Payload would be blocked by request inspection." if findings else "No configured rule matched; simulation is non-destructive.")
