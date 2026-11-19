from flask import Blueprint, request, jsonify, session
from app.extensions import get_db
from app.routes.main import admin_required
bp=Blueprint("admin",__name__,url_prefix="/api/admin")

@bp.get("/users")
@admin_required
def users():
    rows=get_db().execute("SELECT id,username,email,role,active,created_at FROM users ORDER BY id").fetchall()
    return jsonify(users=[dict(r) for r in rows])

@bp.put("/users/<int:user_id>/status")
@admin_required
def user_status(user_id):
    data=request.get_json(silent=True)
    if not isinstance(data,dict): return jsonify(error="Expected a JSON object"),400
    if not isinstance(data.get("active"),bool): return jsonify(error="active must be a boolean"),400
    if user_id==session.get("user_id"): return jsonify(error="Cannot disable current administrator"),400
    db=get_db(); cursor=db.execute("UPDATE users SET active=? WHERE id=?",(int(data["active"]),user_id)); db.commit()
    if not cursor.rowcount: return jsonify(error="User not found"),404
    return jsonify(message="User status updated")
