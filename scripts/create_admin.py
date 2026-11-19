"""Create the initial administrator from environment values; credentials are not hardcoded."""
import os
from dotenv import load_dotenv
load_dotenv()
from werkzeug.security import generate_password_hash
from app import create_app
from app.extensions import get_db

app=create_app()
with app.app_context():
    username=os.getenv("BOOTSTRAP_ADMIN_USERNAME","admin")
    email=os.getenv("BOOTSTRAP_ADMIN_EMAIL","admin@example.local")
    password=os.getenv("BOOTSTRAP_ADMIN_PASSWORD","")
    if not password: raise SystemExit("Set BOOTSTRAP_ADMIN_PASSWORD in untracked .env first.")
    db=get_db()
    try:
        db.execute("INSERT INTO users(username,email,password_hash,role) VALUES(?,?,?,'admin')",(username,email,generate_password_hash(password)))
        db.commit()
    except Exception as exc: raise SystemExit("Could not create admin; username/email may already exist.") from exc
print(f"Administrator {username!r} created. Remove BOOTSTRAP_ADMIN_PASSWORD from the environment now.")
