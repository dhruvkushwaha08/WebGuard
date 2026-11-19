import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "development-only-change-me")
    DATABASE_PATH = os.getenv("DATABASE_PATH", str(BASE_DIR / "instance" / "webguard.sqlite3"))
    MAX_CONTENT_LENGTH = 1024 * 1024
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "0") == "1"
    PERMANENT_SESSION_LIFETIME = 1800
    ENABLE_VULNERABLE_DEMO = os.getenv("ENABLE_VULNERABLE_DEMO", "0") == "1"
    ALLOWED_HOSTS = {h.strip() for h in os.getenv("WEBGUARD_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",") if h.strip()}
    JSON_SORT_KEYS = False
