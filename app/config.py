import os
import secrets

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
STORAGE_DIR = os.path.join(BASE_DIR, "storage")
DB_PATH = os.path.join(BASE_DIR, "trustvault.db")

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
    STORAGE_DIR = STORAGE_DIR
    DB_PATH = DB_PATH
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload limit to prevent DoS
    
    # Allowed MIME types & Magic Bytes
    ALLOWED_EXTENSIONS = {"pdf", "txt", "docx", "xlsx", "png", "jpg", "jpeg", "csv"}
    
    # Session security settings
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False  # Set to True in production HTTPS
    PERMANENT_SESSION_LIFETIME = 86400  # 24 hours
