import os
import secrets

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
STORAGE_DIR = os.path.join(BASE_DIR, "storage")
DB_PATH = os.path.join(BASE_DIR, "trustvault.db")

IS_PRODUCTION = os.environ.get("TRUSTVAULT_ENV", "development").lower() == "production"


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY")

    if not SECRET_KEY:
        if IS_PRODUCTION:
            raise RuntimeError(
                "SECRET_KEY must be configured before starting TrustVault in production."
            )
        SECRET_KEY = secrets.token_hex(32)

    STORAGE_DIR = STORAGE_DIR
    DB_PATH = DB_PATH
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024

    ALLOWED_EXTENSIONS = {"pdf", "txt", "docx", "xlsx", "png", "jpg", "jpeg", "csv"}

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = IS_PRODUCTION
    PERMANENT_SESSION_LIFETIME = 86400
    SHOW_DEMO_ACCOUNTS = not IS_PRODUCTION
