import uuid
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from app.database import get_db

def create_user(email: str, password: str, full_name: str, role: str) -> dict:
    """Creates a new user with secure password hash and assigned role."""
    if role not in ("ADMIN", "OWNER", "VIEWER"):
        raise ValueError("Invalid role specified.")
        
    user_id = str(uuid.uuid4())
    pw_hash = generate_password_hash(password, method="scrypt")
    created_at = datetime.now(timezone.utc).isoformat()
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (id, email, password_hash, full_name, role, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, 1, ?)
        """, (user_id, email.lower().strip(), pw_hash, full_name.strip(), role, created_at))
        
    return {
        "id": user_id,
        "email": email.lower().strip(),
        "full_name": full_name.strip(),
        "role": role
    }

def authenticate_user(email: str, password: str):
    """Authenticates user credentials against the database. Returns user row or None."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ? AND is_active = 1", (email.lower().strip(),))
        user = cursor.fetchone()
        
    if user and check_password_hash(user["password_hash"], password):
        return dict(user)
    return None

def get_user_by_id(user_id: str):
    """Retrieves an active user by their UUID."""
    if not user_id:
        return None
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, full_name, role, is_active FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        return dict(user) if user else None

def get_all_users():
    """Retrieves a list of all active users for permission assignment."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, full_name, role FROM users WHERE is_active = 1 ORDER BY full_name ASC")
        return [dict(r) for r in cursor.fetchall()]
