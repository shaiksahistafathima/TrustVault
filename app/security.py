import os
from functools import wraps
from flask import session, request, abort, redirect, url_for, g
from app.auth import get_user_by_id
from app.audit import log_audit_event
from app.database import get_db

MAGIC_NUMBERS = {
    "pdf": [b"%PDF-"],
    "png": [b"\x89PNG\r\n\x1a\n"],
    "jpg": [b"\xff\xd8\xff"],
    "jpeg": [b"\xff\xd8\xff"],
    "docx": [b"PK\x03\x04"],
    "xlsx": [b"PK\x03\x04"],
}

def validate_file_content(file_stream, filename: str) -> tuple[bool, str]:
    """
    Validates file content using file signature (magic bytes).
    Prevents file extension spoofing (e.g., evil.exe renamed to doc.pdf).
    """
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if not ext:
        return False, "File must have a valid extension."
        
    file_stream.seek(0)
    header = file_stream.read(16)
    file_stream.seek(0)
    
    if ext in MAGIC_NUMBERS:
        matches = any(header.startswith(magic) for magic in MAGIC_NUMBERS[ext])
        if not matches:
            return False, f"File signature mismatch. The file content does not match the '{ext}' format."
        return True, "Valid"
        
    if ext in ("txt", "csv"):
        # Check that it is valid UTF-8/ASCII text and contains NO null bytes (binary/executable marker)
        file_stream.seek(0)
        chunk = file_stream.read(4096)
        file_stream.seek(0)
        if b"\x00" in chunk:
            return False, "Binary data or null bytes detected in plain text file."
        try:
            chunk.decode("utf-8")
        except UnicodeDecodeError:
            return False, "Invalid text encoding. Must be valid UTF-8."
        return True, "Valid"
        
    return False, f"File extension '.{ext}' is not permitted."

def get_current_user():
    """Fetches and verifies the active user session directly against the live database."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    user = get_user_by_id(user_id)
    if not user or not user["is_active"]:
        session.clear()
        return None
    return user

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            if request.path.startswith("/api/"):
                log_audit_event(
                    action="UNAUTHORIZED_API_ACCESS",
                    status="DENIED",
                    actor_id=None,
                    ip_address=request.remote_addr or "127.0.0.1",
                    user_agent=request.user_agent.string,
                    details={"path": request.path}
                )
                return {"error": "Authentication required"}, 401
            return redirect(url_for("auth.login", next=request.path))
        g.user = user
        return f(*args, **kwargs)
    return decorated_function

def roles_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user()
            if not user:
                return redirect(url_for("auth.login"))
            if user["role"] not in allowed_roles:
                log_audit_event(
                    action="ROLE_PRIVILEGE_VIOLATION",
                    status="DENIED",
                    actor_id=user["id"],
                    actor_email=user["email"],
                    ip_address=request.remote_addr or "127.0.0.1",
                    user_agent=request.user_agent.string,
                    details={"path": request.path, "required_roles": list(allowed_roles), "user_role": user["role"]}
                )
                if request.path.startswith("/api/"):
                    return {"error": "Insufficient privileges for this action"}, 403
                abort(403)
            g.user = user
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_document_with_auth(document_id: str, required_level: str = "READ") -> tuple[dict, str]:
    """
    CRITICAL AUTHORIZATION CHECK:
    The single point of truth for document authorization.
    Verifies user permissions directly against live DB records.
    Logs all attempts (including denied ones) to the tamper-evident audit trail.
    
    Returns: (document_dict, user_role_on_doc) or raises HTTP 403/404.
    """
    user = g.user if hasattr(g, "user") and g.user else get_current_user()
    if not user:
        log_audit_event(
            action="UNAUTHENTICATED_DOC_ACCESS",
            status="DENIED",
            document_id=document_id,
            ip_address=request.remote_addr or "127.0.0.1",
            user_agent=request.user_agent.string,
            details={"requested_level": required_level}
        )
        abort(401)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM documents WHERE id = ? AND is_deleted = 0", (document_id,))
        doc = cursor.fetchone()
        
    if not doc:
        # Document not found or soft-deleted
        log_audit_event(
            action="DOCUMENT_NOT_FOUND",
            status="DENIED",
            actor_id=user["id"],
            actor_email=user["email"],
            document_id=document_id,
            ip_address=request.remote_addr or "127.0.0.1",
            user_agent=request.user_agent.string,
            details={"requested_level": required_level}
        )
        abort(404)

    doc_dict = dict(doc)

    # 1. Document Owner has full access
    if doc_dict["owner_id"] == user["id"]:
        return doc_dict, "OWNER"

    # 2. Query explicit permissions (per-document ACL)
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT permission_level FROM document_permissions
            WHERE document_id = ? AND user_id = ?
        """, (document_id, user["id"]))
        perm = cursor.fetchone()

    if perm:
        perm_level = perm["permission_level"]
        if required_level == "READ" and perm_level in ("READ", "EDIT"):
            return doc_dict, perm_level
        if required_level == "EDIT" and perm_level == "EDIT":
            return doc_dict, perm_level

    # 3. Access Denied: Log to audit trail and refuse request immediately
    log_audit_event(
        action="UNAUTHORIZED_DOCUMENT_ACCESS_ATTEMPT",
        status="DENIED",
        actor_id=user["id"],
        actor_email=user["email"],
        document_id=document_id,
        ip_address=request.remote_addr or "127.0.0.1",
        user_agent=request.user_agent.string,
        details={
            "required_level": required_level,
            "document_title": doc_dict["title"],
            "reason": "User not granted explicit permission"
        }
    )
    abort(403)
