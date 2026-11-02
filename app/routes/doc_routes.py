
import os
import uuid
import hashlib
from datetime import datetime, timezone

from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, g, send_file, abort
)
from werkzeug.utils import secure_filename

from app.config import Config
from app.database import get_db
from app.security import (
    login_required,
    get_document_with_auth,
    validate_file_content
)
from app.audit import log_audit_event
from app.auth import get_all_users


doc_bp = Blueprint("docs", __name__)


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@doc_bp.route("/")
@login_required
def dashboard():
    """Show documents owned by or shared with the logged-in user."""

    user_id = g.user["id"]

    with get_db() as conn:
        cursor = conn.cursor()

        # Documents owned by the logged-in user
        cursor.execute("""
            SELECT *
            FROM documents
            WHERE owner_id = ?
              AND is_deleted = 0
            ORDER BY created_at DESC
        """, (user_id,))

        owned_docs = [dict(row) for row in cursor.fetchall()]

        # Documents shared with the logged-in user
        cursor.execute("""
            SELECT
                d.*,
                owner.full_name AS owner_name,
                p.permission_level AS user_permission
            FROM documents d
            JOIN document_permissions p
                ON p.document_id = d.id
            JOIN users owner
                ON owner.id = d.owner_id
            JOIN users recipient
                ON recipient.id = p.user_id
            WHERE p.user_id = ?
              AND d.owner_id != ?
              AND d.is_deleted = 0
              AND recipient.is_active = 1
              AND owner.is_active = 1
            ORDER BY d.created_at DESC
        """, (user_id, user_id))

        shared_docs = [dict(row) for row in cursor.fetchall()]

    return render_template(
        "dashboard.html",
        owned_docs=owned_docs,
        shared_docs=shared_docs
    )


# --------------------------------------------------
# DOCUMENT DETAILS
# --------------------------------------------------

@doc_bp.route("/documents/<document_id>")
@login_required
def document_detail(document_id: str):
    """Show document details while protecting sensitive information."""

    doc, permission_level = get_document_with_auth(
        document_id,
        required_level="READ"
    )

    permissions = []
    doc_audit = []
    eligible_users = []

    # Only the owner can view permissions and audit history
    if permission_level == "OWNER":

        with get_db() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT
                    p.id AS perm_id,
                    p.permission_level,
                    p.granted_at,
                    u.id AS user_id,
                    u.email,
                    u.full_name,
                    u.role
                FROM document_permissions p
                JOIN users u ON p.user_id = u.id
                WHERE p.document_id = ?
                ORDER BY p.granted_at DESC
            """, (document_id,))

            permissions = [
                dict(row) for row in cursor.fetchall()
            ]

            cursor.execute("""
                SELECT *
                FROM audit_logs
                WHERE document_id = ?
                ORDER BY sequence_number DESC
                LIMIT 50
            """, (document_id,))

            doc_audit = [
                dict(row) for row in cursor.fetchall()
            ]

        all_users = get_all_users()

        shared_user_ids = {
            p["user_id"] for p in permissions
        } | {doc["owner_id"]}

        eligible_users = [
            user for user in all_users
            if user["id"] not in shared_user_ids
        ]

    return render_template(
        "document_detail.html",
        doc=doc,
        permission_level=permission_level,
        permissions=permissions,
        eligible_users=eligible_users,
        doc_audit=doc_audit
    )


# --------------------------------------------------
# UPLOAD DOCUMENT
# --------------------------------------------------

@doc_bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    """Secure document upload with file validation."""

    user = g.user

    if user["role"] not in ("ADMIN", "OWNER"):
        flash(
            "Viewers cannot upload documents. "
            "Role requires OWNER or ADMIN.",
            "error"
        )
        return redirect(url_for("docs.dashboard"))

    if request.method == "POST":

        file = request.files.get("file")
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        category = request.form.get("category", "General").strip()

        if not file or not file.filename:
            flash("Please select a file to upload.", "error")
            return redirect(request.url)

        original_filename = secure_filename(file.filename)

        is_valid, reason = validate_file_content(
            file.stream,
            original_filename
        )

        if not is_valid:

            log_audit_event(
                action="MALICIOUS_UPLOAD_BLOCKED",
                status="DENIED",
                actor_id=user["id"],
                actor_email=user["email"],
                ip_address=request.remote_addr or "127.0.0.1",
                user_agent=request.user_agent.string,
                details={
                    "filename": original_filename,
                    "reason": reason
                }
            )

            flash(f"Upload rejected: {reason}", "error")
            return redirect(request.url)

        # Generate a unique storage filename
        doc_id = str(uuid.uuid4())

        ext = (
            original_filename.rsplit(".", 1)[-1].lower()
            if "." in original_filename else "dat"
        )

        storage_filename = f"{doc_id}.{ext}"

        storage_path = os.path.join(
            Config.STORAGE_DIR,
            storage_filename
        )

        # Calculate file hash
        file.seek(0)
        file_bytes = file.read()

        file_sha256 = hashlib.sha256(
            file_bytes
        ).hexdigest()

        file_size = len(file_bytes)

        with open(storage_path, "wb") as f:
            f.write(file_bytes)

        now_iso = datetime.now(timezone.utc).isoformat()

        final_title = title if title else original_filename

        with get_db() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO documents (
                    id, title, description, category,
                    storage_path, original_filename,
                    file_size, mime_type, file_sha256,
                    owner_id, is_deleted, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
            """, (
                doc_id,
                final_title,
                description,
                category,
                storage_path,
                original_filename,
                file_size,
                file.content_type or "application/octet-stream",
                file_sha256,
                user["id"],
                now_iso,
                now_iso
            ))

        log_audit_event(
            action="DOCUMENT_UPLOAD",
            status="SUCCESS",
            actor_id=user["id"],
            actor_email=user["email"],
            document_id=doc_id,
            ip_address=request.remote_addr or "127.0.0.1",
            user_agent=request.user_agent.string,
            details={
                "title": final_title,
                "file_size": file_size,
                "file_sha256": file_sha256,
                "category": category
            }
        )

        flash(
            f"Document '{final_title}' securely uploaded.",
            "success"
        )

        return redirect(
            url_for(
                "docs.document_detail",
                document_id=doc_id
            )
        )

    return render_template("upload.html")


# --------------------------------------------------
# DOWNLOAD DOCUMENT
# --------------------------------------------------

@doc_bp.route("/documents/<document_id>/download")
@login_required
def download_document(document_id: str):
    """Check live permissions before downloading a document."""

    doc, permission_level = get_document_with_auth(
        document_id,
        required_level="READ"
    )

    user = g.user

    if not os.path.exists(doc["storage_path"]):

        log_audit_event(
            action="FILE_MISSING_ON_DISK",
            status="ERROR",
            actor_id=user["id"],
            actor_email=user["email"],
            document_id=document_id,
            ip_address=request.remote_addr or "127.0.0.1",
            user_agent=request.user_agent.string
        )

        abort(404)

    log_audit_event(
        action="DOCUMENT_DOWNLOAD",
        status="SUCCESS",
        actor_id=user["id"],
        actor_email=user["email"],
        document_id=document_id,
        ip_address=request.remote_addr or "127.0.0.1",
        user_agent=request.user_agent.string,
        details={
            "document_title": doc["title"],
            "file_size": doc["file_size"],
            "permission_used": permission_level
        }
    )

    return send_file(
        doc["storage_path"],
        as_attachment=True,
        download_name=doc["original_filename"],
        mimetype=doc["mime_type"]
    )


# --------------------------------------------------
# GRANT PERMISSION
# --------------------------------------------------

@doc_bp.route("/documents/<document_id>/share", methods=["POST"])
@login_required
def grant_permission(document_id: str):
    """Grant READ or EDIT permission. Owner only."""

    doc, permission_level = get_document_with_auth(
        document_id,
        required_level="EDIT"
    )

    user = g.user

    if permission_level != "OWNER":
        flash(
            "Only the document owner can grant permissions.",
            "error"
        )
        return redirect(
            url_for(
                "docs.document_detail",
                document_id=document_id
            )
        )

    target_user_id = request.form.get("user_id")

    perm_level = request.form.get(
        "permission_level",
        "READ"
    )

    if perm_level not in ("READ", "EDIT"):
        flash("Invalid permission level.", "error")
        return redirect(
            url_for(
                "docs.document_detail",
                document_id=document_id
            )
        )

    if target_user_id == user["id"]:
        flash("Cannot grant permissions to yourself.", "error")
        return redirect(
            url_for(
                "docs.document_detail",
                document_id=document_id
            )
        )

    perm_id = str(uuid.uuid4())

    now_iso = datetime.now(timezone.utc).isoformat()

    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, email
            FROM users
            WHERE id = ?
              AND is_active = 1
        """, (target_user_id,))

        target_user = cursor.fetchone()

        if not target_user:
            flash(
                "Target user does not exist or is inactive.",
                "error"
            )
            return redirect(
                url_for(
                    "docs.document_detail",
                    document_id=document_id
                )
            )

        cursor.execute("""
            INSERT INTO document_permissions (
                id, document_id, user_id,
                permission_level, granted_by, granted_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(document_id, user_id)
            DO UPDATE SET
                permission_level = excluded.permission_level,
                granted_by = excluded.granted_by,
                granted_at = excluded.granted_at
        """, (
            perm_id,
            document_id,
            target_user_id,
            perm_level,
            user["id"],
            now_iso
        ))

    log_audit_event(
        action="GRANT_PERMISSION",
        status="SUCCESS",
        actor_id=user["id"],
        actor_email=user["email"],
        document_id=document_id,
        ip_address=request.remote_addr or "127.0.0.1",
        user_agent=request.user_agent.string,
        details={
            "target_user_id": target_user_id,
            "target_user_email": target_user["email"],
            "permission_level": perm_level
        }
    )

    flash(
        f"Granted {perm_level} access to {target_user['email']}.",
        "success"
    )

    return redirect(
        url_for(
            "docs.document_detail",
            document_id=document_id
        )
    )


# --------------------------------------------------
# REVOKE PERMISSION
# --------------------------------------------------

@doc_bp.route(
    "/documents/<document_id>/revoke/<target_user_id>",
    methods=["POST"]
)
@login_required
def revoke_permission(document_id: str, target_user_id: str):
    """Revoke a user's document access. Owner only."""

    doc, permission_level = get_document_with_auth(
        document_id,
        required_level="EDIT"
    )

    user = g.user

    if permission_level != "OWNER":
        flash(
            "Only the document owner can revoke permissions.",
            "error"
        )
        return redirect(
            url_for(
                "docs.document_detail",
                document_id=document_id
            )
        )

    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT email FROM users WHERE id = ?",
            (target_user_id,)
        )

        target_user = cursor.fetchone()

        target_email = (
            target_user["email"]
            if target_user else "Unknown"
        )

        cursor.execute("""
            DELETE FROM document_permissions
            WHERE document_id = ?
              AND user_id = ?
        """, (document_id, target_user_id))

        rows_deleted = cursor.rowcount

    log_audit_event(
        action="REVOKE_PERMISSION",
        status="SUCCESS",
        actor_id=user["id"],
        actor_email=user["email"],
        document_id=document_id,
        ip_address=request.remote_addr or "127.0.0.1",
        user_agent=request.user_agent.string,
        details={
            "revoked_user_id": target_user_id,
            "revoked_user_email": target_email,
            "success": rows_deleted > 0
        }
    )

    flash(
        f"Access immediately revoked for {target_email}.",
        "info"
    )

    return redirect(
        url_for(
            "docs.document_detail",
            document_id=document_id
        )
    )


# --------------------------------------------------
# EDIT DOCUMENT
# --------------------------------------------------

@doc_bp.route(
    "/documents/<document_id>/edit",
    methods=["POST"]
)
@login_required
def edit_document(document_id: str):
    """Edit document metadata. Requires EDIT or OWNER access."""

    doc, permission_level = get_document_with_auth(
        document_id,
        required_level="EDIT"
    )

    user = g.user

    new_title = (
        request.form.get("title", "").strip()
        or doc["title"]
    )

    new_description = request.form.get(
        "description",
        ""
    ).strip()

    new_category = request.form.get(
        "category",
        doc["category"]
    ).strip()

    now_iso = datetime.now(timezone.utc).isoformat()

    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE documents
            SET title = ?,
                description = ?,
                category = ?,
                updated_at = ?
            WHERE id = ?
        """, (
            new_title,
            new_description,
            new_category,
            now_iso,
            document_id
        ))

    log_audit_event(
        action="DOCUMENT_METADATA_EDIT",
        status="SUCCESS",
        actor_id=user["id"],
        actor_email=user["email"],
        document_id=document_id,
        ip_address=request.remote_addr or "127.0.0.1",
        user_agent=request.user_agent.string,
        details={
            "old_title": doc["title"],
            "new_title": new_title,
            "category": new_category
        }
    )

    flash("Document details updated.", "success")

    return redirect(
        url_for(
            "docs.document_detail",
            document_id=document_id
        )
    )


# --------------------------------------------------
# DELETE DOCUMENT
# --------------------------------------------------

@doc_bp.route(
    "/documents/<document_id>/delete",
    methods=["POST"]
)
@login_required
def delete_document(document_id: str):
    """Soft-delete a document. Owner only."""

    doc, permission_level = get_document_with_auth(
        document_id,
        required_level="EDIT"
    )

    user = g.user

    if permission_level != "OWNER":
        flash(
            "Only the document owner can delete this document.",
            "error"
        )
        return redirect(
            url_for(
                "docs.document_detail",
                document_id=document_id
            )
        )

    now_iso = datetime.now(timezone.utc).isoformat()

    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE documents
            SET is_deleted = 1,
                updated_at = ?
            WHERE id = ?
        """, (now_iso, document_id))

    log_audit_event(
        action="DOCUMENT_DELETE",
        status="SUCCESS",
        actor_id=user["id"],
        actor_email=user["email"],
        document_id=document_id,
        ip_address=request.remote_addr or "127.0.0.1",
        user_agent=request.user_agent.string,
        details={
            "title": doc["title"]
        }
    )

    flash(
        f"Document '{doc['title']}' deleted.",
        "info"
    )

    return redirect(url_for("docs.dashboard"))


# --------------------------------------------------
# SEARCH DOCUMENTS
# --------------------------------------------------

@doc_bp.route("/search")
@login_required
def search():
    """Search only documents the logged-in user can access."""

    user = g.user

    query = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()

    sql = """
        SELECT DISTINCT
            d.*,
            u.full_name AS owner_name,
            CASE
                WHEN d.owner_id = ? THEN 'OWNER'
                ELSE p.permission_level
            END AS user_permission
        FROM documents d
        JOIN users u
            ON d.owner_id = u.id
        LEFT JOIN document_permissions p
            ON d.id = p.document_id
            AND p.user_id = ?
        WHERE d.is_deleted = 0
          AND (d.owner_id = ? OR p.user_id = ?)
    """

    params = [
        user["id"],
        user["id"],
        user["id"],
        user["id"]
    ]

    if query:
        sql += """
            AND (
                d.title LIKE ?
                OR d.description LIKE ?
                OR u.full_name LIKE ?
            )
        """

        search_term = f"%{query}%"

        params.extend([
            search_term,
            search_term,
            search_term
        ])

    if category:
        sql += " AND d.category = ?"
        params.append(category)

    if date_from:
        sql += " AND d.created_at >= ?"
        params.append(date_from)

    if date_to:
        sql += " AND d.created_at <= ?"
        params.append(date_to + "T23:59:59")

    sql += " ORDER BY d.created_at DESC"

    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute(sql, params)

        results = [
            dict(row) for row in cursor.fetchall()
        ]

    return render_template(
        "search.html",
        results=results,
        query=query,
        category=category,
        date_from=date_from,
        date_to=date_to
    )
