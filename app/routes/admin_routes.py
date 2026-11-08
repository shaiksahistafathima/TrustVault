
import re
import sqlite3

from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, g, jsonify
)

from app.security import roles_required
from app.database import get_db
from app.audit import log_audit_event, verify_audit_chain
from app.auth import create_user, get_all_users


admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/audit")
@roles_required("ADMIN")
def audit_view():
    """Administrative overview of document activity and security events."""
    status_filter = request.args.get("status", "")
    action_filter = request.args.get("action", "")

    sql = "SELECT * FROM audit_logs WHERE 1=1"
    params = []

    if status_filter:
        sql += " AND status = ?"
        params.append(status_filter)

    if action_filter:
        sql += " AND action LIKE ?"
        params.append(f"%{action_filter}%")

    sql += " ORDER BY sequence_number DESC LIMIT 200"

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(sql, params)
        logs = [dict(r) for r in cursor.fetchall()]

        cursor.execute("SELECT COUNT(*) as total_events FROM audit_logs")
        total_events = cursor.fetchone()["total_events"]

        cursor.execute(
            "SELECT COUNT(*) as denied_events FROM audit_logs WHERE status = 'DENIED'"
        )
        denied_events = cursor.fetchone()["denied_events"]

        cursor.execute(
            "SELECT COUNT(*) as total_docs FROM documents WHERE is_deleted = 0"
        )
        total_docs = cursor.fetchone()["total_docs"]

    return render_template(
        "admin_audit.html",
        logs=logs,
        total_events=total_events,
        denied_events=denied_events,
        total_docs=total_docs,
        status_filter=status_filter,
        action_filter=action_filter
    )


@admin_bp.route("/audit/verify", methods=["GET", "POST"])
@roles_required("ADMIN")
def audit_verify():
    """Verifies the stored SHA-256 audit hash chain."""
    user = g.user
    verification_result = verify_audit_chain()

    log_audit_event(
        action="CRYPTOGRAPHIC_AUDIT_CHAIN_VERIFIED",
        status="SUCCESS" if verification_result["valid"] else "ERROR",
        actor_id=user["id"],
        actor_email=user["email"],
        ip_address=request.remote_addr or "127.0.0.1",
        user_agent=request.user_agent.string,
        details=verification_result
    )

    if request.headers.get("Accept") == "application/json" or request.is_json:
        return jsonify(verification_result)

    if verification_result["valid"]:
        flash(
            f"Verification Succeeded: {verification_result['message']}",
            "success"
        )
    else:
        flash(
            f"TAMPERING DETECTED: {verification_result['reason']}",
            "error"
        )

    return render_template("admin_verify.html", result=verification_result)


@admin_bp.route("/users")
@roles_required("ADMIN")
def manage_users():
    """Admin user management."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, email, full_name, role, is_active, created_at
            FROM users
            ORDER BY created_at DESC
        """)
        all_users = [dict(r) for r in cursor.fetchall()]

    return render_template("admin_users.html", users=all_users)


@admin_bp.route("/users/create", methods=["POST"])
@roles_required("ADMIN")
def create_demo_account():
    """Allows an authenticated Admin to create accounts with assigned roles."""
    admin_user = g.user

    full_name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")
    role = request.form.get("role", "").strip().upper()

    if not full_name or len(full_name) > 100:
        flash("Enter a name between 1 and 100 characters.", "error")
        return redirect(url_for("admin.manage_users"))

    if not email or len(email) > 254 or not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+", email
    ):
        flash("Enter a valid email address.", "error")
        return redirect(url_for("admin.manage_users"))

    if role not in ("ADMIN", "OWNER", "VIEWER"):
        flash("Select a valid account role.", "error")
        return redirect(url_for("admin.manage_users"))

    if not 12 <= len(password) <= 128:
        flash("Password must contain between 12 and 128 characters.", "error")
        return redirect(url_for("admin.manage_users"))

    if password != confirm_password:
        flash("Passwords do not match.", "error")
        return redirect(url_for("admin.manage_users"))

    try:
        new_user = create_user(
            email=email,
            password=password,
            full_name=full_name,
            role=role
        )
    except sqlite3.IntegrityError:
        flash("An account with this email address already exists.", "error")
        return redirect(url_for("admin.manage_users"))

    log_audit_event(
        action="USER_CREATED_BY_ADMIN",
        status="SUCCESS",
        actor_id=admin_user["id"],
        actor_email=admin_user["email"],
        ip_address=request.remote_addr or "127.0.0.1",
        user_agent=request.user_agent.string,
        details={
            "target_user_id": new_user["id"],
            "target_email": new_user["email"],
            "assigned_role": new_user["role"]
        }
    )

    flash(
        f"{role} account created successfully for {email}.",
        "success"
    )
    return redirect(url_for("admin.manage_users"))


@admin_bp.route("/users/<user_id>/toggle-active", methods=["POST"])
@roles_required("ADMIN")
def toggle_user_active(user_id: str):
    """Toggles user active state and applies immediate access revocation."""
    admin_user = g.user

    if user_id == admin_user["id"]:
        flash("You cannot deactivate your own administrative account.", "error")
        return redirect(url_for("admin.manage_users"))

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT email, is_active FROM users WHERE id = ?",
            (user_id,)
        )
        target = cursor.fetchone()

        if not target:
            flash("User not found.", "error")
            return redirect(url_for("admin.manage_users"))

        new_status = 0 if target["is_active"] else 1

        cursor.execute(
            "UPDATE users SET is_active = ? WHERE id = ?",
            (new_status, user_id)
        )

    action_label = (
        "ACCOUNT_DEACTIVATED" if new_status == 0
        else "ACCOUNT_REACTIVATED"
    )

    log_audit_event(
        action=action_label,
        status="SUCCESS",
        actor_id=admin_user["id"],
        actor_email=admin_user["email"],
        ip_address=request.remote_addr or "127.0.0.1",
        user_agent=request.user_agent.string,
        details={
            "target_user_id": user_id,
            "target_email": target["email"],
            "new_active_status": new_status
        }
    )

    flash(
        f"User {target['email']} "
        f"{'deactivated (immediate revocation applied)' if new_status == 0 else 'reactivated'}.",
        "info"
    )

    return redirect(url_for("admin.manage_users"))
