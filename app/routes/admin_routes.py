from flask import Blueprint, render_template, request, redirect, url_for, flash, g, jsonify
from app.security import roles_required
from app.database import get_db
from app.audit import log_audit_event, verify_audit_chain
from app.auth import get_all_users

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

@admin_bp.route("/audit")
@roles_required("ADMIN")
def audit_view():
    """
    Administrative overview of all document activity, security events,
    permission changes, and unauthorized access attempts.
    """
    user = g.user
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
        
        # Summary metrics
        cursor.execute("SELECT COUNT(*) as total_events FROM audit_logs")
        total_events = cursor.fetchone()["total_events"]
        
        cursor.execute("SELECT COUNT(*) as denied_events FROM audit_logs WHERE status = 'DENIED'")
        denied_events = cursor.fetchone()["denied_events"]
        
        cursor.execute("SELECT COUNT(*) as total_docs FROM documents WHERE is_deleted = 0")
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
    """
    Verifies the entire cryptographic SHA-256 hash chain from genesis to head.
    Detects any row alteration, row deletion, or sequence tampering.
    """
    user = g.user
    verification_result = verify_audit_chain()
    
    # Log the verification run itself into the chain
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
        flash(f"Verification Succeeded: {verification_result['message']}", "success")
    else:
        flash(f"TAMPERING DETECTED: {verification_result['reason']}", "error")
        
    return render_template("admin_verify.html", result=verification_result)

@admin_bp.route("/users")
@roles_required("ADMIN")
def manage_users():
    """Admin user management for immediate account suspension."""
    users = get_all_users()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, full_name, role, is_active, created_at FROM users ORDER BY created_at DESC")
        all_users = [dict(r) for r in cursor.fetchall()]
        
    return render_template("admin_users.html", users=all_users)

@admin_bp.route("/users/<user_id>/toggle-active", methods=["POST"])
@roles_required("ADMIN")
def toggle_user_active(user_id: str):
    """
    Toggles user active state.
    Deactivating a user instantly cuts off their ability to perform any action or download.
    """
    admin_user = g.user
    if user_id == admin_user["id"]:
        flash("You cannot deactivate your own administrative account.", "error")
        return redirect(url_for("admin.manage_users"))
        
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT email, is_active FROM users WHERE id = ?", (user_id,))
        target = cursor.fetchone()
        if not target:
            flash("User not found.", "error")
            return redirect(url_for("admin.manage_users"))
            
        new_status = 0 if target["is_active"] else 1
        cursor.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_status, user_id))
        
    action_label = "ACCOUNT_DEACTIVATED" if new_status == 0 else "ACCOUNT_REACTIVATED"
    log_audit_event(
        action=action_label,
        status="SUCCESS",
        actor_id=admin_user["id"],
        actor_email=admin_user["email"],
        ip_address=request.remote_addr or "127.0.0.1",
        user_agent=request.user_agent.string,
        details={"target_user_id": user_id, "target_email": target["email"], "new_active_status": new_status}
    )
    
    flash(f"User {target['email']} {'deactivated (immediate revocation applied)' if new_status == 0 else 'reactivated'}.", "info")
    return redirect(url_for("admin.manage_users"))
