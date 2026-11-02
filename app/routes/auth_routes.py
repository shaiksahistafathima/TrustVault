from flask import Blueprint, render_template, request, redirect, url_for, session, flash, g
from app.auth import authenticate_user
from app.audit import log_audit_event
from app.security import login_required

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        
        user = authenticate_user(email, password)
        if user:
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = True
            
            log_audit_event(
                action="USER_LOGIN_SUCCESS",
                status="SUCCESS",
                actor_id=user["id"],
                actor_email=user["email"],
                ip_address=request.remote_addr or "127.0.0.1",
                user_agent=request.user_agent.string,
                details={"role": user["role"]}
            )
            flash("Welcome to TrustVault.", "success")
            next_url = request.args.get("next") or url_for("docs.dashboard")
            return redirect(next_url)
        else:
            log_audit_event(
                action="USER_LOGIN_FAILED",
                status="DENIED",
                actor_email=email,
                ip_address=request.remote_addr or "127.0.0.1",
                user_agent=request.user_agent.string,
                details={"reason": "Invalid credentials or inactive account"}
            )
            flash("Invalid email or password.", "error")
            
    return render_template("login.html")

@auth_bp.route("/logout", methods=["POST"])
def logout():
    user_id = session.get("user_id")
    if user_id:
        log_audit_event(
            action="USER_LOGOUT",
            status="SUCCESS",
            actor_id=user_id,
            ip_address=request.remote_addr or "127.0.0.1",
            user_agent=request.user_agent.string
        )
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))
