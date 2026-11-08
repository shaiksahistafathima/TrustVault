
import re
import sqlite3

from flask import (
    Blueprint, render_template, request, redirect,
    url_for, session, flash
)

from app.auth import authenticate_user, create_user
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


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not full_name or len(full_name) > 100:
            flash("Enter a name between 1 and 100 characters.", "error")
            return render_template("register.html")

        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(email) > 254:
            flash("Enter a valid email address.", "error")
            return render_template("register.html")

        if len(password) < 12 or len(password) > 128:
            flash("Password must be between 12 and 128 characters.", "error")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        try:
            # Public registration can ONLY create VIEWER accounts.
            user = create_user(
                email=email,
                password=password,
                full_name=full_name,
                role="VIEWER"
            )
        except sqlite3.IntegrityError:
            flash("An account with this email already exists.", "error")
            return render_template("register.html")

        log_audit_event(
            action="USER_REGISTERED",
            status="SUCCESS",
            actor_id=user["id"],
            actor_email=user["email"],
            ip_address=request.remote_addr or "127.0.0.1",
            user_agent=request.user_agent.string,
            details={"role": "VIEWER"}
        )

        flash("Account created successfully. Please sign in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


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
