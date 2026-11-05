
import os
import re
import uuid
from datetime import datetime, timezone
from getpass import getpass

from werkzeug.security import generate_password_hash


def create_initial_admin(email, full_name, password):
    """Create the first administrator and audit event atomically."""

    from app.database import init_db, get_db
    from app.audit import append_audit_event

    email = email.strip().lower()
    full_name = full_name.strip()

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise ValueError("Please enter a valid email address.")

    if not full_name:
        raise ValueError("Full name cannot be empty.")

    if len(password) < 12:
        raise ValueError("Password must contain at least 12 characters.")

    init_db()

    user_id = str(uuid.uuid4())
    password_hash = generate_password_hash(password, method="scrypt")
    created_at = datetime.now(timezone.utc).isoformat()

    with get_db() as conn:
        # Lock the database before checking whether it is empty.
        conn.execute("BEGIN IMMEDIATE")

        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]

        if user_count != 0:
            raise ValueError(
                "Bootstrap refused: users already exist. "
                "This command is only for a completely empty database."
            )

        cursor.execute("""
            INSERT INTO users (
                id, email, password_hash, full_name,
                role, is_active, created_at
            )
            VALUES (?, ?, ?, ?, 'ADMIN', 1, ?)
        """, (
            user_id,
            email,
            password_hash,
            full_name,
            created_at
        ))

        # This uses the SAME connection and transaction.
        append_audit_event(
            conn=conn,
            action="ADMIN_ACCOUNT_BOOTSTRAPPED",
            status="SUCCESS",
            actor_id=user_id,
            actor_email=email,
            ip_address="127.0.0.1",
            user_agent="TrustVault-AdminBootstrap/1.0",
            details={
                "role": "ADMIN",
                "method": "one_time_cli_bootstrap"
            }
        )

    return {
        "id": user_id,
        "email": email,
        "full_name": full_name,
        "role": "ADMIN"
    }



def bootstrap_admin_from_environment():
    """Create the first production administrator from private environment variables."""

    if os.environ.get("TRUSTVAULT_ENV", "").lower() != "production":
        return False

    password = os.environ.pop("TRUSTVAULT_BOOTSTRAP_ADMIN_PASSWORD", "")
    email = os.environ.get("TRUSTVAULT_BOOTSTRAP_ADMIN_EMAIL", "").strip()
    full_name = os.environ.get("TRUSTVAULT_BOOTSTRAP_ADMIN_NAME", "").strip()

    from app.database import init_db, get_db

    init_db()
    with get_db() as conn:
        existing_user = conn.execute(
            "SELECT 1 FROM users LIMIT 1"
        ).fetchone()

    if existing_user:
        print("TrustVault administrator already exists. Bootstrap skipped.")
        return False

    if not email or not full_name or not password:
        raise RuntimeError(
            "Configure all three TRUSTVAULT_BOOTSTRAP_ADMIN environment variables."
        )

    admin = create_initial_admin(email, full_name, password)

    print("TrustVault initial administrator created:", admin["email"])
    return True


def main():
    if os.environ.get("TRUSTVAULT_ENV", "").lower() != "production":
        print("ERROR: This command is only allowed in production mode.")
        return 1

    if not os.environ.get("SECRET_KEY"):
        print("ERROR: Configure SECRET_KEY before running bootstrap.")
        return 1

    print("TrustVault — First Administrator Setup")
    print("---------------------------------------")

    email = input("Administrator email: ").strip()
    full_name = input("Administrator full name: ").strip()

    password = getpass("Administrator password: ")
    confirmation = getpass("Confirm password: ")

    if password != confirmation:
        print("ERROR: Passwords do not match.")
        return 1

    try:
        admin = create_initial_admin(email, full_name, password)
    except ValueError as error:
        print(f"ERROR: {error}")
        return 1

    print("\nAdministrator created successfully.")
    print(f"Email: {admin['email']}")
    print("Role: ADMIN")
    print("Audit event: ADMIN_ACCOUNT_BOOTSTRAPPED")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
