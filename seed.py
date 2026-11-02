import os
import uuid
import hashlib
from datetime import datetime, timezone
from app.config import Config
from app.database import init_db, get_db
from app.auth import create_user
from app.audit import log_audit_event

def seed_database():
    print("[*] Initializing TrustVault Database & Schema...")
    init_db()
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM users")
        if cursor.fetchone()["count"] > 0:
            print("[!] Users already exist. Skipping seed.")
            return

    print("[*] Creating Seed User Accounts...")
    admin = create_user("admin@trustvault.local", "AdminSecure2026!", "Security Administrator", "ADMIN")
    owner = create_user("owner@trustvault.local", "OwnerSecure2026!", "Alice (Document Owner)", "OWNER")
    viewer = create_user("viewer@trustvault.local", "ViewerSecure2026!", "Bob (Authorized Viewer)", "VIEWER")
    outsider = create_user("outsider@trustvault.local", "OutsiderSecure2026!", "Eve (Unauthorized Outsider)", "VIEWER")

    print("[+] Created 4 Users:")
    print(f"    - Admin:    {admin['email']} / AdminSecure2026! (Role: ADMIN)")
    print(f"    - Owner:    {owner['email']} / OwnerSecure2026! (Role: OWNER)")
    print(f"    - Viewer:   {viewer['email']} / ViewerSecure2026! (Role: VIEWER)")
    print(f"    - Outsider: {outsider['email']} / OutsiderSecure2026! (Role: VIEWER)")

    # Seed Document 1: Highly Confidential (Owner only)
    doc1_id = str(uuid.uuid4())
    doc1_content = b"%PDF-1.4\n%Confidential Executive Salary Breakdown 2026\nDirector: $250,000\nVP: $210,000\n%%EOF"
    doc1_hash = hashlib.sha256(doc1_content).hexdigest()
    doc1_path = os.path.join(Config.STORAGE_DIR, f"{doc1_id}.pdf")
    with open(doc1_path, "wb") as f:
        f.write(doc1_content)

    now_iso = datetime.now(timezone.utc).isoformat()

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO documents (
                id, title, description, category, storage_path,
                original_filename, file_size, mime_type, file_sha256,
                owner_id, is_deleted, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
        """, (
            doc1_id, "Executive_Salary_2026.pdf", "Strictly confidential executive compensation structure.",
            "Employee Salaries", doc1_path, "Executive_Salary_2026.pdf", len(doc1_content),
            "application/pdf", doc1_hash, owner["id"], now_iso, now_iso
        ))

    log_audit_event(
        action="DOCUMENT_UPLOAD",
        status="SUCCESS",
        actor_id=owner["id"],
        actor_email=owner["email"],
        document_id=doc1_id,
        ip_address="127.0.0.1",
        user_agent="TrustVault-SeedEngine/1.0",
        details={"title": "Executive_Salary_2026.pdf", "category": "Employee Salaries"}
    )
    print(f"[+] Seeded Document 1: 'Executive_Salary_2026.pdf' (UUID: {doc1_id}) [Owner-only]")

    # Seed Document 2: Shared Contract (Owner + Viewer READ permission)
    doc2_id = str(uuid.uuid4())
    doc2_content = b"%PDF-1.4\n%Master Services Agreement between TrustVault and Acme Corp.\nTerms: 36 Months.\n%%EOF"
    doc2_hash = hashlib.sha256(doc2_content).hexdigest()
    doc2_path = os.path.join(Config.STORAGE_DIR, f"{doc2_id}.pdf")
    with open(doc2_path, "wb") as f:
        f.write(doc2_content)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO documents (
                id, title, description, category, storage_path,
                original_filename, file_size, mime_type, file_sha256,
                owner_id, is_deleted, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
        """, (
            doc2_id, "Master_Services_Agreement.pdf", "Signed vendor agreement for Acme Corp.",
            "Confidential Contracts", doc2_path, "Master_Services_Agreement.pdf", len(doc2_content),
            "application/pdf", doc2_hash, owner["id"], now_iso, now_iso
        ))

        # Grant READ access to Bob (viewer)
        cursor.execute("""
            INSERT INTO document_permissions (id, document_id, user_id, permission_level, granted_by, granted_at)
            VALUES (?, ?, ?, 'READ', ?, ?)
        """, (str(uuid.uuid4()), doc2_id, viewer["id"], owner["id"], now_iso))

    log_audit_event(
        action="DOCUMENT_UPLOAD",
        status="SUCCESS",
        actor_id=owner["id"],
        actor_email=owner["email"],
        document_id=doc2_id,
        ip_address="127.0.0.1",
        user_agent="TrustVault-SeedEngine/1.0",
        details={"title": "Master_Services_Agreement.pdf", "category": "Confidential Contracts"}
    )

    log_audit_event(
        action="GRANT_PERMISSION",
        status="SUCCESS",
        actor_id=owner["id"],
        actor_email=owner["email"],
        document_id=doc2_id,
        ip_address="127.0.0.1",
        user_agent="TrustVault-SeedEngine/1.0",
        details={"target_user_email": viewer["email"], "permission_level": "READ"}
    )
    print(f"[+] Seeded Document 2: 'Master_Services_Agreement.pdf' (UUID: {doc2_id}) [Shared with {viewer['email']}]")
    print("[*] Database successfully seeded with cryptographically chained audit events!")

if __name__ == "__main__":
    seed_database()
