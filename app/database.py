import sqlite3
import os
from contextlib import contextmanager
from app.config import Config

def get_db_connection():
    """Returns a SQLite connection with foreign keys and row factory enabled."""
    conn = sqlite3.connect(Config.DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn

@contextmanager
def get_db():
    """Context manager for safe database transactions."""
    conn = get_db_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    """Initializes the database schema and seeds initial genesis record for the audit chain."""
    os.makedirs(Config.STORAGE_DIR, exist_ok=True)
    with get_db() as conn:
        cursor = conn.cursor()
        
        # 1. Users Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('ADMIN', 'OWNER', 'VIEWER')),
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
        """)
        
        # 2. Documents Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                category TEXT NOT NULL DEFAULT 'General',
                storage_path TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                mime_type TEXT NOT NULL,
                file_sha256 TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                is_deleted INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE RESTRICT
            )
        """)
        
        # 3. Document Permissions Table (Per-document ACL)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS document_permissions (
                id TEXT PRIMARY KEY,
                document_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                permission_level TEXT NOT NULL CHECK(permission_level IN ('READ', 'EDIT')),
                granted_by TEXT NOT NULL,
                granted_at TEXT NOT NULL,
                UNIQUE(document_id, user_id),
                FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (granted_by) REFERENCES users(id)
            )
        """)
        
        # 4. Tamper-Evident Audit Logs Table (Hash-Chained)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
                id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                actor_id TEXT,
                actor_email TEXT,
                action TEXT NOT NULL,
                document_id TEXT,
                status TEXT NOT NULL CHECK(status IN ('SUCCESS', 'DENIED', 'ERROR')),
                ip_address TEXT NOT NULL,
                user_agent TEXT NOT NULL,
                details TEXT,
                prev_hash TEXT NOT NULL,
                row_hash TEXT NOT NULL,
                FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL,
                FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE SET NULL
            )
        """)
        
        # Indexes for fast and secure lookups
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_docs_owner ON documents(owner_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_perms_doc_user ON document_permissions(document_id, user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_doc ON audit_logs(document_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs(actor_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_seq ON audit_logs(sequence_number)")
                # 5. Audit hash version migration
        audit_columns = {
            row["name"]
            for row in cursor.execute("PRAGMA table_info(audit_logs)").fetchall()
        }

        if "hash_version" not in audit_columns:
            cursor.execute("""
                ALTER TABLE audit_logs
                ADD COLUMN hash_version INTEGER NOT NULL DEFAULT 1
            """)
