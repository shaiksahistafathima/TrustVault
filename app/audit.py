
import hashlib
import json
import uuid
from datetime import datetime, timezone

from app.database import get_db

GENESIS_PREV_HASH = "0" * 64


def compute_row_hash(
    seq, log_id, timestamp, actor_id, action,
    doc_id, status, ip, details, prev_hash
):
    """Version 1 hash: preserves compatibility with existing records."""
    canonical_payload = (
        f"SEQ:{seq}|ID:{log_id}|TS:{timestamp}|ACTOR:{actor_id or 'ANON'}|"
        f"ACTION:{action}|DOC:{doc_id or 'NONE'}|STATUS:{status}|IP:{ip}|"
        f"DETAILS:{details or ''}|PREV:{prev_hash}"
    )
    return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()


def compute_row_hash_v2(
    seq, log_id, timestamp, actor_id, actor_email,
    action, doc_id, status, ip, user_agent, details, prev_hash
):
    """Version 2 hash: also protects actor email and user agent."""
    payload = {
        "sequence_number": seq,
        "id": log_id,
        "timestamp": timestamp,
        "actor_id": actor_id or "",
        "actor_email": actor_email or "",
        "action": action,
        "document_id": doc_id or "",
        "status": status,
        "ip_address": ip,
        "user_agent": user_agent or "",
        "details": details or "",
        "prev_hash": prev_hash
    }

    canonical_payload = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    )

    return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()


def log_audit_event(
    action, status, actor_id=None, actor_email=None,
    document_id=None, ip_address="127.0.0.1",
    user_agent="Unknown", details=None
):
    """Append a Version 2 tamper-evident audit event."""

    log_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    details_str = json.dumps(details or {}, sort_keys=True)

    with get_db() as conn:
        # Acquire the SQLite write lock before reading the latest sequence.
        conn.execute("BEGIN IMMEDIATE")

        cursor = conn.cursor()

        cursor.execute("""
            SELECT sequence_number, row_hash
            FROM audit_logs
            ORDER BY sequence_number DESC
            LIMIT 1
        """)

        last_row = cursor.fetchone()

        if last_row:
            next_seq = last_row["sequence_number"] + 1
            prev_hash = last_row["row_hash"]
        else:
            next_seq = 1
            prev_hash = GENESIS_PREV_HASH

        hash_version = 2

        row_hash = compute_row_hash_v2(
            seq=next_seq,
            log_id=log_id,
            timestamp=timestamp,
            actor_id=actor_id,
            actor_email=actor_email,
            action=action,
            doc_id=document_id,
            status=status,
            ip=ip_address,
            user_agent=user_agent,
            details=details_str,
            prev_hash=prev_hash
        )

        cursor.execute("""
            INSERT INTO audit_logs (
                sequence_number, id, timestamp, actor_id, actor_email,
                action, document_id, status, ip_address, user_agent,
                details, prev_hash, row_hash, hash_version
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            next_seq, log_id, timestamp, actor_id, actor_email,
            action, document_id, status, ip_address, user_agent,
            details_str, prev_hash, row_hash, hash_version
        ))

    return log_id


def verify_audit_chain():
    """
    Verify the complete chain using each record's hash version.
    Version 1 records retain their original verification algorithm.
    Version 2 records protect every recorded field.
    """

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT *
            FROM audit_logs
            ORDER BY sequence_number ASC
        """)
        rows = cursor.fetchall()

    if not rows:
        return {
            "valid": True,
            "total_records": 0,
            "message": "Audit log is empty."
        }

    expected_prev_hash = GENESIS_PREV_HASH

    for idx, row in enumerate(rows):
        seq = row["sequence_number"]
        version = row["hash_version"]

        if seq != idx + 1:
            return {
                "valid": False,
                "broken_at_sequence": seq,
                "reason": (
                    f"Sequence break: expected {idx + 1}, "
                    f"found {seq}."
                )
            }

        if row["prev_hash"] != expected_prev_hash:
            return {
                "valid": False,
                "broken_at_sequence": seq,
                "reason": f"Chain link severed at sequence {seq}."
            }

        if version == 1:
            recalculated_hash = compute_row_hash(
                seq=seq,
                log_id=row["id"],
                timestamp=row["timestamp"],
                actor_id=row["actor_id"] or "",
                action=row["action"],
                doc_id=row["document_id"] or "",
                status=row["status"],
                ip=row["ip_address"],
                details=row["details"],
                prev_hash=row["prev_hash"]
            )

        elif version == 2:
            recalculated_hash = compute_row_hash_v2(
                seq=seq,
                log_id=row["id"],
                timestamp=row["timestamp"],
                actor_id=row["actor_id"],
                actor_email=row["actor_email"],
                action=row["action"],
                doc_id=row["document_id"],
                status=row["status"],
                ip=row["ip_address"],
                user_agent=row["user_agent"],
                details=row["details"],
                prev_hash=row["prev_hash"]
            )

        else:
            return {
                "valid": False,
                "broken_at_sequence": seq,
                "reason": f"Unsupported hash version {version}."
            }

        if recalculated_hash != row["row_hash"]:
            return {
                "valid": False,
                "broken_at_sequence": seq,
                "reason": (
                    f"Tampering detected at sequence {seq}."
                )
            }

        expected_prev_hash = row["row_hash"]

    return {
        "valid": True,
        "total_records": len(rows),
        "latest_hash": expected_prev_hash,
        "message": (
            f"Integrity verified across {len(rows)} audit records."
        )
    }
