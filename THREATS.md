# TrustVault — Threat Model & Security Posture (THREATS.md)

## Executive Summary
TrustVault is built on three foundational invariants:
1. **Zero Unauthenticated/Unauthorized Reachability**: A document is accessible strictly by an entity with an active, explicit database-backed grant.
2. **Non-Repudiable, Tamper-Evident Auditability**: Every access attempt (including refused/denied breaches) is permanently recorded in a SHA-256 cryptographic hash chain.
3. **Deterministic Instant Revocation**: Taking access away severs reachability on the very next HTTP request; no cached grants or persistent signed URLs can outlive revocation.

This document details the threat analysis using the **STRIDE** methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege), the architectural mitigations implemented, automated test coverage, and knowingly accepted risks.

---

## Threat Matrix & Mitigation Catalog

| Threat ID | Category | Attack Vector | Potential Impact | Implemented Mitigation | Verification Test |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **THREAT-01** | Elevation of Privilege | **IDOR (Insecure Direct Object Reference)**: Attacker iterates document IDs (`/documents/<uuid>/download`) to read other users' files. | Critical data leak | Server-side `get_document_with_auth()` performs a live database ACL check on every single request. Predictable auto-increment IDs are replaced with cryptographic UUIDv4. | `test_01_unauthorized_user_cannot_download_confidential_document` |
| **THREAT-02** | Repudiation | **Silent Probing**: Attacker probes unauthorized files, but server returns 403 without recording who probed it. | Inability to prove insider breach or reconnaissance | Denied attempts (`403 Forbidden`) trigger an immutable audit event (`UNAUTHORIZED_DOCUMENT_ACCESS_ATTEMPT`) recording the actor, IP, timestamp, and target document. | `test_02_denied_attempt_is_permanently_logged_in_audit_trail` |
| **THREAT-03** | Tampering | **Audit Record Alteration**: A rogue database operator or SQL injection modifies or deletes audit logs to cover tracks. | Destruction of legal/compliance evidence | **Cryptographic Hash Chaining**: Every log row incorporates `SHA-256(prev_hash + seq + timestamp + actor + action + doc + status + details)`. Modifying any byte invalidates the chain. | `test_02_detects_data_tampering_in_audit_record` |
| **THREAT-04** | Tampering | **Log Sequence Deletion**: Attacker deletes specific log rows (e.g., row #2) to eliminate breach evidence. | Tampering goes unnoticed | Verification engine validates strict arithmetic continuity `seq == idx + 1`. Deleted rows cause an immediate sequence-break failure. | `test_03_detects_row_deletion_attempt` |
| **THREAT-05** | Information Disclosure | **Direct Storage Link Bypass**: Files stored in public static folders (e.g. `/uploads/contract.pdf`) reachable via web server bypass. | Full repository exposure | Files are stored outside the web root (`storage/`) using UUID filenames (`uuid.ext`). No direct HTTP routes exist; files are exclusively served through authenticated server-side streams. | `test_05_unauthenticated_requests_are_rejected` |
| **THREAT-06** | Elevation of Privilege | **Stale Grant / Delayed Revocation**: Attacker retains an active session or a pre-signed URL (e.g., 15-minute S3 URL) after access is revoked. | Unauthorized download post-revocation | Zero static pre-signed URLs. Database permissions are evaluated synchronously during the streaming request. Revoking a permission or suspending a user cuts off access in milliseconds. | `test_instant_permission_revocation`, `test_instant_account_suspension` |
| **THREAT-07** | Tampering / Exploitation | **MIME / File Extension Spoofing**: Attacker renames malicious executable (`malware.exe`) to `invoice.pdf` or uploads polyglot HTML files. | Remote Code Execution or Stored XSS | File signature (magic bytes) validation inspects initial byte headers (`%PDF-`, `\x89PNG`, `PK\x03\x04`). Binary null bytes in plain text/CSV trigger instant rejection. | `test_spoofed_executable_rejected`, `test_null_byte_in_text_file_rejected` |
| **THREAT-08** | Tampering | **Path Traversal on Upload**: Filename containing `../../etc/passwd` overwrites system files. | Host system compromise | User filenames are sanitized using `secure_filename()` for display, and stored physically using an independent random `uuid.uuid4()` identifier. | Architecture invariant |
| **THREAT-09** | Information Disclosure | **Search Engine Metadata Leakage**: Unauthorized user searches for words like "salary" and sees filenames/owners they are not allowed to view. | Confidential metadata leakage | Document search executes SQL queries with strict permission predicates (`d.owner_id = ? OR p.user_id = ?`). Non-permitted files are filtered at the database level, not in application memory. | `docs.search` SQL predicate check |
| **THREAT-10** | Elevation of Privilege | **Viewer Granting Access**: A Viewer attempts to POST to `/documents/<id>/share` to grant access to an accomplice. | Unauthorized privilege delegation | `grant_permission` strictly validates that the requesting user has `permission_level == 'OWNER'`. Viewers receive 403 and an audit alert. | `grant_permission` access check |
| **THREAT-11** | Denial of Service | **Storage Exhaustion (Zip/File Bombs)**: Attacker uploads 5GB files to exhaust disk space and take down the server. | Service downtime | Strict `MAX_CONTENT_LENGTH = 16MB` enforced by web server and reverse proxy. Excess payloads are rejected before disk buffering. | `Config.MAX_CONTENT_LENGTH` |
| **THREAT-12** | Information Disclosure | **Soft-Delete Exfiltration**: Deleted documents remain reachable if queried directly by ID. | Access to retired/destroyed documents | All queries filter `WHERE is_deleted = 0`. Attempting to read a soft-deleted document returns 404 and logs the attempt. | `get_document_with_auth` check |
| **THREAT-13** | Spoofing / Session Hijacking | **Session Cookie Interception**: Attacker steals session cookies via XSS or packet sniffing. | Account impersonation | Session cookies configured with `HttpOnly = True`, `SameSite = 'Lax'`, strict CSP (`Content-Security-Policy`), and `X-Frame-Options: DENY`. | `app/__init__.py` header middleware |
| **THREAT-14** | Information Disclosure | **Admin Document Snooping**: Superuser reads confidential documents without explicit grants. | Separation-of-duties violation | Administrators do not have blanket read access to document contents. Admin role governs audit logs, cryptographic verification, and account deactivation. Emergency access generates high-priority audit alerts. | `get_document_with_auth` enforcement |

---

## Detailed Threat Deep Dives

### 1. Insecure Direct Object References (IDOR) & Zero-Knowledge Enumeration
* **Vector**: Attackers often probe integer IDs (`/documents/1`, `/documents/2`) to discover documents. Even with 128-bit UUIDs, an attacker who obtains a UUID (from an email or shoulder surfing) must not be able to fetch the file.
* **Defense**: `get_document_with_auth()` operates as the **single authorization choke point**. It queries the document and the caller's specific permission record in a single transaction. If the caller is not the owner and has no active permission row, access is denied immediately.
* **Test Case**: `test_01_unauthorized_user_cannot_download_confidential_document` verifies that `outsider@trustvault.local` cannot download `Executive_Salary_2026.pdf` even when supplying the exact UUID.

### 2. Immediate Revocation vs. Pre-Signed S3 URLs
* **Vector**: Many platforms generate AWS S3 pre-signed URLs with a 15-minute or 1-hour expiration. If an owner revokes access at 12:01 PM, the user can continue downloading the file using their pre-signed URL until 12:16 PM.
* **Defense**: TrustVault **deliberately avoids static pre-signed URLs**. Every download request is mediated by the application server. Access validity is evaluated against the database at the precise moment of download.
* **Test Case**: `test_instant_permission_revocation` verifies that within milliseconds of an owner clicking "Revoke", the user's subsequent download request is blocked with `403 Forbidden`.

### 3. Cryptographic Hash Chain for Audit Immutability
* **Vector**: A compromised database account or rogue insider runs `UPDATE audit_logs SET details = ...` or `DELETE FROM audit_logs WHERE action = 'UNAUTHORIZED_DOCUMENT_ACCESS_ATTEMPT'`.
* **Defense**: Each audit row calculates:
  $$\text{row\_hash} = \text{SHA256}(\text{SEQ} \parallel \text{ID} \parallel \text{TS} \parallel \text{ACTOR} \parallel \text{ACTION} \parallel \text{DOC} \parallel \text{STATUS} \parallel \text{IP} \parallel \text{DETAILS} \parallel \text{prev\_hash})$$
  Modifying any record alters its `row_hash`, causing a mismatch with the `prev_hash` of the next block. Deleting a row causes a sequence number discontinuity ($seq \ne idx + 1$).
* **Test Case**: `test_02_detects_data_tampering_in_audit_record` alters row #2 and proves that `verify_audit_chain()` immediately halts, pinpoints sequence #2, and flags data tampering.

---

## Knowingly Accepted Risks & Justifications

1. **Host-Level / Kernel Memory Dumping**:
   * *Risk*: An attacker with root/SYSTEM access to the physical host can attach a debugger (`gdb` / `WinDbg`) to the Python process and extract session keys or file buffers from RAM.
   * *Justification*: Accepted. Protecting process memory against a compromised host kernel is out of scope for application-layer software; host OS isolation, whole-disk encryption (BitLocker/LUKS), and hypervisor security must protect this boundary.

2. **Client-Side Display Capture / Shoulder Surfing**:
   * *Risk*: An authorized viewer who downloads a confidential contract can take a screenshot, print it to PDF, or photograph their monitor with a smartphone.
   * *Justification*: Accepted. Application-layer access controls govern *data delivery and reachability*, not physical display capture. To mitigate this without custom DRM software, future iterations could overlay dynamic watermarks (viewer email + timestamp) across rendered previews.

3. **Denial of Service via High-Rate Failed Login Attempts**:
   * *Risk*: An external attacker could spam `/login` with invalid credentials, generating thousands of `USER_LOGIN_FAILED` audit events and bloating the audit database.
   * *Justification*: Accepted for development tier; production deployment requires reverse-proxy rate limiting (e.g. Nginx `limit_req` or Cloudflare WAF) to throttle IP addresses exceeding 10 failed requests per minute.
