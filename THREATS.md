# TrustVault — Threat Model & Security Posture

## Executive Summary

TrustVault is built on three foundational security principles:

1. **Server-Side Access Control:** Documents are accessible only to authenticated users who own the document or have an active, explicit database-backed permission grant.

2. **Tamper-Evident Audit Trail:** Document access attempts, including denied attempts, are recorded in a SHA-256 hash-chained audit log. The chain helps detect unauthorized modification and certain forms of deletion, but does not guarantee absolute immutability or non-repudiation.

3. **Revocation on Subsequent Requests:** Every document access request checks the current database permissions. After a permission is revoked, subsequent requests are denied. An already-running download may not be interrupted.

This document details the threat analysis using the **STRIDE** methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege), the architectural mitigations implemented, automated test coverage, and knowingly accepted risks.

---

## Threat Matrix & Mitigation Catalog

| Threat ID | Category | Attack Vector | Potential Impact | Implemented Mitigation | Verification Test |
|---|---|---|---|---|---|
| **THREAT-01** | Elevation of Privilege | **IDOR (Insecure Direct Object Reference):** An attacker iterates document IDs (`/documents/<uuid>/download`) to read other users' files. | Critical data leak | Server-side `get_document_with_auth()` performs a database-backed access-control check on document requests. Cryptographic UUIDv4 identifiers make enumeration harder but do not replace authorization checks. | `test_01_unauthorized_user_cannot_download_confidential_document` |
| **THREAT-02** | Repudiation | **Silent Probing:** An attacker probes unauthorized files, but the server returns 403 without recording who probed them. | Reduced ability to investigate unauthorized access attempts | Denied attempts (`403 Forbidden`) trigger a tamper-evident audit event (`UNAUTHORIZED_DOCUMENT_ACCESS_ATTEMPT`) recording the actor, IP address, timestamp, and target document where available. | `test_02_denied_attempt_is_permanently_logged_in_audit_trail` |
| **THREAT-03** | Tampering | **Audit Record Alteration:** A rogue database operator or SQL injection modifies audit logs to cover tracks. | Unauthorized modification of audit evidence | **Versioned Cryptographic Hash Chaining:** Version 1 records use a SHA-256 hash of a formatted text payload. Version 2 records use SHA-256 over canonical JSON containing the sequence number, record ID, timestamp, actor ID, actor email, action, document ID, status, IP address, user agent, details, and previous hash. Verification recalculates each record's hash and checks chain linkage. | `test_02_detects_data_tampering_in_audit_record` |
| **THREAT-04** | Tampering | **Log Sequence Deletion:** An attacker deletes specific audit rows to eliminate breach evidence. | Tampering with audit history | The verification engine validates sequence continuity (`seq == idx + 1`), previous-hash linkage, and recalculated record hashes. Interior deletions are detected. Trailing deletions may require an external checkpoint to detect reliably. | `test_03_detects_row_deletion_attempt` |
| **THREAT-05** | Information Disclosure | **Direct Storage Link Bypass:** Files stored in public static folders could be reachable without application authorization. | Confidential document exposure | Files are stored outside the web root (`storage/`) using UUID-based filenames. Documents are served through application-controlled authenticated routes rather than public static URLs. | `test_05_unauthenticated_requests_are_rejected` |
| **THREAT-06** | Elevation of Privilege | **Stale Grant / Delayed Revocation:** An attacker retains an active session or previously issued access URL after access is revoked. | Unauthorized access after revocation | TrustVault avoids static pre-signed document URLs. Permission and account status are checked against the database on subsequent document requests. Revocation blocks subsequent requests after the change is committed. An already-running download may not be interrupted. | `test_instant_permission_revocation`, `test_instant_account_suspension` |
| **THREAT-07** | Tampering / Exploitation | **MIME / File Extension Spoofing:** An attacker renames a malicious executable to a permitted extension or uploads potentially unsafe content. | Unsafe file handling or content exposure | File signature validation checks supported file formats. Binary null bytes in plain-text or CSV uploads are rejected. These checks reduce risk but do not establish that every accepted file is harmless. | `test_spoofed_executable_rejected`, `test_null_byte_in_text_file_rejected` |
| **THREAT-08** | Tampering | **Path Traversal on Upload:** A filename containing `../../etc/passwd` attempts to overwrite system files. | Host system compromise | User-supplied filenames are sanitized using `secure_filename()` for display. Files are physically stored using independently generated UUID identifiers rather than user-controlled paths. | Architecture invariant |
| **THREAT-09** | Information Disclosure | **Search Metadata Leakage:** An unauthorized user searches for terms such as "salary" and discovers filenames or owners of restricted documents. | Confidential metadata disclosure | Document search applies database-level ownership and permission predicates so that unauthorized documents are excluded from search results. | `docs.search` SQL predicate check |
| **THREAT-10** | Elevation of Privilege | **Viewer Granting Access:** A Viewer attempts to POST to `/documents/<id>/share` to grant access to another user. | Unauthorized privilege delegation | `grant_permission` validates that the requesting user has `permission_level == 'OWNER'`. Unauthorized requests are rejected. | `grant_permission` access check |
| **THREAT-11** | Denial of Service | **Storage Exhaustion:** An attacker uploads oversized files or resource-intensive content to exhaust disk space. | Service downtime | Flask `MAX_CONTENT_LENGTH` is configured to 16 MB to limit incoming request size. Reverse-proxy request limits and storage quotas must be configured separately in production. | `Config.MAX_CONTENT_LENGTH` |
| **THREAT-12** | Information Disclosure | **Soft-Delete Exfiltration:** Deleted documents remain reachable if queried directly by ID. | Access to retired documents | Document authorization queries exclude soft-deleted records. Attempts to access deleted documents are expected to be rejected. | `get_document_with_auth` check |
| **THREAT-13** | Spoofing / Session Hijacking | **Session Cookie Interception:** An attacker attempts to steal session cookies through XSS or network interception. | Account impersonation | Session cookies are configured with `HttpOnly = True` and `SameSite = 'Lax'`. The application sets security headers including `X-Frame-Options: DENY` and a Content Security Policy. Production deployment must use HTTPS and secure cookie settings. CSP is not a complete XSS defense. | `app/__init__.py` header middleware |
| **THREAT-14** | Information Disclosure | **Admin Document Snooping:** An administrator attempts to read confidential documents without an explicit document permission. | Separation-of-duties violation | The intended authorization design does not grant administrators blanket document-read access. Administrative functions are separated from ordinary document access. Emergency-access claims must be supported by an explicit implementation and audit event before being treated as implemented. | `get_document_with_auth` enforcement |

---

## Detailed Threat Deep Dives

### 1. Insecure Direct Object References (IDOR) & Document Enumeration

**Vector:** Attackers may probe document identifiers to discover documents. UUIDs make guessing more difficult, but an attacker who obtains a valid UUID must still be prevented from accessing the document without authorization.

**Defense:** `get_document_with_auth()` acts as a central authorization check. It evaluates document ownership and the caller's permission record. If the caller is neither the owner nor a user with an active permission grant, access is denied.

**Test Case:** `test_01_unauthorized_user_cannot_download_confidential_document` verifies that `outsider@trustvault.local` cannot download `Executive_Salary_2026.pdf` even when supplying its exact UUID.

### 2. Revocation on Subsequent Requests vs. Pre-Signed URLs

**Vector:** Some platforms generate pre-signed storage URLs that remain usable until expiration. Revoking a user's application permission does not necessarily invalidate an already-issued independent storage URL.

**Defense:** TrustVault avoids static pre-signed document URLs. Document download requests are mediated by the application server, which evaluates the current database permission and account status.

**Limitation:** A permission revocation blocks subsequent requests after the change is committed. It does not necessarily terminate a download that has already started.

**Test Case:** `test_instant_permission_revocation` verifies that after an owner revokes access, the user's subsequent download request is blocked with `403 Forbidden`.

### 3. Cryptographic Hash Chain for Audit Tamper Detection

**Vector:** A compromised database account or rogue insider may attempt to modify or delete audit records, for example:

```sql
UPDATE audit_logs
SET details = 'modified'
WHERE sequence_number = 2;
```

**Defense:** TrustVault uses two versioned SHA-256 hash algorithms.

- **Version 1:** Hashes a formatted text payload containing the sequence number, record ID, timestamp, actor ID, action, document ID, status, IP address, details, and previous hash.
- **Version 2:** Hashes canonical JSON containing the sequence number, record ID, timestamp, actor ID, actor email, action, document ID, status, IP address, user agent, details, and previous hash. JSON keys are sorted, separators are normalized, and UTF-8 encoding is used.

New audit events use Version 2. The verifier retains Version 1 support for existing records.

For each record, `verify_audit_chain()` checks:

1. Sequence continuity (`seq == idx + 1`).
2. Previous-hash linkage.
3. Recalculated hash equality using the record's stored hash version.

**Detection Limitation:** Modifying a protected field or deleting an interior record causes verification failure. However, deleting trailing records may go undetected if the remaining chain is internally valid. An independently stored checkpoint containing the expected final sequence number and hash is needed to detect such rollback reliably.

**Security Classification:** The audit mechanism is tamper-evident, not absolutely immutable. A hash chain alone does not establish non-repudiation or independently prove the identity of the person behind an account.

**Test Case:** `test_02_detects_data_tampering_in_audit_record` verifies that modifying an audit record is detected by the chain verification mechanism.

---

## Knowingly Accepted Risks & Justifications

### 1. Host-Level / Kernel Memory Dumping

**Risk:** An attacker with root or SYSTEM access to the physical host may attach a debugger (`gdb` or `WinDbg`) to the Python process and attempt to extract session keys or file buffers from memory.

**Justification:** Accepted. Protecting process memory against a compromised host kernel is outside the scope of application-layer security. Host OS isolation, whole-disk encryption (BitLocker/LUKS), and hypervisor security must protect this boundary.

### 2. Client-Side Display Capture / Shoulder Surfing

**Risk:** An authorized viewer who downloads a confidential contract can take a screenshot, print it to PDF, or photograph their monitor.

**Justification:** Accepted. Application-layer access controls govern data delivery and reachability, not physical display capture. Future iterations could overlay dynamic watermarks containing the viewer's email and timestamp across rendered previews.

### 3. Denial of Service via High-Rate Failed Login Attempts

**Risk:** An external attacker could repeatedly submit invalid credentials to `/login`, generating many `USER_LOGIN_FAILED` audit events and increasing database usage.

**Justification:** Accepted for the development tier. Production deployment requires authentication rate limiting, such as Nginx `limit_req` or an appropriately configured WAF, together with monitoring and retention controls.

---

## Production Deployment Considerations

The current implementation is a security-focused application prototype and should not be described as production-ready without additional deployment hardening.

Before production deployment:

1. Set a strong, persistent, secret `SECRET_KEY` through environment configuration.
2. Enable HTTPS and secure session cookies.
3. Configure reverse-proxy request-size limits and rate limiting.
4. Establish a secure administrator bootstrap process.
5. Protect database backups and private document storage.
6. Consider independent audit-chain checkpoints stored outside the application database.
7. Configure monitoring, backup recovery, and audit retention policies.
8. Conduct security testing against the deployed environment, including authentication, authorization, upload handling, and session management.

**Final Security Position:** TrustVault demonstrates server-side document authorization, permission revocation on subsequent requests, private file storage, and a versioned tamper-evident audit mechanism. Its security claims are limited to implemented and tested behavior; further hardening is required before production use.
