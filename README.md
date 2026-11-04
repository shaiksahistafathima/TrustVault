# TrustVault — Secure Document Sharing with a Tamper-Evident Audit Trail

> **RISE Assessment Submission**  
> Built for server-side document access control, auditable activity, and immediate permission revocation on subsequent requests.

---

## Local Demo Accounts for Evaluators

Demo accounts are created locally by running `python seed.py`. These credentials are for local evaluation only. Never use the demo accounts in production.

| Role | Email Address | Password | Permissions & Scope |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin@trustvault.local` | `AdminSecure2026!` | Views system-wide audit telemetry, verifies cryptographic hash chain integrity, and can instantly suspend rogue accounts. |
| **Document Owner** | `owner@trustvault.local` | `OwnerSecure2026!` | Uploads documents, manages metadata, grants named `READ`/`EDIT` permissions, and revokes access instantly. |
| **Viewer** | `viewer@trustvault.local` | `ViewerSecure2026!` | Granted `READ` access to `Master_Services_Agreement.pdf`. Has zero access to unshared files. |
| **Outsider** | `outsider@trustvault.local` | `OutsiderSecure2026!` | Zero permissions granted. Used to demonstrate that unauthorized access attempts are blocked and logged. |

---

## 🏛️ Architecture & Three Core Invariants

```
               [ User Request ]
                      │
                      ▼
         ┌────────────────────────┐
         │ Session Authentication │
         └────────────┬───────────┘
                      │
                      ▼
     ┌─────────────────────────────────┐
     │  Live Database ACL Verification │  ◄── Real-time permissions
     │    (get_document_with_auth)     │      Zero pre-signed URLs
     └────────┬───────────────┬────────┘
              │               │
     [Granted / 200]    [Denied / 403]
              │               │
              ▼               ▼
     ┌─────────────────────────────────┐
     │  Cryptographic Audit Append     │  ◄── SHA-256 Hash Chain
     │ (Upload, Download, Denied 403)  │      Tamper-evident
     └────────┬────────────────────────┘
              │
              ▼
   [ Stream Isolated File Bytes ]
   (storage/{doc_uuid}.{ext})
```

### Invariant 1: A document is reachable only by someone who was granted it
- Document files never have public HTTP URLs. They are stored outside the web root (`storage/`) under UUID filenames.
- Every read, view, or download request is mediated by `get_document_with_auth()` which validates the caller against the live database.

### Invariant 2: You can prove who reached it (Tamper-Evident)
- Every action (upload, download, edit, grant, revoke) is logged to `audit_logs`.
- **Blocked breach attempts (`403 Forbidden`) are logged with equal priority** including caller identity, target document, IP address, and timestamp.
- Each audit log row hashes its predecessor:
  $$\text{row\_hash} = \text{SHA256}(\text{SEQ} \parallel \text{ID} \parallel \text{TS} \parallel \text{ACTOR} \parallel \text{ACTION} \parallel \text{DOC} \parallel \text{STATUS} \parallel \text{IP} \parallel \text{DETAILS} \parallel \text{prev\_hash})$$
- The administrator can verify the entire chain from Genesis to Head at any time via `/admin/audit/verify`.

### Invariant 3: Taking access away works immediately
- Zero static pre-signed S3 links with expiration windows.
- Access is checked dynamically on every byte transfer. As soon as an owner revokes permission or an admin suspends a user, the very next HTTP request fails with `403 Forbidden`.

---

## 🚀 Setup & Local Execution (Clean Clone)

### Prerequisites
- Python 3.10+

### Quick Start
```bash
# 1. Clone the repository
git clone https://github.com/your-username/trustvault.git
cd trustvault

# 2. Install dependencies
python -m pip install -r requirements.txt

# 3. Run database seed script
python seed.py

# 4. Start the application
python run.py
```
Open **http://127.0.0.1:5000** in your browser.

---

## 🧪 Automated Security Test Suite

The test suite contains **21 automated tests** covering access control, audit integrity, CSRF protection, upload validation, and permission revocation:

```bash
python -m unittest discover -s tests
```

### What the tests prove:
1. `tests/test_security_authz.py`:
   - An outsider cannot download confidential documents (`403 Forbidden`).
   - The refused attempt is permanently written to the audit trail with `status='DENIED'`.
   - A viewer can download shared documents, but receives `403` for unshared files.
   - Anonymous requests are rejected (`401`).
2. `tests/test_instant_revocation.py`:
   - Owner revokes Viewer access -> Viewer's subsequent download fails immediately (`403`).
   - Admin suspends Viewer account -> Viewer's active session is rejected immediately.
3. `tests/test_audit_integrity.py`:
   - Simulates SQL injection altering an audit row -> `verify_audit_chain()` detects tampering and flags the sequence.
   - Simulates deleting an audit row -> sequence break is detected.
4. `tests/test_upload_validation.py`:
   - Executable files renamed to `.pdf` (MIME spoofing) are rejected via magic-byte inspection.
   - Null bytes in text files are rejected.

---

## 📖 API Documentation & Authorization Matrix

| Endpoint | Method | Allowed Caller | Description | Audit Event Logged |
| :--- | :---: | :--- | :--- | :--- |
| `/login` | `POST` | Public | Authenticates user and issues secure HTTP-only session cookie. | `USER_LOGIN_SUCCESS` / `USER_LOGIN_FAILED` |
| `/logout` | `POST` | Authenticated | Clears user session. | `USER_LOGOUT` |
| `/` | `GET` | Authenticated | Lists only documents owned by or shared with the caller. | None |
| `/upload` | `POST` | `OWNER`, `ADMIN` | Validates magic bytes, computes SHA-256 hash, and saves file. | `DOCUMENT_UPLOAD` / `MALICIOUS_UPLOAD_BLOCKED` |
| `/documents/<id>` | `GET` | Document Owner or Authorized (`READ`/`EDIT`) | Inspects document metadata, active permissions, and file-specific audit log. | `DOCUMENT_VIEW` (or `ACCESS_DENIED`) |
| `/documents/<id>/download` | `GET` | Document Owner or Authorized (`READ`/`EDIT`) | Streams file bytes with live permission verification. | `DOCUMENT_DOWNLOAD` (or `UNAUTHORIZED_DOCUMENT_ACCESS_ATTEMPT`) |
| `/documents/<id>/share` | `POST` | Document Owner only | Grants `READ` or `EDIT` permission to a named user email. | `GRANT_PERMISSION` |
| `/documents/<id>/revoke/<userId>` | `POST` | Document Owner only | Instantly revokes named user access from database. | `REVOKE_PERMISSION` |
| `/documents/<id>/edit` | `POST` | Document Owner or `EDIT` | Modifies document title, category, or notes. | `DOCUMENT_METADATA_EDIT` |
| `/documents/<id>/delete` | `POST` | Document Owner only | Soft-deletes document (`is_deleted = 1`). | `DOCUMENT_DELETE` |
| `/search` | `GET` | Authenticated | Filters accessible documents by keyword, owner, category, date. | None (SQL-isolated) |
| `/admin/audit` | `GET` | `ADMIN` only | Views system-wide audit telemetry and blocked attacks. | None |
| `/admin/audit/verify` | `GET`/`POST`| `ADMIN` only | Executes cryptographic verification of the SHA-256 hash chain. | `CRYPTOGRAPHIC_AUDIT_CHAIN_VERIFIED` |
| `/admin/users/<id>/toggle-active` | `POST` | `ADMIN` only | Instantly suspends or reactivates a user account. | `ACCOUNT_DEACTIVATED` / `ACCOUNT_REACTIVATED` |

---

## 📝 Architectural Write-Up (Submission Deliverable)

### 1. What was built
- Multi-role RBAC (`ADMIN`, `OWNER`, `VIEWER`) and per-document ACL (`READ`, `EDIT`).
- Isolated document storage with magic-byte verification and zero public HTTP URLs.
- Server-mediated streaming download engine with synchronous live database verification.
- Tamper-evident, append-only SHA-256 hash chain recording both successful and denied (`403`) events.
- Administrative security telemetry and automated cryptographic verification interface.

### 2. What was deliberately NOT built (and why)
- **Pre-signed Cloud URLs (e.g. S3 Pre-signed)**: Deliberately avoided because pre-signed URLs cannot be revoked until their TTL expires (typically 15-60 minutes). Server-mediated streaming guarantees instant revocation.
- **Client-side permission filtering**: Deliberately avoided. The server never returns metadata of unauthorized files to the frontend.
- **In-place Audit Edits**: The database schema contains zero `UPDATE` or `DELETE` endpoints for audit records; the table is strictly append-only.

### 3. How AI was used and where it was wrong
- AI was used for rapid prototyping of route structures and HTML layouts.
- As documented in `PROMPTS.md`, AI repeatedly suggested insecure patterns:
  1. Generating 15-minute S3 URLs (which violates instant revocation).
  2. Omitting audit logging for 403 Forbidden attempts (which hides reconnaissance attacks).
  3. Filtering search results in Python memory instead of SQL (which leaks metadata).
  4. Relying on file extensions rather than magic bytes (which permits executable uploads).
- Catching and correcting these mistakes was central to ensuring enterprise-grade defense.

### 4. Known Gaps & Future Enhancements
- **Dynamic Watermarking**: To deter authorized viewers from photographing their screens, an image/PDF rendering pipeline with dynamic user-email watermarks can be added.
- **Rate-Limiting**: Adding Redis-based sliding window rate limits for `/login` in production to prevent audit table bloat from brute-force scripts.
