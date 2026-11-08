# TrustVault — Secure Document Sharing with a Tamper-Evident Audit Trail

> **RISE Assessment Submission**  
> Built for server-side document access control, auditable activity, and permission revocation on subsequent requests.

---

## Local Demo Accounts for Evaluators

Demo accounts are created locally by running `python seed.py`. These credentials are for local evaluation only. Never use the demo accounts in production.

| Role | Email Address | Password | Permissions & Scope |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin@trustvault.local` | `AdminSecure2026!` | Views system-wide audit telemetry, verifies cryptographic hash chain integrity, and can suspend or reactivate user accounts. |
| **Document Owner** | `owner@trustvault.local` | `OwnerSecure2026!` | Uploads documents, manages metadata, grants named `READ`/`EDIT` permissions, and revokes access for subsequent requests. |
| **Viewer** | `viewer@trustvault.local` | `ViewerSecure2026!` | Granted `READ` access to `Master_Services_Agreement.pdf`. Has zero access to unshared files. |
| **Outsider** | `outsider@trustvault.local` | `OutsiderSecure2026!` | Zero permissions granted. Used to demonstrate that unauthorized access attempts are blocked and logged. |

---

## 🏛️ Architecture & Three Core Invariants

```text
               [ User Request ]
                      |
                      v
         +------------------------+
         | Session Authentication |
         +------------+-----------+
                      |
                      v
     +---------------------------------+
     |  Live Database ACL Verification |
     |    (get_document_with_auth)     |
     |      Zero pre-signed URLs       |
     +----------+----------------------+
                |
         +------+------+
         |             |
    [Granted]      [Denied]
         |             |
         v             v
     +---------------------------------+
     |  Cryptographic Audit Append     |
     |  Upload, Download, Denied 403   |
     |       SHA-256 Hash Chain        |
     +----------------+----------------+
                      |
                      v
           [ Stream Isolated File Bytes ]
           (storage/{doc_uuid}.{ext})
```

### Invariant 1: A document is reachable only by someone who was granted it

- Document files never have public HTTP URLs. They are stored outside the web root (`storage/`) under UUID filenames.
- Every document access request is mediated by `get_document_with_auth()`, which validates the caller against the live database.

### Invariant 2: You can prove who reached it (Tamper-Evident)

- Every action (upload, download, edit, grant, revoke) is logged to `audit_logs`.
- **Denied document access attempts are logged** with the caller identity (when authenticated), target document, IP address, and timestamp. Authenticated users without permission receive `403 Forbidden`; unauthenticated requests receive `401 Unauthorized`; missing or soft-deleted documents receive `404 Not Found`.
- Each audit log row hashes its predecessor.

  New Version 2 audit records use a canonical JSON payload containing `sequence_number`, `id`, `timestamp`, `actor_id`, `actor_email`, `action`, `document_id`, `status`, `ip_address`, `user_agent`, `details`, and `prev_hash`. The JSON is serialized with sorted keys and compact separators, then hashed with SHA-256. Version 1 records remain supported for backward compatibility.
- The administrator can verify the entire chain from Genesis to Head via `/admin/audit/verify`.

### Invariant 3: Revoked access is denied on subsequent requests

- No static pre-signed S3 links with expiration windows are used.
- Authorization is checked against the live database on each new download request before streaming begins. After permission is revoked or an account is suspended, subsequent requests are denied. A download already in progress is not guaranteed to be interrupted.

---

## 🚀 Setup & Local Execution (Clean Clone)

### Prerequisites

- Python 3.10+
- Git

### Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/shaiksahistafathima/TrustVault.git
cd TrustVault

# 2. Create a virtual environment
python -m venv .venv

# 3. Activate the virtual environment

# Windows PowerShell
.\.venv\Scripts\Activate.ps1

# macOS / Linux
source .venv/bin/activate

# 4. Install dependencies
python -m pip install -r requirements.txt

# 5. Initialize the database with local demo accounts
python seed.py

# 6. Start the application
python run.py
```

Open **http://127.0.0.1:5000** in your browser.

**Note:** Public registration is also available through the `/register` page. Newly registered accounts receive the `VIEWER` role. Administrators can create additional evaluator accounts through the Users page.

---

## 🧪 Automated Security Test Suite

The test suite contains **40 automated tests** covering access control, audit integrity, CSRF protection, upload validation, and permission revocation.

Run the tests using:

```bash
python -m unittest discover -s tests -v
```

### What the tests prove

1. `tests/test_security_authz.py`:
   - An outsider cannot download confidential documents (`403 Forbidden`).
   - The refused attempt is recorded in the audit trail with `status='DENIED'`.
   - A viewer can download shared documents, but receives `403` for unshared files.
   - Anonymous requests are denied or redirected to the login page, depending on the route.

2. `tests/test_instant_revocation.py`:
   - Owner revokes Viewer access → Viewer's subsequent download request is denied (`403`).
   - Admin suspends Viewer account → Viewer's subsequent authenticated request is rejected.

3. `tests/test_audit_integrity.py`:
   - Simulates modification of an audit row → `verify_audit_chain()` detects tampering and flags the sequence.
   - Simulates deleting an audit row → sequence break is detected.

4. `tests/test_upload_validation.py`:
   - Executable files renamed to `.pdf` (MIME spoofing) are rejected via magic-byte inspection.
   - Null bytes in text files are rejected.

---

## 📖 API Documentation & Authorization Matrix

| Endpoint | Method | Allowed Caller | Description | Audit Event Logged |
| :--- | :---: | :--- | :--- | :--- |
| `/login` | `GET` / `POST` | Public | Displays the login form and authenticates users. | `USER_LOGIN_SUCCESS` / `USER_LOGIN_FAILED` |
| `/register` | `GET` / `POST` | Public | Allows visitors to create an account with the `VIEWER` role. | `USER_REGISTERED` |
| `/logout` | `POST` | Authenticated | Clears the user session. | `USER_LOGOUT` |
| `/` | `GET` | Authenticated | Lists documents owned by or shared with the caller. | None |
| `/upload` | `GET` / `POST` | `OWNER`, `ADMIN` | Displays the upload form; validates and stores uploaded files. | `DOCUMENT_UPLOAD` / `MALICIOUS_UPLOAD_BLOCKED` |
| `/documents/<id>` | `GET` | Document Owner or authorized `READ` / `EDIT` user | Displays document details. Only the owner sees permissions and document audit history. | No direct view event |
| `/documents/<id>/download` | `GET` | Document Owner or authorized `READ` / `EDIT` user | Checks live permission before streaming the file. | `DOCUMENT_DOWNLOAD` / `UNAUTHORIZED_DOCUMENT_ACCESS_ATTEMPT` / `FILE_MISSING_ON_DISK` |
| `/documents/<id>/share` | `POST` | Document Owner only | Grants `READ` or `EDIT` permission to a named user. | `GRANT_PERMISSION` |
| `/documents/<id>/revoke/<userId>` | `POST` | Document Owner only | Revokes a user's permission; subsequent requests are denied. | `REVOKE_PERMISSION` |
| `/documents/<id>/edit` | `POST` | Document Owner or authorized `EDIT` user | Modifies document title, category, or notes. | `DOCUMENT_METADATA_EDIT` |
| `/documents/<id>/delete` | `POST` | Document Owner only | Soft-deletes the document (`is_deleted = 1`). | `DOCUMENT_DELETE` |
| `/search` | `GET` | Authenticated | Searches documents accessible to the caller. | None |
| `/admin/audit` | `GET` | `ADMIN` only | Displays system-wide audit records. | None |
| `/admin/audit/verify` | `GET` / `POST` | `ADMIN` only | Verifies the audit hash chain. | `CRYPTOGRAPHIC_AUDIT_CHAIN_VERIFIED` |
| `/admin/users` | `GET` | `ADMIN` only | Displays user accounts, roles, and active status. | None |
| `/admin/users/create` | `POST` | `ADMIN` only | Creates an evaluator or other permitted user account with an assigned role. | `USER_CREATED_BY_ADMIN` |
| `/admin/users/<id>/toggle-active` | `POST` | `ADMIN` only | Suspends or reactivates an account; subsequent requests reflect its status. | `ACCOUNT_DEACTIVATED` / `ACCOUNT_REACTIVATED` |

---

## 📝 Architectural Write-Up (Submission Deliverable)

### 1. What was built

- Multi-role RBAC (`ADMIN`, `OWNER`, `VIEWER`) and per-document ACL (`READ`, `EDIT`).
- Isolated document storage with magic-byte verification and zero public HTTP URLs.
- Server-mediated streaming download engine with synchronous live database verification.
- Tamper-evident SHA-256 hash chain recording successful actions and recorded denied attempts.
- Administrative security telemetry and automated cryptographic verification interface.
- Public account registration with the `VIEWER` role and Admin-managed account creation.

### 2. What was deliberately NOT built (and why)

- **Pre-signed Cloud URLs (e.g. S3 Pre-signed):** Deliberately avoided because pre-signed URLs cannot be revoked until their TTL expires (typically 15–60 minutes). Server-mediated downloads allow permissions to be checked on each new request. A download already in progress is not guaranteed to be interrupted.
- **Client-side permission filtering:** Deliberately avoided. The server never returns metadata of unauthorized files to the frontend.
- **In-place Audit Edits:** The application provides no normal route to update or delete audit records. The hash chain makes changes to recorded entries detectable, but it does not make the database physically immutable. Direct database access or deletion of the latest records may evade detection without an independently stored checkpoint.

### 3. How AI was used and reviewed

- AI assistance was used during project planning, implementation guidance, code development, and documentation.
- The development record in `PROMPTS.md` summarizes six genuine project interactions and links them to the corresponding commits.
- Subsequent review identified areas that needed correction or more precise treatment:
  1. Automatic demo-account seeding was removed from the production startup command.
  2. Security documentation was revised to avoid describing a hash chain as tamper-proof or request-based revocation as unconditional instant revocation.
  3. The repository clone URL in the README was corrected.
  4. Inline login-page JavaScript was moved to an external file when the Content Security Policy was tightened.
  5. Audit-chain documentation was clarified to explain that a hash chain alone cannot reliably detect deletion of the latest records without an independently retained checkpoint.
- These are documented development and review outcomes. They should not be interpreted as proof that AI originally proposed each insecure implementation.

### 4. Known Gaps & Future Enhancements

- **Dynamic Watermarking:** To deter authorized viewers from photographing their screens, an image/PDF rendering pipeline with dynamic user-email watermarks can be added.
- **Rate-Limiting:** Adding Redis-based sliding window rate limits for `/login` in production to prevent audit table bloat from brute-force scripts.
- **Deployment Persistence (Render Free Tier):** The free service may spin down after inactivity. Without a separately configured persistent disk and production database, uploaded files and SQLite data on the instance filesystem may be lost during restarts or redeployments. The free demo deployment should not be used for permanent document storage.
