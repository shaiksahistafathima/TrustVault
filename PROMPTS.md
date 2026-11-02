# AI Interaction Log & Security Audit Record (PROMPTS.md)

This log documents the interaction history with AI assistance during the development of TrustVault. As mandated by the challenge, each dated entry details what was requested, what the AI generated, the specific security vulnerabilities or architectural flaws identified in the AI's output, and the corrective engineering implemented.

---

## Reusable System Context & Security Invariant Prompt

Before running development prompts, the following context instruction was maintained across all prompts to constrain code generation:

```markdown
SYSTEM CONTEXT FOR TRUSTVAULT:
You are building an uncompromising security platform with three non-negotiable invariants:
1. Reachability: A document can never be reached without server-evaluated permission. No direct URLs.
2. Non-repudiation: Audit trail must be immutable, tamper-evident (hash chain), and record DENIED attempts.
3. Instant Revocation: Taking access away must cut off downloads on the very next request. No unrevocable tokens.
Always write code that fails securely. Never filter permissions in memory when SQL filtering is possible.
```

---

## Dated Entry 1: 2026-10-26 — File Download Delivery & Access Revocation

### 1. What was asked
> *"Write a secure file download endpoint for TrustVault. When an authorized user requests a document, generate an AWS S3 pre-signed URL valid for 15 minutes and redirect the user's browser to it."*

### 2. What the AI produced
```python
@app.route("/documents/<doc_id>/download")
@login_required
def download_document(doc_id):
    doc = get_document_by_id(doc_id)
    if not has_permission(current_user.id, doc_id):
        abort(403)
    s3_client = boto3.client('s3')
    presigned_url = s3_client.generate_presigned_url(
        'get_object',
        Params={'Bucket': 'trustvault-bucket', 'Key': doc.storage_key},
        ExpiresIn=900  # 15 minutes
    )
    return redirect(presigned_url)
```

### 3. What was wrong with it (Fatal Security Flaw)
* **Direct Violation of Invariant Three (Instant Revocation)**: Pre-signed URLs are cryptographically signed tokens that the storage service (S3) evaluates independently of our application database.
* Once the pre-signed URL is generated, the user can save the link or share it with external parties. If the document owner clicks **"Revoke Access"** one minute later, the user **can still download the file for the remaining 14 minutes**, because S3 has no knowledge of our application's revocation event!
* Furthermore, once redirected to S3, TrustVault loses the ability to log whether the download actually completed or how many times the URL was fetched.

### 4. What was done instead
* Completely rejected pre-signed storage URLs.
* Implemented **server-mediated streaming** through `send_file()`. Every download request passes synchronously through `get_document_with_auth(document_id, 'READ')`, which queries the live database table `document_permissions` on every single invocation.
* When access is revoked in the database, the very next HTTP request returns `403 Forbidden` within milliseconds.
* See implementation in: `app/routes/doc_routes.py` (`download_document`) and `app/security.py` (`get_document_with_auth`).

---

## Dated Entry 2: 2026-10-27 — Audit Logging for Unauthorized Probes

### 1. What was asked
> *"Create an audit logging helper function that records document access events into an audit_logs table, and wrap our document view/download routes with it."*

### 2. What the AI produced
```python
def log_document_access(user_id, document_id, action):
    db.execute(
        "INSERT INTO audit_logs (user_id, document_id, action, timestamp) VALUES (?, ?, ?, ?)",
        (user_id, document_id, action, datetime.utcnow())
    )

@app.route("/documents/<doc_id>/download")
def download(doc_id):
    if not check_access(current_user.id, doc_id):
        abort(403)
    log_document_access(current_user.id, doc_id, "DOWNLOAD")
    return send_file(...)
```

### 3. What was wrong with it (Fatal Security & Audit Flaw)
* **Missing Audit of Denied Attempts (Silent Probing)**: The AI placed the audit logging function *after* the `abort(403)` check. If an attacker runs an automated script to brute-force document UUIDs or test whether an ex-employee's link still works, the server returns 403, and **zero audit records are written**!
* This fails Invariant Two: *"You can prove who reached it. Afterwards, from the record, including the attempts that were refused."*
* **Mutable Log Table**: The table used a simple `INSERT` without integrity protection. Any administrator or attacker with SQL access could update or delete rows without detection.

### 4. What was done instead
* Refactored `get_document_with_auth()` in `app/security.py` to explicitly log `UNAUTHORIZED_DOCUMENT_ACCESS_ATTEMPT` with `status="DENIED"` inside the authorization failure branch *before* raising `abort(403)`.
* Every denied attempt logs the actor ID, target document ID, IP address, user agent, and failure reason.
* Implemented the **SHA-256 cryptographic hash chain** (`app/audit.py`) so every entry is linked to its predecessor.
* See verification test: `tests/test_security_authz.py` (`test_02_denied_attempt_is_permanently_logged_in_audit_trail`).

---

## Dated Entry 3: 2026-10-28 — Document Search & In-Memory Information Leaks

### 1. What was asked
> *"Implement the search endpoint so users can search documents by title, owner name, category, and date range."*

### 2. What the AI produced
```python
@app.route("/search")
@login_required
def search_documents():
    query = request.args.get("q")
    all_docs = db.execute("SELECT * FROM documents WHERE title LIKE ?", (f"%{query}%",)).fetchall()
    
    # Filter for permissions in Python
    accessible_docs = []
    for doc in all_docs:
        if doc.owner_id == current_user.id or user_has_permission(current_user.id, doc.id):
            accessible_docs.append(doc)
            
    return render_template("search.html", results=accessible_docs)
```

### 3. What was wrong with it (Architectural & Data Exposure Flaw)
* **Data Leakage & In-Memory Vulnerability**: Fetching all documents matching the keyword into application memory (`all_docs`) and then filtering in Python is a severe antipattern.
* If a pagination limit or error occurs during processing, unpermitted records can bleed into response caches or debug dumps.
* Furthermore, an attacker can use timing differences in search responses to infer the existence and quantity of confidential documents they do not own.

### 4. What was done instead
* Pushed permission filtering directly into the SQL engine query using a strict relational join and `WHERE` predicate:
```sql
SELECT DISTINCT d.*, u.full_name as owner_name
FROM documents d
JOIN users u ON d.owner_id = u.id
LEFT JOIN document_permissions p ON d.id = p.document_id AND p.user_id = ?
WHERE d.is_deleted = 0
  AND (d.owner_id = ? OR p.user_id = ?)
  AND (d.title LIKE ? OR d.description LIKE ?)
```
* An unauthorized user cannot even discover the existence of a document title or metadata via search.
* See implementation in: `app/routes/doc_routes.py` (`search`).

---

## Dated Entry 4: 2026-10-29 — File Upload Security & Extension Checking

### 1. What was asked
> *"Write a validation function for uploaded documents that ensures only safe files like PDF, PNG, and DOCX are saved to disk."*

### 2. What the AI produced
```python
ALLOWED_EXTENSIONS = {'pdf', 'png', 'docx', 'xlsx', 'txt'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/upload", methods=["POST"])
def upload_file():
    file = request.files['file']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        return "Uploaded", 200
```

### 3. What was wrong with it (MIME Confusion & Storage Overwrite Flaw)
* **Extension-Only Check Vulnerability**: Checking only `filename.rsplit('.', 1)[1]` allows an attacker to take an executable Windows binary (`malware.exe`), rename it to `report.pdf`, and upload it. The server blindly accepts it as a PDF!
* **Namespace Collision & Traversal**: Saving with `file.save(os.path.join(UPLOAD_FOLDER, filename))` allows filename collisions where User B uploads a file with the same name as User A, potentially corrupting or overwriting storage references.

### 4. What was done instead
* Implemented **Magic-Byte Signature Verification** (`validate_file_content` in `app/security.py`). The server inspects the first 16 bytes of the stream (`b"%PDF-"`, `b"\x89PNG\r\n\x1a\n"`, `b"PK\x03\x04"`). If an executable PE header (`b"MZ"`) or null byte is disguised as a text/PDF file, it is immediately rejected.
* Decoupled physical storage from the original filename by assigning a random `uuid.uuid4()` as the physical storage key on disk (`storage/{doc_id}.{ext}`).
* See tests: `tests/test_upload_validation.py`.

---

## Dated Entry 5: 2026-10-30 — Audit Trail Immutability & Database Schema

### 1. What was asked
> *"Design the database table for audit logs. Include an update route so administrators can annotate audit logs with notes or corrections."*

### 2. What the AI produced
```sql
CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id TEXT,
    action TEXT,
    document_id TEXT,
    notes TEXT,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

@admin_bp.route("/audit/<log_id>/update", methods=["POST"])
@admin_required
def update_audit_log(log_id):
    notes = request.form.get("notes")
    db.execute("UPDATE audit_logs SET notes = ?, updated_at = NOW() WHERE id = ?", (notes, log_id))
    return "Updated", 200
```

### 3. What was wrong with it (Fundamental Audit Failure)
* **Violation of Non-Repudiation**: An audit trail that allows `UPDATE` queries is fundamentally un-auditable. A malicious or compromised administrator could alter notes or wipe out breach descriptions.
* The challenge guidelines explicitly state: *"An audit trail that can be quietly altered is not evidence, and we will ask you what stops that."*

### 4. What was done instead
* Completely prohibited any `UPDATE` or `DELETE` endpoints for audit records.
* Built a **cryptographic hash chain** in `app/audit.py`. Every row links to the previous row's SHA-256 hash.
* Built the `verify_audit_chain()` verification function that scans from sequence 1 to N. Any modification or deletion of past records breaks the cryptographic chain and triggers an alert.
* See tests: `tests/test_audit_integrity.py` (`test_02_detects_data_tampering_in_audit_record`).
