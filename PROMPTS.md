# TrustVault — AI Interaction Log & Security Audit Record

This file records genuine AI-assisted development work for the Snovasys TrustVault challenge (November 1–7, 2026).

**Accuracy note:** Prompt descriptions below are faithful summaries of the development interactions, not claimed verbatim quotations. Commit links point to actual repository commits. A commit proves the recorded code or documentation change, not by itself the exact wording of a prompt.

## Reusable project context

The following security principles summarize the constraints used when reviewing TrustVault:

1. **Server-side authorization:** Every document operation must check the current user's permission on the server.
2. **Auditability:** Record relevant document activity, including denied access attempts. Use a hash chain to make changes to recorded entries detectable.
3. **Revocation:** Check current permissions on subsequent requests; do not rely on long-lived access links that bypass the application.
4. **Least privilege:** Admin, Owner, and Viewer roles must have distinct permissions.
5. **Honest security claims:** Distinguish implemented protections from limitations and accepted risks.

---

## Entry 1 — 2026-11-01: Initial TrustVault project planning and build guidance

### 1. Prompt summary
I provided the Snovasys TrustVault challenge brief and asked for help building a secure document-sharing platform, starting from the beginning. I requested step-by-step guidance.

### 2. AI-assisted output
The initial application structure and implementation included:
- Flask application setup and authentication.
- Document routes and permission checks.
- Database and storage setup.
- Audit logging and verification code.
- Admin pages and project documentation.

Initial implementation commit (created 2026-11-02):
[ eaf35c8 — Build TrustVault secure document sharing platform ](https://github.com/shaiksahistafathima/TrustVault/commit/eaf35c8)

### 3. Issue identified during subsequent review
The original deployment command in the Procfile ran `seed.py` before starting Gunicorn. Automatically creating demo accounts during production startup could expose predictable demo credentials in a deployed environment.

### 4. Corrective action
The production startup command was changed so it starts Gunicorn without automatically running the demo seed script. The correction is recorded in Entry 2.

---

## Entry 2 — 2026-11-02: Prevent automatic demo seeding in production

### 1. Prompt summary
During deployment review, the production startup process was examined to prevent demo-account creation from running automatically.

### 2. AI-assisted output
The Procfile startup command was changed from:

`python seed.py && gunicorn wsgi:app`

to:

`gunicorn wsgi:app`

### 3. Issue and limitation identified
Automatic demo seeding is inappropriate for production because demo accounts and their credentials should not be created automatically on every application startup.

Removing the seed command does not, by itself, solve secure first-admin provisioning. A separate secure production bootstrap process is still required.

### 4. Corrective action
Automatic seeding was removed from the production Procfile. Demo seeding remains a separate setup operation.

Commit:
[ fc4762d — Remove automatic demo seeding from production startup ](https://github.com/shaiksahistafathima/TrustVault/commit/fc4762d)

---

## Entry 3 — 2026-11-04: Make security and setup documentation more accurate

### 1. Prompt summary
I worked on improving the README setup instructions and making the project's security descriptions accurately reflect the implementation.

### 2. AI-assisted output
The README wording and setup documentation were revised.

For example, the description changed from claiming a "tamper-proof" platform and "instant permission revocation" to describing a tamper-evident audit trail and permission revocation on subsequent requests.

### 3. Issue identified
Terms such as "tamper-proof" and unqualified "instant revocation" can overstate what an application with a database-backed hash chain and request-based authorization can guarantee.

A hash chain provides tamper evidence; it does not make a database physically immutable or independently prove that its latest records were never deleted.

### 4. Corrective action
The README wording was made more precise, and setup/security documentation was improved to avoid claiming guarantees beyond the implemented design.

Commit:
[ b6d0bc4 — Improve setup instructions and security documentation ](https://github.com/shaiksahistafathima/TrustVault/commit/b6d0bc4)

---

## Entry 4 — 2026-11-04: Correct the repository clone instructions

### 1. Prompt summary
I asked for the incorrect GitHub clone URL in the README to be corrected.

### 2. AI-assisted output
The repository clone URL in the README was corrected.

### 3. Issue identified
An incorrect clone URL would prevent someone following the setup instructions from cloning the intended project repository.

### 4. Corrective action
The README clone URL was updated to point to the TrustVault GitHub repository.

Commit:
[ 66df200 — Fix GitHub clone URL in README ](https://github.com/shaiksahistafathima/TrustVault/commit/66df200)

---

## Entry 5 — 2026-11-05: Strengthen login CSP and refine the threat model

### 1. Prompt summary
I continued the security review of the login page and threat documentation, focusing on the Content Security Policy and making the documented audit/security guarantees more accurate.

### 2. AI-assisted output
The changes included:
- Tightening the script policy in `app/__init__.py` by removing `unsafe-inline` from `script-src`.
- Moving login-page JavaScript behavior into `app/static/js/login.js`.
- Updating `app/templates/login.html` to use the external JavaScript.
- Revising `THREATS.md` to describe security controls, limitations, and accepted risks more carefully.

### 3. Issue identified
Inline JavaScript event handlers are incompatible with a restrictive script policy that disallows inline scripts. Tightening the policy therefore required moving the login behavior into an external JavaScript file.

The threat documentation also needed to distinguish hash-chain tampering detection from protection against deletion of the latest audit records. A hash chain alone cannot guarantee detection of every possible database rollback or tail deletion without an independently retained checkpoint.

### 4. Corrective action
The login behavior was moved to an external JavaScript file, and the threat model was revised to describe the limitations of the audit chain rather than claiming absolute immutability.

Commit:
[ c746e98 — Strengthen login CSP and audit threat documentation ](https://github.com/shaiksahistafathima/TrustVault/commit/c746e98)

---

## Accuracy and evidence notes

- Prompt descriptions in this log are summaries, not fabricated verbatim quotations.
- Commit links refer to actual Git history.
- A code or documentation change is not automatically proof that every related security requirement has been satisfied.
- Security claims must be supported by implementation review and tests.
- Further AI interactions and corrections should be added with their real dates as development continues.


---

## Entry 6 - 2026-11-05: Expand authorization tests and clarify audit limitations

### 1. Prompt summary
During the continued security review, I worked through additional authorization tests and asked for the documentation to reflect the actual limits of the audit hash chain.

### 2. AI-assisted output
The work added tests covering:
- EDIT users attempting owner-only permission and deletion operations.
- Non-admin access to administrator pages.
- Outsider access to confidential document details and search results.
- Viewer attempts to delete, share, revoke, or upload documents.

The audit documentation was also clarified to explain the limitation around deletion of the latest records without an independently retained checkpoint.

### 3. Issue identified
Authorization must be enforced by the server for each protected operation, not merely hidden in the user interface. Earlier tests did not cover all of these role and route combinations.

The audit hash chain also cannot independently guarantee detection of every possible tail deletion.

### 4. Corrective action
Additional authorization tests were added and the audit limitations were documented honestly. The full test suite was subsequently verified with 29 passing tests.

Commit:
[ 5a1a331 - Expand authorization tests and clarify audit limits ](https://github.com/shaiksahistafathima/TrustVault/commit/5a1a331)
