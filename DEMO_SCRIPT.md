# TrustVault — 5-Minute Demo Video Script (DEMO_SCRIPT.md)

Use this structure to record your 5-minute demo video. It demonstrates the main security features and addresses the evaluation criteria.

---

### Minute 0:00 – 0:45: The Problem & The Three Invariants

- **Camera / Voice**: Introduce yourself and the mission of TrustVault.
- **Key Talking Points**:
  - *"TrustVault is not a generic file-sharing CRUD app. It is a zero-trust document security platform designed around three important security principles:"*
  1. **Zero Unpermitted Reachability**: Documents have no public download URLs. The server checks live permissions before processing each download request.
  2. **Tamper-Evident Auditability**: Document access events, including denied 403 attempts, are recorded in a SHA-256 hash-linked audit chain.
  3. **Permission Revocation**: After access is revoked, subsequent download requests are denied.

---

### Minute 0:45 – 1:45: Multi-Role Architecture & Document Isolation

- **Screen**: Navigate to `http://127.0.0.1:5000/login`.
- **Action 1**: Click **"Fill Owner"** and log in as `owner@trustvault.local`.
- **Action 2**: Show the dashboard. Open `Executive_Salary_2026.pdf`.
  - Explain: *"This document is owned by Alice. It is stored on disk using a randomized UUID filename (`storage/<uuid>.pdf`), outside the public web root. Users cannot access it through a public static URL."*
  - Show the SHA-256 integrity hash displayed on the screen.
- **Action 3**: Upload a new document (e.g. `Test_Contract.pdf`). Explain that the application checks file signatures (magic bytes) to reject files whose contents do not match their claimed file type.

---

### Minute 1:45 – 2:45: Attack Simulation: IDOR & Denied Audit Recording

- **Screen**: Open an Incognito window or sign out.
- **Action 1**: Log in as `outsider@trustvault.local` (Eve).
  - Note: Eve's dashboard is empty because she owns no documents and has received no shares.
- **Action 2**: Paste the URL of Alice's confidential document: `http://127.0.0.1:5000/documents/<uuid>/download`.
- **Result**: The screen shows **403 Access Refused**.
- **Crucial Talking Point**:
  - *"Notice that Eve was blocked by server-side authorization. But more importantly: did Eve leave a trace?"*
- **Action 3**: Sign in as `admin@trustvault.local` and go to **Audit Trail**.
  - Show the relevant row: `UNAUTHORIZED_DOCUMENT_ACCESS_ATTEMPT` with `status: DENIED`, showing the recorded actor information, IP address, and timestamp where available.
  - *"TrustVault records denied document-access attempts, giving administrators an audit trail of unauthorized access attempts."*

---

### Minute 2:45 – 3:45: Permission Revocation Proof

- **Screen**: Sign in as `owner@trustvault.local`.
- **Action 1**: Open `Master_Services_Agreement.pdf`.
  - Show that `viewer@trustvault.local` currently has `READ` permission.
- **Action 2**: Switch to a window logged in as `viewer@trustvault.local`.
  - Click **Download Secure File** → The download succeeds (`200 OK`).
- **Action 3**: Switch back to Owner window → Click **"Revoke Now"** next to `viewer@trustvault.local`.
- **Action 4**: Switch back to Viewer window → Click **Download Secure File** again.
- **Result**: The subsequent request is denied with **403 Forbidden**.
- **Talking Point**:
  - *"TrustVault avoids static pre-signed download URLs. It evaluates permissions against live database records, so revocation is enforced on subsequent download requests. An already-started download is not guaranteed to be interrupted."*

---

### Minute 3:45 – 4:30: Cryptographic Hash Chain Verification

- **Screen**: Sign in as `admin@trustvault.local`.
- **Action 1**: Navigate to **Audit Trail** → Click **"Verify Hash Chain Integrity"**.
  - Show the green verification card: *"Integrity Verified: Chain Untampered across N blocks. Latest hash: `<sha256>`"*.
- **Talking Point**:
  - *"Each audit record includes fields such as the sequence number, timestamp, actor, action, document, details, and the previous record's SHA-256 hash. This hash linkage helps detect modifications to retained records and deletions within the chain. However, deleting the latest record may not be detected without an independently stored checkpoint. Our audit trail is tamper-evident, not physically immutable."*

---

### Minute 4:30 – 5:00: Automated Security Tests & Conclusion

- **Screen**: Open the terminal.
- **Action**: Run `python -m unittest discover -s tests`.
  - Show the previously verified result: **40 tests passed**.
- **Final Talking Point**:
  - *"We have 40 automated tests covering IDOR, permission revocation, magic-byte upload validation, CSRF protection, and audit tamper detection. These tests exercise important security controls and help catch regressions in the scenarios they cover. All identified threats are documented in `THREATS.md`, and AI-assisted development and debugging history is documented in `PROMPTS.md`."*
- **Closing**: Thank the evaluators.