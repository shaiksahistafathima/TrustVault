# TrustVault — 5-Minute Demo Video Script (DEMO_SCRIPT.md)

Use this exact structure to record your 5-minute demo video. Following this script ensures you showcase all required criteria and directly address the evaluation rubric.

---

### Minute 0:00 – 0:45: The Problem & The Three Invariants
- **Camera / Voice**: Introduce yourself and the mission of TrustVault.
- **Key Talking Points**:
  - *"TrustVault is not a generic file sharing CRUD app. It is a zero-trust document security platform designed around three non-negotiable invariants:"*
  1. **Zero Unpermitted Reachability**: No static URLs, no direct S3 links. The server verifies access on every byte.
  2. **Tamper-Evident Auditability**: Every access, including denied 403 breach attempts, is linked in a SHA-256 cryptographic hash chain.
  3. **Deterministic Instant Revocation**: Taking access away stops downloads within milliseconds.

---

### Minute 0:45 – 1:45: Multi-Role Architecture & Document Isolation
- **Screen**: Navigate to `http://127.0.0.1:5000/login`.
- **Action 1**: Click **"Fill Owner"** and log in as `owner@trustvault.local`.
- **Action 2**: Show the dashboard. Open `Executive_Salary_2026.pdf`.
  - Explain: *"This document is owned by Alice. It is stored on disk with a randomized UUID (`storage/<uuid>.pdf`), completely outside the public web root. It has no public URL."*
  - Show the SHA-256 integrity hash displayed on the screen.
- **Action 3**: Upload a new document (e.g. `Test_Contract.pdf`). Show that magic bytes are verified, preventing executable renaming.

---

### Minute 1:45 – 2:45: Attack Simulation: IDOR & Denied Audit Recording
- **Screen**: Open an Incognito window or sign out.
- **Action 1**: Log in as `outsider@trustvault.local` (Eve).
  - Note: Eve's dashboard is completely empty. She owns nothing and has received no shares.
- **Action 2**: Paste the URL of Alice's confidential document: `http://127.0.0.1:5000/documents/<uuid>/download`.
- **Result**: The screen shows **403 Access Refused**.
- **Crucial Talking Point**:
  - *"Notice that Eve was blocked by server-side authorization. But more importantly: did Eve leave a trace?"*
- **Action 3**: Sign in as `admin@trustvault.local` and go to **Audit Trail**.
  - Show the top row: `UNAUTHORIZED_DOCUMENT_ACCESS_ATTEMPT` with `status: DENIED`, showing Eve's email, IP address, and timestamp.
  - *"In TrustVault, you can always prove who attempted to reach a document, even when they were refused."*

---

### Minute 2:45 – 3:45: Instant Revocation Proof
- **Screen**: Sign in as `owner@trustvault.local`.
- **Action 1**: Open `Master_Services_Agreement.pdf`.
  - Show that `viewer@trustvault.local` currently has `READ` permission.
- **Action 2**: Switch to a window logged in as `viewer@trustvault.local`.
  - Click **Download Secure File** -> The download succeeds (`200 OK`).
- **Action 3**: Switch back to Owner window -> Click **"Revoke Now"** next to `viewer@trustvault.local`.
- **Action 4**: Immediately switch back to Viewer window -> Click **Download Secure File** again.
- **Result**: Immediate **403 Forbidden**!
- **Talking Point**:
  - *"Because we avoided static pre-signed URLs with expiration windows and evaluate permissions on live database records, revocation is instantaneous down to the millisecond."*

---

### Minute 3:45 – 4:30: Cryptographic Hash Chain Verification
- **Screen**: Sign in as `admin@trustvault.local`.
- **Action 1**: Navigate to **Audit Trail** -> Click **"Verify Hash Chain Integrity"**.
  - Show the green verification card: *"Integrity Verified: Chain Untampered across N blocks. Latest hash: `<sha256>`"*.
- **Talking Point**:
  - *"Each audit record hashes the sequence number, timestamp, actor, action, document, details, and the previous block's SHA-256 hash. If any database operator attempts to modify a record or delete an entry, the chain breaks immediately."*

---

### Minute 4:30 – 5:00: Automated Security Tests & Conclusion
- **Screen**: Open the terminal.
- **Action**: Run `python -m unittest discover -s tests`.
  - Show the 14 passing adversarial security tests.
- **Final Talking Point**:
  - *"We have 14 automated tests covering IDOR, instant revocation, magic-byte spoofing, and audit tamper detection. If any developer removes a single authorization check, these tests fail instantly. All threats are cataloged in `THREATS.md`, and all AI debugging history is documented in `PROMPTS.md`."*
- **Closing**: Thank the evaluators.
