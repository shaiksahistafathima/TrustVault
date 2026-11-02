
import unittest

from test_support import TrustVaultTestCase
from app.database import get_db


class TestSecurityAuthorization(TrustVaultTestCase):
    """
    Adversarial tests for document authorization.
    """

    def setUp(self):
        super().setUp()

        with get_db() as conn:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT id FROM users WHERE email = ?",
                ("outsider@trustvault.local",)
            )
            self.outsider_id = cursor.fetchone()["id"]

            cursor.execute(
                "SELECT id FROM users WHERE email = ?",
                ("viewer@trustvault.local",)
            )
            self.viewer_id = cursor.fetchone()["id"]

            cursor.execute(
                "SELECT id FROM documents WHERE title = ?",
                ("Executive_Salary_2026.pdf",)
            )
            self.confidential_doc_id = cursor.fetchone()["id"]

            cursor.execute(
                "SELECT id FROM documents WHERE title = ?",
                ("Master_Services_Agreement.pdf",)
            )
            self.shared_doc_id = cursor.fetchone()["id"]

    def login(self, email, password):
        token = self.get_csrf_token("/login")

        return self.client.post(
            "/login",
            data={
                "email": email,
                "password": password,
                "csrf_token": token
            },
            follow_redirects=True
        )

    def test_01_outsider_cannot_download_confidential_document(self):
        self.login(
            "outsider@trustvault.local",
            "OutsiderSecure2026!"
        )

        response = self.client.get(
            f"/documents/{self.confidential_doc_id}/download"
        )

        self.assertEqual(response.status_code, 403)

    def test_02_denied_attempt_is_recorded_in_audit(self):
        self.login(
            "outsider@trustvault.local",
            "OutsiderSecure2026!"
        )

        self.client.get(
            f"/documents/{self.confidential_doc_id}/download"
        )

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT action, status
                FROM audit_logs
                WHERE document_id = ?
                AND actor_id = ?
                AND status = 'DENIED'
                ORDER BY sequence_number DESC
                LIMIT 1
            """, (
                self.confidential_doc_id,
                self.outsider_id
            ))
            denied_log = cursor.fetchone()

        self.assertIsNotNone(denied_log)
        self.assertEqual(
            denied_log["action"],
            "UNAUTHORIZED_DOCUMENT_ACCESS_ATTEMPT"
        )
        self.assertEqual(denied_log["status"], "DENIED")

    def test_03_authorized_viewer_can_download_shared_document(self):
        self.login(
            "viewer@trustvault.local",
            "ViewerSecure2026!"
        )

        response = self.client.get(
            f"/documents/{self.shared_doc_id}/download"
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data.startswith(b"%PDF"))
        response.close()

    def test_04_viewer_cannot_download_unshared_document(self):
        self.login(
            "viewer@trustvault.local",
            "ViewerSecure2026!"
        )

        response = self.client.get(
            f"/documents/{self.confidential_doc_id}/download"
        )

        self.assertEqual(response.status_code, 403)

    def test_05_anonymous_user_cannot_download_document(self):
        anonymous_client = self.app.test_client()

        response = anonymous_client.get(
            f"/documents/{self.confidential_doc_id}/download"
        )

        self.assertIn(response.status_code, (302, 401, 403))

    def test_06_read_user_cannot_edit_document_metadata(self):
        self.login(
            "viewer@trustvault.local",
            "ViewerSecure2026!"
        )

        token = self.get_csrf_token(
            f"/documents/{self.shared_doc_id}"
        )

        response = self.client.post(
            f"/documents/{self.shared_doc_id}/edit",
            data={
                "title": "Unauthorized_Edit_Attempt",
                "description": "Testing READ permission",
                "category": "General",
                "csrf_token": token
            },
            follow_redirects=False
        )

        self.assertEqual(response.status_code, 403)

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT title FROM documents WHERE id = ?",
                (self.shared_doc_id,)
            )
            document = cursor.fetchone()

        self.assertEqual(
            document["title"],
            "Master_Services_Agreement.pdf"
        )
if __name__ == "__main__":
    unittest.main()
