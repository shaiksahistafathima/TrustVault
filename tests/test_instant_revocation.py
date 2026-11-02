
import unittest

from test_support import TrustVaultTestCase
from app.database import get_db


class TestInstantRevocation(TrustVaultTestCase):

    def setUp(self):
        super().setUp()

        self.viewer_client = self.app.test_client()
        self.owner_client = self.app.test_client()
        self.admin_client = self.app.test_client()

        with get_db() as conn:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT id FROM documents WHERE title = ?",
                ("Master_Services_Agreement.pdf",)
            )
            self.doc_id = cursor.fetchone()["id"]

            cursor.execute(
                "SELECT id FROM users WHERE email = ?",
                ("viewer@trustvault.local",)
            )
            self.viewer_id = cursor.fetchone()["id"]

    def login(self, client, email, password):
        token = self.get_csrf_token("/login", client)

        return client.post(
            "/login",
            data={
                "email": email,
                "password": password,
                "csrf_token": token
            },
            follow_redirects=True
        )

    def test_instant_permission_revocation(self):

        # Viewer logs in and downloads the shared document.
        self.login(
            self.viewer_client,
            "viewer@trustvault.local",
            "ViewerSecure2026!"
        )

        first_response = self.viewer_client.get(
            f"/documents/{self.doc_id}/download"
        )

        self.assertEqual(first_response.status_code, 200)
        first_response.close()

        # Owner uses a separate session to revoke permission.
        self.login(
            self.owner_client,
            "owner@trustvault.local",
            "OwnerSecure2026!"
        )

        token = self.get_csrf_token(
            f"/documents/{self.doc_id}",
            self.owner_client
        )

        revoke_response = self.owner_client.post(
            f"/documents/{self.doc_id}/revoke/{self.viewer_id}",
            data={"csrf_token": token},
            follow_redirects=True
        )

        self.assertEqual(revoke_response.status_code, 200)

        # Viewer reuses the original session without logging in again.
        second_response = self.viewer_client.get(
            f"/documents/{self.doc_id}/download"
        )

        self.assertEqual(
            second_response.status_code,
            403,
            "REVOCATION FAILED: Existing Viewer session still has access!"
        )

    def test_instant_account_suspension(self):

        # Viewer logs in and confirms initial access.
        self.login(
            self.viewer_client,
            "viewer@trustvault.local",
            "ViewerSecure2026!"
        )

        first_response = self.viewer_client.get(
            f"/documents/{self.doc_id}/download"
        )

        self.assertEqual(first_response.status_code, 200)
        first_response.close()

        # Admin suspends Viewer using a separate session.
        self.login(
            self.admin_client,
            "admin@trustvault.local",
            "AdminSecure2026!"
        )

        token = self.get_csrf_token(
            "/admin/users",
            self.admin_client
        )

        suspend_response = self.admin_client.post(
            f"/admin/users/{self.viewer_id}/toggle-active",
            data={"csrf_token": token},
            follow_redirects=True
        )

        self.assertEqual(suspend_response.status_code, 200)

        # Viewer tries again using the original login session.
        response_after_suspend = self.viewer_client.get(
            f"/documents/{self.doc_id}/download"
        )

        self.assertIn(
            response_after_suspend.status_code,
            (302, 401, 403),
            "SECURITY FAILURE: Suspended account retained access!"
        )


if __name__ == "__main__":
    unittest.main()
