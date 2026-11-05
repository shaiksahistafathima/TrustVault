import io
import unittest

from test_support import TrustVaultTestCase
from app.database import get_db


class TestAdditionalAuthorization(TrustVaultTestCase):

    def setUp(self):
        super().setUp()

        with get_db() as conn:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT id FROM users WHERE email = ?",
                ("viewer@trustvault.local",)
            )
            self.viewer_id = cursor.fetchone()["id"]

            cursor.execute(
                "SELECT id FROM users WHERE email = ?",
                ("outsider@trustvault.local",)
            )
            self.outsider_id = cursor.fetchone()["id"]

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

    def test_viewer_cannot_grant_permission(self):
        self.login(
            self.client,
            "viewer@trustvault.local",
            "ViewerSecure2026!"
        )

        token = self.get_csrf_token(
            f"/documents/{self.shared_doc_id}",
            self.client
        )

        response = self.client.post(
            f"/documents/{self.shared_doc_id}/share",
            data={
                "user_id": self.outsider_id,
                "permission_level": "READ",
                "csrf_token": token
            }
        )

        self.assertEqual(response.status_code, 403)

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id FROM document_permissions
                WHERE document_id = ? AND user_id = ?
            """, (self.shared_doc_id, self.outsider_id))

            self.assertIsNone(cursor.fetchone())

    def test_viewer_cannot_revoke_permission(self):
        self.login(
            self.client,
            "viewer@trustvault.local",
            "ViewerSecure2026!"
        )

        token = self.get_csrf_token(
            f"/documents/{self.shared_doc_id}",
            self.client
        )

        response = self.client.post(
            f"/documents/{self.shared_doc_id}/revoke/{self.outsider_id}",
            data={"csrf_token": token}
        )

        self.assertEqual(response.status_code, 403)

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id FROM document_permissions
                WHERE document_id = ? AND user_id = ?
            """, (self.shared_doc_id, self.viewer_id))

            self.assertIsNotNone(cursor.fetchone())

    def test_viewer_cannot_delete_document(self):
        self.login(
            self.client,
            "viewer@trustvault.local",
            "ViewerSecure2026!"
        )

        token = self.get_csrf_token(
            f"/documents/{self.shared_doc_id}",
            self.client
        )

        response = self.client.post(
            f"/documents/{self.shared_doc_id}/delete",
            data={"csrf_token": token}
        )

        self.assertEqual(response.status_code, 403)

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT is_deleted FROM documents WHERE id = ?",
                (self.shared_doc_id,)
            )

            self.assertEqual(cursor.fetchone()["is_deleted"], 0)

    def test_edit_permission_does_not_allow_owner_only_actions(self):
        with get_db() as conn:
            conn.execute("""
                UPDATE document_permissions
                SET permission_level = 'EDIT'
                WHERE document_id = ? AND user_id = ?
            """, (self.shared_doc_id, self.viewer_id))

        self.login(
            self.client,
            "viewer@trustvault.local",
            "ViewerSecure2026!"
        )

        token = self.get_csrf_token(
            f"/documents/{self.shared_doc_id}",
            self.client
        )

        grant_response = self.client.post(
            f"/documents/{self.shared_doc_id}/share",
            data={
                "user_id": self.outsider_id,
                "permission_level": "READ",
                "csrf_token": token
            }
        )

        revoke_response = self.client.post(
            f"/documents/{self.shared_doc_id}/revoke/{self.outsider_id}",
            data={"csrf_token": token}
        )

        delete_response = self.client.post(
            f"/documents/{self.shared_doc_id}/delete",
            data={"csrf_token": token}
        )

        self.assertEqual(grant_response.status_code, 302)
        self.assertEqual(revoke_response.status_code, 302)
        self.assertEqual(delete_response.status_code, 302)

        with get_db() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT permission_level
                FROM document_permissions
                WHERE document_id = ? AND user_id = ?
            """, (self.shared_doc_id, self.viewer_id))

            self.assertEqual(
                cursor.fetchone()["permission_level"],
                "EDIT"
            )

            cursor.execute("""
                SELECT id FROM document_permissions
                WHERE document_id = ? AND user_id = ?
            """, (self.shared_doc_id, self.outsider_id))

            self.assertIsNone(cursor.fetchone())

            cursor.execute(
                "SELECT is_deleted FROM documents WHERE id = ?",
                (self.shared_doc_id,)
            )

            self.assertEqual(cursor.fetchone()["is_deleted"], 0)

    def test_non_admin_users_cannot_access_admin_pages(self):
        accounts = [
            ("owner@trustvault.local", "OwnerSecure2026!"),
            ("viewer@trustvault.local", "ViewerSecure2026!")
        ]

        for email, password in accounts:
            client = self.app.test_client()

            self.login(client, email, password)

            self.assertEqual(
                client.get("/admin/audit").status_code,
                403
            )

            self.assertEqual(
                client.get("/admin/users").status_code,
                403
            )

    def test_viewer_cannot_upload_documents(self):
        self.login(
            self.client,
            "viewer@trustvault.local",
            "ViewerSecure2026!"
        )

        token = self.get_csrf_token("/", self.client)

        with get_db() as conn:
            before = conn.execute(
                "SELECT COUNT(*) FROM documents"
            ).fetchone()[0]

        response = self.client.post(
            "/upload",
            data={
                "csrf_token": token,
                "file": (io.BytesIO(b"%PDF-1.4 Test PDF"), "test.pdf"),
                "title": "Unauthorized Upload"
            },
            content_type="multipart/form-data"
        )

        self.assertEqual(response.status_code, 302)

        with get_db() as conn:
            after = conn.execute(
                "SELECT COUNT(*) FROM documents"
            ).fetchone()[0]

        self.assertEqual(before, after)

    def test_outsider_cannot_view_confidential_document_details(self):
        self.login(
            self.client,
            "outsider@trustvault.local",
            "OutsiderSecure2026!"
        )

        response = self.client.get(
            f"/documents/{self.confidential_doc_id}"
        )

        self.assertEqual(response.status_code, 403)

    def test_outsider_search_does_not_reveal_confidential_document(self):
        self.login(
            self.client,
            "outsider@trustvault.local",
            "OutsiderSecure2026!"
        )

        response = self.client.get(
            "/search?q=Executive_Salary_2026.pdf"
        )

        self.assertEqual(response.status_code, 200)

        page = response.get_data(as_text=True)

        # The search box echoes the query, so check the results area instead.
        self.assertIn("0 found", page)
        self.assertIn(
            "No accessible documents matched your search criteria.",
            page
        )


if __name__ == "__main__":
    unittest.main()
