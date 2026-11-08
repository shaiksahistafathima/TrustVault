
from test_support import TrustVaultTestCase


class TestAdminUsers(TrustVaultTestCase):

    def login_as_admin(self):
        token = self.get_csrf_token("/login")

        return self.client.post(
            "/login",
            data={
                "email": "admin@trustvault.local",
                "password": "AdminSecure2026!",
                "csrf_token": token
            },
            follow_redirects=True
        )

    def test_admin_users_page_opens(self):
        self.login_as_admin()

        response = self.client.get("/admin/users")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Create Demo Account", response.data)
        self.assertIn(b"Account Role", response.data)
