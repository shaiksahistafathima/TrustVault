


from test_support import TrustVaultTestCase


class TestCSRFProtection(TrustVaultTestCase):

    def test_01_login_rejects_missing_csrf_token(self):
        response = self.client.post(
            "/login",
            data={
                "email": "owner@trustvault.local",
                "password": "OwnerSecure2026!"
            }
        )

        self.assertEqual(response.status_code, 400)

    def test_02_login_accepts_valid_csrf_token(self):
        token = self.get_csrf_token("/login")

        response = self.client.post(
            "/login",
            data={
                "email": "owner@trustvault.local",
                "password": "OwnerSecure2026!",
                "csrf_token": token
            }
        )

        self.assertEqual(response.status_code, 302)

        with self.client.session_transaction() as session:
            self.assertIn("user_id", session)

    def test_03_logout_rejects_get_request(self):
        response = self.client.get("/logout")

        self.assertEqual(response.status_code, 405)

    def test_04_logout_rejects_missing_csrf_token(self):
        token = self.get_csrf_token("/login")

        self.client.post(
            "/login",
            data={
                "email": "owner@trustvault.local",
                "password": "OwnerSecure2026!",
                "csrf_token": token
            }
        )

        response = self.client.post("/logout")

        self.assertEqual(response.status_code, 400)

    def test_05_logout_accepts_valid_csrf_token(self):
        token = self.get_csrf_token("/login")

        self.client.post(
            "/login",
            data={
                "email": "owner@trustvault.local",
                "password": "OwnerSecure2026!",
                "csrf_token": token
            }
        )

        token = self.get_csrf_token("/")

        response = self.client.post(
            "/logout",
            data={"csrf_token": token}
        )

        self.assertEqual(response.status_code, 302)

        with self.client.session_transaction() as session:
            self.assertNotIn("user_id", session)
