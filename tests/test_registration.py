
from test_support import TrustVaultTestCase


class TestRegistration(TrustVaultTestCase):

    def test_01_registration_page_opens(self):
        response = self.client.get("/register")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Create Your Account", response.data)

    def test_02_new_user_can_register_as_viewer(self):
        token = self.get_csrf_token("/register")

        response = self.client.post(
            "/register",
            data={
                "full_name": "Test Viewer",
                "email": "newviewer@example.com",
                "password": "TrustVaultTest2026!",
                "confirm_password": "TrustVaultTest2026!",
                "csrf_token": token
            }
        )

        self.assertEqual(response.status_code, 302)

        # Sign in using the newly registered account.
        token = self.get_csrf_token("/login")

        login_response = self.client.post(
            "/login",
            data={
                "email": "newviewer@example.com",
                "password": "TrustVaultTest2026!",
                "csrf_token": token
            }
        )

        self.assertEqual(login_response.status_code, 302)

        dashboard = self.client.get("/")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn(b"VIEWER", dashboard.data)

    def test_03_registration_rejects_duplicate_email(self):
        token = self.get_csrf_token("/register")

        response = self.client.post(
            "/register",
            data={
                "full_name": "Duplicate User",
                "email": "owner@trustvault.local",
                "password": "TrustVaultTest2026!",
                "confirm_password": "TrustVaultTest2026!",
                "csrf_token": token
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"already exists", response.data)

    def test_04_registration_rejects_password_mismatch(self):
        token = self.get_csrf_token("/register")

        response = self.client.post(
            "/register",
            data={
                "full_name": "Test User",
                "email": "mismatch@example.com",
                "password": "TrustVaultTest2026!",
                "confirm_password": "DifferentPassword2026!",
                "csrf_token": token
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Passwords do not match", response.data)

    def test_05_registration_rejects_short_password(self):
        token = self.get_csrf_token("/register")

        response = self.client.post(
            "/register",
            data={
                "full_name": "Test User",
                "email": "shortpass@example.com",
                "password": "short",
                "confirm_password": "short",
                "csrf_token": token
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"12 and 128", response.data)

    def test_06_registration_rejects_missing_csrf_token(self):
        response = self.client.post(
            "/register",
            data={
                "full_name": "Test User",
                "email": "csrf@example.com",
                "password": "TrustVaultTest2026!",
                "confirm_password": "TrustVaultTest2026!"
            }
        )

        self.assertEqual(response.status_code, 400)
