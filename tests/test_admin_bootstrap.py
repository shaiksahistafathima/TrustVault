
import os
import tempfile
import unittest
from unittest.mock import patch

from app.config import Config
from app.database import get_db, init_db
from app.audit import verify_audit_chain
from app.auth import create_user
from bootstrap_admin import create_initial_admin


class TestAdminBootstrap(unittest.TestCase):

    def setUp(self):
        self.temp_folder = tempfile.TemporaryDirectory()

        self.old_db_path = Config.DB_PATH
        self.old_storage_path = Config.STORAGE_DIR

        Config.DB_PATH = os.path.join(
            self.temp_folder.name, "bootstrap_test.db"
        )
        Config.STORAGE_DIR = os.path.join(
            self.temp_folder.name, "storage"
        )

        # Initialize the isolated temporary database.
        init_db()

    def tearDown(self):
        Config.DB_PATH = self.old_db_path
        Config.STORAGE_DIR = self.old_storage_path
        self.temp_folder.cleanup()

    def test_first_admin_created_with_valid_audit(self):
        admin = create_initial_admin(
            "admin@example.com",
            "Test Administrator",
            "StrongPassword2026!"
        )

        self.assertEqual(admin["role"], "ADMIN")

        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE email = ?",
                ("admin@example.com",)
            ).fetchone()

            event = conn.execute(
                "SELECT * FROM audit_logs"
            ).fetchone()

        self.assertIsNotNone(user)
        self.assertEqual(user["role"], "ADMIN")
        self.assertNotEqual(
            user["password_hash"],
            "StrongPassword2026!"
        )

        self.assertIsNotNone(event)
        self.assertEqual(
            event["action"],
            "ADMIN_ACCOUNT_BOOTSTRAPPED"
        )

        self.assertTrue(verify_audit_chain()["valid"])

    def test_second_bootstrap_is_refused(self):
        create_initial_admin(
            "admin@example.com",
            "Test Administrator",
            "StrongPassword2026!"
        )

        with self.assertRaises(ValueError):
            create_initial_admin(
                "another@example.com",
                "Another Administrator",
                "AnotherPassword2026!"
            )

    def test_existing_user_prevents_bootstrap(self):
        create_user(
            "viewer@example.com",
            "ViewerPassword2026!",
            "Existing Viewer",
            "VIEWER"
        )

        with self.assertRaises(ValueError):
            create_initial_admin(
                "admin@example.com",
                "Test Administrator",
                "StrongPassword2026!"
            )

    def test_audit_failure_rolls_back_admin_creation(self):
        with patch(
            "app.audit.append_audit_event",
            side_effect=RuntimeError("Simulated audit failure")
        ):
            with self.assertRaises(RuntimeError):
                create_initial_admin(
                    "admin@example.com",
                    "Test Administrator",
                    "StrongPassword2026!"
                )

        with get_db() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM users"
            ).fetchone()[0]

        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
