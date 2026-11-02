
import os
import re
import tempfile
import unittest

from app import create_app
from app.config import Config
from seed import seed_database


class TrustVaultTestCase(unittest.TestCase):

    def setUp(self):
        # Save the real project paths.
        self.old_db_path = Config.DB_PATH
        self.old_storage_path = Config.STORAGE_DIR

        # Create isolated temporary test storage.
        self.temp_folder = tempfile.TemporaryDirectory()

        Config.DB_PATH = os.path.join(
            self.temp_folder.name, "test_trustvault.db"
        )
        Config.STORAGE_DIR = os.path.join(
            self.temp_folder.name, "storage"
        )

        os.makedirs(Config.STORAGE_DIR, exist_ok=True)

        # Create a fresh database and sample users/documents.
        self.app = create_app()
        self.app.config["TESTING"] = True
        seed_database()

        self.client = self.app.test_client()
    def get_csrf_token(self, path="/login", client=None):
        test_client = client or self.client

        response = test_client.get(path)
        self.assertEqual(response.status_code, 200)

        match = re.search(
            rb'name="csrf_token"\s+value="([^"]+)"',
            response.data
        )

        self.assertIsNotNone(match, "CSRF token not found in page")

        return match.group(1).decode()
    def tearDown(self):
        
        # Restore the original project paths.
        Config.DB_PATH = self.old_db_path
        Config.STORAGE_DIR = self.old_storage_path

        # Delete temporary test data.
        self.temp_folder.cleanup()
