
import unittest
import tempfile
import os

from app.config import Config
from app import create_app
from app.database import get_db
from app.audit import log_audit_event, verify_audit_chain


class TestAuditIntegrity(unittest.TestCase):

    def setUp(self):
        # Create a separate temporary database
        self.temp_folder = tempfile.TemporaryDirectory()

        self.old_db_path = Config.DB_PATH
        self.old_storage_path = Config.STORAGE_DIR

        Config.DB_PATH = os.path.join(
            self.temp_folder.name, "test_trustvault.db"
        )
        Config.STORAGE_DIR = self.temp_folder.name

        self.app = create_app()
        self.app.config["TESTING"] = True

        # Create three test audit records
        for i in range(3):
            log_audit_event(
                action="TEST_EVENT",
                status="SUCCESS",
                details={"test_number": i + 1}
            )

    def tearDown(self):
        # Restore original database settings
        Config.DB_PATH = self.old_db_path
        Config.STORAGE_DIR = self.old_storage_path

        # Delete the temporary database
        self.temp_folder.cleanup()

    def test_01_chain_is_initially_valid(self):
        result = verify_audit_chain()

        self.assertTrue(result["valid"])
        self.assertEqual(result["total_records"], 3)

    def test_02_detects_data_tampering(self):
        with get_db() as conn:
            conn.execute(
                "UPDATE audit_logs SET details = ? WHERE sequence_number = 2",
                ('{"tampered": true}',)
            )

        result = verify_audit_chain()

        self.assertFalse(result["valid"])
        self.assertEqual(result["broken_at_sequence"], 2)
        self.assertIn("tampering detected", result["reason"].lower())

    def test_03_detects_record_deletion(self):
        with get_db() as conn:
            conn.execute(
                "DELETE FROM audit_logs WHERE sequence_number = 2"
            )

        result = verify_audit_chain()

        self.assertFalse(result["valid"])
        self.assertEqual(result["broken_at_sequence"], 3)
        self.assertIn("sequence break", result["reason"].lower())

    def test_04_detects_broken_hash_link(self):
        with get_db() as conn:
            conn.execute(
                "UPDATE audit_logs SET prev_hash = ? WHERE sequence_number = 2",
                ("f" * 64,)
            )

        result = verify_audit_chain()

        self.assertFalse(result["valid"])
        self.assertEqual(result["broken_at_sequence"], 2)
        self.assertIn("chain link severed", result["reason"].lower())


if __name__ == "__main__":
    unittest.main()
