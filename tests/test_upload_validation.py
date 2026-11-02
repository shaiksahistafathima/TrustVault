import unittest
import io
from app import create_app
from app.security import validate_file_content

class TestUploadValidation(unittest.TestCase):
    """
    Tests file upload security:
    MIME spoofing, magic bytes inspection, executable rejection.
    """

    def test_valid_pdf_accepted(self):
        valid_pdf_stream = io.BytesIO(b"%PDF-1.5 Valid PDF Content Here")
        is_valid, msg = validate_file_content(valid_pdf_stream, "contract.pdf")
        self.assertTrue(is_valid)

    def test_spoofed_executable_rejected(self):
        """
        Attacker renames evil.exe (starts with DOS/PE header 'MZ') to legitimate.pdf.
        """
        spoofed_stream = io.BytesIO(b"MZ\x90\x00\x03\x00\x00\x00Executable binary content")
        is_valid, msg = validate_file_content(spoofed_stream, "legitimate.pdf")
        self.assertFalse(is_valid, "Executable disguised as PDF must be rejected!")
        self.assertIn("mismatch", msg.lower())

    def test_null_byte_in_text_file_rejected(self):
        """
        Attacker embeds null bytes inside a .txt or .csv file to trigger buffer overflows or parser bugs.
        """
        null_byte_stream = io.BytesIO(b"Normal text line\x00malicious binary trailer")
        is_valid, msg = validate_file_content(null_byte_stream, "notes.txt")
        self.assertFalse(is_valid)
        self.assertIn("null bytes", msg.lower())

    def test_disallowed_extension_rejected(self):
        sh_stream = io.BytesIO(b"#!/bin/bash\nrm -rf /")
        is_valid, msg = validate_file_content(sh_stream, "script.sh")
        self.assertFalse(is_valid)

if __name__ == "__main__":
    unittest.main()
