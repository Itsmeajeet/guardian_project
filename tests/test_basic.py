"""Tests: proof the scanner behaves. Run with:  python -m unittest discover tests

WHY tests matter in security software: a scanner that silently stops
detecting, or starts flagging everything, is dangerous. Tests catch that.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_tmp_home = tempfile.mkdtemp()
os.environ["GUARDIAN_HOME"] = _tmp_home   # keep tests away from real data

from guardian.ai_score import Model, DEFAULT_MODEL           # noqa: E402
from guardian.scanner import scan_path                       # noqa: E402
from guardian.signatures import EICAR                        # noqa: E402
from guardian.urlcheck import check_url                      # noqa: E402
from guardian.quarantine import quarantine_file, restore    # noqa: E402


class GuardianTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def write(self, name, data):
        p = self.dir / name
        p.write_bytes(data)
        return p

    def scan_one(self, p):
        return next(scan_path(p))

    def test_eicar_is_detected_by_signature(self):
        r = self.scan_one(self.write("test.txt", EICAR))
        self.assertEqual(r.verdict, "malicious")
        self.assertEqual(r.signature, "EICAR-Test-File")

    def test_plain_text_is_clean(self):
        r = self.scan_one(self.write("notes.txt", b"hello world"))
        self.assertEqual(r.verdict, "clean")

    def test_double_extension_exe_is_flagged(self):
        r = self.scan_one(self.write("invoice.pdf.exe", b"MZ" + b"\x00" * 100))
        self.assertIn(r.verdict, ("suspicious", "malicious"))

    def test_exe_disguised_as_jpg_is_flagged(self):
        r = self.scan_one(self.write("photo.jpg", b"MZ" + b"\x00" * 100))
        self.assertIn(r.verdict, ("suspicious", "malicious"))

    def test_malicious_looking_script_is_suspicious(self):
        script = b"powershell -enc AAAA\n$x=[Convert]::FromBase64String('x')\nIEX $x\n"
        r = self.scan_one(self.write("run.ps1", script))
        self.assertIn(r.verdict, ("suspicious", "malicious"))

    def test_normal_script_is_clean(self):
        r = self.scan_one(self.write("hello.sh", b"#!/bin/sh\necho hi\n"))
        self.assertEqual(r.verdict, "clean")

    def test_url_rules(self):
        self.assertGreaterEqual(check_url("http://192.168.4.5/login")[0], 40)
        self.assertLess(check_url("https://www.wikipedia.org")[0], 30)

    def test_training_moves_weights(self):
        m = Model(DEFAULT_MODEL["bias"], DEFAULT_MODEL["weights"])
        before = m.weights["is_exec"]
        # Teach it that executables alone are bad.
        m.train([({"is_exec": 1.0}, 1)] * 20, epochs=50)
        self.assertGreater(m.weights["is_exec"], before)

    def test_quarantine_and_restore(self):
        p = self.write("evil.bin", b"data")
        dest = quarantine_file(p, "a" * 64, "test")
        self.assertFalse(p.exists())
        self.assertTrue(dest.exists())
        restore(dest.name)
        self.assertTrue(p.exists())


if __name__ == "__main__":
    unittest.main()
