"""Heuristics: rules of thumb that spot SUSPICIOUS files nobody has seen before.

Signatures catch known threats. Heuristics look at HOW a file behaves or looks
and ask "is this the kind of thing malware does?". Each rule here is weak on
its own (a legitimate file can trip one), so we do not issue verdicts from
single rules. We turn every rule into a number (a "feature") and let the
scoring model in ai_score.py weigh them together.
"""

import re
import zipfile
from pathlib import Path

from . import config
from .hashing import shannon_entropy

EXEC_EXTS = {".exe", ".dll", ".scr", ".com", ".msi", ".bat", ".cmd", ".ps1",
             ".vbs", ".js", ".jar", ".apk", ".app", ".command", ".sh", ".hta"}
SCRIPT_EXTS = {".bat", ".cmd", ".ps1", ".vbs", ".js", ".sh", ".hta", ".command"}
DOC_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
            ".txt", ".jpg", ".jpeg", ".png", ".mp3", ".mp4", ".zip"}
MACRO_EXTS = {".docm", ".xlsm", ".pptm"}

# The first bytes of a file ("magic numbers") reveal its TRUE type, no matter
# what the name says. A file called holiday.jpg that starts with "MZ" is
# actually a Windows program in disguise.
MAGIC_EXEC = (b"MZ", b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
              b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")

# Command patterns commonly seen in malicious scripts (downloaders, droppers).
SUSPICIOUS_SCRIPT_PATTERNS = [
    r"powershell.{0,40}-enc",          # encoded PowerShell command
    r"frombase64string",               # decoding hidden payloads
    r"invoke-expression|\biex\b",      # running text as code
    r"downloadstring|downloadfile",    # fetching code from the internet
    r"certutil.{0,30}-urlcache",       # abusing a Windows tool to download
    r"wscript\.shell",                 # script that launches programs
    r"curl[^\n|]{0,100}\|\s*(ba)?sh",  # "download and run" on Linux/macOS
    r"chmod\s\+x",                     # make a downloaded file runnable
    r"reg\s+add.{0,60}\\run",          # persist across reboots (Windows)
    r"vssadmin.{0,20}delete",          # ransomware: delete backups
]

FEATURES = [
    "double_ext", "rtlo", "disguised_exec", "is_exec", "high_entropy_exec",
    "script_hits", "macro_doc", "exec_in_temp", "hidden_exec",
    # Added in v0.2 (filled in by rules.py and archive.py, not by this file):
    "rule_hits", "encrypted_archive", "archive_bomb",
]

OFFICE_EXTS = {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".odt",
               ".ods", ".odp", ".epub"}  # legitimate files that are really ZIPs


def analyze(path: Path) -> tuple[dict, list[str]]:
    """Inspect one file on disk. Returns (features, human-readable reasons)."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(config.MAX_INSPECT_BYTES)
    except OSError:
        return {k: 0.0 for k in FEATURES}, [
            "Could not read the file (permission denied or in use)."]
    f, reasons = analyze_data(path.name, head, path.parts)
    macro_in_office(path, f, reasons)
    return f, reasons


def macro_in_office(path: Path, f: dict, reasons: list) -> None:
    """Office files are ZIPs; a 'vbaProject.bin' inside means hidden macros."""
    if f["macro_doc"]:
        return
    if path.suffix.lower() in {".docx", ".xlsx", ".pptx", ".doc", ".xls"} \
            and zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as z:
                if any(n.lower().endswith("vbaproject.bin") for n in z.namelist()):
                    f["macro_doc"] = 1.0
                    reasons.append("Office file secretly contains a macro project.")
        except (zipfile.BadZipFile, OSError):
            pass


def analyze_data(name: str, head: bytes, parts: tuple = ()) -> tuple[dict, list[str]]:
    """Inspect a file's name + first bytes.

    WHY this is separate from analyze(path): archive scanning (archive.py)
    needs to judge files that only exist IN MEMORY inside a ZIP, with no path
    on disk. One function that takes (name, bytes) serves both cases.
    """
    f = {k: 0.0 for k in FEATURES}
    reasons: list[str] = []
    ext = Path(name).suffix.lower()

    # 1. Double extension: "invoice.pdf.exe" hides the real type.
    segments = name.lower().split(".")
    if len(segments) >= 3 and ("." + segments[-2]) in DOC_EXTS and ext in EXEC_EXTS:
        f["double_ext"] = 1.0
        reasons.append("Double extension: looks like a document but is a program.")

    # 2. Right-to-left override: an invisible character that REVERSES how a
    #    name is displayed ("photo\u202egpj.exe" displays as "photoexe.jpg").
    if "\u202e" in name:
        f["rtlo"] = 1.0
        reasons.append("Filename contains a hidden right-to-left override character.")

    # 3. True type vs. claimed type, using magic numbers.
    is_exec_magic = head.startswith(MAGIC_EXEC)
    is_exec = is_exec_magic or ext in EXEC_EXTS
    if is_exec:
        f["is_exec"] = 1.0
    if is_exec_magic and ext in DOC_EXTS:
        f["disguised_exec"] = 1.0
        reasons.append(f"Named '{ext}' but its contents are a program.")

    # 4. Packed / encrypted executable.
    if is_exec_magic and len(head) > 4096 and shannon_entropy(head) > 7.2:
        f["high_entropy_exec"] = 1.0
        reasons.append("Program is heavily packed or encrypted (very random bytes).")

    # 5. Suspicious script commands.
    if ext in SCRIPT_EXTS:
        text = head[:262144].decode("utf-8", errors="ignore").lower()
        hits = [p for p in SUSPICIOUS_SCRIPT_PATTERNS if re.search(p, text)]
        f["script_hits"] = float(min(len(hits), 3))
        if hits:
            reasons.append(f"Script uses {len(hits)} command pattern(s) common in malware.")

    # 6. Office file with macros enabled by its extension. (Macros hidden
    #    inside a normal-looking .docx need the file on disk: macro_in_office.)
    if ext in MACRO_EXTS:
        f["macro_doc"] = 1.0
        reasons.append("Office file with macros enabled.")

    # 7. Programs sitting in temp folders or hidden.
    lowered_parts = [p.lower() for p in parts]
    if is_exec and any(p in ("temp", "tmp", "appdata") for p in lowered_parts):
        f["exec_in_temp"] = 1.0
        reasons.append("Program located in a temporary folder.")
    if is_exec and name.startswith("."):
        f["hidden_exec"] = 1.0
        reasons.append("Hidden program file.")

    return f, reasons
