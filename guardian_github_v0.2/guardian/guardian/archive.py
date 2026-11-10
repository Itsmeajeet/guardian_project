"""Archive scanning: look INSIDE .zip / .tar files without unpacking to disk.

WHY: malware almost never arrives as a bare program. It arrives zipped
("invoice.zip") because email and chat filters ignore what is inside.

SAFETY RULES (every one of these stops a real attack technique):
  * Never extract to disk. A malicious archive can contain a path like
    "../../startup/evil.exe" ("zip-slip") that writes outside the folder you
    chose. We only ever read members into memory, so there is nothing to escape.
  * Cap everything: member count, size per member, total size, nesting depth.
    A "zip bomb" is a tiny file that expands to terabytes; limits make the
    scanner finish quickly instead of running out of memory.
  * Never trust sizes written in the archive header (attackers can lie). We
    read at most MAX_MEMBER_BYTES+1 bytes and see what we really got.
  * A malformed archive must never crash the scan. It becomes a note.
"""

import io
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Callable

MAX_MEMBERS = 2000
MAX_MEMBER_BYTES = 20 * 1024 * 1024
MAX_TOTAL_BYTES = 200 * 1024 * 1024
MAX_DEPTH = 2           # an archive inside an archive inside an archive: stop there
BOMB_RATIO = 100        # expands 100x or more (and is not tiny) => suspicious
BOMB_MIN_BYTES = 1024 * 1024

TAR_EXTS = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")
ZIP_MAGIC = b"PK\x03\x04"


@dataclass
class ArchiveReport:
    members_checked: int = 0
    findings: list = field(default_factory=list)   # [(member display name, ScanResult)]
    encrypted: bool = False
    bomb: bool = False
    notes: list = field(default_factory=list)


class _Budget:
    def __init__(self) -> None:
        self.used = 0


def archive_kind(name: str, head: bytes, office_exts: set) -> str:
    """Return 'zip', 'tar' or '' for a file, judged by CONTENT, not just name."""
    lower = name.lower()
    ext = "." + lower.rsplit(".", 1)[-1] if "." in lower else ""
    if head.startswith(ZIP_MAGIC) and ext not in office_exts:
        return "zip"   # includes .jar and .apk, which are ZIPs too
    if lower.endswith(TAR_EXTS):
        return "tar"
    return ""


def is_encrypted(info: "zipfile.ZipInfo") -> bool:
    """Bit 0 of a ZIP entry's flags means 'password protected'."""
    return bool(info.flag_bits & 0x1)


def inspect(source, kind: str, evaluate: Callable, depth: int = 0,
            prefix: str = "", report: "ArchiveReport | None" = None,
            budget: "_Budget | None" = None) -> ArchiveReport:
    """Walk an archive. `source` is a path or an in-memory BytesIO.

    `evaluate(name, data)` is supplied by the scanner and returns a ScanResult;
    passing it in (instead of importing the scanner) avoids circular imports
    and keeps this module independent and easy to test.
    """
    report = report or ArchiveReport()
    budget = budget or _Budget()
    if kind == "zip":
        _walk_zip(source, evaluate, depth, prefix, report, budget)
    else:
        _walk_tar(source, evaluate, depth, prefix, report, budget)
    return report


def _record(report, display, name, data, evaluate, depth, prefix, budget):
    res = evaluate(PurePosixPath(name).name or name, data)
    report.members_checked += 1
    if res.verdict != "clean":
        report.findings.append((display, res))
    if depth < MAX_DEPTH:
        if data.startswith(ZIP_MAGIC):
            inspect(io.BytesIO(data), "zip", evaluate, depth + 1, display + "!/", report, budget)
        elif name.lower().endswith(TAR_EXTS):
            inspect(io.BytesIO(data), "tar", evaluate, depth + 1, display + "!/", report, budget)


def _walk_zip(source, evaluate, depth, prefix, report, budget):
    # Broad `except Exception` is deliberate in this file: archive parsers
    # raise many different errors on hostile input, and a scanner must
    # degrade to a note rather than crash.
    try:
        zf = zipfile.ZipFile(source)
    except Exception as e:
        report.notes.append(f"{prefix or 'archive'}: could not be opened ({type(e).__name__})")
        return
    with zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            if report.members_checked >= MAX_MEMBERS:
                report.notes.append("Archive has too many files; the rest were not inspected.")
                return
            display = prefix + info.filename
            if is_encrypted(info):
                report.encrypted = True
                continue
            ratio = info.file_size / max(info.compress_size, 1)
            if info.file_size >= BOMB_MIN_BYTES and ratio >= BOMB_RATIO:
                report.bomb = True
            if info.file_size > MAX_MEMBER_BYTES:
                report.notes.append(f"{display}: too large to inspect")
                continue
            if budget.used + info.file_size > MAX_TOTAL_BYTES:
                report.notes.append("Archive is too large overall; the rest was not inspected.")
                return
            try:
                with zf.open(info) as fh:
                    data = fh.read(MAX_MEMBER_BYTES + 1)
            except Exception as e:
                report.notes.append(f"{display}: unreadable ({type(e).__name__})")
                continue
            if len(data) > MAX_MEMBER_BYTES:
                report.bomb = True
                report.notes.append(f"{display}: larger than its header claims")
                continue
            budget.used += len(data)
            _record(report, display, info.filename, data, evaluate, depth, prefix, budget)


def _walk_tar(source, evaluate, depth, prefix, report, budget):
    try:
        if isinstance(source, (str, bytes)) or hasattr(source, "__fspath__"):
            tf = tarfile.open(source, mode="r:*")
        else:
            tf = tarfile.open(fileobj=source, mode="r:*")
    except Exception as e:
        report.notes.append(f"{prefix or 'archive'}: could not be opened ({type(e).__name__})")
        return
    with tf:
        try:
            for member in tf:   # streaming: never loads the whole archive
                if not member.isfile():
                    continue    # skips symlinks, devices and directories
                if report.members_checked >= MAX_MEMBERS:
                    report.notes.append("Archive has too many files; the rest were not inspected.")
                    return
                display = prefix + member.name
                if member.size > MAX_MEMBER_BYTES:
                    # Stop here: skipping past a huge compressed member would
                    # force us to decompress all of it (a CPU bomb).
                    report.bomb = True
                    report.notes.append(f"{display}: too large to inspect; stopped scanning here")
                    return
                if budget.used + member.size > MAX_TOTAL_BYTES:
                    report.notes.append("Archive is too large overall; the rest was not inspected.")
                    return
                fh = tf.extractfile(member)
                if fh is None:
                    continue
                data = fh.read(MAX_MEMBER_BYTES + 1)
                budget.used += len(data)
                _record(report, display, member.name, data, evaluate, depth, prefix, budget)
        except Exception as e:
            report.notes.append(f"{prefix or 'archive'}: stopped early ({type(e).__name__})")
