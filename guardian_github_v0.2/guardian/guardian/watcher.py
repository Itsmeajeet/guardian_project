"""Real-time protection for downloads: watch a folder and scan new files.

WHY polling: every operating system has its own "file changed" notification
system (inotify on Linux, FSEvents on macOS, ReadDirectoryChangesW on
Windows). Libraries like `watchdog` wrap them. To keep this project free of
dependencies and easy to read, we simply check the folder every second or two.
It is simple, works everywhere, and is plenty fast for downloads.
"""

import time
from pathlib import Path
from typing import Callable

from .quarantine import quarantine_file
from .scanner import Engine, ScanResult


def default_downloads() -> Path:
    return Path.home() / "Downloads"


def _wait_until_stable(path: Path, tries: int = 10) -> bool:
    """A browser writes a download gradually. Scanning a half-written file
    gives wrong answers, so wait until its size stops changing."""
    last = -1
    for _ in range(tries):
        try:
            size = path.stat().st_size
        except OSError:
            return False
        if size == last:
            return True
        last = size
        time.sleep(0.5)
    return True


def watch(folder: Path, on_result: Callable[[ScanResult], None],
          auto_quarantine: bool = True, interval: float = 1.5,
          stop: Callable[[], bool] = lambda: False) -> None:
    folder = Path(folder)
    engine = Engine()
    seen = {p for p in folder.iterdir() if p.is_file()}
    while not stop():
        try:
            current = {p for p in folder.iterdir() if p.is_file()}
        except OSError:
            time.sleep(interval)
            continue
        for p in sorted(current - seen):
            # Ignore partial-download markers from common browsers.
            if p.suffix.lower() in {".crdownload", ".part", ".tmp", ".download"}:
                continue
            if not _wait_until_stable(p):
                continue
            res = engine.scan_file(p)
            if auto_quarantine and res.verdict == "malicious":
                quarantine_file(p, res.sha256, "; ".join(res.reasons))
                res.quarantined = True
                res.reasons.append("Moved to quarantine.")
            on_result(res)
        seen = current
        time.sleep(interval)
