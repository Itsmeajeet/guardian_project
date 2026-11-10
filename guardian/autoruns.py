"""Startup audit: list everything that launches automatically, and flag the odd.

WHY: after getting onto a computer, malware wants to SURVIVE A REBOOT. It does
that by adding itself to the places the operating system runs on startup. That
is called "persistence", and checking those places is one of the most
effective ways to find an infection that a file scan missed.

READ-ONLY: this module only LISTS and JUDGES. It never edits or removes
anything, because deleting a startup entry blindly can break a legitimate
program. You decide, then remove it yourself.

Where each OS keeps startup entries:
  Windows : registry "Run" keys, and the Startup folders
  macOS   : LaunchAgents / LaunchDaemons (.plist files)
  Linux   : ~/.config/autostart/*.desktop, systemd user services, crontab
"""

import os
import plistlib
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .heuristics import SUSPICIOUS_SCRIPT_PATTERNS

RISKY_LOCATIONS = ("/tmp/", "/var/tmp/", "/dev/shm/", "\\temp\\", "\\downloads\\",
                   "/downloads/", "\\appdata\\local\\temp")


@dataclass
class Entry:
    source: str                 # where we found it
    name: str
    command: str
    reasons: list = field(default_factory=list)

    @property
    def risk(self) -> str:
        n = len(self.reasons)
        return "high" if n >= 2 else "medium" if n == 1 else "low"


def assess(command: str) -> list:
    """Return the reasons a startup command looks suspicious (may be empty)."""
    reasons = []
    low = command.lower().replace("\\\\", "\\")
    hits = [p for p in SUSPICIOUS_SCRIPT_PATTERNS if re.search(p, low)]
    if hits:
        reasons.append("Command uses patterns common in malware (encoded, download-and-run, etc.).")
    if any(loc in low for loc in RISKY_LOCATIONS):
        reasons.append("Runs a program from a temporary or Downloads folder.")
    if re.search(r"https?://", low):
        reasons.append("Fetches something from the internet at startup.")
    return reasons


def _make(source: str, name: str, command: str) -> Entry:
    return Entry(source, name, command.strip(), assess(command))


def _linux(home: Path, include_cron: bool) -> list:
    out = []
    for d, key, label in ((home / ".config" / "autostart", "Exec=", "autostart"),
                          (home / ".config" / "systemd" / "user", "ExecStart=", "systemd user service")):
        if not d.is_dir():
            continue
        for f in sorted(d.iterdir()):
            if f.suffix not in (".desktop", ".service"):
                continue
            try:
                for line in f.read_text(errors="ignore").splitlines():
                    if line.startswith(key):
                        out.append(_make(f"{label}: {f}", f.name, line[len(key):]))
            except OSError:
                continue
    if include_cron:
        try:
            r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if line.strip() and not line.lstrip().startswith("#"):
                    out.append(_make("crontab", line.split()[0] if line.split() else "cron", line))
        except (OSError, subprocess.SubprocessError):
            pass
    return out


def _macos(home: Path) -> list:
    out = []
    for d in (home / "Library" / "LaunchAgents", Path("/Library/LaunchAgents"),
              Path("/Library/LaunchDaemons")):
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.plist")):
            try:
                with open(f, "rb") as fh:
                    pl = plistlib.load(fh)
                args = pl.get("ProgramArguments") or [pl.get("Program", "")]
                out.append(_make(f"LaunchAgent: {f}", pl.get("Label", f.stem), " ".join(map(str, args))))
            except Exception:  # corrupt or binary plists: skip, never crash
                continue
    return out


def _windows() -> list:
    out = []
    try:
        import winreg
    except ImportError:
        return out
    keys = [(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce")]
    for root, path, label in keys:
        try:
            with winreg.OpenKey(root, path) as k:   # opened read-only
                i = 0
                while True:
                    try:
                        name, value, _t = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    out.append(_make(f"Registry {label}", name, str(value)))
                    i += 1
        except OSError:
            continue
    for env, sub in (("APPDATA", r"Microsoft\Windows\Start Menu\Programs\Startup"),
                     ("PROGRAMDATA", r"Microsoft\Windows\Start Menu\Programs\StartUp")):
        base = os.environ.get(env)
        if base and (Path(base) / sub).is_dir():
            for f in sorted((Path(base) / sub).iterdir()):
                out.append(_make("Startup folder", f.name, str(f)))
    return out


def collect(home: Optional[Path] = None, platform: Optional[str] = None,
            include_cron: bool = True) -> list:
    """Gather startup entries for this OS. Parameters exist so tests can fake them."""
    home = Path(home) if home else Path.home()
    platform = platform or sys.platform
    if platform.startswith("win"):
        return _windows()
    if platform == "darwin":
        return _macos(home)
    return _linux(home, include_cron)
