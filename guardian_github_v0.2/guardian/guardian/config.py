"""Where Guardian keeps its files, and the settings every module shares.

WHY this file exists: every module needs to agree on one place to store the
signature database, the quarantine folder and the AI model. Putting those
paths in ONE file means you change them in one place, and tests can point
them at a temporary folder by setting the GUARDIAN_HOME environment variable.
"""

import os
from pathlib import Path


def home() -> Path:
    """Return (and create) Guardian's data folder.

    Path.home() works on Windows, macOS and Linux, so the same code runs on
    every desktop operating system. That is the heart of "cross-platform".
    """
    base = Path(os.environ.get("GUARDIAN_HOME", Path.home() / ".guardian"))
    base.mkdir(parents=True, exist_ok=True)
    return base


def signatures_path() -> Path:
    return home() / "signatures.json"


def model_path() -> Path:
    return home() / "model.json"


def quarantine_dir() -> Path:
    d = home() / "quarantine"
    d.mkdir(parents=True, exist_ok=True)
    return d


def feeds_path() -> Path:
    return home() / "feeds.json"


def rules_path() -> Path:
    return home() / "rules.json"


def allowlist_path() -> Path:
    return home() / "allowlist.json"


def db_path() -> Path:
    """One SQLite file holds scan history and the scan cache."""
    return home() / "guardian.db"


# Files bigger than this are only hashed, not deeply inspected. Reading a
# 4 GB video into memory to look for scripts would freeze the computer.
MAX_INSPECT_BYTES = 2 * 1024 * 1024

# Verdict thresholds for the AI score (a probability from 0.0 to 1.0).
SUSPICIOUS_AT = 0.40
MALICIOUS_AT = 0.90
