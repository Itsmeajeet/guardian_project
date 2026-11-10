"""The signature database: a list of fingerprints of things known to be bad.

This is "signature-based detection", the oldest and still most important
layer of any antivirus. It is fast and has almost no false alarms, but it can
only catch threats somebody has ALREADY seen. That weakness is why we add
heuristics and an AI score on top (see heuristics.py and ai_score.py).
"""

import json
import time
from typing import Optional

from . import config
from .hashing import sha256_bytes

# The EICAR test string is an industry-standard HARMLESS file that every
# antivirus is meant to flag. It lets you test a scanner without real malware.
# (Built from two halves only so this source file itself is easy to read.)
# Joined at runtime on purpose: Python merges adjacent literals into ONE string
# in the compiled .pyc file, and antivirus products (correctly!) flag any file
# containing the full EICAR string, including a cached .pyc of this module.
EICAR = b"".join([
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$",
    b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
])


class SignatureDB:
    def __init__(self) -> None:
        self.hashes: dict[str, str] = {}   # sha256 -> threat name
        self.bad_urls: set[str] = set()    # known-malicious URLs / hosts
        self.updated: float = 0.0
        # Seed entry so a fresh install can already pass the EICAR test.
        self.hashes[sha256_bytes(EICAR)] = "EICAR-Test-File"

    # ---- persistence -------------------------------------------------
    @classmethod
    def load(cls) -> "SignatureDB":
        db = cls()
        path = config.signatures_path()
        if path.exists():
            try:
                data = json.loads(path.read_text())
                db.hashes.update(data.get("hashes", {}))
                db.bad_urls.update(data.get("bad_urls", []))
                db.updated = data.get("updated", 0.0)
            except (json.JSONDecodeError, OSError):
                pass  # a corrupt file must never crash the scanner
        return db

    def save(self) -> None:
        config.signatures_path().write_text(
            json.dumps(
                {
                    "hashes": self.hashes,
                    "bad_urls": sorted(self.bad_urls),
                    "updated": self.updated,
                }
            )
        )

    # ---- use ---------------------------------------------------------
    def lookup(self, sha256: str) -> Optional[str]:
        return self.hashes.get(sha256.lower())

    def add_hashes(self, items: dict[str, str]) -> int:
        before = len(self.hashes)
        for h, name in items.items():
            h = h.strip().lower()
            if len(h) == 64 and all(c in "0123456789abcdef" for c in h):
                self.hashes[h] = name
        self.updated = time.time()
        return len(self.hashes) - before

    def add_urls(self, urls: set[str]) -> int:
        before = len(self.bad_urls)
        self.bad_urls.update(u.strip().lower() for u in urls if u.strip())
        self.updated = time.time()
        return len(self.bad_urls) - before
