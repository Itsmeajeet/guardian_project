"""Allowlist: files YOU have decided are safe (the cure for false positives).

Every detector makes mistakes. Without an allowlist, one wrong alarm on a
program you trust would nag you forever, and users learn to ignore warnings
(or uninstall the scanner). So we let the user say "this exact file is fine".

SAFETY DESIGN:
  * We allowlist by SHA-256 hash, not by file name or folder. If malware
    replaces the file, the hash changes and the exemption no longer applies.
  * It only overrides the AI/heuristic/rule verdicts. A match in the
    known-malware signature database still wins: you cannot accidentally
    allowlist known malware.
"""

import hashlib
import json
import time

from . import config


class Allowlist:
    def __init__(self, items: dict) -> None:
        self.items = items  # sha256 -> {"note": str, "time": float}

    @classmethod
    def load(cls) -> "Allowlist":
        p = config.allowlist_path()
        if p.exists():
            try:
                data = json.loads(p.read_text())
                if isinstance(data, dict):
                    return cls({k.lower(): v for k, v in data.items() if isinstance(v, dict)})
            except (json.JSONDecodeError, OSError):
                pass
        return cls({})

    def save(self) -> None:
        config.allowlist_path().write_text(json.dumps(self.items, indent=2))

    def add(self, sha256: str, note: str = "") -> None:
        self.items[sha256.lower()] = {"note": note[:200], "time": time.time()}
        self.save()

    def remove(self, sha256: str) -> bool:
        existed = self.items.pop(sha256.lower(), None) is not None
        if existed:
            self.save()
        return existed

    def __contains__(self, sha256: str) -> bool:
        return sha256.lower() in self.items

    @property
    def version(self) -> str:
        return hashlib.sha256(",".join(sorted(self.items)).encode()).hexdigest()[:16]
