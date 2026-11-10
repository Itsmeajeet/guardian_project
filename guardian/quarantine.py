"""Quarantine: isolate a dangerous file instead of deleting it.

WHY not delete: detections can be wrong (false positives). If Guardian deleted
your thesis because of a bad guess, that would be worse than the "virus".
Quarantine moves the file into a safe folder, renames it so it cannot be
double-clicked by accident, and remembers where it came from so you can restore it.
"""

import json
import os
import shutil
import time
from pathlib import Path

from . import config


def _index_path() -> Path:
    return config.quarantine_dir() / "index.json"


def _load_index() -> dict:
    p = _index_path()
    if p.exists():
        try:
            return json.loads(p.read_text())
        except json.JSONDecodeError:
            return {}
    return {}


def quarantine_file(path: Path, sha256: str, reason: str) -> Path:
    path = Path(path)
    dest = config.quarantine_dir() / f"{sha256[:16]}-{int(time.time())}.quar"
    shutil.move(str(path), dest)
    try:
        os.chmod(dest, 0o600)  # owner read/write only; no execute bit
    except OSError:
        pass
    idx = _load_index()
    idx[dest.name] = {"original": str(path), "sha256": sha256,
                      "reason": reason, "time": time.time()}
    _index_path().write_text(json.dumps(idx, indent=2))
    return dest


def list_quarantined() -> dict:
    return _load_index()


def restore(name: str) -> Path:
    idx = _load_index()
    entry = idx.get(name)
    if not entry:
        raise KeyError(f"No quarantined item called {name}")
    original = Path(entry["original"])
    original.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(config.quarantine_dir() / name), original)
    del idx[name]
    _index_path().write_text(json.dumps(idx, indent=2))
    return original
