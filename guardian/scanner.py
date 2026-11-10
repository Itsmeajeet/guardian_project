"""The scanner: combines every detection layer into one verdict per file.

Layers, from most to least certain:
  1. Signature match   -> "malicious" (known-bad fingerprint, near-zero false alarms)
  2. Custom rules      -> raise the risk score (rules.py)
  3. Heuristics + AI   -> a probability that the file is malware (heuristics.py, ai_score.py)
  4. Archive contents  -> the same checks on every file INSIDE a zip/tar (archive.py)
  5. Your allowlist    -> can cancel a heuristic false alarm, never a known-malware match
This "defence in depth" idea (several different checks, not one) is how every
real security product is built.
"""

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

from . import __version__, archive, config
from .ai_score import Model
from .allowlist import Allowlist
from .hashing import sha256_bytes, sha256_file
from .heuristics import OFFICE_EXTS, analyze_data, macro_in_office
from .rules import Rules
from .signatures import SignatureDB

RANK = {"clean": 0, "error": 0, "suspicious": 1, "malicious": 2}
BATCH = 64   # how many files are queued for the worker threads at once


@dataclass
class ScanResult:
    path: str
    sha256: str = ""
    verdict: str = "clean"           # clean | suspicious | malicious | error
    score: float = 0.0               # 0.0 - 1.0 probability from the model
    signature: Optional[str] = None  # threat name if a signature matched
    reasons: list = field(default_factory=list)
    factors: list = field(default_factory=list)   # top AI factors
    members_checked: int = 0         # files inspected inside an archive
    cached: bool = False             # True if answered from the scan cache
    quarantined: bool = False        # set by whoever moved the file away


class Engine:
    """Everything needed to judge a file, loaded once and reused.

    WHY a class: loading the signature database, rules and model from disk
    for EVERY file would be painfully slow. Load once, judge many.
    """

    def __init__(self, db: Optional[SignatureDB] = None, model: Optional[Model] = None,
                 rules: Optional[Rules] = None, allow: Optional[Allowlist] = None,
                 scan_archives: bool = True) -> None:
        self.db = db or SignatureDB.load()
        self.model = model or Model.load()
        self.rules = rules or Rules.load()
        self.allow = allow or Allowlist.load()
        self.scan_archives = scan_archives

    def stamp(self) -> str:
        """A fingerprint of the engine's current knowledge.

        The scan cache is only valid if the engine has not changed: new
        signatures, a retrained model, edited rules or a new allowlist entry
        could all change a verdict, so they all change this stamp and
        automatically make old cache entries useless.
        """
        parts = [__version__, str(self.db.updated), str(len(self.db.hashes)),
                 str(len(self.db.bad_urls)), repr(self.model.bias),
                 repr(sorted(self.model.weights.items())), self.rules.version,
                 self.allow.version, str(self.scan_archives)]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:24]

    # ---- judging bytes (used for archive members and for files) ---------
    def _verdict_from(self, res: ScanResult, features: dict) -> None:
        res.score = self.model.predict(features)
        res.factors = self.model.top_factors(features)
        if res.score >= config.MALICIOUS_AT:
            res.verdict = "malicious"
        elif res.score >= config.SUSPICIOUS_AT:
            res.verdict = "suspicious"

    def _apply_rules(self, name: str, data: bytes, features: dict, res: ScanResult) -> None:
        hits = self.rules.match(name, data)
        if hits:
            features["rule_hits"] = float(min(sum(h.severity for h in hits), 3))
            for h in hits:
                res.reasons.append(f"Rule '{h.name}': {h.description}")

    def _apply_allowlist(self, res: ScanResult) -> None:
        if res.sha256 in self.allow and not res.signature and res.verdict != "clean":
            res.reasons.append(f"Was {res.verdict} ({res.score:.0%}) but you allowlisted this exact file.")
            res.verdict, res.score = "clean", 0.0

    def evaluate_bytes(self, name: str, data: bytes) -> ScanResult:
        """Judge a file that exists only in memory (a member of an archive)."""
        res = ScanResult(path=name, sha256=sha256_bytes(data))
        hit = self.db.lookup(res.sha256)
        if hit:
            res.verdict, res.signature, res.score = "malicious", hit, 1.0
            res.reasons.append(f"Matches known threat: {hit}")
            return res
        features, reasons = analyze_data(name, data[:config.MAX_INSPECT_BYTES])
        res.reasons.extend(reasons)
        self._apply_rules(name, data[:config.MAX_INSPECT_BYTES], features, res)
        self._verdict_from(res, features)
        self._apply_allowlist(res)
        return res

    # ---- judging a file on disk ----------------------------------------
    def scan_file(self, path: Path) -> ScanResult:
        path = Path(path)
        res = ScanResult(path=str(path))
        try:
            res.sha256 = sha256_file(path)
            with open(path, "rb") as fh:
                head = fh.read(config.MAX_INSPECT_BYTES)
        except OSError as e:
            res.verdict = "error"
            res.reasons.append(f"Could not read file: {e.strerror or e}")
            return res

        # Layer 1: known-bad fingerprint.
        hit = self.db.lookup(res.sha256)
        if hit:
            res.verdict, res.signature, res.score = "malicious", hit, 1.0
            res.reasons.append(f"Matches known threat: {hit}")
            return res

        # Layers 2-3: heuristics, rules, AI score.
        features, reasons = analyze_data(path.name, head, path.parts)
        macro_in_office(path, features, reasons)
        res.reasons.extend(reasons)
        self._apply_rules(path.name, head, features, res)

        # Layer 4: look inside archives.
        members = []
        kind = archive.archive_kind(path.name, head, OFFICE_EXTS) if self.scan_archives else ""
        if kind:
            rep = archive.inspect(path, kind, self.evaluate_bytes)
            res.members_checked = rep.members_checked
            members = rep.findings
            if rep.encrypted:
                features["encrypted_archive"] = 1.0
                res.reasons.append("Password-protected archive: its contents cannot be inspected.")
            if rep.bomb:
                features["archive_bomb"] = 1.0
                res.reasons.append("Archive expands to a huge size (possible zip bomb).")
            res.reasons.extend(rep.notes)

        self._verdict_from(res, features)

        # The archive is as dangerous as the worst thing inside it.
        for display, m in members:
            res.reasons.append(f"Inside {display}: {m.reasons[0] if m.reasons else m.verdict}")
            if m.signature and not res.signature:
                res.signature = f"{m.signature} (inside archive)"
            if RANK[m.verdict] > RANK[res.verdict]:
                res.verdict = m.verdict
            res.score = max(res.score, m.score)

        self._apply_allowlist(res)
        return res


# ---- convenience wrappers (keep the simple API from v0.1 working) -------
def scan_file(path: Path, db: SignatureDB, model: Model) -> ScanResult:
    return Engine(db, model).scan_file(path)


def _safe_scan(engine: Engine, path: Path) -> ScanResult:
    """Never let one weird file crash a 500,000-file scan."""
    try:
        return engine.scan_file(path)
    except Exception as e:  # deliberate: report and carry on
        return ScanResult(path=str(path), verdict="error",
                          reasons=[f"Internal error while scanning: {type(e).__name__}: {e}"])


def _walk_files(target: Path) -> Iterator[Path]:
    for root, _dirs, files in os.walk(target):
        for name in files:
            p = Path(root) / name
            if p.is_symlink():
                continue  # never follow links: they can loop or escape the folder
            yield p


def scan_path(target: Path, db: Optional[SignatureDB] = None, model: Optional[Model] = None,
              *, engine: Optional[Engine] = None, workers: Optional[int] = None,
              use_cache: bool = False, store=None) -> Iterator[ScanResult]:
    """Scan a file, or walk a whole folder, yielding results as they finish.

    WHY threads: scanning is mostly waiting for the disk and hashing (both
    release Python's global lock), so several files can be processed at once
    and a big folder scans several times faster.

    WHY batches: queueing 500,000 files at once would eat memory, so we feed
    the workers 64 at a time and yield each batch's results in order.

    WHY the cache is touched only on this (the calling) thread: a SQLite
    connection must not be shared between threads, so workers never see it.
    """
    from .history import Store
    engine = engine or Engine(db, model)
    target = Path(target)
    own_store = False
    if use_cache and store is None:
        store, own_store = Store(), True
    stamp = engine.stamp() if store else ""
    workers = workers or min(8, (os.cpu_count() or 2))
    paths = iter([target]) if target.is_file() else _walk_files(target)

    def drain(pending):
        for p, st, fut in pending:
            res = fut.result()
            if store and st:
                store.cache_put(str(p), st.st_size, st.st_mtime_ns, stamp, res)
            yield res
        pending.clear()
        if store:
            store.commit()

    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            pending = []
            for p in paths:
                st = None
                if store:
                    try:
                        st = p.stat()
                        cached = store.cache_get(str(p), st.st_size, st.st_mtime_ns, stamp)
                        if cached:
                            yield cached
                            continue
                    except OSError:
                        st = None
                pending.append((p, st, pool.submit(_safe_scan, engine, p)))
                if len(pending) >= BATCH:
                    yield from drain(pending)
            yield from drain(pending)
    finally:
        if own_store:
            store.close()
