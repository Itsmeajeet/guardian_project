"""Scan history and the scan cache, stored in one SQLite database.

WHY SQLite instead of JSON files: history grows without limit and we need to
ask questions ("show the last 10 scans", "is this exact file already checked?").
SQLite is a real database that ships INSIDE Python, needs no server, handles
crashes safely, and works on every operating system.

SECURITY NOTE: every value goes into SQL through `?` placeholders, never by
pasting text into the query string. File names are attacker-controlled; pasting
them into SQL would allow "SQL injection".
"""

import dataclasses
import json
import sqlite3
import time
from typing import Optional

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started REAL NOT NULL, finished REAL,
    target TEXT NOT NULL, files INTEGER DEFAULT 0, flagged INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL, path TEXT NOT NULL, sha256 TEXT,
    verdict TEXT NOT NULL, score REAL, signature TEXT, reasons TEXT, time REAL);
CREATE TABLE IF NOT EXISTS cache (
    path TEXT PRIMARY KEY, size INTEGER, mtime_ns INTEGER,
    stamp TEXT, result TEXT);
"""


class Store:
    def __init__(self) -> None:
        self.db = sqlite3.connect(str(config.db_path()), timeout=15)
        self.db.executescript(SCHEMA)
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- history -----------------------------------------------------
    def start_scan(self, target: str) -> int:
        cur = self.db.execute("INSERT INTO scans (started, target) VALUES (?, ?)",
                              (time.time(), str(target)))
        self.db.commit()
        return cur.lastrowid

    def add_finding(self, scan_id: int, r) -> None:
        self.db.execute(
            "INSERT INTO findings (scan_id, path, sha256, verdict, score, signature, reasons, time) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, r.path, r.sha256, r.verdict, r.score, r.signature,
             json.dumps(r.reasons), time.time()))

    def finish_scan(self, scan_id: int, files: int, flagged: int) -> None:
        self.db.execute("UPDATE scans SET finished=?, files=?, flagged=? WHERE id=?",
                        (time.time(), files, flagged, scan_id))
        self.db.commit()

    def recent_scans(self, n: int = 10) -> list:
        cur = self.db.execute(
            "SELECT id, started, finished, target, files, flagged FROM scans "
            "ORDER BY id DESC LIMIT ?", (n,))
        return cur.fetchall()

    def findings_for(self, scan_id: int) -> list:
        cur = self.db.execute(
            "SELECT path, verdict, score, signature, reasons FROM findings "
            "WHERE scan_id=? ORDER BY id", (scan_id,))
        return [(p, v, s, sig, json.loads(r or "[]")) for p, v, s, sig, r in cur.fetchall()]

    # ---- cache -------------------------------------------------------
    def cache_get(self, path: str, size: int, mtime_ns: int, stamp: str):
        """Return a cached ScanResult if this exact file was already judged by
        this exact engine (same signatures, model, rules and allowlist)."""
        from .scanner import ScanResult
        row = self.db.execute(
            "SELECT result FROM cache WHERE path=? AND size=? AND mtime_ns=? AND stamp=?",
            (path, size, mtime_ns, stamp)).fetchone()
        if not row:
            return None
        try:
            r = ScanResult(**json.loads(row[0]))
            r.cached = True
            return r
        except (TypeError, json.JSONDecodeError):
            return None

    def cache_put(self, path: str, size: int, mtime_ns: int, stamp: str, r) -> None:
        if r.verdict == "error":
            return
        self.db.execute(
            "INSERT OR REPLACE INTO cache (path, size, mtime_ns, stamp, result) VALUES (?, ?, ?, ?, ?)",
            (path, size, mtime_ns, stamp, json.dumps(dataclasses.asdict(r))))

    def commit(self) -> None:
        self.db.commit()

    def stats(self) -> dict:
        q = lambda sql: self.db.execute(sql).fetchone()[0]
        return {"scans": q("SELECT COUNT(*) FROM scans"),
                "findings": q("SELECT COUNT(*) FROM findings"),
                "cached_files": q("SELECT COUNT(*) FROM cache")}
