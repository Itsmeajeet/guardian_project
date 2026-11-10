"""Command-line interface: how a human (or another program) drives Guardian.

WHY build the CLI before the window app: it is the easiest thing to test and
script, and the window app is just a friendlier face on the same functions.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

from . import __version__, autoruns, config, updater
from .advisor import advice_for, ask_ai, explain
from .ai_score import Model
from .allowlist import Allowlist
from .hashing import sha256_file
from .history import Store
from .quarantine import list_quarantined, quarantine_file, restore
from .report import write_report
from .rules import Rules
from .scanner import Engine, scan_path
from .signatures import SignatureDB
from .urlcheck import check_url
from .watcher import default_downloads, watch

ICON = {"clean": "[ OK ]", "suspicious": "[WARN]", "malicious": "[BAD ]", "error": "[ERR ]"}


def cmd_scan(a) -> int:
    engine = Engine(scan_archives=not a.no_archives)
    store = None if a.no_history else Store()
    scan_id = store.start_scan(a.path) if store else None
    flagged, total, bad, susp, cached = [], 0, 0, 0, 0
    started = time.time()
    try:
        for r in scan_path(Path(a.path), engine=engine, workers=a.workers,
                           use_cache=not a.no_cache, store=store):
            total += 1
            cached += r.cached
            if r.verdict == "malicious":
                bad += 1
                if a.quarantine:
                    dest = quarantine_file(Path(r.path), r.sha256, "; ".join(r.reasons))
                    r.quarantined = True
                    r.reasons.append(f"Moved to quarantine: {dest.name}")
            elif r.verdict == "suspicious":
                susp += 1
            if r.verdict in ("suspicious", "malicious", "error") or a.verbose:
                if r.verdict != "clean":
                    flagged.append(r)
                print(f"{ICON[r.verdict]} {r.path}  ({r.score:.0%})")
                for reason in r.reasons:
                    print(f"         - {reason}")
                if store and r.verdict != "clean":
                    store.add_finding(scan_id, r)
    finally:
        if store:
            store.finish_scan(scan_id, total, len(flagged))
            store.close()
    took = time.time() - started
    extra = f", {cached} from cache" if cached else ""
    print(f"\nScanned {total} file(s) in {took:.1f}s{extra}; {bad} malicious, {susp} suspicious.")
    if a.report:
        out = write_report(flagged, total, a.path, a.report)
        print(f"Report saved: {out}")
    return 1 if bad else 0


def cmd_watch(a) -> int:
    folder = Path(a.folder) if a.folder else default_downloads()
    print(f"Guarding {folder}  (Ctrl+C to stop)")

    def show(r):
        print(ICON[r.verdict], r.path)
        if r.verdict != "clean":
            print(explain(r))

    try:
        watch(folder, show, auto_quarantine=not a.no_quarantine)
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


def cmd_url(a) -> int:
    risk, why = check_url(a.url)
    label = "HIGH RISK" if risk >= 60 else "CAUTION" if risk >= 30 else "looks OK"
    print(f"{a.url}\nRisk {risk}/100 - {label}")
    for w in why:
        print(" -", w)
    return 1 if risk >= 60 else 0


def cmd_update(_a) -> int:
    for name, status in updater.update_all().items():
        print(f"{name}: {status}")
    return 0


def cmd_explain(a) -> int:
    engine = Engine()
    for r in scan_path(Path(a.path), engine=engine):
        print(ask_ai(r) if a.ai else explain(r))
        print()
    return 0


def cmd_train(a) -> int:
    """Retrain the AI from a CSV: columns = feature names..., label (1 bad / 0 clean)."""
    import csv
    from .heuristics import FEATURES
    samples = []
    with open(a.csv, newline="") as f:
        for row in csv.DictReader(f):
            feats = {k: float(row.get(k, 0) or 0) for k in FEATURES}
            samples.append((feats, int(row["label"])))
    model = Model.load()
    model.train(samples)
    model.save()
    print(f"Retrained on {len(samples)} samples; model saved.")
    return 0


def cmd_quarantine(a) -> int:
    if a.restore:
        print("Restored to", restore(a.restore))
    else:
        items = list_quarantined()
        for name, e in items.items():
            print(f"{name}  <-  {e['original']}")
        if not items:
            print("Quarantine is empty.")
    return 0


def cmd_allow(a) -> int:
    allow = Allowlist.load()
    if a.list:
        for h, v in allow.items.items():
            print(f"{h}  {v.get('note', '')}")
        if not allow.items:
            print("Allowlist is empty.")
        return 0
    if a.remove:
        print("Removed." if allow.remove(a.remove) else "That hash was not on the list.")
        return 0
    if not a.target:
        print("Give a file to allowlist, or use --list / --remove.")
        return 2
    p = Path(a.target)
    h = sha256_file(p) if p.is_file() else a.target
    if len(h) != 64:
        print("Not a file, and not a 64-character SHA-256 hash.")
        return 2
    allow.add(h, a.note or (p.name if p.is_file() else ""))
    print(f"Allowlisted {h[:16]}...  (only this exact file content; known malware can never be allowlisted)")
    return 0


def cmd_history(a) -> int:
    with Store() as s:
        if a.scan:
            for path, verdict, score, sig, reasons in s.findings_for(a.scan):
                print(f"{verdict.upper():10} {score:4.0%}  {path}")
                for r in reasons:
                    print(f"             - {r}")
            return 0
        rows = s.recent_scans(a.n)
        if not rows:
            print("No scans recorded yet.")
        for sid, start, fin, target, files, flagged in rows:
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(start))
            print(f"#{sid:<4} {when}  {files or 0:>6} files  {flagged or 0:>3} flagged  {target}")
        if rows:
            print("\nSee the details of one scan with: guardian history --scan <number>")
    return 0


def cmd_autoruns(a) -> int:
    entries = autoruns.collect()
    if a.json:
        print(json.dumps([{"source": e.source, "name": e.name, "command": e.command,
                           "risk": e.risk, "reasons": e.reasons} for e in entries], indent=2))
        return 0
    if not entries:
        print("No startup entries found (or this system keeps them somewhere Guardian does not read).")
        return 0
    for e in sorted(entries, key=lambda e: ("high", "medium", "low").index(e.risk)):
        tag = {"high": "[HIGH]", "medium": "[MED ]", "low": "[ ok ]"}[e.risk]
        print(f"{tag} {e.name}\n         {e.command[:110]}\n         ({e.source})")
        for r in e.reasons:
            print(f"         ! {r}")
    flagged = sum(1 for e in entries if e.reasons)
    print(f"\n{len(entries)} startup entries, {flagged} worth a look. Guardian never changes them; you decide.")
    return 1 if any(e.risk == "high" for e in entries) else 0


def cmd_status(_a) -> int:
    db = SignatureDB.load()
    rules = Rules.load()
    allow = Allowlist.load()
    with Store() as s:
        st = s.stats()
    age = "never updated" if not db.updated else \
        f"updated {(time.time() - db.updated) / 86400:.1f} days ago"
    print(f"Guardian {__version__}")
    print(f"  Signatures : {len(db.hashes):,} file hashes, {len(db.bad_urls):,} bad URLs ({age})")
    print(f"  Rules      : {len(rules.rules)} active  ({config.rules_path()})")
    print(f"  Allowlist  : {len(allow.items)} trusted files")
    print(f"  Quarantine : {len(list_quarantined())} items")
    print(f"  History    : {st['scans']} scans, {st['findings']} findings, {st['cached_files']} cached files")
    print(f"  Data folder: {config.home()}")
    if not db.updated:
        print("\nTip: run 'guardian update' to download fresh threat data.")
    return 0


def cmd_rules(a) -> int:
    rules = Rules.load()
    if a.path:
        print(config.rules_path())
        return 0
    for r in rules.rules:
        print(f"[sev {r.severity}] {r.name}: {r.description}")
    print(f"\n{len(rules.rules)} rules. Edit {config.rules_path()} to add your own.")
    return 0


def cmd_gui(_a) -> int:
    from .gui import run
    run()
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="guardian", description="Guardian security scanner")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a file or folder (looks inside zip/tar archives too)")
    s.add_argument("path")
    s.add_argument("-q", "--quarantine", action="store_true", help="move malicious files to quarantine")
    s.add_argument("-v", "--verbose", action="store_true", help="also list clean files")
    s.add_argument("--report", metavar="FILE", help="save a report (.html or .json)")
    s.add_argument("--workers", type=int, help="number of parallel scan threads")
    s.add_argument("--no-cache", action="store_true", help="re-check every file, ignore the cache")
    s.add_argument("--no-archives", action="store_true", help="do not look inside archives")
    s.add_argument("--no-history", action="store_true", help="do not record this scan")
    s.set_defaults(fn=cmd_scan)

    w = sub.add_parser("watch", help="guard a folder (default: Downloads)")
    w.add_argument("folder", nargs="?"); w.add_argument("--no-quarantine", action="store_true")
    w.set_defaults(fn=cmd_watch)

    u = sub.add_parser("url", help="check a link before clicking")
    u.add_argument("url"); u.set_defaults(fn=cmd_url)

    sub.add_parser("update", help="download fresh threat data").set_defaults(fn=cmd_update)

    e = sub.add_parser("explain", help="plain-language explanation of a scan")
    e.add_argument("path"); e.add_argument("--ai", action="store_true")
    e.set_defaults(fn=cmd_explain)

    t = sub.add_parser("train", help="retrain the AI model from a CSV")
    t.add_argument("csv"); t.set_defaults(fn=cmd_train)

    q = sub.add_parser("quarantine", help="list or restore quarantined files")
    q.add_argument("--restore"); q.set_defaults(fn=cmd_quarantine)

    al = sub.add_parser("allow", help="mark an exact file as safe (fixes false alarms)")
    al.add_argument("target", nargs="?", help="a file, or a SHA-256 hash")
    al.add_argument("--note"); al.add_argument("--list", action="store_true")
    al.add_argument("--remove", metavar="HASH"); al.set_defaults(fn=cmd_allow)

    h = sub.add_parser("history", help="show past scans")
    h.add_argument("-n", type=int, default=10); h.add_argument("--scan", type=int)
    h.set_defaults(fn=cmd_history)

    au = sub.add_parser("autoruns", help="audit programs that start automatically (read-only)")
    au.add_argument("--json", action="store_true"); au.set_defaults(fn=cmd_autoruns)

    sub.add_parser("status", help="show what Guardian knows and when it last updated").set_defaults(fn=cmd_status)

    r = sub.add_parser("rules", help="list the detection rules")
    r.add_argument("--path", action="store_true", help="print where the rules file is"); r.set_defaults(fn=cmd_rules)

    sub.add_parser("gui", help="open the window app").set_defaults(fn=cmd_gui)

    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except BrokenPipeError:
        # `guardian scan . | head`: the reader closed early. That is normal,
        # not an error. Point stdout at /dev/null so Python does not complain
        # again while shutting down.
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except (OSError, ValueError, AttributeError):
            pass
        return 0
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
